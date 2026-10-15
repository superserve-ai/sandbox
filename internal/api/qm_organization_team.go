package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type qmTeamResult struct {
	QMOrgID        string `json:"qm_org_id"`
	IdempotencyKey string `json:"idempotency_key"`
	SSTeamID       string `json:"ss_team_id"`
	Namespace      string `json:"namespace"`
	AuthorityID    string `json:"authority_id"`
}

type qmTeamConfig struct{ namespace, authority, region, token string }

var qmTeamNamespace = regexp.MustCompile(`^[a-z][a-z0-9-]{2,39}$`)
var errQMTeamConflict = errors.New("organization team binding conflict")
var errQMTeamGone = errors.New("organization backing team deleted")

func canonicalQMUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}

// This credential belongs only to the central QM provisioning service. Customer
// keys and the host-shared internal token cannot authorize resource creation.
func (h *Handlers) QMOrganizationTeamHandler() gin.HandlerFunc {
	cfg := qmTeamConfig{os.Getenv("QM_TEAM_NAMESPACE"), os.Getenv("QM_TEAM_AUTHORITY_ID"), os.Getenv("QM_TEAM_REGION"), os.Getenv("QM_TEAM_SERVICE_TOKEN")}
	for _, key := range []string{"INTERNAL_API_TOKEN", "OPERATOR_API_TOKEN", "QM_AUTH_SERVICE_TOKEN", "TEAM_CREATION_INTERNAL_TOKEN"} {
		if cfg.token == os.Getenv(key) {
			cfg.token = ""
		}
	}
	return qmOrganizationTeamHandler(h.Pool, cfg)
}

func qmOrganizationTeamHandler(pool *pgxpool.Pool, cfg qmTeamConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		tokens := c.Request.Header.Values("X-QM-Team-Service-Token")
		c.Request.Header.Del("X-QM-Team-Service-Token")
		if len(cfg.token) < 32 || len(cfg.token) > 4096 || !qmTeamNamespace.MatchString(cfg.namespace) || !canonicalQMUUID(cfg.authority) || (cfg.region != "use" && cfg.region != "usw") {
			c.AbortWithStatusJSON(503, gin.H{"error": "team_service_unavailable"})
			return
		}
		if len(tokens) != 1 || len(tokens[0]) > 4096 || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(cfg.token)) != 1 {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_service_credential"})
			return
		}
		org := c.Param("qm_org_id")
		if !canonicalQMUUID(org) {
			c.AbortWithStatusJSON(400, gin.H{"error": "invalid_org"})
			return
		}
		key := "qm-org:v1:" + org
		if c.Request.Method == http.MethodPost {
			var input struct {
				IdempotencyKey string `json:"idempotency_key"`
			}
			body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 1024))
			if err != nil || decodeUniqueJSON(body, &input) != nil || input.IdempotencyKey != key || c.Request.URL.RawQuery != "" {
				c.AbortWithStatusJSON(400, gin.H{"error": "invalid_idempotency_key"})
				return
			}
		} else if c.Request.Method != http.MethodGet || len(c.Request.URL.Query()) != 1 || len(c.Request.URL.Query()["idempotency_key"]) != 1 || c.Query("idempotency_key") != key {
			c.AbortWithStatusJSON(400, gin.H{"error": "invalid_idempotency_key"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if pool == nil {
			c.AbortWithStatusJSON(503, gin.H{"error": "team_service_unavailable"})
			return
		}
		var result qmTeamResult
		var err error
		if c.Request.Method == http.MethodPost {
			result, err = ensureQMTeam(ctx, pool, cfg, org)
		} else {
			result, err = readQMTeam(ctx, pool, cfg, org)
		}
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			c.JSON(404, gin.H{"error": "organization_team_absent", "qm_org_id": org, "idempotency_key": key, "namespace": cfg.namespace, "authority_id": cfg.authority})
		case errors.Is(err, errQMTeamGone):
			c.JSON(410, gin.H{"error": "organization_team_deleted"})
		case errors.Is(err, errQMTeamConflict):
			c.JSON(409, gin.H{"error": "organization_team_conflict"})
		case err != nil:
			c.JSON(503, gin.H{"error": "team_service_unavailable"})
		default:
			c.JSON(200, result)
		}
	}
}

func readQMTeam(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, cfg qmTeamConfig, org string) (qmTeamResult, error) {
	var authority, regionIdentity string
	if err := q.QueryRow(ctx, `SELECT authority_id::text,home_region FROM qm_team_service_authority WHERE namespace=$1`, cfg.namespace).Scan(&authority, &regionIdentity); err != nil || authority != cfg.authority || regionIdentity != cfg.region {
		return qmTeamResult{}, errQMTeamConflict
	}
	result := qmTeamResult{QMOrgID: org, Namespace: cfg.namespace}
	var liveID *string
	var region string
	err := q.QueryRow(ctx, `SELECT b.idempotency_key,b.team_id::text,b.authority_id::text,b.home_region,t.id::text
 FROM qm_organization_teams b LEFT JOIN team t ON t.id=b.team_id AND t.home_region=b.home_region AND b.deleted_at IS NULL
 WHERE b.namespace=$1 AND b.qm_org_id=$2`, cfg.namespace, org).Scan(&result.IdempotencyKey, &result.SSTeamID, &result.AuthorityID, &region, &liveID)
	if err != nil {
		return qmTeamResult{}, err
	}
	if result.AuthorityID != cfg.authority || region != cfg.region || result.IdempotencyKey != "qm-org:v1:"+org {
		return qmTeamResult{}, errQMTeamConflict
	}
	if liveID == nil {
		return qmTeamResult{}, errQMTeamGone
	}
	return result, nil
}

func ensureQMTeam(ctx context.Context, pool *pgxpool.Pool, cfg qmTeamConfig, org string) (qmTeamResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return qmTeamResult{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "qm-org:"+cfg.namespace+":"+org); err != nil {
		return qmTeamResult{}, err
	}
	result, err := readQMTeam(ctx, tx, cfg, org)
	if err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	id := uuid.NewString()
	// Names are not ownership evidence. A conflicting name aborts this transaction.
	if _, err = tx.Exec(ctx, `INSERT INTO team(id,name,home_region) VALUES($1,$2,$3)`, id, "qm-"+cfg.namespace+"-"+org, cfg.region); err != nil {
		return qmTeamResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO qm_organization_teams(namespace,qm_org_id,idempotency_key,authority_id,team_id,home_region) VALUES($1,$2,$3,$4,$5,$6)`, cfg.namespace, org, "qm-org:v1:"+org, cfg.authority, id, cfg.region); err != nil {
		return qmTeamResult{}, err
	}
	result, err = readQMTeam(ctx, tx, cfg, org)
	if err != nil {
		return qmTeamResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return qmTeamResult{}, err
	}
	return result, nil
}
