package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/authz"
	"net/http"
	"strings"
	"time"
)

type abuseMutation struct {
	Source   string          `json:"source"`
	Reason   string          `json:"reason"`
	Evidence json.RawMessage `json:"evidence"`
}
type abuseRestrictionInput struct {
	SubjectType  string     `json:"subject_type"`
	SubjectValue string     `json:"subject_value"`
	UserID       *uuid.UUID `json:"user_id"`
	TeamID       *uuid.UUID `json:"team_id"`
	Action       string     `json:"action"`
	ExpiresAt    *time.Time `json:"expires_at"`
	abuseMutation
}

// All abuse mutations serialize state-change ID allocation with commit order.
// Without this, a later transaction can commit a larger sequence value first,
// causing generation readers to miss the earlier transaction when it commits.
const abuseMutationLockKey int64 = 0x53534142555345

func (h *Handlers) withAbuseMutation(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, abuseMutationLockKey); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) requireAbuse(c *gin.Context, write bool) (uuid.UUID, bool) {
	actor, err := internalActorID(c)
	if err != nil {
		return uuid.Nil, false
	}
	if err = h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actor); err != nil {
		if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrForbidden)
		} else {
			respondError(c, ErrInternal)
		}
		return uuid.Nil, false
	}
	perm := "platform:abuse:read"
	if write {
		perm = "platform:abuse:write"
	}
	if err = h.rbacService().RequirePlatformPermission(c.Request.Context(), actor, perm); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
		} else {
			respondError(c, ErrInternal)
		}
		return uuid.Nil, false
	}
	return actor, true
}
func (h *Handlers) GetPlatformAbuseTeamTrust(c *gin.Context) {
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	if _, ok := h.requireAbuse(c, false); !ok {
		return
	}
	var out struct {
		TeamID    uuid.UUID       `json:"team_id"`
		Verified  bool            `json:"verified"`
		Source    string          `json:"source"`
		Reason    *string         `json:"reason,omitempty"`
		Evidence  json.RawMessage `json:"evidence"`
		UpdatedAt time.Time       `json:"updated_at"`
	}
	err = h.Pool.QueryRow(c, `SELECT team_id,verified,source,reason,evidence,updated_at FROM abuse_team_trust WHERE team_id=$1`, team).Scan(&out.TeamID, &out.Verified, &out.Source, &out.Reason, &out.Evidence, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		out.TeamID = team
		out.Evidence = json.RawMessage(`{}`)
	} else if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) SetPlatformAbuseTeamTrust(c *gin.Context) {
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	var in struct {
		Verified bool `json:"verified"`
		abuseMutation
	}
	if c.ShouldBindJSON(&in) != nil {
		respondError(c, ErrBadRequest)
		return
	}
	ev := in.Evidence
	if len(ev) == 0 {
		ev = []byte(`{}`)
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "platform_admin"
	}
	err = h.withAbuseMutation(c, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c, `INSERT INTO abuse_team_trust(team_id,verified,source,reason,evidence,updated_at,revoked_at) VALUES($1,$2,$3,$4,$5,now(),CASE WHEN $2 THEN NULL ELSE now() END) ON CONFLICT(team_id) DO UPDATE SET verified=EXCLUDED.verified,source=EXCLUDED.source,reason=EXCLUDED.reason,evidence=EXCLUDED.evidence,updated_at=now(),revoked_at=EXCLUDED.revoked_at`, team, in.Verified, source, in.Reason, ev); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(team_id,reason) VALUES($1,'team trust changed')`, team); err != nil {
			return err
		}
		auditValue, err := json.Marshal(struct {
			Verified bool            `json:"verified"`
			Source   string          `json:"source"`
			Reason   string          `json:"reason,omitempty"`
			Evidence json.RawMessage `json:"evidence"`
		}{in.Verified, source, in.Reason, ev})
		if err != nil {
			return err
		}
		_, err = tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,team_id,event_type,new_value,metadata) VALUES($1,$2,'abuse.team_trust.changed',$3,$4)`, actor, team, auditValue, `{"source":"platform_admin"}`)
		return err
	})
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) ListPlatformAbuseRestrictions(c *gin.Context) {
	if _, ok := h.requireAbuse(c, false); !ok {
		return
	}
	rows, err := h.Pool.Query(c, `SELECT id,subject_type,subject_value,subject_user_id,subject_team_id,action,source,reason,evidence,created_at,expires_at,released_at FROM abuse_restrictions WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at>now()) ORDER BY created_at DESC`)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var typ, val, act, src, reason string
		var uid, tid *uuid.UUID
		var ev []byte
		var created time.Time
		var exp, rel *time.Time
		if err := rows.Scan(&id, &typ, &val, &uid, &tid, &act, &src, &reason, &ev, &created, &exp, &rel); err != nil {
			respondError(c, ErrInternal)
			return
		}
		out = append(out, gin.H{"id": id, "subject_type": typ, "subject_value": val, "user_id": uid, "team_id": tid, "action": act, "source": src, "reason": reason, "evidence": json.RawMessage(ev), "created_at": created, "expires_at": exp, "released_at": rel})
	}
	if err := rows.Err(); err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) CreatePlatformAbuseRestriction(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	var in abuseRestrictionInput
	if c.ShouldBindJSON(&in) != nil || in.Reason == "" {
		respondError(c, ErrBadRequest)
		return
	}
	switch in.SubjectType {
	case "user":
		if in.UserID == nil {
			respondError(c, ErrBadRequest)
			return
		}
		// UUID-backed subjects use the typed ID as their canonical value so
		// listings, audit records, and resolution cannot disagree.
		in.SubjectValue = in.UserID.String()
	case "team":
		if in.TeamID == nil {
			respondError(c, ErrBadRequest)
			return
		}
		in.SubjectValue = in.TeamID.String()
	case "ip":
		var err error
		in.SubjectValue, err = abuse.NormalizeIP(in.SubjectValue)
		if err != nil {
			respondError(c, ErrBadRequest)
			return
		}
	case "domain":
		var err error
		in.SubjectValue, err = abuse.NormalizeDomain(in.SubjectValue)
		if err != nil {
			respondError(c, ErrBadRequest)
			return
		}
	default:
		respondError(c, ErrBadRequest)
		return
	}
	if in.SubjectValue == "" || in.Action == "" {
		respondError(c, ErrBadRequest)
		return
	}
	id := uuid.New()
	ev := in.Evidence
	if len(ev) == 0 {
		ev = []byte(`{}`)
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "platform_admin"
	}
	auditValue, err := json.Marshal(struct {
		ID           uuid.UUID       `json:"id"`
		SubjectType  string          `json:"subject_type"`
		SubjectValue string          `json:"subject_value"`
		UserID       *uuid.UUID      `json:"user_id,omitempty"`
		TeamID       *uuid.UUID      `json:"team_id,omitempty"`
		Action       string          `json:"action"`
		Source       string          `json:"source"`
		Reason       string          `json:"reason"`
		Evidence     json.RawMessage `json:"evidence"`
		ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
	}{id, in.SubjectType, in.SubjectValue, in.UserID, in.TeamID, in.Action, source, in.Reason, ev, in.ExpiresAt})
	if err != nil {
		respondError(c, ErrBadRequest)
		return
	}
	err = h.withAbuseMutation(c, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c, `INSERT INTO abuse_restrictions(id,subject_type,subject_value,subject_user_id,subject_team_id,action,source,reason,evidence,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, in.SubjectType, in.SubjectValue, in.UserID, in.TeamID, in.Action, source, in.Reason, ev, actor, in.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(team_id,reason) VALUES($1,'restriction changed')`, in.TeamID); err != nil {
			return err
		}
		_, err := tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,team_id,event_type,new_value,metadata) VALUES($1,$2,'abuse.restriction.created',$3,$4)`, actor, in.TeamID, auditValue, `{"source":"platform_admin"}`)
		return err
	})
	if err != nil {
		if isAbuseValidationError(err) {
			respondError(c, ErrBadRequest)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// isAbuseValidationError identifies database errors caused by invalid input
// or violated abuse-control constraints. Unexpected transaction/store errors
// must remain internal failures so callers can retry them appropriately.
func isAbuseValidationError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "22") || strings.HasPrefix(pgErr.Code, "23")
}

func (h *Handlers) ReleasePlatformAbuseRestriction(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	id, err := parseUUIDParam(c, "restriction_id")
	if err != nil {
		return
	}
	err = h.withAbuseMutation(c, func(tx pgx.Tx) error {
		result, err := tx.Exec(c, `UPDATE abuse_restrictions SET released_at=now(),released_by=$2,updated_at=now() WHERE id=$1 AND released_at IS NULL`, id, actor)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(reason) VALUES('restriction released')`); err != nil {
			return err
		}
		auditValue, err := json.Marshal(struct {
			ID       uuid.UUID `json:"id"`
			Released bool      `json:"released"`
		}{id, true})
		if err != nil {
			return err
		}
		_, err = tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,event_type,new_value) VALUES($1,'abuse.restriction.released',$2)`, actor, auditValue)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			respondError(c, err)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	c.Status(http.StatusNoContent)
}
func (h *Handlers) RecordPlatformAbuseRefresh(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	var in struct {
		TeamID *uuid.UUID `json:"team_id"`
		Reason string     `json:"reason"`
	}
	if c.ShouldBindJSON(&in) != nil {
		respondError(c, ErrBadRequest)
		return
	}
	err := h.withAbuseMutation(c, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(team_id,reason) VALUES($1,COALESCE(NULLIF($2,''),'refresh requested'))`, in.TeamID, in.Reason); err != nil {
			return err
		}
		_, err := tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,team_id,event_type,metadata) VALUES($1,$2,'abuse.state.refresh_requested',$3)`, actor, in.TeamID, []byte(`{"source":"platform_admin"}`))
		return err
	})
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) ListPlatformAbuseTrustedIdentities(c *gin.Context) {
	if _, ok := h.requireAbuse(c, false); !ok {
		return
	}
	rows, err := h.Pool.Query(c, `SELECT id,auth_provider,domain,source,evidence,created_at,updated_at,revoked_at FROM abuse_trusted_identities ORDER BY domain`)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var p, d, s string
		var ev []byte
		var cr, up time.Time
		var rv *time.Time
		if err := rows.Scan(&id, &p, &d, &s, &ev, &cr, &up, &rv); err != nil {
			respondError(c, ErrInternal)
			return
		}
		out = append(out, gin.H{"id": id, "auth_provider": p, "domain": d, "source": s, "evidence": json.RawMessage(ev), "created_at": cr, "updated_at": up, "revoked_at": rv})
	}
	if err := rows.Err(); err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, out)
}
func (h *Handlers) AddPlatformAbuseTrustedIdentity(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	var in struct {
		AuthProvider string          `json:"auth_provider"`
		Domain       string          `json:"domain"`
		Source       string          `json:"source"`
		Evidence     json.RawMessage `json:"evidence"`
	}
	if c.ShouldBindJSON(&in) != nil {
		respondError(c, ErrBadRequest)
		return
	}
	p := strings.ToLower(strings.TrimSpace(in.AuthProvider))
	d, e := abuse.NormalizeDomain(in.Domain)
	if p == "" || e != nil {
		respondError(c, ErrBadRequest)
		return
	}
	if len(in.Evidence) == 0 {
		in.Evidence = []byte(`{}`)
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "platform_admin"
	}
	id := uuid.New()
	e = h.withAbuseMutation(c, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c, `INSERT INTO abuse_trusted_identities(id,auth_provider,domain,source,evidence) VALUES($1,$2,$3,$4,$5)`, id, p, d, source, in.Evidence); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(reason) VALUES('trusted identity changed')`); err != nil {
			return err
		}
		auditValue, err := json.Marshal(struct {
			ID           uuid.UUID       `json:"id"`
			State        string          `json:"state"`
			AuthProvider string          `json:"auth_provider"`
			Domain       string          `json:"domain"`
			Source       string          `json:"source"`
			Evidence     json.RawMessage `json:"evidence"`
		}{id, "active", p, d, source, in.Evidence})
		if err != nil {
			return err
		}
		_, err = tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,event_type,new_value) VALUES($1,'abuse.trusted_identity.created',$2)`, actor, auditValue)
		return err
	})
	if e != nil {
		if isAbuseValidationError(e) {
			respondError(c, ErrBadRequest)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}
func (h *Handlers) RevokePlatformAbuseTrustedIdentity(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	id, e := parseUUIDParam(c, "identity_id")
	if e != nil {
		return
	}
	e = h.withAbuseMutation(c, func(tx pgx.Tx) error {
		result, err := tx.Exec(c, `UPDATE abuse_trusted_identities SET revoked_at=now(),updated_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(reason) VALUES('trusted identity changed')`); err != nil {
			return err
		}
		auditValue, err := json.Marshal(struct {
			ID      uuid.UUID `json:"id"`
			State   string    `json:"state"`
			Revoked bool      `json:"revoked"`
		}{id, "revoked", true})
		if err != nil {
			return err
		}
		_, err = tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,event_type,new_value) VALUES($1,'abuse.trusted_identity.revoked',$2)`, actor, auditValue)
		return err
	})
	if e != nil {
		if errors.Is(e, ErrConflict) {
			respondError(c, ErrConflict)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	c.Status(http.StatusNoContent)
}
