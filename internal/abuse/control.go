// Package abuse contains the authoritative, cache-independent abuse state
// contract consumed by reconciliation and lifecycle caches.
package abuse

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type Action string

const (
	ActionSignup Action = "signup"
	ActionCreate Action = "create"
	ActionResume Action = "resume"
)

type Request struct {
	UserID, TeamID uuid.UUID
	IP, Domain     string
	// AuthProvider identifies the provider for the corporate identity represented
	// by Domain. A matching active association grants the same trust precedence
	// as an explicitly verified team.
	AuthProvider  string
	Action        Action
	GlobalEnabled bool
}
type Decision struct {
	Allowed       bool
	Reason        string
	RestrictionID *uuid.UUID
	// ExpiresAt lets downstream caches stop serving a denial when the
	// authoritative restriction expires without a state-change row.
	ExpiresAt  *time.Time
	Generation int64
}

// IsTrustedIdentity checks the runtime-managed provider/domain association.
// Resolve applies a matching active association as a trust signal for the
// request; it is not a user record or deploy-time list.
func IsTrustedIdentity(ctx context.Context, q db.DBTX, provider, domain string) (bool, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	var err error
	domain, err = NormalizeDomain(domain)
	if err != nil || provider == "" {
		return false, err
	}
	var ok bool
	err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM abuse_trusted_identities WHERE auth_provider=$1 AND domain=$2 AND revoked_at IS NULL)`, provider, domain).Scan(&ok)
	return ok, err
}

// NormalizeIP accepts exactly one address and deliberately rejects CIDR.
func NormalizeIP(value string) (string, error) {
	v := strings.TrimSpace(value)
	if strings.Contains(v, "/") {
		return "", fmt.Errorf("CIDR is not supported")
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	return ip.String(), nil
}
func NormalizeDomain(value string) (string, error) {
	v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if v == "" || strings.ContainsAny(v, "*/") || strings.Contains(v, "..") {
		return "", fmt.Errorf("invalid exact domain")
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid exact domain")
		}
	}
	return v, nil
}

// Resolve reads current state on every call. Verified teams and approved
// corporate identities take precedence over restrictions, and released/expired
// rows are never applicable.
func Resolve(ctx context.Context, q db.DBTX, req Request) (Decision, error) {
	if !isSupportedAction(req.Action) {
		return Decision{}, fmt.Errorf("unsupported abuse action %q", req.Action)
	}
	if !req.GlobalEnabled {
		return Decision{Allowed: true, Reason: "global_off"}, nil
	}
	// Capture the invalidation token before reading trust state. If a trust or
	// identity mutation races this evaluation, the decision retains the older
	// token and downstream caches are forced to re-evaluate it.
	generation, err := currentGeneration(ctx, q, req.TeamID)
	if err != nil {
		return Decision{}, err
	}
	var verified bool
	if err := q.QueryRow(ctx, `SELECT COALESCE(verified,false) AND revoked_at IS NULL FROM abuse_team_trust WHERE team_id=$1`, req.TeamID).Scan(&verified); err != nil && err != pgx.ErrNoRows {
		return Decision{}, err
	}
	if verified {
		return currentDecision(ctx, q, req, true, generation)
	}
	if req.AuthProvider != "" && req.Domain != "" {
		trusted, err := IsTrustedIdentity(ctx, q, req.AuthProvider, req.Domain)
		if err != nil {
			return Decision{}, err
		}
		if trusted {
			decision, err := currentDecision(ctx, q, req, true, generation)
			if err == nil {
				decision.Reason = "trusted_identity"
			}
			return decision, err
		}
	}
	return currentDecision(ctx, q, req, false, generation)
}

func isSupportedAction(action Action) bool {
	switch action {
	case ActionSignup, ActionCreate, ActionResume:
		return true
	default:
		return false
	}
}

func currentGeneration(ctx context.Context, q db.DBTX, teamID uuid.UUID) (int64, error) {
	var generation int64
	if err := q.QueryRow(ctx, `SELECT COALESCE(MAX(id),0) FROM abuse_state_changes WHERE team_id=$1 OR team_id IS NULL`, teamID).Scan(&generation); err != nil {
		return 0, err
	}
	return generation, nil
}

func currentDecision(ctx context.Context, q db.DBTX, req Request, verified bool, generation int64) (Decision, error) {
	var id uuid.UUID
	if verified {
		return Decision{Allowed: true, Reason: "verified_team", Generation: generation}, nil
	}
	var ipValue, domainValue string
	if req.IP != "" {
		ip, err := NormalizeIP(req.IP)
		if err != nil {
			return Decision{}, err
		}
		ipValue = ip
	}
	if req.Domain != "" {
		domain, err := NormalizeDomain(req.Domain)
		if err != nil {
			return Decision{}, err
		}
		domainValue = domain
	}
	if req.UserID == uuid.Nil && req.TeamID == uuid.Nil && ipValue == "" && domainValue == "" {
		return Decision{Allowed: true, Reason: "no_restriction", Generation: generation}, nil
	}
	// Subject references and canonical values are checked independently so an
	// IP can never satisfy a domain restriction (or vice versa).
	var expiresAt *time.Time
	err := q.QueryRow(ctx, `SELECT id,expires_at FROM abuse_restrictions WHERE action=$1 AND released_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AND ((subject_type='user' AND subject_user_id=$2) OR (subject_type='team' AND subject_team_id=$3) OR (subject_type='ip' AND subject_value=$4) OR (subject_type='domain' AND subject_value=$5)) ORDER BY created_at DESC LIMIT 1`, string(req.Action), req.UserID, req.TeamID, ipValue, domainValue).Scan(&id, &expiresAt)
	if err == nil {
		return Decision{Allowed: false, Reason: "active_restriction", RestrictionID: &id, ExpiresAt: expiresAt, Generation: generation}, nil
	}
	if err != pgx.ErrNoRows {
		return Decision{}, err
	}
	return Decision{Allowed: true, Reason: "no_restriction", Generation: generation}, nil
}

// ActiveAt is useful to workers re-checking state immediately before action.
func ActiveAt(expires *time.Time, released *time.Time, now time.Time) bool {
	return released == nil && (expires == nil || expires.After(now))
}
