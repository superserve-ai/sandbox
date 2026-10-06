package abuse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

var ErrInvalidIncident = errors.New("invalid mining incident")

type incidentPool interface {
	Begin(context.Context) (pgx.Tx, error)
}

// IncidentStore is a host-bound service, not a tenant-facing ingest API. The
// assignments source is populated from host-owned network state, never guests.
type IncidentStore struct {
	pool        incidentPool
	hostID      string
	assignments MiningPolicySource
}

func NewIncidentStore(pool incidentPool, hostID string, assignments MiningPolicySource) *IncidentStore {
	return &IncidentStore{pool: pool, hostID: hostID, assignments: assignments}
}

func incidentDigest(i MiningIncident) (string, error) {
	if i.ID == uuid.Nil || i.SandboxID == uuid.Nil || i.TeamID == uuid.Nil || i.HostID == "" || len(i.HostID) > 256 || i.Assignment == "" || len(i.Assignment) > 256 || i.ObservedAt.IsZero() || len(i.Evidence.Kind) == 0 || len(i.Evidence.Kind) > 64 || len(i.Evidence.Indicator) == 0 || len(i.Evidence.Indicator) > 2048 || len(i.Evidence.PolicyRevision) > 256 {
		return "", ErrInvalidIncident
	}
	if _, err := netip.ParseAddr(i.HostIP); err != nil {
		return "", ErrInvalidIncident
	}
	// Canonical UTC and database timestamp precision make retry bodies stable.
	i.ObservedAt = i.ObservedAt.UTC().Truncate(time.Microsecond)
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *IncidentStore) RecordIncident(ctx context.Context, i MiningIncident) (IncidentReceipt, error) {
	digest, err := incidentDigest(i)
	if err != nil {
		return IncidentReceipt{}, err
	}
	if s.hostID == "" || i.HostID != s.hostID || s.pool == nil {
		return IncidentReceipt{}, ErrInvalidIncident
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IncidentReceipt{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, MutationLockKey); err != nil {
		return IncidentReceipt{}, err
	}
	var oldDigest, oldHost string
	err = tx.QueryRow(ctx, `SELECT body_digest,host_id FROM abuse_mining_incidents WHERE id=$1`, i.ID).Scan(&oldDigest, &oldHost)
	if err == nil {
		if oldDigest != digest || oldHost != s.hostID {
			return IncidentReceipt{}, fmt.Errorf("%w: incident body changed", ErrInvalidIncident)
		}
		receipt, err := s.status(ctx, tx, i.ID)
		if err != nil {
			return receipt, err
		}
		return receipt, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IncidentReceipt{}, err
	}
	// A reused ID on another host is rejected by the global primary key as well.
	if s.assignments == nil {
		return IncidentReceipt{}, ErrInvalidIncident
	}
	assignment, ok := s.assignments.MiningPolicy(i.SandboxID, i.HostIP)
	if !ok {
		if source, supportsRetirement := s.assignments.(interface{ AssignmentRetired(MiningIncident) bool }); supportsRetirement && source.AssignmentRetired(i) {
			return IncidentReceipt{}, fmt.Errorf("%w: retired assignment", ErrInvalidIncident)
		}
		// Startup reattachment and expired trust can temporarily hide a valid
		// assignment. Keep its durable observation until authority becomes known.
		return IncidentReceipt{}, errors.New("mining attribution temporarily unavailable")
	}
	if assignment.TeamID != i.TeamID || assignment.HostID != i.HostID || assignment.Assignment != i.Assignment {
		return IncidentReceipt{}, fmt.Errorf("%w: stale assignment", ErrInvalidIncident)
	}
	var team uuid.UUID
	var host string
	err = tx.QueryRow(ctx, `SELECT team_id,host_id FROM sandbox WHERE id=$1 AND destroyed_at IS NULL FOR SHARE`, i.SandboxID).Scan(&team, &host)
	if errors.Is(err, pgx.ErrNoRows) {
		return IncidentReceipt{}, fmt.Errorf("%w: sandbox no longer assigned", ErrInvalidIncident)
	}
	if err != nil {
		return IncidentReceipt{}, err
	}
	if team != i.TeamID || host != s.hostID {
		return IncidentReceipt{}, fmt.Errorf("%w: foreign sandbox", ErrInvalidIncident)
	}
	policy, err := ResolveTeamPolicy(ctx, tx, team)
	if err != nil {
		return IncidentReceipt{}, err
	}
	var releaseGeneration int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(id),0) FROM abuse_state_changes WHERE reason='restriction released' AND (team_id=$1 OR team_id IS NULL)`, team).Scan(&releaseGeneration); err != nil {
		return IncidentReceipt{}, err
	}
	receipt := IncidentReceipt{IncidentID: i.ID, Disposition: IncidentIgnored}
	if policy.Trusted {
		receipt.Disposition = IncidentExempt
	} else if policy.Known && policy.Mode == ModeEnforce && i.Generation >= releaseGeneration {
		receipt.Disposition = IncidentApplied
		receipt.RestrictionID = uuid.New()
	}
	evidence, err := json.Marshal(i)
	if err != nil {
		return receipt, err
	}
	if receipt.Disposition == IncidentApplied {
		_, err = tx.Exec(ctx, `INSERT INTO abuse_restrictions(id,subject_type,subject_value,subject_team_id,action,source,reason,evidence) VALUES($1,'team',$2,$3,'create','mining_detector','host mining policy match',$4)`, receipt.RestrictionID, team.String(), team, evidence)
		if err != nil {
			return receipt, err
		}
	}
	var restriction any
	if receipt.RestrictionID != uuid.Nil {
		restriction = receipt.RestrictionID
	}
	_, err = tx.Exec(ctx, `INSERT INTO abuse_mining_incidents(id,host_id,sandbox_id,team_id,assignment,body_digest,disposition,restriction_id,evidence,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, i.ID, s.hostID, i.SandboxID, team, i.Assignment, digest, string(receipt.Disposition), restriction, evidence, i.ObservedAt)
	if err != nil {
		return receipt, err
	}
	// General audit records carry identifiers, not private destination evidence.
	auditValue, err := json.Marshal(struct {
		IncidentID    uuid.UUID           `json:"incident_id"`
		SandboxID     uuid.UUID           `json:"sandbox_id"`
		RestrictionID uuid.UUID           `json:"restriction_id"`
		Disposition   IncidentDisposition `json:"disposition"`
	}{i.ID, i.SandboxID, receipt.RestrictionID, receipt.Disposition})
	if err != nil {
		return receipt, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(team_id,event_type,new_value,metadata) VALUES($1,'abuse.mining_incident.recorded',$2,$3)`, team, auditValue, `{"source":"mining_detector","actor_type":"host"}`); err != nil {
		return receipt, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO abuse_state_changes(team_id,reason) VALUES($1,'mining incident recorded')`, team); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit(ctx)
}

func (s *IncidentStore) IncidentStatus(ctx context.Context, id uuid.UUID) (IncidentReceipt, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IncidentReceipt{}, err
	}
	defer tx.Rollback(ctx)
	receipt, err := s.status(ctx, tx, id)
	if err != nil {
		return receipt, err
	}
	return receipt, tx.Commit(ctx)
}

func (s *IncidentStore) status(ctx context.Context, q db.DBTX, id uuid.UUID) (IncidentReceipt, error) {
	var team uuid.UUID
	var restriction *uuid.UUID
	var disposition string
	var active bool
	err := q.QueryRow(ctx, `SELECT i.team_id,i.disposition,i.restriction_id,COALESCE(r.released_at IS NULL AND (r.expires_at IS NULL OR r.expires_at>now()) AND r.id IS NOT NULL,false) FROM abuse_mining_incidents i LEFT JOIN abuse_restrictions r ON r.id=i.restriction_id WHERE i.id=$1 AND i.host_id=$2`, id, s.hostID).Scan(&team, &disposition, &restriction, &active)
	receipt := IncidentReceipt{IncidentID: id, Disposition: IncidentDisposition(disposition)}
	if err != nil {
		return receipt, err
	}
	if restriction != nil {
		receipt.RestrictionID = *restriction
	}
	if receipt.Disposition != IncidentApplied {
		return receipt, nil
	}
	if !active {
		receipt.Disposition = IncidentReleased
		return receipt, nil
	}
	policy, err := ResolveTeamPolicy(ctx, q, team)
	if err != nil {
		return receipt, err
	}
	if policy.Trusted {
		receipt.Disposition = IncidentExempt
	} else if !policy.Known || policy.Mode != ModeEnforce {
		receipt.Disposition = IncidentIgnored
	}
	return receipt, nil
}
