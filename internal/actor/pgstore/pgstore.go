// Package pgstore is the Postgres-backed actor.Store. Each lease operation maps
// to the single atomic UPDATE defined in db/queries/actors.sql, so the
// single-writer invariant (proven against the in-memory reference in
// internal/actor) holds for real under Postgres MVCC — concurrent acquirers
// serialize on the row lock and exactly one wins.
package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/db"
)

// PgStore implements actor.Store over sqlc-generated queries.
type PgStore struct {
	q *db.Queries
}

// New builds a PgStore from a sqlc Queries handle.
func New(q *db.Queries) *PgStore { return &PgStore{q: q} }

// compile-time checks that PgStore satisfies the contracts.
var (
	_ actor.Store      = (*PgStore)(nil)
	_ actor.AlarmStore = (*PgStore)(nil)
)

// SetAlarm schedules a wake for actorID at fireAt (Epic 5.5).
func (s *PgStore) SetAlarm(ctx context.Context, actorID string, fireAt time.Time) (actor.Alarm, error) {
	aid, err := uuid.Parse(actorID)
	if err != nil {
		return actor.Alarm{}, err
	}
	row, err := s.q.CreateActorAlarm(ctx, db.CreateActorAlarmParams{ActorID: aid, FireAt: fireAt})
	if err != nil {
		return actor.Alarm{}, err
	}
	return actor.Alarm{ID: row.ID.String(), ActorID: actorID, FireAt: row.FireAt}, nil
}

// DueAlarms returns alarms whose FireAt <= now (due-indexed), oldest first.
func (s *PgStore) DueAlarms(ctx context.Context, now time.Time, limit int) ([]actor.Alarm, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.DueActorAlarms(ctx, db.DueActorAlarmsParams{FireAt: now, Limit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]actor.Alarm, 0, len(rows))
	for _, r := range rows {
		out = append(out, actor.Alarm{ID: r.ID.String(), ActorID: r.ActorID.String(), FireAt: r.FireAt})
	}
	return out, nil
}

// DeleteAlarm removes a fired alarm.
func (s *PgStore) DeleteAlarm(ctx context.Context, id string) error {
	aid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	return s.q.DeleteActorAlarm(ctx, aid)
}

func (s *PgStore) GetOrCreate(ctx context.Context, teamID, name string, defaults actor.Actor, _ time.Time) (actor.Actor, bool, error) {
	tid, err := uuid.Parse(teamID)
	if err != nil {
		return actor.Actor{}, false, err
	}
	row, err := s.q.CreateActorIfAbsent(ctx, db.CreateActorIfAbsentParams{
		TeamID:     tid,
		Name:       name,
		TemplateID: parseOptUUID(defaults.Template),
		StateID:    strPtr(defaults.StateID),
	})
	if err == nil {
		return fromDB(row), true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// Already existed (ON CONFLICT DO NOTHING returned no row) — read it.
		existing, gerr := s.q.GetActorByName(ctx, db.GetActorByNameParams{TeamID: tid, Name: name})
		if gerr != nil {
			return actor.Actor{}, false, gerr
		}
		return fromDB(existing), false, nil
	}
	return actor.Actor{}, false, err
}

func (s *PgStore) Get(ctx context.Context, id string) (actor.Actor, error) {
	aid, err := uuid.Parse(id)
	if err != nil {
		return actor.Actor{}, err
	}
	row, err := s.q.GetActor(ctx, aid)
	if errors.Is(err, pgx.ErrNoRows) {
		return actor.Actor{}, actor.ErrNotFound
	}
	if err != nil {
		return actor.Actor{}, err
	}
	return fromDB(row), nil
}

func (s *PgStore) TryAcquireLease(ctx context.Context, id, holder string, now time.Time, ttl time.Duration) (actor.LeaseOutcome, error) {
	aid, err := uuid.Parse(id)
	if err != nil {
		return actor.LeaseOutcome{}, err
	}
	row, err := s.q.TryAcquireActorLease(ctx, db.TryAcquireActorLeaseParams{
		ID:               aid,
		LeaseHolder:      &holder,
		LeaseExpiresAt:   ts(now.Add(ttl)),
		LeaseExpiresAt_2: ts(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// A valid foreign holder blocked the grant. Read it for diagnostics.
		cur, gerr := s.q.GetActor(ctx, aid)
		if gerr != nil {
			return actor.LeaseOutcome{Granted: false}, nil
		}
		return actor.LeaseOutcome{Granted: false, CurrentHolder: ptrStr(cur.LeaseHolder)}, nil
	}
	if err != nil {
		return actor.LeaseOutcome{}, err
	}
	return actor.LeaseOutcome{Granted: true, Token: row.LeaseToken, Expires: row.LeaseExpiresAt.Time}, nil
}

func (s *PgStore) RenewLease(ctx context.Context, id, holder string, token int64, now time.Time, ttl time.Duration) (actor.LeaseOutcome, error) {
	aid, err := uuid.Parse(id)
	if err != nil {
		return actor.LeaseOutcome{}, err
	}
	row, err := s.q.RenewActorLease(ctx, db.RenewActorLeaseParams{
		ID:               aid,
		LeaseHolder:      &holder,
		LeaseToken:       token,
		LeaseExpiresAt:   ts(now.Add(ttl)),
		LeaseExpiresAt_2: ts(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return actor.LeaseOutcome{Granted: false}, actor.ErrFenced
	}
	if err != nil {
		return actor.LeaseOutcome{}, err
	}
	return actor.LeaseOutcome{Granted: true, Token: row.LeaseToken, Expires: row.LeaseExpiresAt.Time}, nil
}

func (s *PgStore) ReleaseLease(ctx context.Context, id, holder string, token int64) error {
	aid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	return s.q.ReleaseActorLease(ctx, db.ReleaseActorLeaseParams{ID: aid, LeaseHolder: &holder, LeaseToken: token})
}

func (s *PgStore) CheckFence(ctx context.Context, id string, token int64, now time.Time) error {
	aid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	ok, err := s.q.CheckActorFence(ctx, db.CheckActorFenceParams{ID: aid, LeaseToken: token, LeaseExpiresAt: ts(now)})
	if err != nil {
		return err
	}
	if !ok {
		return actor.ErrFenced
	}
	return nil
}

func (s *PgStore) SetTier(ctx context.Context, id string, tier actor.Tier, host string, _ time.Time) error {
	aid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	return s.q.SetActorTier(ctx, db.SetActorTierParams{ID: aid, Tier: string(tier), Column3: host})
}

// --- conversions ---

func fromDB(a db.Actor) actor.Actor {
	out := actor.Actor{
		ID:          a.ID.String(),
		TeamID:      a.TeamID.String(),
		Name:        a.Name,
		StateID:     ptrStr(a.StateID),
		HomeHost:    ptrStr(a.HomeHost),
		Tier:        actor.Tier(a.Tier),
		LeaseHolder: ptrStr(a.LeaseHolder),
		LeaseToken:  a.LeaseToken,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
	if a.TemplateID.Valid {
		out.Template = uuid.UUID(a.TemplateID.Bytes).String()
	}
	if a.LeaseExpiresAt.Valid {
		out.LeaseExpires = a.LeaseExpiresAt.Time
	}
	return out
}

func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()} }

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseOptUUID(s string) pgtype.UUID {
	if s == "" {
		return pgtype.UUID{}
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}
