// Package actor implements the durable-Actor runtime layer (Epic 5): a stable,
// addressable, single-writer identity that lives on top of a Sandbox + a
// durable /state filesystem. This package owns the two correctness-critical
// invariants:
//
//   - Identity: a (team, name) resolves to exactly one Actor row, created on
//     first reference (wake-on-reference / getActor semantics).
//   - Single-writer: at most one live instance holds the Actor's lease at a
//     time. The lease carries a monotonic fencing token so a writer that lost
//     the lease (expiry, partition) is rejected by storage even if it doesn't
//     yet know it lost — fencing-as-backstop, so a routing bug can't corrupt
//     /state.
//
// The lease state machine is defined here and exercised against an in-memory
// Store (memstore.go) in tests; the production Store is Postgres-backed
// (store_pg.go) where each operation is a single atomic UPDATE.
package actor

import (
	"errors"
	"time"
)

// Tier is the hibernation depth of an Actor's compute, mirroring the latency
// tiers validated in cmd/latencybench (Tier-1 wake p99 < 10ms — proven).
type Tier string

const (
	TierCold    Tier = "cold"  // no live VM; restore from object storage on wake
	TierLive    Tier = "live"  // running, holding the lease
	TierPaused1 Tier = "tier1" // paused-in-RAM (between turns; ~sub-ms wake)
	TierPaused2 Tier = "tier2" // local snapshot + UFFD
	TierPaused3 Tier = "tier3" // cold cross-host
)

// Actor is the durable identity record.
type Actor struct {
	ID       string // stable opaque id
	TeamID   string
	Name     string // addressable name, unique per team
	Template string // template the compute boots from (optional)
	StateID  string // durable /state provider key (state.Provider identity)
	HomeHost string // last/current host (stickiness)
	Tier     Tier

	// Lease (single-writer). Holder is the instance currently allowed to write;
	// Token is the monotonic fence; Expires bounds the lease so a dead holder's
	// grip is released automatically.
	LeaseHolder  string
	LeaseToken   int64
	LeaseExpires time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasValidLease reports whether a non-expired lease is held as of now.
func (a *Actor) HasValidLease(now time.Time) bool {
	return a.LeaseHolder != "" && now.Before(a.LeaseExpires)
}

// LeaseOutcome is the result of an acquire/renew attempt.
type LeaseOutcome struct {
	// Granted is true if the caller now holds (or still holds) the lease.
	Granted bool
	// Token is the fencing token to stamp on writes. Valid only when Granted.
	Token int64
	// Expires is when the lease lapses unless renewed. Valid only when Granted.
	Expires time.Time
	// CurrentHolder is who holds it (set when Granted is false, for diagnostics).
	CurrentHolder string
}

var (
	// ErrNotFound is returned when an Actor doesn't exist.
	ErrNotFound = errors.New("actor: not found")
	// ErrLeaseHeld is returned when the lease is validly held by someone else.
	ErrLeaseHeld = errors.New("actor: lease held by another instance")
	// ErrFenced is returned when a write presents a stale fencing token.
	ErrFenced = errors.New("actor: stale fencing token (lease lost)")
)

// Store is the persistence contract for the Actor runtime. Every lease method
// is a single atomic operation (compare-and-swap on the lease columns) so the
// single-writer invariant holds without an external lock. In production this is
// Postgres; tests use the in-memory implementation.
type Store interface {
	// GetOrCreate resolves (team, name) to an Actor, creating it on first
	// reference. The created flag distinguishes a fresh Actor from an existing
	// one. This is the wake-on-reference primitive.
	GetOrCreate(teamID, name string, defaults Actor, now time.Time) (a Actor, created bool, err error)

	// Get fetches an Actor by id.
	Get(id string) (Actor, error)

	// TryAcquireLease atomically grants the lease to holder iff it is free,
	// expired, or already held by holder. On grant it increments the fencing
	// token and extends expiry. On a valid foreign hold it returns Granted=false
	// with the current holder.
	TryAcquireLease(id, holder string, now time.Time, ttl time.Duration) (LeaseOutcome, error)

	// RenewLease extends the lease iff holder still holds it with the given
	// token (no expiry/steal happened in between). Does NOT change the token.
	RenewLease(id, holder string, token int64, now time.Time, ttl time.Duration) (LeaseOutcome, error)

	// ReleaseLease relinquishes the lease iff holder holds it with token.
	// Idempotent: releasing an already-released/stolen lease is not an error.
	ReleaseLease(id, holder string, token int64) error

	// CheckFence verifies token is the current lease token (and unexpired) —
	// the gate a write path calls before mutating /state. Returns ErrFenced
	// otherwise.
	CheckFence(id string, token int64, now time.Time) error

	// SetTier records the Actor's hibernation tier and current host.
	SetTier(id string, tier Tier, host string, now time.Time) error
}
