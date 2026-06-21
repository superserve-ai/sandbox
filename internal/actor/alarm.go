package actor

import (
	"context"
	"sync"
	"time"
)

// Alarm is a scheduled wake for an Actor at FireAt. It implements sleepUntil /
// cron: an Actor sets an alarm, hibernates, and the scheduler wakes it on time
// even from cold — the same wake-on-reference path an inbound event takes.
type Alarm struct {
	ID      string
	ActorID string
	FireAt  time.Time
}

// AlarmStore persists alarms. Separate from Store so a backend can implement one
// without the other; the Postgres impl (pgstore) is backed by the actor_alarm
// table + DueActorAlarms (due-indexed) from db/queries/actors.sql.
type AlarmStore interface {
	// SetAlarm schedules a wake for actorID at fireAt and returns the alarm.
	SetAlarm(ctx context.Context, actorID string, fireAt time.Time) (Alarm, error)
	// DueAlarms returns alarms whose FireAt <= now, oldest first, up to limit.
	DueAlarms(ctx context.Context, now time.Time, limit int) ([]Alarm, error)
	// DeleteAlarm removes a fired alarm.
	DeleteAlarm(ctx context.Context, id string) error
}

// AlarmScheduler fires due alarms by waking their Actors. It extends the reaper
// pattern: Tick is called on a cadence; for each due alarm it invokes wake
// (which routes a synthetic "alarm" event to the Actor, waking it cold if
// needed) and then deletes the alarm. A wake failure leaves the alarm in place
// so the next Tick retries — at-least-once delivery.
type AlarmScheduler struct {
	store AlarmStore
	wake  func(ctx context.Context, a Alarm) error
	now   func() time.Time
	batch int
}

// NewAlarmScheduler builds a scheduler. clock may be nil (time.Now); batch<=0
// defaults to 100 alarms per Tick.
func NewAlarmScheduler(store AlarmStore, wake func(ctx context.Context, a Alarm) error, clock func() time.Time, batch int) *AlarmScheduler {
	if clock == nil {
		clock = time.Now
	}
	if batch <= 0 {
		batch = 100
	}
	return &AlarmScheduler{store: store, wake: wake, now: clock, batch: batch}
}

// Tick fires all currently-due alarms (up to batch). Returns the number fired
// and the first error encountered (firing continues past per-alarm errors so
// one bad Actor doesn't block the rest). A fired alarm is deleted only after its
// wake succeeds.
func (s *AlarmScheduler) Tick(ctx context.Context) (fired int, firstErr error) {
	due, err := s.store.DueAlarms(ctx, s.now(), s.batch)
	if err != nil {
		return 0, err
	}
	for _, a := range due {
		if err := s.wake(ctx, a); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue // leave the alarm; retry next Tick (at-least-once)
		}
		if err := s.store.DeleteAlarm(ctx, a.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fired++
	}
	return fired, firstErr
}

// MemAlarmStore is an in-memory AlarmStore for tests and single-node/dev runs.
type MemAlarmStore struct {
	mu     sync.Mutex
	alarms map[string]Alarm
	seq    int64
}

// NewMemAlarmStore returns an empty in-memory alarm store.
func NewMemAlarmStore() *MemAlarmStore {
	return &MemAlarmStore{alarms: map[string]Alarm{}}
}

func (m *MemAlarmStore) SetAlarm(_ context.Context, actorID string, fireAt time.Time) (Alarm, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	a := Alarm{ID: "alm-" + itoa(m.seq), ActorID: actorID, FireAt: fireAt}
	m.alarms[a.ID] = a
	return a, nil
}

func (m *MemAlarmStore) DueAlarms(_ context.Context, now time.Time, limit int) ([]Alarm, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []Alarm
	for _, a := range m.alarms {
		if !a.FireAt.After(now) {
			due = append(due, a)
		}
	}
	// Oldest-first so earlier alarms fire first; deterministic for tests.
	for i := 0; i < len(due); i++ {
		for j := i + 1; j < len(due); j++ {
			if due[j].FireAt.Before(due[i].FireAt) {
				due[i], due[j] = due[j], due[i]
			}
		}
	}
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	return due, nil
}

func (m *MemAlarmStore) DeleteAlarm(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.alarms, id)
	return nil
}

// Len reports the number of pending alarms (for tests/inspection).
func (m *MemAlarmStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.alarms)
}
