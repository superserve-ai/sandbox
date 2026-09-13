package qm

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTouchThrottle(t *testing.T) {
	now := time.Unix(1789000000, 0)
	r := &PostgresKeyResolver{touched: map[uuid.UUID]time.Time{}, now: func() time.Time { return now }}
	key := uuid.New()
	if !r.shouldTouch(key) {
		t.Fatal("first use not touched")
	}
	now = now.Add(30 * time.Second)
	if r.shouldTouch(key) {
		t.Error("touched again inside the interval")
	}
	now = now.Add(31 * time.Second)
	if !r.shouldTouch(key) {
		t.Error("not touched after the interval")
	}
	if !r.shouldTouch(uuid.New()) {
		t.Error("a different key is throttled by the first")
	}
	for range touchMapMax {
		r.shouldTouch(uuid.New())
	}
	if len(r.touched) > touchMapMax {
		t.Errorf("touch map grew to %d", len(r.touched))
	}
}
