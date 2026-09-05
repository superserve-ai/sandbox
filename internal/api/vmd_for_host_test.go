package api

import (
	"time"

	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type routeFakeRegistry struct{ err error }

func (f *routeFakeRegistry) ClientFor(context.Context, string) (vmdclient.Client, error) {
	return nil, f.err
}

// Invalidate keeps the fake compatible with the registry interface as it
// grows an eviction method.
func (f *routeFakeRegistry) Invalidate(string)                                       {}
func (f *routeFakeRegistry) MarkVerified(context.Context, string, string, time.Time) {}

// A sandbox row referencing an unregistered host is a hard error, never a
// silent fallback to the default client: with more than one host the
// default is the wrong machine for every sandbox not on it, and when the
// real host id coincides with the default, the misroute never even fails.
func TestVMDForHostRefusesFallbackOnMissingHostRow(t *testing.T) {
	h := &Handlers{
		Hosts: &routeFakeRegistry{err: fmt.Errorf("get host: %w", pgx.ErrNoRows)},
	}
	c, err := h.vmdForHost(context.Background(), "ghost-host")
	if err == nil {
		t.Fatalf("missing host row returned a client (%v), want hard error", c)
	}
	if !errors.Is(err, pgx.ErrNoRows) || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("error = %v, want not-registered wrapping ErrNoRows", err)
	}

	// Non-not-found lookup errors surface unchanged.
	h.Hosts = &routeFakeRegistry{err: fmt.Errorf("dial refused")}
	if _, err := h.vmdForHost(context.Background(), "host-a"); err == nil {
		t.Fatal("lookup error returned a client, want error")
	}

	// Registry-less wiring (tests/dev) still uses the default client.
	h.Hosts = nil
	if c, err := h.vmdForHost(context.Background(), "host-a"); err != nil || c != h.VMD {
		t.Fatalf("nil registry: got (%v, %v), want default client", c, err)
	}
}

// Bootstrap parity: the CONFIGURED DEFAULT id keeps routing to the
// configured default client when its row is missing (unpopulated host
// table, the supported single-host mode — the scheduler fallback and the
// build resolver preserve the same mapping). Any OTHER id with a missing
// row stays a hard error even with bootstrap config present.
func TestVMDForHostBootstrapDefaultKeepsRouting(t *testing.T) {
	h := &Handlers{
		Hosts:  &routeFakeRegistry{err: fmt.Errorf("get host: %w", pgx.ErrNoRows)},
		Config: &config.Config{DefaultHostID: "default"},
		VMD:    nil, // nil default client also refuses (guarded)
	}

	// Default id + missing row + a configured default client → bootstrap.
	fake := &stubVMD{}
	h.VMD = fake
	if c, err := h.vmdForHost(context.Background(), "default"); err != nil || c != VMDClient(fake) {
		t.Fatalf("bootstrap default: got (%v, %v), want configured default client", c, err)
	}

	// A non-default id with a missing row is still corruption to surface.
	if _, err := h.vmdForHost(context.Background(), "host-b"); err == nil {
		t.Fatal("non-default missing row returned a client, want hard error")
	}

	// An empty id — only reachable from records that predate host
	// tracking (nullable build host columns) — routes to the configured
	// default without consulting the registry at all.
	if c, err := h.vmdForHost(context.Background(), ""); err != nil || c != VMDClient(fake) {
		t.Fatalf("legacy empty id: got (%v, %v), want configured default client", c, err)
	}
}
