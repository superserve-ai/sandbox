package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestLoadConfigRequiresExplicitHostID(t *testing.T) {
	cases := []struct {
		name    string
		hostID  string
		wantErr bool
	}{
		{"unset", "", true},
		{"legacy default identity", "default", false},
		{"real identity", "host-a", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KERNEL_PATH", "/tmp/kernel")
			t.Setenv("BASE_ROOTFS_PATH", "/tmp/rootfs")
			t.Setenv("HOST_ID", tc.hostID)

			cfg, err := loadConfig()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("loadConfig() = %+v, want error for HOST_ID=%q", cfg, tc.hostID)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig() error: %v", err)
			}
			if cfg.HostID != tc.hostID {
				t.Fatalf("cfg.HostID = %q, want %q", cfg.HostID, tc.hostID)
			}
		})
	}
}

func TestLoadConfigUsesHeartbeatOverrides(t *testing.T) {
	t.Setenv("KERNEL_PATH", "/tmp/kernel")
	t.Setenv("BASE_ROOTFS_PATH", "/tmp/rootfs")
	t.Setenv("HOST_ID", "host-a")
	t.Setenv("VMD_ADVERTISE_ADDR", "10.0.0.2:50051")
	t.Setenv("PROXY_ADVERTISE_ADDR", "10.0.0.2:5007")
	t.Setenv("HOST_REGION", "region-explicit")
	t.Setenv("SANDBOX_ID_REGION", "region-fallback")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error: %v", err)
	}
	if cfg.VMDAdvertiseAddr != "10.0.0.2:50051" {
		t.Fatalf("cfg.VMDAdvertiseAddr = %q, want explicit override", cfg.VMDAdvertiseAddr)
	}
	if cfg.ProxyAdvertiseAddr != "10.0.0.2:5007" {
		t.Fatalf("cfg.ProxyAdvertiseAddr = %q, want explicit override", cfg.ProxyAdvertiseAddr)
	}
	if cfg.HostRegion != "region-explicit" {
		t.Fatalf("cfg.HostRegion = %q, want explicit override", cfg.HostRegion)
	}
}

func TestAdvertisedAddrsPreferExplicitOverrides(t *testing.T) {
	// The host lookup dumps fleet-sized kernel tables, so explicit settings
	// must satisfy both endpoints without it ever running.
	resolved := 0
	hostIP := func() (string, error) {
		resolved++
		return "", fmt.Errorf("host lookup must not run when both addresses are explicit")
	}

	vmdAddr, err := advertisedVMDAddr(hostIP, 50051, "10.0.0.2:50051")
	if err != nil {
		t.Fatalf("advertisedVMDAddr: %v", err)
	}
	if vmdAddr != "10.0.0.2:50051" {
		t.Fatalf("advertisedVMDAddr = %q, want explicit override", vmdAddr)
	}

	proxyAddr, err := advertisedProxyAddr(hostIP, "http://127.0.0.1:5007/health", "10.0.0.2:5007")
	if err != nil {
		t.Fatalf("advertisedProxyAddr: %v", err)
	}
	if proxyAddr != "10.0.0.2:5007" {
		t.Fatalf("advertisedProxyAddr = %q, want explicit override", proxyAddr)
	}
	if resolved != 0 {
		t.Fatalf("host interface resolved %d times, want 0", resolved)
	}
}

// Both endpoints derive from the same interface; the lookup behind them must
// run once no matter how many callers need it.
func TestAdvertisedAddrsShareOneHostLookup(t *testing.T) {
	resolved := 0
	hostIP := func() (string, error) {
		resolved++
		return "10.0.0.3", nil
	}
	memo := func() func() (string, error) {
		var once sync.Once
		var ip string
		var err error
		return func() (string, error) {
			once.Do(func() { ip, err = hostIP() })
			return ip, err
		}
	}()

	vmdAddr, err := advertisedVMDAddr(memo, 50051, "")
	if err != nil {
		t.Fatalf("advertisedVMDAddr: %v", err)
	}
	proxyAddr, err := advertisedProxyAddr(memo, "http://127.0.0.1:5007/health", "")
	if err != nil {
		t.Fatalf("advertisedProxyAddr: %v", err)
	}
	if vmdAddr != "10.0.0.3:50051" {
		t.Fatalf("advertisedVMDAddr = %q, want derived host address", vmdAddr)
	}
	if proxyAddr != "10.0.0.3:5007" {
		t.Fatalf("advertisedProxyAddr = %q, want derived host address", proxyAddr)
	}
	if resolved != 1 {
		t.Fatalf("host interface resolved %d times, want 1", resolved)
	}
}

func TestParseSecretsProxyAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{name: "valid ipv4 + port", input: "192.0.2.1:9443", wantHost: "192.0.2.1", wantPort: 9443},
		{name: "missing port", input: "192.0.2.1", wantErr: true},
		{name: "hostname rejected", input: "proxy.local:9443", wantErr: true},
		{name: "ipv6 rejected", input: "[::1]:9443", wantErr: true},
		{name: "port zero rejected", input: "192.0.2.1:0", wantErr: true},
		{name: "port too large", input: "192.0.2.1:70000", wantErr: true},
		{name: "non-numeric port", input: "192.0.2.1:abc", wantErr: true},
		{name: "empty host", input: ":9443", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseSecretsProxyAddr(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got host=%q port=%d", host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("got (%q, %d), want (%q, %d)", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestPausedNetworkReclaimTriggersConfigured(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		slotPercent    int
		slotReserve    int
		netnsThreshold int
		mountThreshold int
		wantConfigured bool
	}{
		{name: "all disabled", wantConfigured: false},
		{name: "slot percent", slotPercent: 5, wantConfigured: true},
		{name: "slot reserve", slotReserve: 1, wantConfigured: true},
		{name: "netns threshold", netnsThreshold: 1, wantConfigured: true},
		{name: "mount threshold", mountThreshold: 1, wantConfigured: true},
		{name: "mixed disabled", slotPercent: 0, slotReserve: 0, netnsThreshold: 0, mountThreshold: 0, wantConfigured: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pausedNetworkReclaimTriggersConfigured(tc.slotPercent, tc.slotReserve, tc.netnsThreshold, tc.mountThreshold); got != tc.wantConfigured {
				t.Fatalf("pausedNetworkReclaimTriggersConfigured() = %v, want %v", got, tc.wantConfigured)
			}
		})
	}
}

// TestLifecycle_CleanIntentionalShutdownGate pins the receipt-minting
// invariant: only a signal-initiated shutdown with no service error and no
// closer failure qualifies. An unexpected service return — even error-free —
// and a failing closer must both disqualify.
func TestLifecycle_CleanIntentionalShutdownGate(t *testing.T) {
	log := zerolog.Nop()

	t.Run("signal initiated and clean", func(t *testing.T) {
		lc := newLifecycle(log)
		lc.noteSignalInitiated()
		lc.shutdown(context.Background())
		if !lc.cleanIntentionalShutdown() {
			t.Fatal("clean signal-initiated shutdown must qualify")
		}
	})

	t.Run("unexpected error-free service return", func(t *testing.T) {
		lc := newLifecycle(log)
		lc.start("svc", func() error { return nil })
		lc.wait(context.Background())
		lc.shutdown(context.Background())
		if lc.cleanIntentionalShutdown() {
			t.Fatal("a service returning on its own is not intentional, even without error")
		}
	})

	t.Run("service error", func(t *testing.T) {
		lc := newLifecycle(log)
		lc.noteSignalInitiated()
		lc.start("svc", func() error { return fmt.Errorf("boom") })
		lc.wait(context.Background())
		lc.shutdown(context.Background())
		if lc.cleanIntentionalShutdown() {
			t.Fatal("a service error must disqualify")
		}
	})

	t.Run("closer failure", func(t *testing.T) {
		lc := newLifecycle(log)
		lc.noteSignalInitiated()
		lc.addCloser("bad", func(context.Context) error { return fmt.Errorf("close failed") })
		lc.shutdown(context.Background())
		if lc.cleanIntentionalShutdown() {
			t.Fatal("a failing closer must disqualify")
		}
	})

	t.Run("forced gRPC stop", func(t *testing.T) {
		// A drain that overran its budget and force-cancelled active RPCs may
		// have left state the next boot must reconcile — never a clean handoff.
		lc := newLifecycle(log)
		lc.noteSignalInitiated()
		lc.noteForcedRPCStop()
		lc.shutdown(context.Background())
		if lc.cleanIntentionalShutdown() {
			t.Fatal("a forced gRPC stop must disqualify")
		}
	})
}

// A closer that fails or overruns may still have a worker touching its
// dependencies' resources, so shutdown must abort rather than close those
// dependencies out from under it. Covers all three failure shapes; each must
// leave the dependency unclosed, stay bounded, and record the error.
func TestShutdownAbortsOnCloserFailure(t *testing.T) {
	prev := perCloserShutdownTimeout
	perCloserShutdownTimeout = 50 * time.Millisecond
	defer func() { perCloserShutdownTimeout = prev }()

	run := func(t *testing.T, failing func(context.Context) error) {
		lc := newLifecycle(zerolog.Nop())
		var depClosed atomic.Bool
		// LIFO shutdown: registered dep, failing, latest runs as latest,
		// failing, dep. dep (registered first, run last) is the failing
		// closer's dependency and must NOT be closed after the abort.
		lc.addCloser("dep", func(context.Context) error { depClosed.Store(true); return nil })
		lc.addCloser("failing", failing)
		lc.addCloser("latest", func(context.Context) error { return nil })

		start := time.Now()
		lc.shutdown(context.Background())
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("shutdown not bounded: took %v", d)
		}
		if depClosed.Load() {
			t.Fatal("dependency closed after a failed/overrun closer — must abort instead")
		}
		if lc.closerErr == nil {
			t.Fatal("failed closer must record closerErr (bars vouching)")
		}
	}

	// Respects ctx and returns ctx.Err() at its deadline — its worker may still
	// be live, and the outer select can receive this from done instead of
	// selecting closerCtx.Done(). Must still abort.
	t.Run("returns ctx.Err at deadline", func(t *testing.T) {
		run(t, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	})
	// Returns a plain error promptly — the done branch must also abort.
	t.Run("returns error", func(t *testing.T) {
		run(t, func(context.Context) error { return fmt.Errorf("boom") })
	})
	// Ignores ctx entirely and never returns — the deadline branch aborts.
	t.Run("wedged, ignores ctx", func(t *testing.T) {
		run(t, func(context.Context) error { select {} }) // ponytail: never returns
	})
}

// Pressure accounting is opt-in on BOTH halves: an operator-set
// advertise address and a control plane to publish to. A host with an
// address but no control-plane URL never starts a heartbeat, so turning
// the accounting on would buy a startup scan whose results nothing
// reads.
func TestPublishesCapacityPressureRequiresBothHalves(t *testing.T) {
	cases := []struct {
		name            string
		advertiseAddr   string
		controlPlaneURL string
		want            bool
	}{
		{"both set", "10.0.0.2:50051", "http://cp:8080", true},
		{"no advertise address", "", "http://cp:8080", false},
		{"no control plane", "10.0.0.2:50051", "", false},
		{"neither", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publishesCapacityPressure(tc.advertiseAddr, tc.controlPlaneURL); got != tc.want {
				t.Fatalf("publishesCapacityPressure(%q, %q) = %v, want %v",
					tc.advertiseAddr, tc.controlPlaneURL, got, tc.want)
			}
		})
	}
}
