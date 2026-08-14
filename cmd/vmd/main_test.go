package main

import "testing"

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
