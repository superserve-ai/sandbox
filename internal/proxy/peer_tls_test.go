package proxy

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPeerTLSConfigLoadRequiresExpectedSPIFFE(t *testing.T) {
	for _, expected := range []string{"", "   ", "\t\n"} {
		_, err := (PeerTLSConfig{ExpectedSPIFFE: expected}).Load()
		if err == nil || !strings.Contains(err.Error(), "expected peer SPIFFE URI is required") {
			t.Fatalf("Load() with ExpectedSPIFFE %q error = %v, want required-identity error", expected, err)
		}
	}
}

func TestPrivateBindRequiresPrivateNumericAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"10.0.0.2:5008", true},
		{"10.0.0.2:0", false},
		{"172.16.4.9:5008", true},
		{"192.168.1.4:5008", true},
		{"[fd00::2]:5008", true},
		{"8.8.8.8:5008", false},
		{"[2001:db8::2]:5008", false},
		{"[::ffff:0.0.0.0]:5008", false},
		{"[::ffff:8.8.8.8]:5008", false},
		{"[fe80::2%eth0]:5008", false},
		{"[0:0:0:0:0:0:0:0]:5008", false},
		{"[ff02::1]:5008", false},
		{"[fe80::2]:5008", false},
		{"proxy.internal:5008", false},
		{"10.0.0.2:not-a-port", false},
		{"10.0.0.2", false},
		{":5008", false},
		{"0.0.0.0:5008", false},
		{"[::]:5008", false},
	}
	for _, tt := range tests {
		if got := PrivateBind(tt.addr); got != tt.want {
			t.Errorf("PrivateBind(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestPeerTLSRejectsPlaintext(t *testing.T) {
	cfg := peerTestCredentials(t)
	serverConfig, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))
	result := make(chan error, 1)
	go func() { result <- tls.Server(server, serverConfig).Handshake() }()
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("peer accepted plaintext")
	}
}
