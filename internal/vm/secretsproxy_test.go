package vm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordingDaemon stands up a unix-socket HTTP server that records every
// invalidate request so the test can assert vmd posted the right shape.
type recordingDaemon struct {
	t           *testing.T
	socketPath  string
	stopped     chan struct{}
	invalidated []string

	failNext int
}

func newRecordingDaemon(t *testing.T) *recordingDaemon {
	t.Helper()
	dir := t.TempDir()
	d := &recordingDaemon{
		t:          t,
		socketPath: filepath.Join(dir, "daemon.sock"),
		stopped:    make(chan struct{}),
	}

	l, err := net.Listen("unix", d.socketPath)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if d.failNext != 0 {
			w.WriteHeader(d.failNext)
			d.failNext = 0
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[1] != "invalidate" || parts[0] == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		d.invalidated = append(d.invalidated, parts[0])
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		_ = srv.Serve(l)
		close(d.stopped)
	}()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return d
}

func TestSecretsBrokerClient_InvalidateSecret(t *testing.T) {
	d := newRecordingDaemon(t)
	c := NewSecretsBrokerClient(d.socketPath)

	if err := c.InvalidateSecret(context.Background(), "sec-1"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if len(d.invalidated) != 1 || d.invalidated[0] != "sec-1" {
		t.Errorf("recorded invalidations drift: %+v", d.invalidated)
	}
}

func TestSecretsBrokerClient_InvalidateSecret_DisabledNoOp(t *testing.T) {
	c := NewSecretsBrokerClient("") // empty socketPath disables every call
	if c.Enabled() {
		t.Fatal("client with empty socketPath should report Enabled=false")
	}
	if err := c.InvalidateSecret(context.Background(), "sec-1"); err != nil {
		t.Errorf("disabled client should silently succeed, got %v", err)
	}
}

func TestSecretsBrokerClient_InvalidateSecret_SurfaceErrors(t *testing.T) {
	d := newRecordingDaemon(t)
	c := NewSecretsBrokerClient(d.socketPath)

	d.failNext = http.StatusInternalServerError
	err := c.InvalidateSecret(context.Background(), "sec-1")
	if err == nil || !errors.Is(err, ErrDaemonRefused) {
		t.Errorf("want ErrDaemonRefused on 500, got %v", err)
	}
}

func TestInjectHTTPSProxyEnvWithJWT(t *testing.T) {
	trustKeys := []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}

	cases := []struct {
		name        string
		sandboxAddr string
		jwt         string
		wantProxy   string
	}{
		{"happy path", "192.0.2.1:9443", "the.jwt.body", "https://sb:the.jwt.body@192.0.2.1:9443"},
		{"empty addr returns input", "", "x", ""},
		{"empty jwt returns input", "192.0.2.1:9443", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := map[string]string{"MODE": "prod"}
			out := InjectHTTPSProxyEnvWithJWT(in, tc.sandboxAddr, tc.jwt)
			if out["MODE"] != "prod" {
				t.Errorf("existing keys must be preserved")
			}
			if tc.wantProxy == "" {
				if _, ok := out["HTTPS_PROXY"]; ok {
					t.Errorf("HTTPS_PROXY should not be set when addr or jwt is empty")
				}
				for _, k := range trustKeys {
					if _, ok := out[k]; ok {
						t.Errorf("%s should not be set when proxy injection is skipped", k)
					}
				}
				return
			}
			if got := out["HTTPS_PROXY"]; got != tc.wantProxy {
				t.Errorf("HTTPS_PROXY: want %q, got %q", tc.wantProxy, got)
			}
			// HTTP_PROXY must not be set — plain-HTTP egress stays direct.
			if _, ok := out["HTTP_PROXY"]; ok {
				t.Errorf("HTTP_PROXY should not be set")
			}
			for _, k := range trustKeys {
				if out[k] == "" {
					t.Errorf("%s should be set alongside HTTPS_PROXY", k)
				}
			}
		})
	}
}

func TestInjectHTTPSProxyEnvWithJWT_OverridesCustomerTrustVars(t *testing.T) {
	in := map[string]string{
		"SSL_CERT_FILE":       "/customer/path",
		"REQUESTS_CA_BUNDLE":  "/customer/path",
		"NODE_EXTRA_CA_CERTS": "/customer/path",
	}
	out := InjectHTTPSProxyEnvWithJWT(in, "192.0.2.1:9443", "abc")
	if out["SSL_CERT_FILE"] == "/customer/path" {
		t.Error("our SSL_CERT_FILE must override the customer's so TLS trusts the daemon CA")
	}
	if out["REQUESTS_CA_BUNDLE"] == "/customer/path" {
		t.Error("our REQUESTS_CA_BUNDLE must override the customer's")
	}
	if out["NODE_EXTRA_CA_CERTS"] == "/customer/path" {
		t.Error("our NODE_EXTRA_CA_CERTS must override the customer's")
	}
}

func TestInjectHTTPSProxyEnvWithJWT_DoesNotMutateInput(t *testing.T) {
	in := map[string]string{"MODE": "prod"}
	_ = InjectHTTPSProxyEnvWithJWT(in, "10.0.0.3:9443", "abc")
	if _, ok := in["HTTPS_PROXY"]; ok {
		t.Errorf("input map was mutated")
	}
}

func TestRequireProxyForJWT(t *testing.T) {
	cases := []struct {
		name     string
		jwt      string
		proxyURL string
		wantErr  bool
	}{
		{"no JWT, no proxy", "", "", false},
		{"no JWT, proxy set", "", "192.0.2.1:9443", false},
		{"JWT set, proxy set", "tok", "192.0.2.1:9443", false},
		{"JWT set, proxy missing must error", "tok", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireProxyForJWT(tc.jwt, tc.proxyURL)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// json import retained for future test additions that exercise the wire shape.
var _ = json.Marshal
