package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/proxy"
)

func mountedPeerCredentials(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://example.test/peer")
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{identity}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, file := range []struct {
		env, name, kind string
		data            []byte
	}{
		{"PEER_PROXY_CERT_FILE", "peer-cert", "CERTIFICATE", der},
		{"PEER_PROXY_CA_FILE", "peer-ca", "CERTIFICATE", der},
		{"PEER_PROXY_KEY_FILE", "peer-key", "EC PRIVATE KEY", keyDER},
	} {
		path := filepath.Join(dir, file.name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.data}), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(file.env, path)
	}
	t.Setenv("PEER_PROXY_SPIFFE_URI", identity.String())
}

func TestClientOnlyStartupUsesMountedCredentials(t *testing.T) {
	mountedPeerCredentials(t)
	t.Setenv("PEER_PROXY_LISTEN_ADDR", "")
	if peerIngressEnabled(os.Getenv("PEER_PROXY_LISTEN_ADDR")) {
		t.Fatal("ingress enabled")
	}
	cfg, peers, err := newOutboundPeerTransport(zerolog.Nop(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	if cfg.CertFile != os.Getenv("PEER_PROXY_CERT_FILE") || cfg.KeyFile != os.Getenv("PEER_PROXY_KEY_FILE") || cfg.CAFile != os.Getenv("PEER_PROXY_CA_FILE") {
		t.Fatal("runtime credential paths overridden")
	}
	// Client-only mode still validates credentials before creating the pool.
	t.Setenv("PEER_PROXY_KEY_FILE", filepath.Join(t.TempDir(), "missing-key"))
	if _, peers, err := newOutboundPeerTransport(zerolog.Nop(), nil); err == nil {
		peers.Close()
		t.Fatal("client-only startup accepted missing credentials")
	}
}

func TestLocalListenerCannotReenterOwnershipRouting(t *testing.T) {
	var lookups atomic.Int32
	local := proxy.NewHandler([]string{"sandbox.test"}, &listenerResolver{}, zerolog.Nop())
	router := proxy.NewRoutingHandler([]string{"sandbox.test"}, "host-a", proxy.RouteLookupFunc(func(context.Context, string) (proxy.SandboxRoute, error) {
		lookups.Add(1)
		return proxy.SandboxRoute{HostID: "host-b", ProxyAddr: "192.0.2.2:5009"}, nil
	}), nil, local, zerolog.Nop())
	publicMux, localMux := newDataPlaneMuxes(local, router, true)
	// The same local mux is attached to the synchronously bound peer target.
	srv := httptest.NewServer(localMux)
	defer srv.Close()
	for _, path := range []string{"/", "/health"} {
		lookups.Store(0)
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || lookups.Load() != 0 {
			t.Fatalf("%s: local status=%d lookups=%d", path, resp.StatusCode, lookups.Load())
		}
		publicMux.ServeHTTP(httptest.NewRecorder(), req)
		if lookups.Load() != 1 {
			t.Fatalf("%s: public listener bypassed ownership routing", path)
		}
	}
}

func TestIngressOnlyRolloutDoesNotRoutePublicRequests(t *testing.T) {
	local := proxy.NewHandler([]string{"sandbox.test"}, &listenerResolver{}, zerolog.Nop())
	router := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("ingress-only rollout entered ownership routing")
	})
	public, peer := newDataPlaneMuxes(local, router, false)
	for _, mux := range []*http.ServeMux{public, peer} {
		for _, path := range []string{"/", "/health"} {
			req := httptest.NewRequest(http.MethodGet, "http://8080-12345678-1234-1234-1234-123456789abc.sandbox.test"+path, nil)
			result := httptest.NewRecorder()
			mux.ServeHTTP(result, req)
			if result.Code != http.StatusNotFound {
				t.Fatalf("local handler status=%d", result.Code)
			}
		}
	}
}

func TestOwnershipPoolRespectsRoutingGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, url := range []string{"", "not a database URL"} {
		pool, err := newOwnershipPool(ctx, false, url)
		if err != nil || pool != nil {
			t.Fatalf("disabled routing initialized database: pool=%v err=%v", pool, err)
		}
	}
	for _, url := range []string{"", "not a database URL", "postgres://localhost/example"} {
		pool, err := newOwnershipPool(ctx, true, url)
		if pool != nil {
			pool.Close()
		}
		if err == nil {
			t.Fatalf("enabled routing accepted unavailable database %q", url)
		}
	}
}
