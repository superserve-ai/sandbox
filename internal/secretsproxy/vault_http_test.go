package secretsproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPVaultClientHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/secrets/decrypt" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer daemon-tok" {
			t.Errorf("missing or wrong daemon auth: %q", r.Header.Get("Authorization"))
		}
		var req decryptRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.SecretID != "sec-1" {
			t.Errorf("secret_id: want sec-1, got %q", req.SecretID)
		}
		if req.TeamID != "team-1" {
			t.Errorf("team_id: want team-1, got %q", req.TeamID)
		}
		_ = json.NewEncoder(w).Encode(decryptResponse{Value: "sk-real"})
	}))
	defer srv.Close()

	c := NewHTTPVaultClient(srv.URL, "daemon-tok")
	v, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
	if err != nil {
		t.Fatal(err)
	}
	if v != "sk-real" {
		t.Errorf("value: want sk-real, got %q", v)
	}
}

func TestHTTPVaultClientMaps404ToRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewHTTPVaultClient(srv.URL, "daemon-tok")
	_, err := c.FetchCredential(context.Background(), "team-1", "sec-revoked")
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Errorf("want ErrCredentialRevoked, got %v", err)
	}
}

func TestHTTPVaultClientSurfacesAuthFailure(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "bad daemon token", code)
			}))
			defer srv.Close()
			c := NewHTTPVaultClient(srv.URL, "wrong")
			_, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
			if err == nil {
				t.Fatal("want auth error")
			}
			if !strings.Contains(err.Error(), "DAEMON_AUTH_TOKEN") {
				t.Errorf("error should name DAEMON_AUTH_TOKEN for operator clarity, got %v", err)
			}
		})
	}
}

func TestHTTPVaultClientSurfacesGenericFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()
	c := NewHTTPVaultClient(srv.URL, "tok")
	_, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want 500 in error, got %v", err)
	}
}

func TestHTTPVaultClientEmptyValueMapsToRevoked(t *testing.T) {
	// Empty plaintext is treated as a revoked credential so the request
	// path returns the same 503 as any other unusable secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(decryptResponse{Value: ""})
	}))
	defer srv.Close()
	c := NewHTTPVaultClient(srv.URL, "tok")
	_, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Errorf("want ErrCredentialRevoked, got %v", err)
	}
}

func TestHTTPVaultClientRetriesOnTransient5xx(t *testing.T) {
	// One brief upstream hiccup must not fail the request — the client
	// retries 502/503/504 once before giving up.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(decryptResponse{Value: "real-value"})
	}))
	defer srv.Close()
	c := NewHTTPVaultClient(srv.URL, "tok")
	val, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
	if err != nil {
		t.Fatalf("retry should have succeeded, got %v", err)
	}
	if val != "real-value" {
		t.Errorf("value mismatch: got %q", val)
	}
	if calls != 2 {
		t.Errorf("want 2 calls (one fail, one success), got %d", calls)
	}
}

func TestHTTPVaultClientStopsAfterOneRetry(t *testing.T) {
	// Persistent upstream failure shouldn't loop forever — give up after
	// one retry and surface the last error.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NewHTTPVaultClient(srv.URL, "tok")
	if _, err := c.FetchCredential(context.Background(), "team-1", "sec-1"); err == nil {
		t.Errorf("want error on persistent 502, got nil")
	}
	if calls != 2 {
		t.Errorf("want exactly 2 attempts, got %d", calls)
	}
}
