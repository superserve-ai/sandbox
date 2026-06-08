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

func TestHTTPVaultClientRejectsEmptyValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(decryptResponse{Value: ""})
	}))
	defer srv.Close()
	c := NewHTTPVaultClient(srv.URL, "tok")
	_, err := c.FetchCredential(context.Background(), "team-1", "sec-1")
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Errorf("want empty-value error, got %v", err)
	}
}
