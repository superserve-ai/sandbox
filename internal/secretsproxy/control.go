package secretsproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// ControlServer is the daemon-internal HTTP API served over a 0600 unix socket.
type ControlServer struct {
	cachedVault *cachedVault
	revoker     *Revoker

	httpServer  *http.Server
	socketPath  string
	isListening atomic.Bool
}

// NewControlServer builds the server. Nil cachedVault or revoker turn the
// corresponding endpoints into no-ops.
func NewControlServer(socketPath string, cv *cachedVault, r *Revoker) *ControlServer {
	c := &ControlServer{
		cachedVault: cv,
		revoker:     r,
		socketPath:  socketPath,
	}
	c.httpServer = &http.Server{
		Handler:           c.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return c
}

// IsListening reports whether the control socket is bound.
func (c *ControlServer) IsListening() bool { return c.isListening.Load() }

// ListenAndServe binds the unix socket (overwriting any existing one) and serves.
func (c *ControlServer) ListenAndServe() error {
	if err := os.MkdirAll(filepath.Dir(c.socketPath), 0o700); err != nil {
		return err
	}
	if err := os.Remove(c.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", c.socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(c.socketPath, 0o600); err != nil {
		_ = l.Close()
		return err
	}
	return c.Serve(l)
}

// Serve accepts on the provided listener.
func (c *ControlServer) Serve(l net.Listener) error {
	c.isListening.Store(true)
	defer c.isListening.Store(false)
	return c.httpServer.Serve(l)
}

// Shutdown stops the server; safe to call multiple times.
func (c *ControlServer) Shutdown(ctx context.Context) error {
	return c.httpServer.Shutdown(ctx)
}

func (c *ControlServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealth)
	mux.HandleFunc("/v1/secrets/", c.handleSecretAction)
	mux.HandleFunc("/v1/sandboxes/", c.handleSandboxAction)
	return mux
}

func (c *ControlServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (c *ControlServer) handleSecretAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[1] != "invalidate" || parts[0] == "" {
		http.Error(w, "expected /v1/secrets/{id}/invalidate", http.StatusNotFound)
		return
	}
	id := parts[0]
	if c.cachedVault != nil {
		c.cachedVault.Invalidate(id)
	}
	w.WriteHeader(http.StatusOK)
}

func (c *ControlServer) handleSandboxAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/sandboxes/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[1] != "revoke" || parts[0] == "" {
		http.Error(w, "expected /v1/sandboxes/{id}/revoke", http.StatusNotFound)
		return
	}
	if c.revoker != nil {
		c.revoker.RevokeSandbox(parts[0])
	}
	w.WriteHeader(http.StatusOK)
}
