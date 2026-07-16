package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// LocalHTTPServer serves a minimal HTTP API on localhost for the edge proxy
// to resolve instanceID → vmIP without going through gRPC.
//
// It binds to 127.0.0.1 only — the proxy runs on the same host, so there is
// no need to expose this on any external interface.
type LocalHTTPServer struct {
	mgr    *Manager
	log    zerolog.Logger
	server *http.Server
}

// NewLocalHTTPServer creates a LocalHTTPServer backed by the given Manager.
func NewLocalHTTPServer(mgr *Manager, log zerolog.Logger) *LocalHTTPServer {
	s := &LocalHTTPServer{
		mgr: mgr,
		log: log.With().Str("component", "local_http").Logger(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/instances/", s.handleInstance)
	mux.HandleFunc("/verify-snapshot/", s.handleVerifySnapshot)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    64 << 10, // 64 KiB — internal only, be conservative
	}
	return s
}

// ListenAndServe starts the HTTP server bound to 127.0.0.1 and blocks until
// ctx is cancelled. addr must be a host:port string.
func (s *LocalHTTPServer) ListenAndServe(ctx context.Context, addr string) error {
	// Ensure the server always binds to 127.0.0.1 regardless of what the
	// caller passes — this service must not be accessible outside the host.
	_, port, err := splitHostPort(addr)
	if err != nil {
		return fmt.Errorf("local http server: invalid addr %q: %w", addr, err)
	}
	bindAddr := "127.0.0.1:" + port
	lis, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("local http server: %w", err)
	}
	return s.Serve(ctx, lis)
}

// Serve runs the server on an existing listener (e.g. one inherited from a
// systemd socket unit, which keeps it alive across vmd restarts). The
// caller guarantees the listener is loopback-only.
func (s *LocalHTTPServer) Serve(ctx context.Context, lis net.Listener) error {
	s.log.Info().Str("addr", lis.Addr().String()).Msg("local HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.Serve(lis); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("local http server: %w", err)
	case <-ctx.Done():
		return nil
	}
}

// Shutdown gracefully stops the server.
func (s *LocalHTTPServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// instanceResponse is the JSON shape returned by GET /instances/{id}.
type instanceResponse struct {
	VMIP      string `json:"vm_ip"`
	Status    string `json:"status"`
	StartedAt int64  `json:"started_at"` // Unix nanoseconds — proxy lifecycle key
	TeamID    string `json:"team_id,omitempty"`
	OwnerID   string `json:"owner_id,omitempty"`
}

// handleInstance handles GET /instances/{instanceID}.
func (s *LocalHTTPServer) handleInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	instanceID := strings.TrimPrefix(r.URL.Path, "/instances/")
	if instanceID == "" || strings.Contains(instanceID, "/") {
		http.Error(w, "missing instance ID", http.StatusBadRequest)
		return
	}

	info, ok := s.mgr.LookupInstance(instanceID)
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(instanceResponse{
		VMIP:      info.VMIP,
		Status:    info.Status.String(),
		StartedAt: info.CreatedAt.UnixNano(),
		TeamID:    info.TeamID,
		OwnerID:   info.OwnerID,
	}); err != nil {
		s.log.Error().Err(err).Str("instance", instanceID).Msg("failed to encode instance response")
	}
}

// verifySnapshotResponse is the JSON shape returned by POST /verify-snapshot/{id}.
type verifySnapshotResponse struct {
	MemPath string `json:"mem_path"` // re-snapshotted image to compare against the original
}

// handleVerifySnapshot handles POST /verify-snapshot/{vmID}: re-snapshot the
// frozen image and return its path for comparison. Internal/debug only.
func (s *LocalHTTPServer) handleVerifySnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.mgr.cfg.VerifySnapshotEnabled {
		http.Error(w, "verify-snapshot disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	vmID := strings.TrimPrefix(r.URL.Path, "/verify-snapshot/")
	if vmID == "" || strings.Contains(vmID, "/") {
		http.Error(w, "missing vm ID", http.StatusBadRequest)
		return
	}

	// Re-snapshotting a multi-GB image outlasts the default write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))

	memPath, err := s.mgr.VerifySnapshot(r.Context(), vmID)
	if err != nil {
		s.log.Error().Err(err).Str("vm_id", vmID).Msg("verify snapshot failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(verifySnapshotResponse{MemPath: memPath}); err != nil {
		s.log.Error().Err(err).Str("vm_id", vmID).Msg("failed to encode verify response")
	}
}

// splitHostPort extracts the port from a host:port string.
func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}
