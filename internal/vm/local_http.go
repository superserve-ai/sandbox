package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

// LocalHTTPServer serves a minimal HTTP API on localhost for the edge proxy
// to resolve instanceID → vmIP without going through gRPC.
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
	s.server = &http.Server{Handler: mux}
	return s
}

// ListenAndServe starts the HTTP server and blocks until ctx is cancelled.
func (s *LocalHTTPServer) ListenAndServe(ctx context.Context, addr string) error {
	s.server.Addr = addr
	s.log.Info().Str("addr", addr).Msg("local HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
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
}

// handleInstance handles GET /instances/{instanceID}.
func (s *LocalHTTPServer) handleInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	instanceID := strings.TrimPrefix(r.URL.Path, "/instances/")
	if instanceID == "" {
		http.Error(w, "missing instance ID", http.StatusBadRequest)
		return
	}

	info, ok := s.mgr.LookupInstance(instanceID)
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(instanceResponse{
		VMIP:      info.VMIP,
		Status:    info.Status.String(),
		StartedAt: info.CreatedAt.UnixNano(),
	})
}
