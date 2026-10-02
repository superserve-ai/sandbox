package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// BuildAdmission binds work to the daemon's installed host identity. This
// callback is used only for template builds, never sandbox startup or resume.
type BuildAdmission struct{ ControlPlaneURL, Token, HostID, IncarnationID string }

func (a *GRPCAdapter) WithBuildAdmission(cfg BuildAdmission) *GRPCAdapter {
	a.buildAdmission = cfg
	a.mgr.buildIncarnation = cfg.IncarnationID
	return a
}
func (a *GRPCAdapter) buildAdmissionCallback(ctx context.Context, vmID string) (func() error, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	attempts := md.Get("template-build-attempt")
	incarnations := md.Get("template-build-incarnation")
	if len(attempts) == 0 && len(incarnations) == 0 {
		return nil, nil
	}
	cfg := a.buildAdmission
	if len(attempts) != 1 || len(incarnations) != 1 || incarnations[0] != cfg.IncarnationID || cfg.IncarnationID == "" {
		return nil, status.Error(codes.FailedPrecondition, "build incarnation mismatch")
	}
	id, err := uuid.Parse(attempts[0])
	if err != nil || vmID != "build-"+id.String() {
		return nil, status.Error(codes.InvalidArgument, "invalid build attempt identity")
	}
	if cfg.ControlPlaneURL == "" || cfg.Token == "" {
		return nil, status.Error(codes.Unavailable, "build admission unavailable")
	}
	return func() error {
		body, _ := json.Marshal(map[string]string{"attempt_id": id.String(), "incarnation_id": cfg.IncarnationID})
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(callCtx, http.MethodPost, fmt.Sprintf("%s/internal/hosts/%s/template-attempts/admit", cfg.ControlPlaneURL, cfg.HostID), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return status.Error(codes.Unavailable, "build admission response uncertain")
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusConflict {
			return status.Error(codes.FailedPrecondition, "build admission rejected")
		}
		if resp.StatusCode != http.StatusOK {
			return status.Error(codes.Unavailable, "build admission unavailable")
		}
		return nil
	}, nil
}

func (a *GRPCAdapter) checkBuildIncarnation(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	ids := md.Get("template-build-incarnation")
	if len(ids) == 0 {
		return nil
	}
	if len(ids) != 1 || ids[0] == "" || ids[0] != a.buildAdmission.IncarnationID {
		return status.Error(codes.FailedPrecondition, "build incarnation mismatch")
	}
	return nil
}

func (m *Manager) waitBuildStopped(ctx context.Context, id string) error {
	m.buildsMu.RLock()
	rec := m.builds[id]
	var done <-chan struct{}
	if rec != nil {
		done = rec.workerDone
	}
	m.buildsMu.RUnlock()
	if done == nil {
		return m.stopRecoveredBuild(ctx, id)
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
