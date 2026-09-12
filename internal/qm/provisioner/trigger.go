package provisioner

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Trigger starts a provisioner run for a tenant without doing the work in
// the caller's request. Only identifiers travel: the model key is already
// in Secret Manager by the time a run is triggered.
//
// An error wrapping ErrTriggerRejected means the run was definitely not
// started; any other error is ambiguous (a timeout after the request was
// accepted, say) and callers must assume a run may be under way.
type Trigger interface {
	Trigger(ctx context.Context, teamID, tenantID uuid.UUID, mode Mode) error
}

// ErrTriggerRejected marks a definitive refusal to start a run.
var ErrTriggerRejected = errors.New("run not started")

// InProcess runs the plan on a goroutine in the calling process. Used by
// tests and by QM_PROVISIONER_MODE=inprocess for local development.
type InProcess struct {
	Runner *Runner
	Log    zerolog.Logger
	wg     sync.WaitGroup
}

func (p *InProcess) Trigger(_ context.Context, teamID, tenantID uuid.UUID, mode Mode) error {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		// Detached from the request: the run outlives the HTTP response.
		if err := p.Runner.Run(context.Background(), teamID, tenantID, mode); err != nil {
			p.Log.Warn().Str("error", ScrubString(err.Error())).Str("tenant_id", tenantID.String()).Str("mode", string(mode)).Msg("in-process run ended with error")
		}
	}()
	return nil
}

// Wait blocks until every triggered run has returned; tests call it before
// asserting on the store.
func (p *InProcess) Wait() {
	p.wg.Wait()
}

// Recorder is a Trigger that only remembers what it was asked to start.
type Recorder struct {
	mu    sync.Mutex
	Calls []TriggerCall
	// Err, when set, is returned by every Trigger call.
	Err error
}

type TriggerCall struct {
	TeamID   uuid.UUID
	TenantID uuid.UUID
	Mode     Mode
}

func (r *Recorder) Trigger(_ context.Context, teamID, tenantID uuid.UUID, mode Mode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.Calls = append(r.Calls, TriggerCall{TeamID: teamID, TenantID: tenantID, Mode: mode})
	return nil
}
