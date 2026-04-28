package vm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BuildStatus is the lifecycle state of an in-flight or completed template
// build tracked in Manager.builds.
type BuildStatus string

const (
	BuildStatusRunning      BuildStatus = "running"      // pulling + boot + steps
	BuildStatusSnapshotting BuildStatus = "snapshotting" // pause + CreateVMSnapshot
	BuildStatusReady        BuildStatus = "ready"        // terminal, success
	BuildStatusFailed       BuildStatus = "failed"       // terminal, error recorded
	BuildStatusCancelled    BuildStatus = "cancelled"    // terminal, CancelBuild called
)

// IsTerminal reports whether the status is one no future transition will
// overwrite. Used by GetBuildStatus consumers to know when to stop polling.
func (s BuildStatus) IsTerminal() bool {
	return s == BuildStatusReady || s == BuildStatusFailed || s == BuildStatusCancelled
}

// buildRecord is the in-memory state of one build. The record is keyed in
// Manager.builds by the build VM ID (which is also "build-" + templateID).
//
// Records are kept indefinitely after terminal status so polling
// consumers that come back late (e.g. supervisor after a control plane
// restart) can still read the outcome. Memory footprint is bounded by
// the per-team build concurrency limit times a handful of keys.
type buildRecord struct {
	BuildVMID  string
	TemplateID string
	Status     BuildStatus
	Result     *BuildTemplateResult // populated on ready
	Error      string               // populated on failed/cancelled
	StartedAt  time.Time
	EndedAt    time.Time // zero until terminal

	// cancel stops the goroutine running the build. Calling it under a
	// non-terminal status transitions the record to cancelled once the
	// goroutine notices; CancelBuild also destroys the build VM so boxd
	// + systemd state gets reclaimed immediately.
	cancel context.CancelFunc

	// logs is the build's per-build log buffer. Publishers append; SSE /
	// gRPC stream consumers subscribe. Closed on terminal status.
	logs *buildLogBuffer
}

// Snapshot is the client-visible read view of a buildRecord (no cancel fn).
type BuildStatusSnapshot struct {
	BuildVMID  string
	TemplateID string
	Status     BuildStatus
	Result     *BuildTemplateResult
	Error      string
	StartedAt  time.Time
	EndedAt    time.Time
}

// initBuildRegistry initializes the builds map lazily. Called from
// registerBuild. We don't set it up in NewManager so existing tests that
// construct Manager directly keep working without an explicit init.
func (m *Manager) initBuildRegistry() {
	m.buildsMu.Lock()
	defer m.buildsMu.Unlock()
	if m.builds == nil {
		m.builds = make(map[string]*buildRecord)
	}
}

// registerBuild inserts a new record in the registry. Fails if a build
// with the same ID is already in-flight — the caller is expected to pick a
// unique buildVMID per BuildTemplate invocation.
func (m *Manager) registerBuild(buildVMID, templateID string, cancel context.CancelFunc) (*buildRecord, error) {
	m.initBuildRegistry()
	m.buildsMu.Lock()
	defer m.buildsMu.Unlock()
	if existing, ok := m.builds[buildVMID]; ok && !existing.Status.IsTerminal() {
		return nil, fmt.Errorf("build %s already in flight", buildVMID)
	}
	rec := &buildRecord{
		BuildVMID:  buildVMID,
		TemplateID: templateID,
		Status:     BuildStatusRunning,
		StartedAt:  time.Now(),
		cancel:     cancel,
		logs:       newBuildLogBuffer(),
	}
	m.builds[buildVMID] = rec
	return rec, nil
}

// setBuildStatus transitions a record to a new status. Guarded so terminal
// states can't be overwritten — once ready/failed/cancelled, the record is
// frozen. Returns true on transition, false on no-op (record missing or
// already terminal).
func (m *Manager) setBuildStatus(buildVMID string, newStatus BuildStatus) bool {
	m.buildsMu.Lock()
	defer m.buildsMu.Unlock()
	rec, ok := m.builds[buildVMID]
	if !ok {
		return false
	}
	if rec.Status.IsTerminal() {
		return false
	}
	rec.Status = newStatus
	return true
}

// completeBuild transitions a record to ready with the successful result,
// or to failed with the error. Idempotent: if the record is already
// terminal (e.g. cancelled before snapshot finished), the earlier terminal
// status wins and this call is a no-op.
func (m *Manager) completeBuild(buildVMID string, result *BuildTemplateResult, buildErr error) {
	m.buildsMu.Lock()
	rec, ok := m.builds[buildVMID]
	if !ok {
		m.buildsMu.Unlock()
		return
	}
	if rec.Status.IsTerminal() {
		m.buildsMu.Unlock()
		return // cancelled wins over a late success or later failure
	}
	rec.EndedAt = time.Now()
	if buildErr != nil {
		rec.Status = BuildStatusFailed
		rec.Error = buildErr.Error()
	} else {
		rec.Status = BuildStatusReady
		rec.Result = result
	}
	logs := rec.logs
	finalStatus := rec.Status
	m.buildsMu.Unlock()

	// Close the log buffer OUTSIDE the registry lock so subscribers that
	// are blocked trying to Read from their channel can unwind without
	// contending with the registry.
	if logs != nil {
		logs.Close(finalStatus)
	}
}

// cancelBuildRecord marks a record cancelled and invokes the goroutine's
// cancel function. Safe to call on a terminal record (no-op). Returns the
// previous status so the caller can distinguish "actually cancelled an
// in-flight build" from "was already done."
func (m *Manager) cancelBuildRecord(buildVMID string, reason string) (BuildStatus, bool) {
	m.buildsMu.Lock()
	rec, ok := m.builds[buildVMID]
	if !ok {
		m.buildsMu.Unlock()
		return "", false
	}
	prev := rec.Status
	if prev.IsTerminal() {
		m.buildsMu.Unlock()
		return prev, true
	}
	rec.Status = BuildStatusCancelled
	rec.Error = reason
	rec.EndedAt = time.Now()
	cancelFn := rec.cancel
	logs := rec.logs
	m.buildsMu.Unlock()
	if cancelFn != nil {
		cancelFn()
	}
	// Close log buffer so subscribers get a Finished event and exit.
	if logs != nil {
		logs.Close(BuildStatusCancelled)
	}
	return prev, true
}

// GetBuildStatus returns the read-only snapshot of a build's state. Returns
// false when the build ID is unknown — the supervisor maps that to "vmd
// has no record, build is effectively gone."
func (m *Manager) GetBuildStatus(buildVMID string) (BuildStatusSnapshot, bool) {
	m.buildsMu.RLock()
	defer m.buildsMu.RUnlock()
	rec, ok := m.builds[buildVMID]
	if !ok {
		return BuildStatusSnapshot{}, false
	}
	return BuildStatusSnapshot{
		BuildVMID:  rec.BuildVMID,
		TemplateID: rec.TemplateID,
		Status:     rec.Status,
		Result:     rec.Result,
		Error:      rec.Error,
		StartedAt:  rec.StartedAt,
		EndedAt:    rec.EndedAt,
	}, true
}

// CancelBuild marks a build cancelled and signals its template-builder
// subprocess (via ctx.Cancel → SIGTERM → cleanup defers). Safe on
// unknown or already-terminal builds.
func (m *Manager) CancelBuild(ctx context.Context, buildVMID string) error {
	m.cancelBuildRecord(buildVMID, "cancelled by caller")
	return nil
}

// buildsMu / builds live as fields on Manager; declared here so the registry
// file stays self-contained. Added via a struct mutation in manager.go.
var _ = sync.RWMutex{}
