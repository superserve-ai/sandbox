package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/vm/fc/models"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func writeSavedTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func savedTestManager(snapshotDir, runDir string, inst *VMInstance) *Manager {
	return &Manager{
		cfg: ManagerConfig{
			SnapshotDir: snapshotDir,
			RunDir:      runDir,
		},
		log: zerolog.Nop(),
		vms: map[string]*VMInstance{inst.ID: inst},
	}
}

func TestCreateSavedSnapshotPausedFullIsImmutableAndIdempotent(t *testing.T) {
	installInactiveSystemctl(t)
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "11111111-1111-1111-1111-111111111111"
	snapshotID := "snap-111"
	runtimeDir := filepath.Join(snapshotRoot, vmID)
	vmstate := filepath.Join(runtimeDir, "vmstate.snap")
	memory := filepath.Join(runtimeDir, "mem.snap")
	disk := filepath.Join(runRoot, vmID, "rootfs.ext4")
	writeSavedTestFile(t, vmstate, []byte("paused-vmstate"))
	writeSavedTestFile(t, memory, []byte("paused-memory"))
	writeSavedTestFile(t, disk, []byte("paused-disk"))

	inst := &VMInstance{
		ID:           vmID,
		Status:       StatusPaused,
		RunDirID:     vmID,
		DiskPath:     disk,
		SnapshotPath: vmstate,
		MemFilePath:  memory,
		Config: VMConfig{
			VCPU:      2,
			MemoryMiB: 2048,
		},
	}
	mgr := savedTestManager(snapshotRoot, runRoot, inst)

	got, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID)
	if err != nil {
		t.Fatalf("CreateSavedSnapshot: %v", err)
	}
	if got.SourceState != "paused" || inst.Status != StatusPaused {
		t.Fatalf("source state changed: result=%q instance=%s", got.SourceState, inst.Status)
	}
	wantDir := filepath.Join(snapshotRoot, SavedSnapshotsDirName, vmID, snapshotID)
	if filepath.Dir(got.Artifacts.ManifestPath) != wantDir {
		t.Fatalf("manifest dir = %q, want %q", filepath.Dir(got.Artifacts.ManifestPath), wantDir)
	}
	if got.Artifacts.DiskFullPath == "" || got.Artifacts.DiskOverlayPath != "" || got.Artifacts.DiskDeltaPath != "" {
		t.Fatalf("unexpected disk artifacts: %+v", got.Artifacts)
	}
	if got.Resources.DiskSizeMiB != 1 {
		t.Fatalf("inferred disk size = %d MiB, want 1", got.Resources.DiskSizeMiB)
	}
	// vmstate is copied into a new inode, while memory and disk are reflinked.
	// Only the latter seal source-owned extents into the shared branch.
	wantSourceLogical := int64(len("paused-memory") + len("paused-disk"))
	if got.SourceLogicalSizeBytes != wantSourceLogical || got.SourceExclusiveSizeBytes <= 0 {
		t.Fatalf("source storage accounting = logical %d exclusive %d, want logical %d and positive exclusive bytes",
			got.SourceLogicalSizeBytes, got.SourceExclusiveSizeBytes, wantSourceLogical)
	}

	// The committed copies do not share mutable bytes with the retained pause
	// checkpoint. Changing the source after capture cannot change the snapshot.
	writeSavedTestFile(t, vmstate, []byte("changed-vmstate"))
	writeSavedTestFile(t, memory, []byte("changed-memory"))
	writeSavedTestFile(t, disk, []byte("changed-disk"))
	for path, want := range map[string]string{
		got.Artifacts.SnapshotPath: "paused-vmstate",
		got.Artifacts.MemFilePath:  "paused-memory",
		got.Artifacts.DiskFullPath: "paused-disk",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != want {
			t.Errorf("immutable artifact %s = %q, %v; want %q", path, data, readErr, want)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Errorf("stat immutable artifact %s: %v", path, statErr)
		} else if info.Mode().Perm()&0o222 != 0 {
			t.Errorf("artifact %s is writable: mode=%v", path, info.Mode())
		}
	}

	// Lost-response retry returns the committed snapshot without consulting
	// the now-mutated runtime checkpoint.
	retry, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if retry.CreatedAt != got.CreatedAt || retry.Artifacts.ManifestPath != got.Artifacts.ManifestPath {
		t.Fatalf("retry created a different snapshot: first=%+v retry=%+v", got, retry)
	}
	protoResult, err := NewGRPCAdapter(mgr).CreateSnapshot(context.Background(), &vmdpb.CreateSnapshotRequest{
		VmId:       vmID,
		SnapshotId: snapshotID,
	})
	if err != nil {
		t.Fatalf("gRPC idempotent retry: %v", err)
	}
	if protoResult.GetSourceLogicalSizeBytes() != got.SourceLogicalSizeBytes ||
		protoResult.GetSourceExclusiveSizeBytes() != got.SourceExclusiveSizeBytes {
		t.Fatalf("gRPC source storage accounting = logical %d exclusive %d, want logical %d exclusive %d",
			protoResult.GetSourceLogicalSizeBytes(), protoResult.GetSourceExclusiveSizeBytes(),
			got.SourceLogicalSizeBytes, got.SourceExclusiveSizeBytes)
	}

	if err := mgr.DeleteSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("DeleteSavedSnapshot: %v", err)
	}
	if _, err := os.Stat(wantDir); !os.IsNotExist(err) {
		t.Fatalf("saved snapshot dir remains after delete: %v", err)
	}
	if err := mgr.DeleteSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("idempotent DeleteSavedSnapshot: %v", err)
	}
}

func TestDeleteSavedSnapshotWaitsForSourceLifecycleOperation(t *testing.T) {
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "12111111-1111-1111-1111-111111111111"
	snapshotID := "snap-locked"
	dir := filepath.Join(snapshotRoot, SavedSnapshotsDirName, vmID, snapshotID)
	writeSavedTestFile(t, filepath.Join(dir, savedSnapshotManifestName), []byte(`{}`))
	mgr := savedTestManager(snapshotRoot, runRoot, &VMInstance{ID: vmID})

	unlock, err := mgr.lockVMOp(context.Background(), vmID)
	if err != nil {
		t.Fatalf("hold source lifecycle lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = mgr.DeleteSavedSnapshot(ctx, vmID, snapshotID)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("delete while capture lock held = %v, want deadline exceeded", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("timed-out delete touched saved directory: %v", statErr)
	}

	unlock()
	if err := mgr.DeleteSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("delete after source operation completed: %v", err)
	}
}

func TestDeleteSavedSnapshotRemovesMatchingStagingArtifacts(t *testing.T) {
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "13111111-1111-1111-1111-111111111111"
	snapshotID := "snap-cancelled"
	sourceDir := filepath.Join(snapshotRoot, SavedSnapshotsDirName, vmID)
	matching := filepath.Join(sourceDir, "."+snapshotID+".tmp-attempt")
	unrelated := filepath.Join(sourceDir, ".another-snapshot.tmp-attempt")
	writeSavedTestFile(t, filepath.Join(matching, "partial.mem"), []byte("partial"))
	writeSavedTestFile(t, filepath.Join(unrelated, "partial.mem"), []byte("keep"))
	mgr := savedTestManager(snapshotRoot, runRoot, &VMInstance{ID: vmID})

	if err := mgr.DeleteSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("DeleteSavedSnapshot: %v", err)
	}
	if _, err := os.Stat(matching); !os.IsNotExist(err) {
		t.Fatalf("matching staging directory remains: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated staging directory was removed: %v", err)
	}
}

func TestCreateSavedSnapshotPausedLayeredCopiesSidecarsAndPlansFreshClone(t *testing.T) {
	installInactiveSystemctl(t)
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "22222222-2222-2222-2222-222222222222"
	snapshotID := "snap-layered"
	runtimeDir := filepath.Join(snapshotRoot, vmID)
	vmstate := filepath.Join(runtimeDir, "vmstate.snap")
	memory := filepath.Join(runtimeDir, "mem.diff")
	memoryBase := filepath.Join(snapshotRoot, TemplatesDirName, "template-a", "build-a", "mem.snap")
	diskBase := filepath.Join(runRoot, TemplatesDirName, "template-a", "build-a", "base.ext4")
	disk := filepath.Join(runRoot, vmID, "overlay.ext4")
	writeSavedTestFile(t, vmstate, []byte("state"))
	writeSavedTestFile(t, memory, []byte("memory-diff"))
	writeSavedTestFile(t, presence.SidecarPath(memory), []byte("presence"))
	writeSavedTestFile(t, memoryBase, []byte("memory-base"))
	writeSavedTestFile(t, diskBase, []byte("disk-base"))
	writeSavedTestFile(t, disk, []byte("disk-overlay"))

	inst := &VMInstance{
		ID:           vmID,
		Status:       StatusPaused,
		RunDirID:     vmID,
		DiskPath:     disk,
		SnapshotPath: vmstate,
		MemFilePath:  memory,
		BaseMemPath:  memoryBase,
		Config: VMConfig{
			VCPU:        4,
			MemoryMiB:   4096,
			DiskSizeMiB: 8192,
			BasePath:    diskBase,
		},
	}
	mgr := savedTestManager(snapshotRoot, runRoot, inst)
	got, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID)
	if err != nil {
		t.Fatalf("CreateSavedSnapshot: %v", err)
	}
	if got.Artifacts.MemoryBasePath != memoryBase || got.Artifacts.DiskBasePath != diskBase {
		t.Fatalf("base references not retained: %+v", got.Artifacts)
	}
	if filepath.Base(got.Artifacts.MemFilePath) != "mem.diff" || got.Artifacts.DiskOverlayPath == "" {
		t.Fatalf("layered artifacts not selected: %+v", got.Artifacts)
	}
	if got.SourceLogicalSizeBytes != int64(len("memory-diff")+len("disk-overlay")) || got.SourceExclusiveSizeBytes <= 0 {
		t.Fatalf("retained source layer = logical %d exclusive %d; copied vmstate/sidecars must be excluded",
			got.SourceLogicalSizeBytes, got.SourceExclusiveSizeBytes)
	}
	baseRecord, err := os.ReadFile(got.Artifacts.MemFilePath + ".base")
	if err != nil || string(baseRecord) != memoryBase+"\n" {
		t.Fatalf("memory base sidecar = %q, %v", baseRecord, err)
	}
	if data, err := os.ReadFile(presence.SidecarPath(got.Artifacts.MemFilePath)); err != nil || string(data) != "presence" {
		t.Fatalf("memory presence sidecar = %q, %v", data, err)
	}

	manifest, err := mgr.loadSavedSnapshotManifest(got.Artifacts.ManifestPath)
	if err != nil {
		t.Fatalf("loadSavedSnapshotManifest: %v", err)
	}
	cfg, err := savedSnapshotVMConfig(manifest, nil)
	if err != nil {
		t.Fatalf("savedSnapshotVMConfig: %v", err)
	}
	if cfg.BasePath != diskBase || cfg.RootfsPath != got.Artifacts.DiskOverlayPath || cfg.DeltaDir != "" {
		t.Fatalf("restore config = %+v", cfg)
	}
	plan := planRestoreWithSource(cfg.BasePath, cfg.DeltaDir, cfg.RootfsPath, false)
	if plan.action != restoreCloneOverlay || plan.source != got.Artifacts.DiskOverlayPath {
		t.Fatalf("restore plan = %+v, want fresh saved-overlay clone", plan)
	}
}

func TestCreateSavedSnapshotRunningReturnsSourceToRunningAndUsesDelta(t *testing.T) {
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "33333333-3333-3333-3333-333333333333"
	snapshotID := "snap-running"
	diskBase := filepath.Join(runRoot, TemplatesDirName, "template-a", "build-a", "base.ext4")
	disk := filepath.Join(runRoot, vmID, "overlay.ext4")
	writeSavedTestFile(t, diskBase, []byte("immutable-base"))
	writeSavedTestFile(t, disk, []byte("live-overlay"))

	socketPath := filepath.Join(t.TempDir(), "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var patchStates []string
	createCalls := 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/vm":
			var body struct {
				State string `json:"state"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			patchStates = append(patchStates, body.State)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/snapshot/create":
			var body struct {
				SnapshotPath  string `json:"snapshot_path"`
				MemFilePath   string `json:"mem_file_path"`
				BlockDeltaDir string `json:"block_delta_dir"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			createCalls++
			mu.Unlock()
			if err := os.WriteFile(body.SnapshotPath, []byte("vmstate"), 0o600); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(body.MemFilePath, []byte("memory"), 0o600); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(filepath.Join(body.BlockDeltaDir, "rootfs.delta"), []byte("delta"), 0o600); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = io.WriteString(w, "unexpected request")
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	waitForUnixSocket(t, socketPath)

	inst := &VMInstance{
		ID:         vmID,
		Status:     StatusRunning,
		SocketPath: socketPath,
		DiskPath:   disk,
		RunDirID:   vmID,
		Config: VMConfig{
			VCPU:        2,
			MemoryMiB:   1024,
			DiskSizeMiB: 4096,
			BasePath:    diskBase,
		},
		DirtyTracked: true,
	}
	mgr := savedTestManager(snapshotRoot, runRoot, inst)
	got, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID)
	if err != nil {
		t.Fatalf("CreateSavedSnapshot: %v", err)
	}
	if got.SourceState != "running" || inst.Status != StatusRunning || inst.DirtyTracked {
		t.Fatalf("running source not restored cleanly: source=%q status=%s dirty=%v", got.SourceState, inst.Status, inst.DirtyTracked)
	}
	if got.Artifacts.DiskDeltaPath == "" || got.Artifacts.DiskOverlayPath != "" {
		t.Fatalf("running overlay capture did not use block delta: %+v", got.Artifacts)
	}
	if got.SourceLogicalSizeBytes != 0 || got.SourceExclusiveSizeBytes != 0 {
		t.Fatalf("block-delta capture retained unrelated source bytes: logical=%d exclusive=%d",
			got.SourceLogicalSizeBytes, got.SourceExclusiveSizeBytes)
	}
	mu.Lock()
	states := append([]string(nil), patchStates...)
	calls := createCalls
	mu.Unlock()
	if len(states) != 2 || calls != 1 {
		t.Fatalf("firecracker calls: patch states=%v creates=%d", states, calls)
	}

	if _, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("idempotent running retry: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if createCalls != 1 || len(patchStates) != 2 {
		t.Fatalf("idempotent retry touched source: patch=%v creates=%d", patchStates, createCalls)
	}
}

func TestSavedCaptureDisarmsConsumedDirtyBitmapBeforeMaterialization(t *testing.T) {
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	vmID := "34333333-3333-3333-3333-333333333333"
	snapshotID := "snap-diff-materialization-retry"
	diskBase := filepath.Join(runRoot, TemplatesDirName, "template-a", "build-a", "base.ext4")
	disk := filepath.Join(runRoot, vmID, "overlay.ext4")
	memoryBase := filepath.Join(snapshotRoot, TemplatesDirName, "template-a", "build-a", "mem.snap")
	writeSavedTestFile(t, diskBase, []byte("immutable-disk-base"))
	writeSavedTestFile(t, disk, []byte("live-overlay"))
	writeSavedTestFile(t, memoryBase, make([]byte, 2*4096))

	socketPath := filepath.Join(t.TempDir(), "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var mu sync.Mutex
	var snapshotTypes []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/vm":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/snapshot/create":
			var body struct {
				SnapshotPath  string `json:"snapshot_path"`
				MemFilePath   string `json:"mem_file_path"`
				SnapshotType  string `json:"snapshot_type"`
				BlockDeltaDir string `json:"block_delta_dir"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			snapshotTypes = append(snapshotTypes, body.SnapshotType)
			call := len(snapshotTypes)
			mu.Unlock()
			if err := os.WriteFile(body.SnapshotPath, []byte("vmstate"), 0o600); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if call == 1 {
				// The Diff itself succeeds, consuming Firecracker's dirty bitmap,
				// but its missing presence sidecar makes saved-branch
				// materialization fail afterward.
				if err := os.WriteFile(body.MemFilePath, make([]byte, 2*4096), 0o600); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			} else {
				if err := os.WriteFile(body.MemFilePath, []byte("full-memory"), 0o600); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if err := os.WriteFile(filepath.Join(body.BlockDeltaDir, "rootfs.delta"), []byte("disk-delta"), 0o600); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	waitForUnixSocket(t, socketPath)

	inst := &VMInstance{
		ID:           vmID,
		Status:       StatusRunning,
		SocketPath:   socketPath,
		DiskPath:     disk,
		RunDirID:     vmID,
		MemFilePath:  memoryBase,
		BaseMemPath:  memoryBase,
		DirtyTracked: true,
		Config: VMConfig{
			VCPU:        2,
			MemoryMiB:   1024,
			DiskSizeMiB: 4096,
			BasePath:    diskBase,
		},
	}
	mgr := savedTestManager(snapshotRoot, runRoot, inst)
	mgr.cfg.IncrementalSnapshotEnabled = true
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer state.Close()
	mgr.SetStateStore(state)

	if _, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID); err == nil || !strings.Contains(err.Error(), "presence map") {
		t.Fatalf("first capture error = %v, want post-Diff materialization failure", err)
	}
	inst.mu.RLock()
	dirtyTracked := inst.DirtyTracked
	inst.mu.RUnlock()
	if dirtyTracked {
		t.Fatal("successful Diff emission left source dirty tracking armed")
	}
	record, err := state.Get(vmID)
	if err != nil || record == nil {
		t.Fatalf("persisted source state = %+v, %v", record, err)
	}
	if recovered := toInstance(*record); recovered.DirtyTracked {
		t.Fatal("restart recovery re-armed a consumed dirty bitmap")
	}

	if _, err := mgr.CreateSavedSnapshot(context.Background(), vmID, snapshotID); err != nil {
		t.Fatalf("retry capture: %v", err)
	}
	mu.Lock()
	gotTypes := append([]string(nil), snapshotTypes...)
	mu.Unlock()
	if len(gotTypes) != 2 || gotTypes[0] != models.SnapshotCreateParamsSnapshotTypeDiff || gotTypes[1] != models.SnapshotCreateParamsSnapshotTypeFull {
		t.Fatalf("snapshot types = %v, want [Diff Full]", gotTypes)
	}
}

func TestUnpauseSavedSnapshotSourceAcceptsErrorAfterResumeApplied(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var mu sync.Mutex
	state := models.InstanceInfoStatePaused
	patchCalls := 0
	describeCalls := 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/vm":
			mu.Lock()
			state = models.InstanceInfoStateRunning
			patchCalls++
			mu.Unlock()
			// Model an applied command whose response was lost/failed. The
			// caller must resolve the result from DescribeInstance.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"fault_message":"response lost after resume"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/":
			mu.Lock()
			describeCalls++
			current := state
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"app_name":    "Firecracker",
				"id":          "anonymous-instance",
				"state":       current,
				"vmm_version": "test",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	waitForUnixSocket(t, socketPath)

	if err := unpauseSavedSnapshotSource(socketPath); err != nil {
		t.Fatalf("ambiguous unpause should be accepted after running-state proof: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if patchCalls != 1 || describeCalls != 1 {
		t.Fatalf("calls: patch=%d describe=%d, want one of each", patchCalls, describeCalls)
	}
}

func TestSnapshotArtifactSizesIncludesAndDeduplicatesReferencedBases(t *testing.T) {
	owned := t.TempDir()
	writeSavedTestFile(t, filepath.Join(owned, "a"), []byte("abc"))
	writeSavedTestFile(t, filepath.Join(owned, "b"), []byte("12345"))
	baseDir := t.TempDir()
	base := filepath.Join(baseDir, "base")
	alias := filepath.Join(baseDir, "alias")
	writeSavedTestFile(t, base, []byte("1234567"))
	if err := os.Link(base, alias); err != nil {
		t.Fatalf("hardlink: %v", err)
	}

	logical, exclusive, err := snapshotArtifactSizes(owned, base, alias, base)
	if err != nil {
		t.Fatalf("snapshotArtifactSizes: %v", err)
	}
	if logical != 3+5+7 {
		t.Fatalf("logical = %d, want 15 (referenced inode counted once)", logical)
	}
	_, ownedExclusive, err := snapshotArtifactSizes(owned)
	if err != nil {
		t.Fatal(err)
	}
	if exclusive != ownedExclusive || exclusive <= 0 {
		t.Fatalf("exclusive = %d, want owned-only allocated bytes %d", exclusive, ownedExclusive)
	}
}

func TestSnapshotArtifactSizesDoesNotRebillReflinkOwnedPaths(t *testing.T) {
	owned := t.TempDir()
	source := filepath.Join(t.TempDir(), "source-layer")
	shared := filepath.Join(owned, "shared-layer")
	metadata := filepath.Join(owned, "vmstate")
	writeSavedTestFile(t, source, bytes.Repeat([]byte{0x5a}, 8192))
	if err := reflinkImmutableFileContext(context.Background(), source, shared); err != nil {
		t.Skipf("test filesystem has no reflink support: %v", err)
	}
	writeSavedTestFile(t, metadata, []byte("state"))

	logical, exclusive, err := snapshotArtifactSizesWithShared(owned, []string{shared})
	if err != nil {
		t.Fatalf("snapshotArtifactSizesWithShared: %v", err)
	}
	if logical != 8192+int64(len("state")) {
		t.Fatalf("logical = %d, want %d", logical, 8192+len("state"))
	}
	_, metadataExclusive, err := snapshotArtifactSizes(filepath.Dir(metadata), shared)
	if err != nil {
		t.Fatal(err)
	}
	// The comparison directory includes shared too, so derive the metadata's
	// allocation directly through a one-file directory.
	metadataOnly := t.TempDir()
	writeSavedTestFile(t, filepath.Join(metadataOnly, "vmstate"), []byte("state"))
	_, metadataExclusive, err = snapshotArtifactSizes(metadataOnly)
	if err != nil {
		t.Fatal(err)
	}
	if exclusive != metadataExclusive {
		t.Fatalf("exclusive = %d, want metadata-only allocated bytes %d", exclusive, metadataExclusive)
	}
}

func TestSavedSourceLayerUsageCountsOnlyExtentsStillSharedAfterCaptureWrites(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	clone := filepath.Join(dir, "clone")
	writeSavedTestFile(t, source, bytes.Repeat([]byte{0x5a}, 2<<20))
	before, err := exclusiveFileBytes(source)
	if err != nil {
		t.Fatal(err)
	}
	usage := &savedSourceLayerUsage{}
	if err := usage.reflink(context.Background(), source, clone); err != nil {
		t.Skipf("test filesystem has no reflink support: %v", err)
	}

	// Model materializeSavedMemoryBranch overwriting a dirty page after the
	// initial clone. That page is no longer retained from the source.
	f, err := os.OpenFile(clone, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xa5}, 4096), 0); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := exclusiveFileBytes(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := usage.finalize(); err != nil {
		t.Fatal(err)
	}
	wantExclusive := before - after
	if usage.exclusiveBytes != wantExclusive {
		t.Fatalf("retained exclusive bytes = %d, want before-after = %d-%d = %d",
			usage.exclusiveBytes, before, after, wantExclusive)
	}
	wantLogical := int64(0)
	if wantExclusive > 0 {
		wantLogical = 2 << 20
	}
	if usage.logicalBytes != wantLogical {
		t.Fatalf("retained logical bytes = %d, want %d", usage.logicalBytes, wantLogical)
	}
}

func TestApplySparseFileOverwritesOnlyDirtyExtents(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	delta := filepath.Join(dir, "delta")
	const page = int64(4096)
	if err := createSparseFile(target, 3*page); err != nil {
		t.Fatal(err)
	}
	if err := createSparseFile(delta, 3*page); err != nil {
		t.Fatal(err)
	}
	targetFile, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetFile.WriteAt(bytes.Repeat([]byte{'A'}, int(page)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := targetFile.WriteAt(bytes.Repeat([]byte{'C'}, int(page)), 2*page); err != nil {
		t.Fatal(err)
	}
	if err := targetFile.Close(); err != nil {
		t.Fatal(err)
	}
	deltaFile, err := os.OpenFile(delta, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deltaFile.WriteAt(bytes.Repeat([]byte{'B'}, int(page)), page); err != nil {
		t.Fatal(err)
	}
	if err := deltaFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := applySparseFileContext(context.Background(), delta, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []byte{'A', 'B', 'C'} {
		if pageBytes := got[int64(i)*page : int64(i+1)*page]; !bytes.Equal(pageBytes, bytes.Repeat([]byte{want}, int(page))) {
			t.Fatalf("page %d was not preserved/applied as %q", i, want)
		}
	}
}

func TestSavedSnapshotPathsRejectTraversalAndSymlinkParents(t *testing.T) {
	root := t.TempDir()
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if _, err := mgr.savedSnapshotDir("../escape", "snap"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("source traversal code = %s, want InvalidArgument (%v)", status.Code(err), err)
	}
	if _, err := mgr.savedSnapshotDir("source", "../escape"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("snapshot traversal code = %s, want InvalidArgument (%v)", status.Code(err), err)
	}

	outside := t.TempDir()
	writeSavedTestFile(t, filepath.Join(outside, "snap", savedSnapshotManifestName), []byte(`{}`))
	if err := os.MkdirAll(filepath.Join(root, SavedSnapshotsDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, SavedSnapshotsDirName, "source")); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, SavedSnapshotsDirName, "source", "snap", savedSnapshotManifestName)
	if _, err := mgr.loadSavedSnapshotManifest(manifestPath); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("symlink parent code = %s, want InvalidArgument (%v)", status.Code(err), err)
	}
	if err := mgr.DeleteSavedSnapshot(context.Background(), "source", "snap"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("symlink delete code = %s, want FailedPrecondition (%v)", status.Code(err), err)
	}
	if _, err := os.Stat(filepath.Join(outside, "snap", savedSnapshotManifestName)); err != nil {
		t.Fatalf("unsafe delete touched symlink target: %v", err)
	}
}

func TestSavedSnapshotVMConfigUsesImmutableDiskModes(t *testing.T) {
	base := "/var/lib/sandbox/templates/t/base.ext4"
	dir := "/var/lib/sandbox/snapshots/saved/source/snap"
	cases := []struct {
		name string
		disk savedDiskArtifact
		want restoreDiskAction
	}{
		{"block delta", savedDiskArtifact{Kind: diskArtifactBlockDelta, BasePath: base, Path: filepath.Join(dir, "rootfs.delta")}, restoreCreateOverlay},
		{"saved overlay", savedDiskArtifact{Kind: diskArtifactOverlay, BasePath: base, Path: filepath.Join(dir, "rootfs.overlay")}, restoreCloneOverlay},
		{"legacy full", savedDiskArtifact{Kind: diskArtifactFull, Path: filepath.Join(dir, "rootfs.ext4")}, restoreCopyRootfs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &savedSnapshotManifest{Resources: SavedSnapshotResources{VCPU: 2, MemoryMiB: 1024, DiskSizeMiB: 4096}, Disk: tc.disk}
			cfg, err := savedSnapshotVMConfig(manifest, nil)
			if err != nil {
				t.Fatal(err)
			}
			plan := planRestoreWithSource(cfg.BasePath, cfg.DeltaDir, cfg.RootfsPath, false)
			if plan.action != tc.want {
				t.Fatalf("plan action = %v, want %v (cfg=%+v)", plan.action, tc.want, cfg)
			}
		})
	}
}

func writeSavedRestoreFixture(t *testing.T) (*Manager, string, *savedSnapshotManifest) {
	t.Helper()
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	dir := filepath.Join(snapshotRoot, SavedSnapshotsDirName, "source-vm", "snapshot-1")
	manifestPath := filepath.Join(dir, savedSnapshotManifestName)
	manifest := &savedSnapshotManifest{
		SchemaVersion: savedSnapshotSchemaVersion,
		SnapshotID:    "snapshot-1",
		SourceVMID:    "source-vm",
		SourceState:   StatusPaused.String(),
		CreatedAt:     time.Now().UTC(),
		Resources: SavedSnapshotResources{
			VCPU:        1,
			MemoryMiB:   128,
			DiskSizeMiB: 1,
		},
		VMStatePath: filepath.Join(dir, "vmstate.snap"),
		Memory:      savedMemoryArtifact{Path: filepath.Join(dir, "mem.snap")},
		Disk:        savedDiskArtifact{Kind: diskArtifactFull, Path: filepath.Join(dir, "rootfs.ext4")},
	}
	writeSavedTestFile(t, manifest.VMStatePath, []byte("vmstate"))
	writeSavedTestFile(t, manifest.Memory.Path, []byte("memory"))
	writeSavedTestFile(t, manifest.Disk.Path, []byte("disk"))
	if err := populateSavedSnapshotDigests(dir, dir, manifest); err != nil {
		t.Fatalf("populate digests: %v", err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeSavedTestFile(t, manifestPath, encoded)
	mgr := &Manager{
		cfg: ManagerConfig{SnapshotDir: snapshotRoot, RunDir: runRoot},
		log: zerolog.Nop(),
		vms: make(map[string]*VMInstance),
	}
	return mgr, manifestPath, manifest
}

func TestRestoreSavedSnapshotClassifiesMissingAndCorruptArtifactsAsDataLoss(t *testing.T) {
	t.Run("missing manifest", func(t *testing.T) {
		snapshotRoot := t.TempDir()
		mgr := &Manager{cfg: ManagerConfig{SnapshotDir: snapshotRoot}}
		manifestPath := filepath.Join(snapshotRoot, SavedSnapshotsDirName, "source-vm", "snapshot-1", savedSnapshotManifestName)
		_, _, err := mgr.RestoreSavedSnapshot(context.Background(), "child-vm", manifestPath, strings.Repeat("0", 64), nil, nil, "team", "owner")
		if status.Code(err) != codes.DataLoss {
			t.Fatalf("missing manifest code = %s, want DataLoss (%v)", status.Code(err), err)
		}
	})

	t.Run("corrupt manifest", func(t *testing.T) {
		mgr, manifestPath, _ := writeSavedRestoreFixture(t)
		digest, err := sha256File(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		writeSavedTestFile(t, manifestPath, []byte("{not-json"))
		_, _, err = mgr.RestoreSavedSnapshot(context.Background(), "child-vm", manifestPath, digest, nil, nil, "team", "owner")
		if status.Code(err) != codes.DataLoss {
			t.Fatalf("corrupt manifest code = %s, want DataLoss (%v)", status.Code(err), err)
		}
	})

	t.Run("missing owned artifact", func(t *testing.T) {
		mgr, manifestPath, manifest := writeSavedRestoreFixture(t)
		digest, err := sha256File(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(manifest.VMStatePath); err != nil {
			t.Fatal(err)
		}
		_, _, err = mgr.RestoreSavedSnapshot(context.Background(), "child-vm", manifestPath, digest, nil, nil, "team", "owner")
		if status.Code(err) != codes.DataLoss {
			t.Fatalf("missing artifact code = %s, want DataLoss (%v)", status.Code(err), err)
		}
	})

	t.Run("mutated owned artifact", func(t *testing.T) {
		mgr, manifestPath, manifest := writeSavedRestoreFixture(t)
		digest, err := sha256File(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		writeSavedTestFile(t, manifest.Memory.Path, []byte("tampered-memory"))
		_, _, err = mgr.RestoreSavedSnapshot(context.Background(), "child-vm", manifestPath, digest, nil, nil, "team", "owner")
		if status.Code(err) != codes.DataLoss || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("mutated artifact error = %v, want DataLoss digest mismatch", err)
		}
	})

	t.Run("manifest differs from control-plane commit", func(t *testing.T) {
		mgr, manifestPath, _ := writeSavedRestoreFixture(t)
		_, _, err := mgr.RestoreSavedSnapshot(context.Background(), "child-vm", manifestPath, strings.Repeat("f", 64), nil, nil, "team", "owner")
		if status.Code(err) != codes.DataLoss || !strings.Contains(err.Error(), "control-plane digest") {
			t.Fatalf("manifest commit mismatch error = %v, want DataLoss", err)
		}
		if _, exists := mgr.vms["child-vm"]; exists {
			t.Fatal("manifest mismatch allocated a child VM")
		}
	})
}

func TestSavedSnapshotRestoreErrorClassification(t *testing.T) {
	mgr, manifestPath, _ := writeSavedRestoreFixture(t)

	rejected := mgr.classifySavedSnapshotRestoreError(manifestPath, fmt.Errorf("load failed: %w", ErrSnapshotLoadRejected))
	if status.Code(rejected) != codes.DataLoss {
		t.Fatalf("Firecracker rejection code = %s, want DataLoss (%v)", status.Code(rejected), rejected)
	}

	temporary := mgr.classifySavedSnapshotRestoreError(manifestPath, fmt.Errorf("dial local daemon: %w", syscall.ECONNREFUSED))
	if status.Code(temporary) != codes.Unavailable {
		t.Fatalf("temporary host error code = %s, want Unavailable (%v)", status.Code(temporary), temporary)
	}

	ioFailure := savedSnapshotArtifactIOError("read artifact", &os.PathError{Op: "read", Path: manifestPath, Err: syscall.EIO})
	if status.Code(ioFailure) != codes.Unavailable {
		t.Fatalf("temporary artifact I/O code = %s, want Unavailable (%v)", status.Code(ioFailure), ioFailure)
	}
}

func TestSavedSnapshotGRPCBoundaryDoesNotExposeHostArtifactPaths(t *testing.T) {
	t.Run("capture", func(t *testing.T) {
		installInactiveSystemctl(t)
		snapshotRoot := t.TempDir()
		runRoot := t.TempDir()
		privateRoot := filepath.Join(t.TempDir(), "host-private-artifacts")
		missingVMState := filepath.Join(privateRoot, "source", "vmstate.snap")
		memory := filepath.Join(privateRoot, "source", "mem.snap")
		disk := filepath.Join(privateRoot, "source", "rootfs.ext4")
		writeSavedTestFile(t, memory, []byte("memory"))
		writeSavedTestFile(t, disk, []byte("disk"))

		vmID := "source-private-path"
		mgr := savedTestManager(snapshotRoot, runRoot, &VMInstance{
			ID:           vmID,
			Status:       StatusPaused,
			SnapshotPath: missingVMState,
			MemFilePath:  memory,
			DiskPath:     disk,
			Config:       VMConfig{VCPU: 1, MemoryMiB: 128, DiskSizeMiB: 1},
		})
		_, err := NewGRPCAdapter(mgr).CreateSnapshot(context.Background(), &vmdpb.CreateSnapshotRequest{
			VmId:       vmID,
			SnapshotId: "snapshot-private-path",
		})
		if status.Code(err) != codes.DataLoss {
			t.Fatalf("capture code = %s, want DataLoss (%v)", status.Code(err), err)
		}
		if strings.Contains(err.Error(), privateRoot) || strings.Contains(err.Error(), missingVMState) {
			t.Fatalf("capture RPC error exposed host artifact path: %v", err)
		}
		if !strings.Contains(err.Error(), "saved snapshot capture failed") {
			t.Fatalf("capture RPC error lost safe operation context: %v", err)
		}
	})

	t.Run("restore", func(t *testing.T) {
		mgr, manifestPath, manifest := writeSavedRestoreFixture(t)
		privateArtifact := filepath.Join(t.TempDir(), "host-private-memory", "mem.snap")
		manifest.Memory.Path = privateArtifact
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeSavedTestFile(t, manifestPath, encoded)
		digest, err := sha256File(manifestPath)
		if err != nil {
			t.Fatal(err)
		}

		_, err = NewGRPCAdapter(mgr).RestoreSavedSnapshot(context.Background(), &vmdpb.RestoreSavedSnapshotRequest{
			VmId:                   "child-private-path",
			ManifestPath:           manifestPath,
			ExpectedManifestDigest: digest,
		})
		if status.Code(err) != codes.DataLoss {
			t.Fatalf("restore code = %s, want DataLoss (%v)", status.Code(err), err)
		}
		if strings.Contains(err.Error(), privateArtifact) || strings.Contains(err.Error(), manifestPath) {
			t.Fatalf("restore RPC error exposed host artifact path: %v", err)
		}
		if !strings.Contains(err.Error(), "saved snapshot restore failed") {
			t.Fatalf("restore RPC error lost safe operation context: %v", err)
		}
	})
}

func TestCreateSavedSnapshotExistingInvalidManifestIsDataLoss(t *testing.T) {
	snapshotRoot := t.TempDir()
	runRoot := t.TempDir()
	sourceVMID := "source-vm"
	snapshotID := "snapshot-1"
	finalDir := filepath.Join(snapshotRoot, SavedSnapshotsDirName, sourceVMID, snapshotID)
	writeSavedTestFile(t, filepath.Join(finalDir, savedSnapshotManifestName), []byte("{not-json"))
	mgr := savedTestManager(snapshotRoot, runRoot, &VMInstance{ID: sourceVMID})

	_, err := mgr.CreateSavedSnapshot(context.Background(), sourceVMID, snapshotID)
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("existing invalid manifest code = %s, want DataLoss (%v)", status.Code(err), err)
	}
}

func TestCopyWritableDiskFailureDoesNotPoisonRetry(t *testing.T) {
	binDir := t.TempDir()
	fakeCP := filepath.Join(binDir, "cp")
	script := `#!/bin/sh
prev=
for arg in "$@"; do
  src=$prev
  dst=$arg
  prev=$arg
done
if [ "$FAKE_CP_FAIL" = "1" ]; then
  printf partial > "$dst"
  echo synthetic-copy-failure >&2
  exit 41
fi
exec /bin/cp "$src" "$dst"
`
	writeSavedTestFile(t, fakeCP, []byte(script))
	if err := os.Chmod(fakeCP, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CP_FAIL", "1")

	runRoot := t.TempDir()
	source := filepath.Join(t.TempDir(), "source.ext4")
	writeSavedTestFile(t, source, []byte("complete-disk"))
	mgr := &Manager{cfg: ManagerConfig{RunDir: runRoot}}
	destination := filepath.Join(runRoot, "child-vm", "rootfs.ext4")
	if _, err := mgr.copyRootfs(context.Background(), "child-vm", source); err == nil || !strings.Contains(err.Error(), "synthetic-copy-failure") {
		t.Fatalf("first copy error = %v, want synthetic failure", err)
	}
	for _, path := range []string{destination, destination + ".restore-tmp"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed copy left target artifact %q: %v", path, err)
		}
	}

	t.Setenv("FAKE_CP_FAIL", "0")
	got, err := mgr.copyRootfs(context.Background(), "child-vm", source)
	if err != nil {
		t.Fatalf("retry copy: %v", err)
	}
	data, err := os.ReadFile(got)
	if err != nil || string(data) != "complete-disk" {
		t.Fatalf("retry target = %q, %v; want complete disk", data, err)
	}
}

func TestFailedSavedRestoreRemovesProvisionalTargetBeforeRetry(t *testing.T) {
	binDir := t.TempDir()
	fakeCP := filepath.Join(binDir, "cp")
	writeSavedTestFile(t, fakeCP, []byte(`#!/bin/sh
for arg in "$@"; do dst=$arg; done
printf partial > "$dst"
echo synthetic-copy-failure >&2
exit 41
`))
	if err := os.Chmod(fakeCP, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	runRoot := t.TempDir()
	source := filepath.Join(t.TempDir(), "source.ext4")
	snapshot := filepath.Join(t.TempDir(), "vmstate.snap")
	memory := filepath.Join(t.TempDir(), "mem.snap")
	for path, contents := range map[string]string{source: "disk", snapshot: "state", memory: "memory"} {
		writeSavedTestFile(t, path, []byte(contents))
	}
	mgr := &Manager{
		cfg:        ManagerConfig{RunDir: runRoot},
		log:        zerolog.Nop(),
		vms:        make(map[string]*VMInstance),
		restoreSem: make(chan struct{}, 1),
	}
	cfg := VMConfig{RootfsPath: source, savedSnapshotRestore: true}

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := mgr.RestoreVMSnapshot(context.Background(), "child-vm", snapshot, memory, cfg, nil, "team", "owner")
		if err == nil || !strings.Contains(err.Error(), "synthetic-copy-failure") {
			t.Fatalf("attempt %d error = %v, want fresh copy failure", attempt, err)
		}
		mgr.mu.RLock()
		_, tracked := mgr.vms["child-vm"]
		mgr.mu.RUnlock()
		if tracked {
			t.Fatalf("attempt %d left provisional VM tracked", attempt)
		}
		if _, err := os.Stat(filepath.Join(runRoot, "child-vm")); !os.IsNotExist(err) {
			t.Fatalf("attempt %d left partial target directory: %v", attempt, err)
		}
	}
}
