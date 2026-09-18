package vm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func touch(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPausedDiskPath(t *testing.T) {
	if got := pausedDiskPath("/run", "vm-1", "/rec/disk.ext4", "", ""); got != "/rec/disk.ext4" {
		t.Fatalf("recorded disk wins, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "", ""); got != "/run/vm-1/rootfs.ext4" {
		t.Fatalf("plain rootfs, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "rd-9", "/tpl/base.ext4"); got != "/run/rd-9/overlay.ext4" {
		t.Fatalf("overlay under the run dir id, got %s", got)
	}
}

func TestPauseArtifactsMissing(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	mem := touch(t, filepath.Join(dir, "snap", "mem.snap"))
	touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused}},
	}
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("every artifact present must not read as missing")
	}
	if err := os.Remove(mem); err != nil {
		t.Fatal(err)
	}
	if !mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("a missing memory file must read as missing")
	}
	mgr.vms["vm-1"].Status = StatusRunning
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("only paused records qualify")
	}
	if mgr.pauseArtifactsMissing("vm-2", snap, mem) {
		t.Fatal("an unknown vm must not qualify")
	}
}

// slowEmptyStore holds no generation and takes delay to say so.
type slowEmptyStore struct {
	delay time.Duration
	reads atomic.Int32
}

func (s *slowEmptyStore) NewReader(ctx context.Context, _ string) (io.ReadCloser, error) {
	s.reads.Add(1)
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, backup.ErrObjectNotFound
}

func (s *slowEmptyStore) List(context.Context, string) ([]backup.ObjectInfo, error) { return nil, nil }

func newBackupTestManager(t *testing.T, store *slowEmptyStore) *Manager {
	t.Helper()
	dir := t.TempDir()
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, TeamID: "team"}},
	}
	mgr.SetBackupRestore(store, store, filepath.Join(dir, ".restore"), BackupRestoreOptions{Concurrency: 1})
	return mgr
}

func TestResumeFromBackupFailsClosedWithoutARecordedGeneration(t *testing.T) {
	mgr := newBackupTestManager(t, &slowEmptyStore{})
	_, err := mgr.resumeFromBackupLocked(context.Background(), "vm-1", "", nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestResumeFromBackupOutlivesTheCallerAndIsJoinedByTheRetry(t *testing.T) {
	store := &slowEmptyStore{delay: 300 * time.Millisecond}
	mgr := newBackupTestManager(t, store)
	gen := "gen-a"

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := mgr.resumeFromBackupLocked(short, "vm-1", gen, nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("first attempt: err = %v, want Unavailable while the fetch continues", err)
	}
	if _, err := mgr.resumeFromBackupLocked(context.Background(), "vm-1", "gen-b", nil); status.Code(err) != codes.Aborted {
		t.Fatalf("different generation mid-flight: err = %v, want Aborted", err)
	}
	_, err = mgr.resumeFromBackupLocked(context.Background(), "vm-1", gen, nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("retry: err = %v, want FailedPrecondition from the joined fetch finding no backup", err)
	}
	if n := store.reads.Load(); n != 1 {
		t.Fatalf("manifest fetched %d times, want one shared fetch", n)
	}
	mgr.backupFlightsMu.Lock()
	left := len(mgr.backupFlights)
	mgr.backupFlightsMu.Unlock()
	if left != 0 {
		t.Fatal("finished flight must be released")
	}
}

func TestBackupRevivedTargetAdoptsTheSameGenerationOnly(t *testing.T) {
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	defer func() { vmDeadForRetry = orig }()
	live := &VMInstance{ID: "vm-1", Status: StatusRunning, BackupGeneration: "gen-a"}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": live}}
	if mgr.backupRevivedTarget("vm-1", "gen-a") != live {
		t.Fatal("a retry for the same generation must adopt the revived VM")
	}
	if mgr.backupRevivedTarget("vm-1", "gen-b") != nil {
		t.Fatal("a different generation must not adopt it")
	}
	if mgr.backupRevivedTarget("vm-1", "") != nil {
		t.Fatal("no generation must not adopt it")
	}
	live.Unverified = true
	if mgr.backupRevivedTarget("vm-1", "gen-a") != nil {
		t.Fatal("an unverified VM must not be adopted")
	}
}

func TestPauseArtifactsMissingResolvesOmittedPaths(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	mem := touch(t, filepath.Join(dir, "snap", "mem.snap"))
	touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, MemFilePath: mem}},
	}
	if mgr.pauseArtifactsMissing("vm-1", "", "") {
		t.Fatal("a healthy paused VM resumed by id alone must take the warm path")
	}
	if mgr.pauseArtifactsMissing("vm-1", snap, "") || mgr.pauseArtifactsMissing("vm-1", "", mem) {
		t.Fatal("one omitted path must resolve from the record")
	}
	if err := os.Remove(mem); err != nil {
		t.Fatal(err)
	}
	if !mgr.pauseArtifactsMissing("vm-1", "", "") {
		t.Fatal("the record's missing memory file must still be seen")
	}
}

// manifestStore serves one uploaded generation's manifest and nothing else.
type manifestStore struct {
	object string
	body   []byte
}

func (s *manifestStore) NewReader(_ context.Context, object string) (io.ReadCloser, error) {
	if object != s.object {
		return nil, backup.ErrObjectNotFound
	}
	return io.NopCloser(strings.NewReader(string(s.body))), nil
}

func (s *manifestStore) List(context.Context, string) ([]backup.ObjectInfo, error) {
	return []backup.ObjectInfo{{Name: s.object, Created: time.Now()}}, nil
}

func TestResumeFromBackupKeepsTheLocalDiskWhenOnlyAnOlderPauseIsBackedUp(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	disk := touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	older := backup.GenerationManifest{SandboxID: "vm-1", Generation: "gen-a", Files: []backup.ManifestFile{
		{Name: "vmstate.snap", Object: "vmstate.snap", SHA256: "aaaa"},
		{Name: "rootfs.ext4", Object: "rootfs.ext4", SHA256: "dddd"},
	}}
	body, _ := json.Marshal(older)
	object, _ := backup.SandboxObject("vm-1", "gen-a", backup.ManifestObject)
	store := &manifestStore{object: object, body: body}
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, MemFilePath: filepath.Join(dir, "snap", "mem.snap")}},
	}
	mgr.SetBackupRestore(store, store, filepath.Join(dir, ".restore"), BackupRestoreOptions{})

	if !mgr.pauseArtifactsMissing("vm-1", "", "") {
		t.Fatal("the newer pause's memory file is gone")
	}
	_, err := mgr.resumeFromBackupLocked(context.Background(), "vm-1", "gen-b", nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition: only an older pause is backed up", err)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatal("the newer local disk must survive a refused restore")
	}
	if _, err := os.Stat(filepath.Join(dir, ".restore", "staging", "vm-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no staging dir may be left behind")
	}
}

func TestResumeVMRetryAdoptsTheBackupRevivedVM(t *testing.T) {
	origDead, origProbe := vmDeadForRetry, boxdHealthProbe
	vmDeadForRetry = func(*Manager, string) bool { return false }
	boxdHealthProbe = func(context.Context, string, time.Duration) error { return nil }
	defer func() { vmDeadForRetry, boxdHealthProbe = origDead, origProbe }()

	live := &VMInstance{ID: "vm-1", Status: StatusRunning, IP: "192.0.2.9", PID: 41, BackupGeneration: "gen-a", Config: VMConfig{VCPU: 2, MemoryMiB: 512}}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": live}, netMgr: &ownedNetMgr{&fakeNetMgr{}}}
	store := &slowEmptyStore{}
	mgr.SetBackupRestore(store, store, t.TempDir(), BackupRestoreOptions{})
	a := NewGRPCAdapter(mgr)

	resp, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{VmId: "vm-1", SnapshotPath: "/gone/vmstate.snap", MemFilePath: "/gone/mem.snap", BackupGeneration: "gen-a"})
	if err != nil {
		t.Fatalf("retry with the original request must adopt the revived VM, got %v", err)
	}
	if resp.GetIpAddress() != "192.0.2.9" || resp.GetPid() != 41 {
		t.Fatalf("response = %+v, want the live VM", resp)
	}
}

// ownedNetMgr answers ownership for every VM so the readiness gate passes.
type ownedNetMgr struct{ *fakeNetMgr }

func (o *ownedNetMgr) GetVMNetInfo(string) *network.VMNetInfo { return &network.VMNetInfo{} }

func TestResumeVMWithoutAGenerationTellsTheControlPlaneWhatItNeeds(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms:    map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, MemFilePath: filepath.Join(dir, "snap", "mem.snap")}},
		netMgr: &ownedNetMgr{&fakeNetMgr{}},
	}
	store := &slowEmptyStore{}
	mgr.SetBackupRestore(store, store, filepath.Join(dir, ".restore"), BackupRestoreOptions{})
	a := NewGRPCAdapter(mgr)

	_, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{VmId: "vm-1"})
	if !vmdclient.IsPauseArtifactsMissing(err) {
		t.Fatalf("err = %v, want the pause-artifacts-missing mark", err)
	}
	if n := store.reads.Load(); n != 0 {
		t.Fatal("no fetch may start before the control plane names the generation")
	}
}

func TestSetBackupRestoreSweepsStagingLeftByAPreviousProcess(t *testing.T) {
	root := t.TempDir()
	touch(t, filepath.Join(root, "staging", "vm-old", "rootfs.ext4"))
	touch(t, filepath.Join(root, ".base-cache", ".unpacked-abc"))
	bystander := touch(t, filepath.Join(root, "unrelated", "keep.me"))
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	store := &slowEmptyStore{}
	mgr.SetBackupRestore(store, store, root, BackupRestoreOptions{})
	if _, err := os.Stat(filepath.Join(root, "staging", "vm-old")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale staging must be swept at startup")
	}
	if _, err := os.Stat(filepath.Join(root, ".base-cache", ".unpacked-abc")); err != nil {
		t.Fatal("the base cache must survive startup")
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Fatal("nothing outside the owned staging subtree may be touched")
	}
}
