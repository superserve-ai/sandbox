package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/network"
)

type startupBuildNetMgr struct {
	*fakeNetMgr
	kept             map[string]bool
	namespaceLookups int
	released         []string
}

func (n *startupBuildNetMgr) ReleaseSlot(owner string, slot int) {
	ns := fmt.Sprintf("ns-%d", slot)
	if n.reserved[owner] == ns {
		delete(n.reserved, owner)
		n.released = append(n.released, owner)
	}
}

func (n *startupBuildNetMgr) SlotPressure() network.SlotPressureStats {
	return network.SlotPressureStats{Used: len(n.reserved)}
}

func (n *startupBuildNetMgr) NamespaceForPID(int) string {
	n.namespaceLookups++
	return ""
}

func (n *startupBuildNetMgr) SweepOrphanNamespaces(keep map[string]bool) int {
	n.kept = keep
	return 0
}

func TestRestartProtectsSurvivingBuildNamespace(t *testing.T) {
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cgroups := filepath.Join(t.TempDir(), "vms")
	buildID := "build-11111111-1111-1111-1111-111111111111"
	if err := os.MkdirAll(filepath.Join(cgroups, buildID), 0o755); err != nil {
		t.Fatal(err)
	}
	netMgr := &startupBuildNetMgr{fakeNetMgr: &fakeNetMgr{}}
	m := &Manager{log: zerolog.Nop(), state: state, netMgr: netMgr, cgroups: &cgroupTree{vms: cgroups},
		cfg: ManagerConfig{TemplateBuilderBin: "/usr/local/bin/template-builder"}}
	m.builderScan = func(string) ([]builderProc, error) {
		return []builderProc{{pid: 123, start: 456, buildID: buildID, slot: 17, hasSlot: true}}, nil
	}
	if !m.ReserveStartupSlots(t.Context()) {
		t.Fatal("startup record reservation failed")
	}
	protected, err := m.ProtectSurvivingBuildSlots()
	if err != nil {
		t.Fatal(err)
	}
	reapProtected, sweepSafe := m.ReapRecordlessCgroupVMs(t.Context())
	if !sweepSafe {
		t.Fatal("live build unexpectedly made startup sweep unsafe")
	}
	if netMgr.namespaceLookups != 0 {
		t.Fatal("cgroup reap inspected a live build VM for teardown")
	}
	if _, err := os.Stat(filepath.Join(cgroups, buildID)); err != nil {
		t.Fatalf("cgroup reap removed live build VM: %v", err)
	}
	m.SweepStartupOrphanNamespaces(append(reapProtected, protected...)...)
	if !netMgr.kept["ns-17"] {
		t.Fatal("startup sweep did not keep live build namespace")
	}
	if got := netMgr.reserved[buildID]; got != "ns-17" {
		t.Fatalf("startup pool reservation = %q, want ns-17", got)
	}
	if len(m.survivingBuilders) != 1 {
		t.Fatal("pressure publication lost surviving builder")
	}
}

func TestSurvivingBuildWithoutKnownSlotBlocksStartup(t *testing.T) {
	m := &Manager{cfg: ManagerConfig{TemplateBuilderBin: "/usr/local/bin/template-builder"}, netMgr: &fakeNetMgr{}}
	m.builderScan = func(string) ([]builderProc, error) {
		return []builderProc{{pid: 123, start: 456, buildID: "build-1"}}, nil
	}
	if _, err := m.ProtectSurvivingBuildSlots(); err == nil {
		t.Fatal("unresolved live build slot cannot permit startup reclaim")
	}
	m.builderScan = func(string) ([]builderProc, error) { return nil, errors.New("unreadable /proc") }
	if _, err := m.ProtectSurvivingBuildSlots(); err == nil {
		t.Fatal("inconclusive builder discovery cannot permit startup reclaim")
	}
}

func TestCompletedPredecessorBuildReleasesOwnedSlot(t *testing.T) {
	const buildID = "build-completed"
	netMgr := &startupBuildNetMgr{fakeNetMgr: &fakeNetMgr{}}
	m := &Manager{log: zerolog.Nop(), netMgr: netMgr}
	m.builderScan = func(string) ([]builderProc, error) {
		return []builderProc{{pid: 101, start: 7, buildID: buildID, slot: 17, hasSlot: true}}, nil
	}
	if _, err := m.ProtectSurvivingBuildSlots(); err != nil {
		t.Fatal(err)
	}
	m.reattachComplete.Store(true)
	alive := true
	m.builderAlive = func(builderProc) bool { return alive }
	if m.PressureReady() || m.CapacityPressure().UsedNetSlots != 1 {
		t.Fatal("live predecessor lost its reservation or pressure gate")
	}
	alive = false
	if !m.PressureReady() || m.CapacityPressure().UsedNetSlots != 0 {
		t.Fatal("completed predecessor left stale slot pressure")
	}
	if len(netMgr.released) != 1 || netMgr.released[0] != buildID {
		t.Fatalf("slot releases = %v", netMgr.released)
	}
	if !m.PressureReady() || len(netMgr.released) != 1 {
		t.Fatal("completed predecessor released its slot more than once")
	}
}

func TestExitedPredecessorCannotReleaseReplacementSlot(t *testing.T) {
	netMgr := &startupBuildNetMgr{fakeNetMgr: &fakeNetMgr{}}
	m := &Manager{log: zerolog.Nop(), netMgr: netMgr}
	m.builderScan = func(string) ([]builderProc, error) {
		return []builderProc{{pid: 101, start: 7, buildID: "build-old", slot: 17, hasSlot: true}}, nil
	}
	if _, err := m.ProtectSurvivingBuildSlots(); err != nil {
		t.Fatal(err)
	}
	delete(netMgr.reserved, "build-old")
	netMgr.reserved["build-new"] = "ns-17"
	m.reattachComplete.Store(true)
	m.builderAlive = func(builderProc) bool { return false }
	if !m.PressureReady() || m.CapacityPressure().UsedNetSlots != 1 || len(netMgr.released) != 0 {
		t.Fatal("stale predecessor release affected a newer slot owner")
	}
}

func TestBuilderSlotFromArgs(t *testing.T) {
	if slot, ok := builderSlotFromArgs([]string{"/usr/local/bin/template-builder", "--build-id", "build-1", "--slot-index", "17"}); !ok || slot != 17 {
		t.Fatalf("slot = %d, valid = %t", slot, ok)
	}
	for _, args := range [][]string{
		{"/usr/local/bin/template-builder", "--build-id", "build-1"},
		{"/usr/local/bin/template-builder", "--slot-index", "invalid"},
	} {
		if _, ok := builderSlotFromArgs(args); ok {
			t.Fatalf("accepted missing or invalid slot: %q", args)
		}
	}
}

func TestRecoveredBuilderHelper(t *testing.T) {
	if os.Getenv("BUILD_RECOVERY_HELPER") != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestRecoveredBuildMustStopBeforeCleanupOrRetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const buildID = "build-11111111-1111-1111-1111-111111111111"
	cmd := exec.Command(bin, "-test.run=TestRecoveredBuilderHelper", "-args", "--build-id", buildID, "--slot-index", "17")
	cmd.Env = append(os.Environ(), "BUILD_RECOVERY_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		procs, err := findAttemptBuilders(bin, buildID)
		if err != nil {
			t.Fatal(err)
		}
		if len(procs) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper builder was not discovered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	root := t.TempDir()
	artifact := filepath.Join(root, TemplatesDirName, "tpl", buildID, "mem.snap")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("unfinished"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A fresh manager models a same-incarnation daemon restart: no in-memory
	// record exists for the builder left by the previous process.
	netMgr := &startupBuildNetMgr{fakeNetMgr: &fakeNetMgr{}}
	m := &Manager{log: zerolog.Nop(), netMgr: netMgr, cfg: ManagerConfig{SnapshotDir: root, RunDir: root, TemplateBuilderBin: bin}}
	m.builderScan = func(string) ([]builderProc, error) {
		procs, err := findAttemptBuilders(bin, buildID)
		if err != nil || len(procs) != 1 {
			return nil, fmt.Errorf("find predecessor builder: processes=%v err=%v", procs, err)
		}
		procs[0].buildID, procs[0].slot, procs[0].hasSlot = buildID, 17, true
		return procs, nil
	}
	if _, err := m.ProtectSurvivingBuildSlots(); err != nil {
		t.Fatal(err)
	}
	m.reattachComplete.Store(true)
	if m.PressureReady() || m.CapacityPressure().UsedNetSlots != 1 {
		t.Fatal("live predecessor cancellation target lost its slot reservation")
	}
	if status, ok := m.GetBuildStatus(buildID); !ok || status.Status != BuildStatusRunning {
		t.Fatalf("surviving builder status: %+v, found=%t", status, ok)
	}
	if err := m.DeleteBuildArtifacts("tpl", buildID); err == nil {
		t.Fatal("deleted artifacts while predecessor builder was running")
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Fatal("cleanup removed the active artifact")
	}
	if _, err := m.registerBuild(buildID, "tpl", 1, 512, nil, func() error { return m.prepareBuildDir("tpl", buildID) }); err == nil {
		t.Fatal("retry reused a build id still owned by the predecessor")
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Fatal("retry removed the active artifact")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.CancelBuild(ctx, buildID); err != nil {
		t.Fatal(err)
	}
	if procs, err := findAttemptBuilders(bin, buildID); err != nil || len(procs) != 0 {
		t.Fatalf("cancel left predecessor builder running: processes=%v err=%v", procs, err)
	}
	if err := m.waitBuildStopped(ctx, buildID); err != nil {
		t.Fatalf("cancel did not confirm predecessor exit: %v", err)
	}
	_ = cmd.Wait() // Reap the test child so /proc can confirm its exit.
	if !m.PressureReady() || m.CapacityPressure().UsedNetSlots != 0 {
		t.Fatal("cancelled predecessor left stale slot pressure")
	}
	if len(netMgr.released) != 1 || netMgr.released[0] != buildID {
		t.Fatalf("cancelled predecessor slot releases = %v", netMgr.released)
	}
	if status, ok := m.GetBuildStatus(buildID); ok {
		t.Fatalf("stopped builder still reported: %+v", status)
	}
	if err := m.DeleteBuildArtifacts("tpl", buildID); err != nil {
		t.Fatalf("cleanup after confirmed exit: %v", err)
	}
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatalf("artifact after cleanup: %v", err)
	}
}

func TestAttemptBuilderCmdlineRequiresExactIdentity(t *testing.T) {
	bin := "/usr/local/bin/template-builder"
	for _, cmdline := range [][]byte{
		[]byte(bin + "\x00--build-id\x00build-other\x00"),
		[]byte(bin + "\x00--spec\x00build-target\x00"),
		[]byte("/other/template-builder\x00--build-id\x00build-target\x00"),
	} {
		if attemptBuilderCmdlineMatches(cmdline, bin, "build-target") {
			t.Fatalf("matched unrelated process: %q", cmdline)
		}
	}
	if !attemptBuilderCmdlineMatches([]byte(bin+"\x00--build-id\x00build-target\x00"), bin, "build-target") {
		t.Fatal("did not match exact attempt")
	}
}
