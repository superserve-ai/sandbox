package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/vm"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

const boxdPort = 49983

func main() {
	templateID := flag.String("template-id", "", "template UUID")
	buildID := flag.String("build-id", "", "build UUID for tracking")
	specJSON := flag.String("spec", "", "build spec JSON")
	vcpu := flag.Uint("vcpu", 1, "vCPU count")
	memory := flag.Uint("memory", 1024, "memory MiB")
	disk := flag.Uint("disk", 4096, "disk MiB")
	runDir := flag.String("run-dir", "", "base path for rootfs output")
	snapshotDir := flag.String("snapshot-dir", "", "base path for snapshot output")
	kernelPath := flag.String("kernel", "", "path to vmlinux")
	fcBin := flag.String("firecracker", "", "path to firecracker binary")
	boxdBin := flag.String("boxd", "", "path to boxd binary")
	hostIface := flag.String("host-interface", "ens4", "host network interface")
	slotIndex := flag.Int("slot-index", 200, "network slot index (must not collide with vmd)")
	timeout := flag.Duration("timeout", 15*time.Minute, "build timeout")
	flag.Parse()

	if *templateID == "" || *specJSON == "" || *runDir == "" || *snapshotDir == "" || *kernelPath == "" || *fcBin == "" || *boxdBin == "" {
		flag.Usage()
		os.Exit(2)
	}

	var spec builder.BuildSpec
	if err := json.Unmarshal([]byte(*specJSON), &spec); err != nil {
		log.Fatalf("parse spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Handle SIGTERM/SIGINT for clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	err := runBuild(ctx, buildConfig{
		templateID: *templateID,
		buildID:    *buildID,
		spec:       spec,
		vcpu:       uint32(*vcpu),
		memoryMiB:  uint32(*memory),
		diskMiB:    uint32(*disk),
		runDir:     *runDir,
		snapshotDir: *snapshotDir,
		kernelPath: *kernelPath,
		fcBin:      *fcBin,
		boxdBin:    *boxdBin,
		hostIface:  *hostIface,
		slotIndex:  *slotIndex,
	})
	if err != nil {
		log.Fatalf("build failed: %v", err)
	}
}

type buildConfig struct {
	templateID  string
	buildID     string
	spec        builder.BuildSpec
	vcpu        uint32
	memoryMiB   uint32
	diskMiB     uint32
	runDir      string
	snapshotDir string
	kernelPath  string
	fcBin       string
	boxdBin     string
	hostIface   string
	slotIndex   int
}

func runBuild(ctx context.Context, cfg buildConfig) error {
	buildVMID := "build-" + cfg.templateID
	rootfsDir := filepath.Join(cfg.runDir, "templates", cfg.templateID)
	rootfsPath := filepath.Join(rootfsDir, "rootfs.ext4")
	snapDir := filepath.Join(cfg.snapshotDir, "templates", cfg.templateID)

	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return fmt.Errorf("mkdir rootfs dir: %w", err)
	}
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return fmt.Errorf("mkdir snapshot dir: %w", err)
	}

	// Phase 1: produce rootfs.ext4 from OCI image
	emitLog("system", "building rootfs from %s", cfg.spec.From)
	b, err := builder.NewBuilder(builder.Config{BoxdBinaryPath: cfg.boxdBin})
	if err != nil {
		return fmt.Errorf("create builder: %w", err)
	}
	br, err := b.BuildRootfs(ctx, cfg.spec, rootfsPath, cfg.diskMiB)
	if err != nil {
		return fmt.Errorf("build rootfs: %w", err)
	}
	emitLog("system", "rootfs produced: %s (%d bytes)", br.ResolvedDigest, br.SizeBytes)

	// Phase 2: copy rootfs for the build VM
	perVMRootfs, err := copyRootfs(cfg.runDir, buildVMID, rootfsPath)
	if err != nil {
		return fmt.Errorf("copy rootfs: %w", err)
	}

	// Phase 3: set up network (single slot, no pool, no egress proxy)
	netMgr, netInfo, cleanup, err := setupNetwork(ctx, cfg.hostIface, cfg.slotIndex, buildVMID)
	if err != nil {
		return fmt.Errorf("setup network: %w", err)
	}
	defer cleanup()
	_ = netMgr // kept for defer scope

	// Phase 4: start Firecracker in the network namespace
	socketPath := filepath.Join(cfg.runDir, buildVMID, "firecracker.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	fcCfg := vm.FirecrackerConfig{
		SocketPath: socketPath,
		KernelPath: cfg.kernelPath,
		KernelArgs: "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0 random.trust_cpu=on",
		RootfsPath: perVMRootfs,
		VCPUCount:  int(cfg.vcpu),
		MemSizeMiB: int(cfg.memoryMiB),
		TAPDevice:  network.TAPName,
		MACAddress: netInfo.MACAddress,
		VMID:       buildVMID,
		VMIP:       network.VMInternalIP,
		GatewayIP:  network.VMGatewayIP,
	}

	pid, err := startFirecracker(ctx, cfg.fcBin, socketPath, fcCfg, netInfo.Namespace)
	if err != nil {
		return fmt.Errorf("start firecracker: %w", err)
	}
	defer killProcess(pid)

	// Phase 5: wait for boxd
	emitLog("system", "waiting for boxd")
	if err := waitForBoxd(ctx, netInfo.HostIP, 30*time.Second); err != nil {
		return fmt.Errorf("boxd not ready: %w", err)
	}
	emitLog("system", "boxd ready")

	// Phase 6: execute build steps
	if err := executeBuildSteps(ctx, netInfo.HostIP, cfg.spec); err != nil {
		return fmt.Errorf("build steps: %w", err)
	}

	// Phase 7: start_cmd + ready_cmd
	if err := runStartCmd(ctx, netInfo.HostIP, cfg.spec); err != nil {
		return fmt.Errorf("start_cmd: %w", err)
	}
	if err := pollReadyCmd(ctx, netInfo.HostIP, cfg.spec); err != nil {
		return fmt.Errorf("ready_cmd: %w", err)
	}

	// Phase 8: snapshot
	emitLog("system", "snapshotting")
	snapPath := filepath.Join(snapDir, "vmstate.snap")
	memPath := filepath.Join(snapDir, "mem.snap")
	if err := vm.CreateSnapshot(socketPath, snapPath, memPath); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	emitLog("system", "snapshot captured")

	// Phase 9: write build metadata
	writeBuildMeta(snapDir, snapPath, memPath, rootfsPath, br)

	return nil
}

// ---------------------------------------------------------------------------
// Network setup (single slot, no pool)
// ---------------------------------------------------------------------------

func setupNetwork(ctx context.Context, hostIface string, slotIndex int, vmID string) (*network.Manager, *network.VMNetInfo, func(), error) {
	log := newLogger("network")
	mgr, err := network.NewManager(ctx, hostIface, log,
		network.WithStartSlot(slotIndex),
		network.WithHTTPProxyPort(0), // no egress proxy for builds
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new network manager: %w", err)
	}

	info, err := mgr.SetupVM(ctx, vmID, nil)
	if err != nil {
		mgr.Close()
		return nil, nil, nil, fmt.Errorf("setup VM network: %w", err)
	}

	cleanup := func() {
		mgr.CleanupVM(vmID)
		mgr.Close()
	}

	return mgr, info, cleanup, nil
}

// ---------------------------------------------------------------------------
// Firecracker launch
// ---------------------------------------------------------------------------

func startFirecracker(ctx context.Context, fcBin, socketPath string, cfg vm.FirecrackerConfig, netNS string) (int, error) {
	cmd := exec.Command("ip", "netns", "exec", netNS,
		fcBin, "--api-sock", socketPath, "--id", cfg.VMID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("exec firecracker: %w", err)
	}
	pid := cmd.Process.Pid

	if err := waitForSocket(socketPath, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("wait for socket: %w", err)
	}

	if err := vm.ConfigureMachine(socketPath, cfg); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("configure machine: %w", err)
	}

	if err := vm.StartInstance(socketPath); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("start instance: %w", err)
	}

	go func() { _ = cmd.Wait() }()
	return pid, nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("socket %s not ready after %s", path, timeout)
}

func killProcess(pid int) {
	if pid <= 0 {
		return
	}
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Signal(syscall.SIGKILL)
		_, _ = proc.Wait()
	}
}

// ---------------------------------------------------------------------------
// boxd communication (own HTTP client — no sharing with anyone)
// ---------------------------------------------------------------------------

var boxdClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
}

func processClient(vmIP string) boxdpbconnect.ProcessServiceClient {
	return boxdpbconnect.NewProcessServiceClient(
		boxdClient,
		fmt.Sprintf("http://%s:%d", vmIP, boxdPort),
	)
}

func waitForBoxd(ctx context.Context, vmIP string, timeout time.Duration) error {
	url := fmt.Sprintf("http://%s:%d/health", vmIP, boxdPort)
	deadline := time.Now().Add(timeout)
	healthClient := &http.Client{Timeout: 500 * time.Millisecond}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := healthClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("boxd not ready after %s", timeout)
}

// ---------------------------------------------------------------------------
// Build step execution
// ---------------------------------------------------------------------------

const stepTimeout = 10 * time.Minute

func executeBuildSteps(ctx context.Context, vmIP string, spec builder.BuildSpec) error {
	env := map[string]string{
		"PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":  "/root",
		"USER":  "root",
		"TERM":  "xterm",
		"LANG":  "C.UTF-8",
		"SHELL": "/bin/sh",
	}

	for i, step := range spec.Steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		emitLog("system", "step %d/%d", i+1, len(spec.Steps))
		stepStart := time.Now()

		if err := runBuildStep(ctx, vmIP, step, env); err != nil {
			return fmt.Errorf("step %d/%d failed after %s: %w",
				i+1, len(spec.Steps), time.Since(stepStart).Round(time.Millisecond), err)
		}
		emitLog("system", "step %d/%d complete (%s)", i+1, len(spec.Steps),
			time.Since(stepStart).Round(time.Millisecond))
	}
	return nil
}

func runBuildStep(ctx context.Context, vmIP string, step builder.BuildStep, env map[string]string) error {
	switch {
	case step.Run != nil:
		return runShellCmd(ctx, vmIP, *step.Run, env, "")
	case step.Env != nil:
		env[step.Env.Key] = step.Env.Value
		emitLog("system", "env %s=%s", step.Env.Key, step.Env.Value)
		return nil
	case step.Workdir != nil:
		emitLog("system", "workdir %s", *step.Workdir)
		return nil
	case step.Copy != nil:
		dst := step.Copy.Dst
		shCmd := fmt.Sprintf("mkdir -p %s && printf '%%s' '%s' | base64 -d | tar -C %s -xf -",
			shellQuote(dst), step.Copy.Src, shellQuote(dst))
		return runShellCmd(ctx, vmIP, shCmd, env, "")
	default:
		return fmt.Errorf("step has no op set")
	}
}

func runShellCmd(ctx context.Context, vmIP, cmd string, env map[string]string, workdir string) error {
	emitLog("system", "$ %s", truncate(cmd, 256))

	stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()

	client := processClient(vmIP)
	req := &pb.StartRequest{
		Cmd:       "/bin/sh",
		Args:      []string{"-c", cmd},
		Envs:      env,
		Cwd:       workdir,
		TimeoutMs: uint32(stepTimeout.Milliseconds()),
	}

	stream, err := client.Start(stepCtx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("start exec: %w", err)
	}

	var lastExit int32
	for stream.Receive() {
		event := stream.Msg()
		switch e := event.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch o := e.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				text := strings.TrimRight(string(o.Stdout), "\n")
				if text != "" {
					emitLog("stdout", "%s", text)
				}
			case *pb.DataEvent_Stderr:
				text := strings.TrimRight(string(o.Stderr), "\n")
				if text != "" {
					emitLog("stderr", "%s", text)
				}
			}
		case *pb.ProcessEvent_End:
			lastExit = e.End.ExitCode
		}
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("exec stream: %w", err)
	}
	if lastExit != 0 {
		return fmt.Errorf("exited with code %d", lastExit)
	}
	return nil
}

// ---------------------------------------------------------------------------
// start_cmd + ready_cmd
// ---------------------------------------------------------------------------

func runStartCmd(ctx context.Context, vmIP string, spec builder.BuildSpec) error {
	if spec.StartCmd == "" {
		return nil
	}
	emitLog("system", "start_cmd: %s", truncate(spec.StartCmd, 256))

	go func() {
		client := processClient(vmIP)
		req := &pb.StartRequest{
			Cmd:  "/bin/sh",
			Args: []string{"-c", spec.StartCmd},
		}
		stream, err := client.Start(context.Background(), connect.NewRequest(req))
		if err != nil {
			return
		}
		for stream.Receive() {
		}
	}()

	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func pollReadyCmd(ctx context.Context, vmIP string, spec builder.BuildSpec) error {
	if spec.ReadyCmd == "" {
		return nil
	}
	emitLog("system", "ready_cmd: %s", truncate(spec.ReadyCmd, 256))

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	for attempts := 0; ; attempts++ {
		if probeCtx.Err() != nil {
			return fmt.Errorf("ready_cmd not ready after %d attempts: %w", attempts, probeCtx.Err())
		}

		client := processClient(vmIP)
		req := &pb.StartRequest{
			Cmd:       "/bin/sh",
			Args:      []string{"-c", spec.ReadyCmd},
			TimeoutMs: 2000,
		}
		stream, err := client.Start(probeCtx, connect.NewRequest(req))
		if err == nil {
			var exit int32
			for stream.Receive() {
				if end := stream.Msg().GetEnd(); end != nil {
					exit = end.ExitCode
				}
			}
			if exit == 0 {
				emitLog("system", "ready_cmd succeeded after %d attempts", attempts+1)
				return nil
			}
		}

		select {
		case <-time.After(2 * time.Second):
		case <-probeCtx.Done():
			return probeCtx.Err()
		}
	}
}

// ---------------------------------------------------------------------------
// Rootfs copy
// ---------------------------------------------------------------------------

func copyRootfs(runDir, vmID, srcPath string) (string, error) {
	dstDir := filepath.Join(runDir, vmID)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	dst := filepath.Join(dstDir, "rootfs.ext4")
	cmd := exec.Command("cp", "--reflink=auto", srcPath, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("cp rootfs: %s: %w", string(out), err)
	}
	return dst, nil
}

// ---------------------------------------------------------------------------
// Build metadata
// ---------------------------------------------------------------------------

func writeBuildMeta(dir, snapPath, memPath, rootfsPath string, br builder.BuildRootfsResult) {
	meta := struct {
		SnapshotPath   string `json:"snapshot_path"`
		MemPath        string `json:"mem_path"`
		RootfsPath     string `json:"rootfs_path"`
		ResolvedDigest string `json:"resolved_digest"`
		SizeBytes      int64  `json:"size_bytes"`
		BuiltAt        string `json:"built_at"`
	}{
		SnapshotPath:   snapPath,
		MemPath:        memPath,
		RootfsPath:     rootfsPath,
		ResolvedDigest: br.ResolvedDigest,
		SizeBytes:      br.SizeBytes,
		BuiltAt:        time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "build.meta.json"), data, 0o644)
}

// ---------------------------------------------------------------------------
// Structured log output (NDJSON to stdout for vmd to parse)
// ---------------------------------------------------------------------------

func emitLog(stream, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	line, _ := json.Marshal(struct {
		Stream string `json:"stream"`
		Text   string `json:"text"`
	}{Stream: stream, Text: text})
	fmt.Println(string(line))
}

func newLogger(component string) zerolog.Logger {
	// template-builder logs go to stderr (structured for operators).
	// stdout is reserved for NDJSON build events that vmd parses.
	return zerolog.New(os.Stderr).With().Timestamp().Str("component", component).Logger()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
