package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
		// Emit a user-visible error (stable code + user-friendly message)
		// so vmd can surface it in the build record instead of a generic
		// "exit 1". The raw wrapped chain goes to operator logs only.
		code, msg := classifyBuildError(err)
		emitUser("error", "%s: %s", code, msg)
		emitInternal("error", "%v", err)
		log.Fatalf("build failed: %v", err)
	}
}

// classifyBuildError maps the wrapped error chain to (stable_code,
// user_safe_message). Internal jargon (boxd, rootfs, slot, etc.) stays
// in the raw error logged to operators — never in the customer-visible
// message. Falls back to ("build_failed", "template build failed") for
// anything we haven't explicitly handled.
func classifyBuildError(err error) (code, userMsg string) {
	raw := err.Error()
	switch {
	case strings.Contains(raw, "build rootfs"),
		strings.Contains(raw, "pull "),
		strings.Contains(raw, "manifest "),
		strings.Contains(raw, "resolve reference"):
		return "image_pull_failed", "failed to pull base image — check the reference and that the registry is reachable"

	case strings.Contains(raw, "build steps"):
		// Step failures embed "step N/M failed after X: <subprocess exit
		// detail>" which is already user-meaningful (their command, their
		// exit code). Pass it through trimmed.
		msg := raw
		if idx := strings.Index(msg, "build steps: "); idx >= 0 {
			msg = msg[idx+len("build steps: "):]
		}
		return "step_failed", msg

	case strings.Contains(raw, "copy rootfs"),
		strings.Contains(raw, "start firecracker"),
		strings.Contains(raw, "setup network"),
		strings.Contains(raw, "boxd not ready"):
		return "boot_failed", "build environment failed to boot"

	case strings.Contains(raw, "snapshot"):
		return "snapshot_failed", "failed to capture template snapshot"

	case strings.Contains(raw, "start_cmd"):
		return "start_cmd_failed", "start_cmd did not launch successfully"

	case strings.Contains(raw, "ready_cmd"):
		return "ready_cmd_failed", "ready_cmd did not succeed within the readiness timeout"

	case strings.Contains(raw, "bake context"):
		return "build_failed", "failed to finalize template defaults"

	default:
		return "build_failed", "template build failed"
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
	emitUser("system", "Pulling image %s", cfg.spec.From)
	b, err := builder.NewBuilder(builder.Config{
		BoxdBinaryPath:           cfg.boxdBin,
		MaxUncompressedSizeBytes: int64(cfg.diskMiB) * 1024 * 1024,
	})
	if err != nil {
		return fmt.Errorf("create builder: %w", err)
	}
	br, err := b.BuildRootfs(ctx, cfg.spec, rootfsPath, cfg.diskMiB)
	if err != nil {
		return fmt.Errorf("build rootfs: %w", err)
	}
	emitInternal("system", "rootfs produced: %s (%d bytes)", br.ResolvedDigest, br.SizeBytes)
	emitUser("system", "Image ready")

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
	emitInternal("system", "waiting for boxd")
	if err := waitForBoxd(ctx, netInfo.HostIP, 30*time.Second); err != nil {
		return fmt.Errorf("boxd not ready: %w", err)
	}
	emitInternal("system", "boxd ready")
	emitUser("system", "Starting build environment")

	// Phase 6: execute build steps
	bc, err := executeBuildSteps(ctx, netInfo.HostIP, cfg.spec)
	if err != nil {
		return fmt.Errorf("build steps: %w", err)
	}

	// Phase 7: start_cmd + ready_cmd
	if err := runStartCmd(ctx, netInfo.HostIP, cfg.spec, bc); err != nil {
		return fmt.Errorf("start_cmd: %w", err)
	}
	if err := pollReadyCmd(ctx, netInfo.HostIP, cfg.spec, bc); err != nil {
		return fmt.Errorf("ready_cmd: %w", err)
	}

	// Phase 8: bake the accumulated context into boxd's memory so the
	// defaults travel in the snapshot. Env vars set via `env` steps plus
	// the final user/workdir become the template's runtime defaults for
	// every future sandbox restored from this snapshot.
	if err := postBoxdInit(ctx, netInfo.HostIP, userEnv(bc.env), bc.user, bc.workdir); err != nil {
		return fmt.Errorf("bake context into boxd: %w", err)
	}
	emitInternal("system", "baked context into boxd (user=%q workdir=%q env=%d)",
		bc.user, bc.workdir, len(bc.env))

	// Phase 9: snapshot
	emitUser("system", "Saving template")
	snapPath := filepath.Join(snapDir, "vmstate.snap")
	memPath := filepath.Join(snapDir, "mem.snap")
	if err := vm.CreateSnapshot(socketPath, snapPath, memPath); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	emitInternal("system", "snapshot captured")

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
	// Pdeathsig: kernel kills firecracker if we die for any reason
	// (including SIGKILL), so orphans can't hold TAP/netns.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:    true,
		Pdeathsig: syscall.SIGKILL,
	}

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

// postBoxdInit pushes the template's default context into boxd so it
// travels in the snapshot. Called once, just before vm.CreateSnapshot.
// Failure aborts the build — a snapshot without the intended defaults
// would silently corrupt every sandbox restored from the template.
func postBoxdInit(ctx context.Context, vmIP string, envVars map[string]string, defaultUser, defaultWorkdir string) error {
	body := struct {
		EnvVars        map[string]string `json:"env_vars,omitempty"`
		DefaultUser    string            `json:"default_user,omitempty"`
		DefaultWorkdir string            `json:"default_workdir,omitempty"`
	}{EnvVars: envVars, DefaultUser: defaultUser, DefaultWorkdir: defaultWorkdir}

	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal init body: %w", err)
	}
	url := fmt.Sprintf("http://%s:%d/init", vmIP, boxdPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("build init request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	initClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := initClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /init: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /init: status %d", resp.StatusCode)
	}
	return nil
}

// userEnv filters the build-time env map down to the keys set via `env`
// steps, stripping the platform baseline (PATH/HOME/USER/TERM/LANG/SHELL)
// that template-builder uses to drive build-time exec. Those come from
// boxd's own env at runtime and shouldn't be baked into the template.
func userEnv(buildEnv map[string]string) map[string]string {
	baseline := map[string]struct{}{
		"PATH": {}, "HOME": {}, "USER": {}, "TERM": {}, "LANG": {}, "SHELL": {},
	}
	out := make(map[string]string, len(buildEnv))
	for k, v := range buildEnv {
		if _, skip := baseline[k]; skip {
			continue
		}
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Build step execution
// ---------------------------------------------------------------------------

const stepTimeout = 10 * time.Minute

// buildCtx carries the state that threads through template build steps:
// env vars the next run step sees, the user it runs as, and the cwd. env
// is the initial baseline plus accumulated env steps; user defaults to
// root until a user step switches it; workdir defaults empty (boxd's
// fallback) until a workdir step sets it.
type buildCtx struct {
	env     map[string]string
	user    string
	workdir string
}

func executeBuildSteps(ctx context.Context, vmIP string, spec builder.BuildSpec) (buildCtx, error) {
	bc := buildCtx{
		env: map[string]string{
			"PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME":  "/root",
			"USER":  "root",
			"TERM":  "xterm",
			"LANG":  "C.UTF-8",
			"SHELL": "/bin/sh",
		},
	}

	for i, step := range spec.Steps {
		select {
		case <-ctx.Done():
			return bc, ctx.Err()
		default:
		}

		emitUser("system", "Step %d/%d", i+1, len(spec.Steps))
		stepStart := time.Now()

		next, err := runBuildStep(ctx, vmIP, step, bc)
		if err != nil {
			return bc, fmt.Errorf("step %d/%d failed after %s: %w",
				i+1, len(spec.Steps), time.Since(stepStart).Round(time.Millisecond), err)
		}
		bc = next
		emitUser("system", "Step %d/%d completed (%s)", i+1, len(spec.Steps),
			time.Since(stepStart).Round(time.Millisecond))
	}
	return bc, nil
}

func runBuildStep(ctx context.Context, vmIP string, step builder.BuildStep, bc buildCtx) (buildCtx, error) {
	switch {
	case step.Run != nil:
		if err := runShellCmd(ctx, vmIP, *step.Run, bc); err != nil {
			return bc, err
		}
		return bc, nil
	case step.Env != nil:
		bc.env[step.Env.Key] = step.Env.Value
		emitUser("system", "Set %s", step.Env.Key)
		return bc, nil
	case step.Workdir != nil:
		// Resolve to absolute (Docker semantics: relative paths are joined
		// with the current workdir; base is "/" when no prior workdir).
		target := *step.Workdir
		if !filepath.IsAbs(target) {
			base := bc.workdir
			if base == "" {
				base = "/"
			}
			target = filepath.Join(base, target)
		}
		// Create the directory as root so we can chown it to the build
		// user, then switch back. Running everything as root here avoids
		// permission issues when the user hasn't been created yet.
		ownUser := bc.user
		if ownUser == "" {
			ownUser = "root"
		}
		mkdir := fmt.Sprintf("mkdir -p %s && chown -R %s:%s %s",
			shellQuote(target), shellQuote(ownUser), shellQuote(ownUser), shellQuote(target))
		root := bc
		root.user = "root" // ensure mkdir + chown run as root
		if err := runShellCmd(ctx, vmIP, mkdir, root); err != nil {
			return bc, fmt.Errorf("create workdir %s: %w", target, err)
		}
		bc.workdir = target
		emitUser("system", "Working directory: %s", target)
		return bc, nil
	case step.User != nil:
		name := step.User.Name
		// Check if user exists; create if missing. Running as root so the
		// adduser call can actually create the account.
		root := bc
		root.user = "root"
		check := fmt.Sprintf("id -u %s >/dev/null 2>&1 || adduser --disabled-password --gecos \"\" %s",
			shellQuote(name), shellQuote(name))
		if err := runShellCmd(ctx, vmIP, check, root); err != nil {
			return bc, fmt.Errorf("ensure user %s: %w", name, err)
		}
		if step.User.Sudo {
			sudo := fmt.Sprintf(
				"usermod -aG sudo %s || true; passwd -d %s || true; "+
					"grep -q '^%s ALL=(ALL:ALL) NOPASSWD: ALL' /etc/sudoers || "+
					"echo '%s ALL=(ALL:ALL) NOPASSWD: ALL' >>/etc/sudoers",
				shellQuote(name), shellQuote(name), name, name,
			)
			if err := runShellCmd(ctx, vmIP, sudo, root); err != nil {
				return bc, fmt.Errorf("grant sudo to %s: %w", name, err)
			}
		}
		bc.user = name
		emitUser("system", "User: %s", name)
		return bc, nil
	default:
		return bc, fmt.Errorf("step has no op set")
	}
}

func runShellCmd(ctx context.Context, vmIP, cmd string, bc buildCtx) error {
	emitUser("system", "$ %s", truncate(cmd, 256))

	stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()

	client := processClient(vmIP)
	req := &pb.StartRequest{
		Cmd:       "/bin/sh",
		Args:      []string{"-c", cmd},
		Envs:      bc.env,
		Cwd:       bc.workdir,
		User:      bc.user,
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
					emitUser("stdout", "%s", text)
				}
			case *pb.DataEvent_Stderr:
				text := strings.TrimRight(string(o.Stderr), "\n")
				if text != "" {
					emitUser("stderr", "%s", text)
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

func runStartCmd(ctx context.Context, vmIP string, spec builder.BuildSpec, bc buildCtx) error {
	if spec.StartCmd == "" {
		return nil
	}
	emitUser("system", "Running start command: %s", truncate(spec.StartCmd, 256))

	go func() {
		client := processClient(vmIP)
		req := &pb.StartRequest{
			Cmd:  "/bin/sh",
			Args: []string{"-c", spec.StartCmd},
			Envs: bc.env,
			Cwd:  bc.workdir,
			User: bc.user,
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

func pollReadyCmd(ctx context.Context, vmIP string, spec builder.BuildSpec, bc buildCtx) error {
	if spec.ReadyCmd == "" {
		return nil
	}
	emitUser("system", "Waiting for template to be ready: %s", truncate(spec.ReadyCmd, 256))

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
			Envs:      bc.env,
			Cwd:       bc.workdir,
			User:      bc.user,
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
				emitUser("system", "Template is ready")
				emitInternal("system", "ready_cmd succeeded after %d attempts", attempts+1)
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
//
// Each event carries a visibility tag: "user" events are surfaced to the
// end user over the build-log SSE stream; "internal" events stay in the
// operator journal. This keeps platform plumbing (image digests, slot
// indices, boxd boot timing) out of customer logs.
// ---------------------------------------------------------------------------

type buildEvent struct {
	Visibility string `json:"visibility"`
	Stream     string `json:"stream"`
	Text       string `json:"text"`
}

func emit(visibility, stream, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	line, _ := json.Marshal(buildEvent{Visibility: visibility, Stream: stream, Text: text})
	fmt.Println(string(line))
}

func emitUser(stream, format string, args ...any)     { emit("user", stream, format, args...) }
func emitInternal(stream, format string, args ...any) { emit("internal", stream, format, args...) }

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
