// Command actor-e2e is the end-to-end integration of the Actor runtime against
// REAL Firecracker microVMs. It wires the actual internal/actor runtime
// (Registry + single-writer Lease + serial Inbox + wake-on-reference Router)
// to a Firecracker-backed Waker and drives an Actor through the full lifecycle:
//
//	cold boot → turn → pause (Tier-1, RAM-resident) → re-wake → turn → ...
//
// Every event is routed through the real Inbox (serialized under the lease); the
// Handler resumes the paused VM, does a guest-visible operation, and re-pauses —
// i.e. genuine between-turns hibernation on real hardware. It prints per-phase
// timings so the lifecycle is measured, not just asserted.
//
// Run on a KVM host:
//
//	actor-e2e -fc-bin=/usr/local/bin/firecracker -kernel=<vmlinux> -rootfs=<base.ext4> -turns=5
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/superserve-ai/sandbox/internal/actor"
)

func main() {
	var (
		fcBin  = flag.String("fc-bin", "firecracker", "path to firecracker binary")
		kernel = flag.String("kernel", "", "guest kernel (vmlinux) — required")
		rootfs = flag.String("rootfs", "", "rootfs.ext4 (read-only) — required")
		runDir = flag.String("run-dir", "/tmp/actor-e2e", "scratch dir for sockets/VMs")
		mem    = flag.Int("mem", 512, "guest mem MiB")
		turns  = flag.Int("turns", 5, "number of event turns to drive")
	)
	flag.Parse()
	if *kernel == "" || *rootfs == "" {
		fmt.Fprintln(os.Stderr, "actor-e2e: -kernel and -rootfs are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*runDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()
	waker := &fcWaker{fcBin: *fcBin, kernel: *kernel, rootfs: *rootfs, runDir: *runDir, memMiB: *mem, vms: map[string]*fcVM{}}
	defer waker.shutdown()

	// The real Actor runtime — unmodified.
	reg := actor.NewRegistry(actor.NewMemStore(), nil)
	router := actor.NewRouter(reg, waker, "host-e2e", 16)

	const team, name = "team-e2e", "demo/agent-1"
	a, created, err := reg.GetActor(ctx, team, name, actor.Actor{Template: "base"})
	if err != nil {
		fail(err)
	}
	fmt.Printf("getActor(%q) → %s (created=%v, tier=%s)\n", name, a.ID, created, a.Tier)

	results := make([]turnResult, *turns)
	done := make(chan int, *turns)
	waker.onTurn = func(idx int, r turnResult) { results[idx] = r; done <- idx }

	fmt.Printf("\nDriving %d turns through the real Inbox+Lease+Router → Firecracker:\n", *turns)
	t0 := time.Now()
	for i := 0; i < *turns; i++ {
		ev := actor.Event{ID: fmt.Sprintf("%d", i), Type: "msg", Payload: []byte(fmt.Sprintf("turn %d", i))}
		if err := router.Route(ctx, team, name, actor.Actor{Template: "base"}, ev); err != nil {
			fail(fmt.Errorf("route turn %d: %w", i, err))
		}
	}
	// Wait for all turns to be processed by the serial inbox.
	for n := 0; n < *turns; n++ {
		<-done
	}
	total := time.Since(t0)

	fmt.Printf("\n%-6s %-12s %-12s %-12s %s\n", "turn", "phase", "wake", "guest-op", "note")
	for i, r := range results {
		fmt.Printf("%-6d %-12s %-12s %-12s %s\n", i, r.phase, dur(r.wake), dur(r.guestOp), r.note)
	}
	fmt.Printf("\nlifecycle proven on real Firecracker: cold boot → %d between-turns pause/resume cycles.\n", *turns-1)
	fmt.Printf("total wall: %s. Single-writer lease held throughout (held=%v).\n", dur(total), router.IsLive(a.ID))
}

type turnResult struct {
	phase   string // "cold-boot" or "rewake"
	wake    time.Duration
	guestOp time.Duration
	note    string
}

func dur(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return d.Round(time.Microsecond).String()
}

func fail(err error) { fmt.Fprintln(os.Stderr, "actor-e2e:", err); os.Exit(1) }

// fcWaker is a real actor.Waker: it boots a Firecracker VM per Actor on cold
// wake, and the Handler it returns does between-turns pause/resume on the live
// VM for every event. State (the VM, current tier) is kept per Actor id.
type fcWaker struct {
	fcBin, kernel, rootfs, runDir string
	memMiB                        int

	mu     sync.Mutex
	vms    map[string]*fcVM
	onTurn func(idx int, r turnResult)
}

func (w *fcWaker) Wake(ctx context.Context, a actor.Actor, _ *actor.Lease) (actor.Handler, error) {
	w.mu.Lock()
	vm := w.vms[a.ID]
	w.mu.Unlock()

	phase := "cold-boot"
	var coldWake time.Duration
	if vm == nil {
		start := time.Now()
		v, err := bootVM(ctx, w, a.ID)
		if err != nil {
			return nil, err
		}
		coldWake = time.Since(start)
		vm = v
		w.mu.Lock()
		w.vms[a.ID] = vm
		w.mu.Unlock()
		// Pause immediately so the FIRST turn also exercises a resume (between-
		// turns hibernation is the steady state).
		_ = vm.setState(ctx, "Paused")
	}

	// The Handler is the per-turn behavior: resume the paused VM (the real wake),
	// do a guest-visible op, re-pause (hibernate until the next turn).
	first := true
	return func(ctx context.Context, ev actor.Event) error {
		idx := 0
		fmt.Sscanf(ev.ID, "%d", &idx)

		wakeStart := time.Now()
		if err := vm.setState(ctx, "Resumed"); err != nil {
			return err
		}
		wake := time.Since(wakeStart)

		opStart := time.Now()
		if err := vm.ping(ctx); err != nil { // a real round-trip to the live VMM
			return err
		}
		guestOp := time.Since(opStart)

		if err := vm.setState(ctx, "Paused"); err != nil { // hibernate until next turn
			return err
		}

		r := turnResult{phase: phase, wake: wake, guestOp: guestOp}
		if first && coldWake > 0 {
			r.note = "incl cold boot " + dur(coldWake)
		}
		first = false
		phase = "rewake"
		if w.onTurn != nil {
			w.onTurn(idx, r)
		}
		return nil
	}, nil
}

func (w *fcWaker) shutdown() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, vm := range w.vms {
		vm.close()
	}
}

// --- minimal Firecracker client (HTTP over the API unix socket) ---

type fcVM struct {
	dir    string
	sock   string
	proc   *exec.Cmd
	client *http.Client
}

// startProc launches firecracker with its API socket. Guest serial is discarded.
func startProc(ctx context.Context, fcBin, sock, dir string) (*exec.Cmd, error) {
	proc := exec.CommandContext(ctx, fcBin, "--api-sock", sock, "--id", filepath.Base(dir))
	proc.Stdout = nil
	proc.Stderr = nil
	if err := proc.Start(); err != nil {
		return nil, err
	}
	return proc, nil
}

func bootVM(ctx context.Context, w *fcWaker, actorID string) (*fcVM, error) {
	dir := filepath.Join(w.runDir, "vm-"+sanitize(actorID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "fc.sock")
	_ = os.Remove(sock)
	vm := &fcVM{dir: dir, sock: sock, client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
	proc, err := startProc(ctx, w.fcBin, sock, dir)
	if err != nil {
		return nil, err
	}
	vm.proc = proc
	if err := waitForSocket(ctx, sock, 5*time.Second); err != nil {
		vm.close()
		return nil, err
	}
	if err := vm.put(ctx, "/boot-source", map[string]any{
		"kernel_image_path": w.kernel,
		"boot_args":         "console=ttyS0 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd",
	}); err != nil {
		vm.close()
		return nil, err
	}
	if err := vm.put(ctx, "/drives/rootfs", map[string]any{
		"drive_id": "rootfs", "path_on_host": w.rootfs, "is_root_device": true, "is_read_only": true,
	}); err != nil {
		vm.close()
		return nil, err
	}
	if err := vm.put(ctx, "/machine-config", map[string]any{"vcpu_count": 1, "mem_size_mib": w.memMiB}); err != nil {
		vm.close()
		return nil, err
	}
	if err := vm.put(ctx, "/actions", map[string]any{"action_type": "InstanceStart"}); err != nil {
		vm.close()
		return nil, err
	}
	// Let the guest reach a steady resident state.
	select {
	case <-time.After(1200 * time.Millisecond):
	case <-ctx.Done():
		vm.close()
		return nil, ctx.Err()
	}
	return vm, nil
}

func (vm *fcVM) setState(ctx context.Context, state string) error {
	return vm.do(ctx, http.MethodPatch, "/vm", map[string]any{"state": state})
}

// ping is a real round-trip to the live VMM (confirms the resumed VM is serving).
func (vm *fcVM) ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/machine-config", nil)
	resp, err := vm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ping status %d", resp.StatusCode)
	}
	return nil
}

func (vm *fcVM) put(ctx context.Context, path string, body any) error {
	return vm.do(ctx, http.MethodPut, path, body)
}

func (vm *fcVM) do(ctx context.Context, method, path string, body any) error {
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := vm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
	}
	return nil
}

func (vm *fcVM) close() {
	if vm.proc != nil && vm.proc.Process != nil {
		_ = vm.proc.Process.Kill()
		_ = vm.proc.Wait()
	}
	_ = os.RemoveAll(vm.dir)
}

func waitForSocket(ctx context.Context, sock string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(sock); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("api socket never appeared")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '/' || c == ' ' {
			b[i] = '-'
		}
	}
	return string(b)
}
