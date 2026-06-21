package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// firecrackerProvider is the REAL Tier-1 wake provider. It boots a pool of
// isolated Firecracker microVMs (no network interface, read-only shared rootfs —
// so it never touches the host's live vmd networking or state), pauses them all
// so their memory stays RAM-resident, then measures the in-process latency of a
// bare `PATCH /vm {"state":"Resumed"}` under contention.
//
// Why resume-API latency is the faithful Tier-1 number: under PATCH-Paused the
// guest's memory is never evicted, so a resume faults in ZERO pages. The wake
// cost is vCPU re-entry + KVM scheduling, which is exactly what the PATCH
// Resumed call drives. (Page-in cost only appears at Tier 2/3, where it is
// measured as T_guest against the probe.) The density variable that decides the
// gate is Contention — the number of paused VMs resident on the host when one
// wakes — which this provider holds live during every measurement.
//
// It is gated behind -provider=firecracker and only runs on a Linux KVM host.
type firecrackerProvider struct {
	fcBin  string
	kernel string
	rootfs string // read-only base image, shared across all pool VMs
	runDir string

	cur    *vmPool
	curKey string
}

func newFirecrackerProvider(fcBin, kernel, rootfs, runDir string) (*firecrackerProvider, error) {
	for label, p := range map[string]string{"firecracker": fcBin, "kernel": kernel, "rootfs": rootfs} {
		if p == "" {
			return nil, fmt.Errorf("firecracker provider: %s path is required", label)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("firecracker provider: %s: %w", label, err)
		}
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, fmt.Errorf("firecracker provider: rundir: %w", err)
	}
	return &firecrackerProvider{fcBin: fcBin, kernel: kernel, rootfs: rootfs, runDir: runDir}, nil
}

func (p *firecrackerProvider) Label() string { return "firecracker (REAL — bare pause/resume)" }

// Wake resumes one paused VM in the contention pool, times the PATCH Resumed,
// then re-pauses it so the next iteration measures the same cold-from-paused
// transition. The pool (cell.Contention VMs at cell.MemMiB) is built lazily on
// the first iteration of each (mem, contention) cell and torn down when the cell
// changes, so the K-1 other VMs stay paused-resident during every measurement.
func (p *firecrackerProvider) Wake(ctx context.Context, params WakeParams) (PhaseTimings, error) {
	if params.Cell.Tier != Tier1 {
		return PhaseTimings{}, fmt.Errorf("firecracker provider only implements Tier 1; got tier %s", params.Cell.Tier)
	}
	key := strconv.Itoa(params.Cell.MemMiB) + "/" + strconv.Itoa(params.Cell.Contention)
	if p.cur == nil || p.curKey != key {
		if p.cur != nil {
			p.cur.Close()
		}
		pool, err := bootPool(ctx, p, params.Cell.MemMiB, max1(params.Cell.Contention))
		if err != nil {
			return PhaseTimings{}, fmt.Errorf("boot pool (mem=%d contention=%d): %w", params.Cell.MemMiB, params.Cell.Contention, err)
		}
		p.cur = pool
		p.curKey = key
	}

	target := p.cur.vms[params.Iteration%len(p.cur.vms)]
	start := time.Now()
	if err := target.setState(ctx, "Resumed"); err != nil {
		return PhaseTimings{}, fmt.Errorf("resume: %w", err)
	}
	resume := time.Since(start)
	// Re-pause so the VM is back in the measured (paused-resident) state for the
	// next iteration. Not counted in the wake timing.
	if err := target.setState(ctx, "Paused"); err != nil {
		return PhaseTimings{}, fmt.Errorf("re-pause: %w", err)
	}
	return PhaseTimings{Resume: resume}, nil
}

// Close tears down the active pool. Implements io.Closer; main calls it after the
// sweep so no firecracker processes leak.
func (p *firecrackerProvider) Close() error {
	if p.cur != nil {
		p.cur.Close()
		p.cur = nil
	}
	return nil
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// vmPool is a set of booted-then-paused microVMs held resident together.
type vmPool struct {
	vms []*fcVM
}

func (pool *vmPool) Close() {
	for _, vm := range pool.vms {
		vm.Close()
	}
}

// bootPool boots n VMs and pauses them all, leaving them memory-resident.
func bootPool(ctx context.Context, p *firecrackerProvider, memMiB, n int) (*vmPool, error) {
	pool := &vmPool{}
	for i := 0; i < n; i++ {
		vm, err := bootVM(ctx, p, memMiB, i)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("boot vm %d/%d: %w", i, n, err)
		}
		pool.vms = append(pool.vms, vm)
	}
	// Let the guests reach a steady resident state before pausing.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
		pool.Close()
		return nil, ctx.Err()
	}
	for i, vm := range pool.vms {
		if err := vm.setState(ctx, "Paused"); err != nil {
			pool.Close()
			return nil, fmt.Errorf("pause vm %d: %w", i, err)
		}
	}
	return pool, nil
}

// fcVM is one Firecracker microVM: its process, API socket, and an HTTP client
// bound to that socket.
type fcVM struct {
	id     string
	dir    string
	sock   string
	proc   *exec.Cmd
	client *http.Client
	logBuf *bytes.Buffer
}

func bootVM(ctx context.Context, p *firecrackerProvider, memMiB, idx int) (*fcVM, error) {
	id := fmt.Sprintf("bench-%d-%d", os.Getpid(), idx)
	dir := filepath.Join(p.runDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "fc.sock")
	_ = os.Remove(sock)

	vm := &fcVM{
		id:     id,
		dir:    dir,
		sock:   sock,
		logBuf: &bytes.Buffer{},
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sock)
				},
			},
		},
	}

	proc := exec.CommandContext(ctx, p.fcBin, "--api-sock", sock, "--id", id)
	// Guest serial → the VM's log buffer (used for the optional liveness check;
	// not on the timing path). Keeps firecracker's own stdout out of our table.
	proc.Stdout = vm.logBuf
	proc.Stderr = vm.logBuf
	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	vm.proc = proc

	if err := waitForSocket(ctx, sock, 5*time.Second); err != nil {
		vm.Close()
		return nil, fmt.Errorf("api socket never appeared: %w", err)
	}

	// Configure: boot-source, root drive (read-only, shared), machine-config.
	// No panic=1/reboot=k: if the guest's init dislikes the minimal no-network
	// boot, we want the kernel to halt (VM stays alive and pausable) rather than
	// reboot-loop out from under the benchmark.
	bootArgs := "console=ttyS0 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
	if err := vm.put(ctx, "/boot-source", map[string]any{
		"kernel_image_path": p.kernel,
		"boot_args":         bootArgs,
	}); err != nil {
		vm.Close()
		return nil, err
	}
	if err := vm.put(ctx, "/drives/rootfs", map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   p.rootfs,
		"is_root_device": true,
		"is_read_only":   true,
	}); err != nil {
		vm.Close()
		return nil, err
	}
	if err := vm.put(ctx, "/machine-config", map[string]any{
		"vcpu_count":   1,
		"mem_size_mib": memMiB,
	}); err != nil {
		vm.Close()
		return nil, err
	}
	if err := vm.put(ctx, "/actions", map[string]any{"action_type": "InstanceStart"}); err != nil {
		vm.Close()
		return nil, fmt.Errorf("InstanceStart: %w", err)
	}
	return vm, nil
}

func (vm *fcVM) setState(ctx context.Context, state string) error {
	return vm.patch(ctx, "/vm", map[string]any{"state": state})
}

func (vm *fcVM) put(ctx context.Context, path string, body any) error {
	return vm.do(ctx, http.MethodPut, path, body)
}

func (vm *fcVM) patch(ctx context.Context, path string, body any) error {
	return vm.do(ctx, http.MethodPatch, path, body)
}

func (vm *fcVM) do(ctx context.Context, method, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
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

// Close stops the firecracker process and removes the rundir.
func (vm *fcVM) Close() {
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
			return fmt.Errorf("timeout after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
