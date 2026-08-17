package handoff

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// GatewayController is the gateway routing surface the controller steers. The
// controller runs inside the gateway process, so these are direct in-process
// calls, not socket round-trips.
type GatewayController interface {
	QuiesceGRPC(on bool)
	QuiesceResolver(on bool)
	SetActive(gen Generation)
}

// SystemdActions implements Actions against a real host: it starts and stops
// generation units with systemctl, drives each generation through its control
// socket (preflight → activate), and steers routing through the in-process
// gateway.
//
// The exec and control-socket calls are injectable (run, send) so the wiring is
// unit-testable without a host.
type SystemdActions struct {
	// Gateway is the in-process gateway routing surface.
	Gateway GatewayController
	// Unit maps a generation id to its systemd unit (e.g. superserve-vmd@b).
	Unit func(id string) string
	// GenControl maps a generation id to its control socket path.
	GenControl func(id string) string

	ActivateTimeout time.Duration
	StabilizeWait   time.Duration

	// run executes a command (systemctl). Injectable for tests.
	run func(ctx context.Context, name string, args ...string) error
	// send writes one line to a unix control socket and returns the reply line.
	send func(ctx context.Context, sock, cmd string) (string, error)
}

// NewSystemdActions returns SystemdActions with real systemctl/socket backends.
func NewSystemdActions(gw GatewayController, unit, genControl func(id string) string) *SystemdActions {
	return &SystemdActions{
		Gateway:         gw,
		Unit:            unit,
		GenControl:      genControl,
		ActivateTimeout: 60 * time.Second,
		StabilizeWait:   10 * time.Second,
		run:             runCmd,
		send:            sendControl,
	}
}

func runCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sendControl(ctx context.Context, sock, cmd string) (string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := fmt.Fprintln(conn, cmd); err != nil {
		return "", err
	}
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("control %s: no reply to %q", sock, cmd)
	}
	return strings.TrimSpace(sc.Text()), nil
}

// StartStandby starts the next generation's unit. The unit is Type=notify and
// signals readiness after preflight, so this returns once the generation is
// preflight-ready (bound, validated, awaiting activation).
func (a *SystemdActions) StartStandby(ctx context.Context, next Generation) error {
	return a.run(ctx, "systemctl", "start", a.Unit(next.ID))
}

// AwaitReady confirms the next generation's control socket is reachable and
// reports the preflight phase.
func (a *SystemdActions) AwaitReady(ctx context.Context, next Generation) error {
	resp, err := a.send(ctx, a.GenControl(next.ID), "status")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("generation %s not ready: %s", next.ID, resp)
	}
	return nil
}

// QuiesceGRPC toggles the gateway's control-plane admission hold (in-process).
func (a *SystemdActions) QuiesceGRPC(on bool) { a.Gateway.QuiesceGRPC(on) }

// QuiesceResolver toggles the gateway's resolver admission hold (in-process).
func (a *SystemdActions) QuiesceResolver(on bool) { a.Gateway.QuiesceResolver(on) }

// DrainAndStop stops the previous generation. systemctl stop blocks until the
// unit is inactive — the generation drains, flushes, and exits, which releases
// the writer lease.
func (a *SystemdActions) DrainAndStop(ctx context.Context, prev Generation) error {
	return a.run(ctx, "systemctl", "stop", a.Unit(prev.ID))
}

// Activate tells the next generation to acquire the lease and become the writer,
// blocking until it reports active.
func (a *SystemdActions) Activate(ctx context.Context, next Generation) error {
	actx, cancel := context.WithTimeout(ctx, a.ActivateTimeout)
	defer cancel()
	resp, err := a.send(actx, a.GenControl(next.ID), "activate")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("generation %s activation failed: %s", next.ID, resp)
	}
	return nil
}

// SetActive points the gateway at the generation (in-process).
func (a *SystemdActions) SetActive(gen Generation) { a.Gateway.SetActive(gen) }

// Stabilize waits a settling period and confirms the generation is still active.
func (a *SystemdActions) Stabilize(ctx context.Context, gen Generation) error {
	select {
	case <-time.After(a.StabilizeWait):
	case <-ctx.Done():
		return ctx.Err()
	}
	resp, err := a.send(ctx, a.GenControl(gen.ID), "status")
	if err != nil {
		return err
	}
	if !strings.Contains(resp, "active") {
		return fmt.Errorf("generation %s not active after stabilization: %s", gen.ID, resp)
	}
	return nil
}

// Rollback restores the previous generation as a fresh process: start its unit,
// then activate it. Used when the new generation fails to come up.
func (a *SystemdActions) Rollback(ctx context.Context, prev Generation) error {
	if err := a.run(ctx, "systemctl", "start", a.Unit(prev.ID)); err != nil {
		return err
	}
	return a.Activate(ctx, prev)
}
