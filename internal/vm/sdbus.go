package vm

// One persistent connection to systemd's private socket replaces per-call
// systemctl forks. Under a large concurrent launch burst the forks are the
// dominant cost: each pays fork+exec plus a D-Bus connect/handshake that
// grows with the number of loaded units, and the simultaneous spawns
// compete with PID1 and the starting units for the scheduler. Every helper
// falls back to exec'ing systemctl when the connection is unavailable, so
// the worst case is exactly the exec-only behavior.
//
// Design rules, each load-bearing:
//   - The connection is dialed with its own lifetime context, never a
//     caller's: the library closes the connection when the dialing context
//     ends, so a per-request context would kill it seconds after birth.
//   - No caller ever blocks on connection state. Acquisition is a
//     non-blocking check; if there is no healthy connection, one background
//     dial is kicked off (single-flight, held until it truly returns) and
//     the caller falls back to exec immediately. A wedged PID1 can
//     therefore never stall helpers behind a mutex, and never costs more
//     than one blocked dial goroutine.
//   - Connected() is checked on every acquisition: the library's Conn is
//     two sockets, and the signal socket can die alone, which would
//     otherwise strand every job-completion wait while method calls keep
//     succeeding.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	zlog "github.com/rs/zerolog/log"
)

// systemdDBusEnabled gates the D-Bus path; set once at startup from
// VMD_SYSTEMD_DBUS. Off → helpers exec systemctl as before.
var systemdDBusEnabled atomic.Bool

// SetSystemdDBusEnabled turns the persistent systemd D-Bus path on or off.
// Enabling kicks off the background dial so the first helper call after
// startup doesn't need the exec fallback.
func SetSystemdDBusEnabled(v bool) {
	systemdDBusEnabled.Store(v)
	if v {
		sdbusAcquire()
	}
}

// sdbusRedialCooldown is the minimum gap between dial attempts, so a host
// where systemd is unreachable doesn't burn a dial per helper call.
const sdbusRedialCooldown = 3 * time.Second

var sdbus struct {
	mu       sync.Mutex
	conn     *sddbus.Conn
	dialing  bool
	lastDial time.Time
}

// sdbusAcquire returns a healthy connection or nil, without ever blocking
// on dial or I/O. A nil return means: use the exec fallback for this call.
func sdbusAcquire() *sddbus.Conn {
	sdbus.mu.Lock()
	defer sdbus.mu.Unlock()
	if sdbus.conn != nil {
		if sdbus.conn.Connected() {
			return sdbus.conn
		}
		sdbus.conn.Close()
		sdbus.conn = nil
	}
	if !sdbus.dialing && time.Since(sdbus.lastDial) >= sdbusRedialCooldown {
		sdbus.dialing = true
		sdbus.lastDial = time.Now()
		go sdbusDial()
	}
	return nil
}

// sdbusDial runs one background dial. The connection context is detached —
// its lifetime is the daemon's, not any request's (a deadline on it would
// close the connection when it fired). The attempt stays marked in flight
// until it truly returns: the library's dial+auth I/O has no deadline, so
// abandoning a hung attempt and retrying would leak a goroutine per retry;
// held single-flight, a wedged PID1 costs at most one blocked goroutine
// while every caller keeps exec-falling-back.
func sdbusDial() {
	conn, err := sddbus.NewSystemdConnectionContext(context.Background())

	// The dial outcome is the only signal of which transport the helpers
	// are using — surfaced for the flag rollout.
	if err != nil {
		zlog.Warn().Err(err).Msg("systemd dbus dial failed; helpers exec systemctl")
	} else {
		zlog.Info().Msg("systemd dbus connected")
	}

	sdbus.mu.Lock()
	sdbus.dialing = false
	sdbus.lastDial = time.Now() // cooldown runs from completion, not start
	if err == nil {
		if sdbus.conn == nil {
			sdbus.conn = conn
		} else {
			// Lost a race with a connection cached by someone else.
			defer conn.Close()
		}
	}
	sdbus.mu.Unlock()
}

// sdbusDrop closes and forgets a connection after a transport failure so a
// later acquisition redials — a systemd daemon-reexec kills the socket and
// the library never reconnects on its own. Only drops the current one.
func sdbusDrop(c *sddbus.Conn) {
	sdbus.mu.Lock()
	if sdbus.conn == c {
		sdbus.conn = nil
		c.Close()
	}
	sdbus.mu.Unlock()
}

// sdbusDo runs fn against the shared connection. handled=false means the
// D-Bus path could not produce an answer (flag off, no healthy connection,
// transport failure) and the caller must fall back to exec'ing systemctl.
// handled=true means systemd answered: err is nil or a real method error
// (e.g. NoSuchUnit) that exec'd systemctl would hit identically.
func sdbusDo(fn func(*sddbus.Conn) error) (err error, handled bool) {
	if !systemdDBusEnabled.Load() {
		return nil, false
	}
	conn := sdbusAcquire()
	if conn == nil {
		return nil, false
	}
	err = fn(conn)
	if merr, answered := sdbusAnswer(err); answered {
		return merr, true
	}
	// Transport-shaped failure: drop the corpse so a later call redials —
	// unless it's the CALLER's cancellation, which is this call's result,
	// not evidence the shared bus is dead. Either way the exec path
	// handles this call with today's semantics.
	if sdbusCondemns(err) {
		sdbusDrop(conn)
	}
	return nil, false
}

// sdbusCondemns reports whether a non-answer error condemns the shared
// connection. Caller ctx expiry doesn't: the library surfaces it without
// the connection being unhealthy, and dropping would tear the bus down
// under every other in-flight operation.
func sdbusCondemns(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// sdbusAnswer reports whether systemd answered the call: nil, or a D-Bus
// method error (NoSuchUnit, start-limit, ...) that exec'd systemctl would
// hit identically. Anything else — ErrClosed, raw socket EOF/reset from a
// call in flight at transport death, ctx expiry — is transport-shaped.
func sdbusAnswer(err error) (error, bool) {
	if err == nil {
		return nil, true
	}
	if errors.Is(err, dbus.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil, false
	}
	var de dbus.Error
	if errors.As(err, &de) {
		return err, true
	}
	return nil, false
}

// sdbusNotLoaded reports the method errors meaning "systemd has no such
// unit loaded" — for template instances that is the normal state of every
// stopped/dead VM, and it is a definitive answer (not active, no PID), not
// a reason to fall back to exec.
func sdbusNotLoaded(err error) bool {
	var de dbus.Error
	if !errors.As(err, &de) {
		return false
	}
	switch de.Name {
	case "org.freedesktop.systemd1.NoSuchUnit",
		"org.freedesktop.DBus.Error.UnknownObject",
		"org.freedesktop.DBus.Error.UnknownInterface":
		return true
	}
	return false
}

// sdbusUnitProperty reads one property of a unit (iface "" = the generic
// Unit interface, "Service" = the service-specific one). The ctx bounds
// only this method call, never the connection. notLoaded=true is the
// definitive "unit does not exist" answer — for template instances that is
// the normal state of every stopped VM, not a fallback case.
func sdbusUnitProperty(ctx context.Context, unit, iface, name string) (val any, notLoaded, handled bool) {
	err, ok := sdbusDo(func(c *sddbus.Conn) error {
		var p *sddbus.Property
		var e error
		if iface == "Service" {
			p, e = c.GetServicePropertyContext(ctx, unit, name)
		} else {
			p, e = c.GetUnitPropertyContext(ctx, unit, name)
		}
		if e != nil {
			return e
		}
		val = p.Value.Value()
		return nil
	})
	if !ok {
		return nil, false, false
	}
	if err != nil {
		if sdbusNotLoaded(err) {
			return nil, true, true
		}
		return nil, false, false
	}
	return val, false, true
}
