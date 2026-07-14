package vm

// One persistent connection to systemd's private socket replaces per-call
// systemctl forks. Under a concurrent launch burst the forks are the
// dominant cost: each pays fork+exec plus a D-Bus connect/handshake that
// grows with the number of loaded units, and 100 simultaneous spawns
// compete with PID1 and the starting units for the scheduler. Every helper
// falls back to exec'ing systemctl when the connection is unavailable, so
// the worst case is exactly the exec-only behavior.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

// systemdDBusEnabled gates the D-Bus path; set once at startup from
// VMD_SYSTEMD_DBUS. Off → helpers exec systemctl as before.
var systemdDBusEnabled atomic.Bool

// SetSystemdDBusEnabled turns the persistent systemd D-Bus path on or off.
func SetSystemdDBusEnabled(v bool) { systemdDBusEnabled.Store(v) }

// sdbus holds the shared connection. nil until first use and after a
// transport failure; redialed lazily. The private socket requires root and
// bypasses dbus-daemon entirely.
var sdbus struct {
	mu   sync.Mutex
	conn *sddbus.Conn
}

func sdbusGet(ctx context.Context) (*sddbus.Conn, error) {
	sdbus.mu.Lock()
	defer sdbus.mu.Unlock()
	if sdbus.conn != nil {
		return sdbus.conn, nil
	}
	conn, err := sddbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	sdbus.conn = conn
	return conn, nil
}

// sdbusDrop closes and forgets a connection after a transport failure so
// the next call redials — a systemd daemon-reexec kills the socket and the
// library never reconnects on its own. Only drops the current connection.
func sdbusDrop(c *sddbus.Conn) {
	sdbus.mu.Lock()
	if sdbus.conn == c {
		sdbus.conn = nil
		c.Close()
	}
	sdbus.mu.Unlock()
}

// sdbusDo runs fn against the shared connection. handled=false means the
// D-Bus path could not produce an answer (flag off, dial failed, connection
// closed twice) and the caller must fall back to exec'ing systemctl.
// handled=true means systemd answered: err is nil or a real method error
// (e.g. NoSuchUnit) that the fallback would hit too.
func sdbusDo(ctx context.Context, fn func(*sddbus.Conn) error) (err error, handled bool) {
	if !systemdDBusEnabled.Load() {
		return nil, false
	}
	conn, derr := sdbusGet(ctx)
	if derr != nil {
		return nil, false
	}
	err = fn(conn)
	if sdbusClosed(err) {
		sdbusDrop(conn)
		if conn, derr = sdbusGet(ctx); derr != nil {
			return nil, false
		}
		err = fn(conn)
		if sdbusClosed(err) {
			sdbusDrop(conn)
			return nil, false
		}
	}
	if merr, answered := sdbusAnswer(err); answered {
		return merr, true
	}
	// Transport-shaped failure (net error, ctx expiry mid-call): let the
	// exec path try; it either succeeds or fails with today's semantics.
	return nil, false
}

// sdbusClosed reports a dead connection — the one error worth a redial.
func sdbusClosed(err error) bool { return errors.Is(err, dbus.ErrClosed) }

// sdbusAnswer reports whether systemd answered the call: nil, or a D-Bus
// method error (NoSuchUnit, start-limit, ...) that exec'd systemctl would
// hit identically. Anything else is transport-shaped → not answered.
func sdbusAnswer(err error) (error, bool) {
	if err == nil {
		return nil, true
	}
	var de dbus.Error
	if errors.As(err, &de) {
		return err, true
	}
	return nil, false
}

// sdbusUnitProperty reads one property of a unit (iface "" = the generic
// Unit interface, "Service" = the service-specific one).
func sdbusUnitProperty(ctx context.Context, unit, iface, name string) (any, error, bool) {
	var val any
	err, handled := sdbusDo(ctx, func(c *sddbus.Conn) error {
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
	return val, err, handled
}
