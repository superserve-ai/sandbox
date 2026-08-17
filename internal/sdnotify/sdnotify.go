// Package sdnotify sends readiness and lifecycle notifications to systemd via
// the sd_notify(3) protocol, so a Type=notify unit reports "ready" only when
// the daemon is actually serving — not merely when the process has forked.
//
// When NOTIFY_SOCKET is unset (the process is not running under a Type=notify
// unit — local runs, tests) every call is a silent no-op.
package sdnotify

import (
	"net"
	"os"
	"strings"
)

// Ready reports that the daemon has finished startup and is serving. For a
// Type=notify unit, systemd holds the unit in "activating" until this arrives.
func Ready() error { return notify("READY=1") }

// Stopping reports that the daemon has begun shutting down.
func Stopping() error { return notify("STOPPING=1") }

// Status sets the human-readable status line shown by `systemctl status`.
func Status(s string) error { return notify("STATUS=" + s) }

func notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	name := socket
	// A leading '@' denotes an abstract-namespace socket: the address is a NUL
	// byte followed by the remaining name.
	if strings.HasPrefix(name, "@") {
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
