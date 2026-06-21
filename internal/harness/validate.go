package harness

import (
	"errors"
	"fmt"
	"strings"
)

// maxPort is the highest valid TCP port. Ports are 1..65535 (0 is "unset").
const maxPort = 65535

// Validate enforces the Harness Contract invariants on a Manifest and returns
// every problem aggregated into one error (via errors.Join), so a bad manifest
// surfaces all its faults in a single load rather than one-at-a-time. Each
// problem is wrapped with its field name. A nil return means the runtime can
// consume the Manifest as-is.
//
// Rules:
//   - start: non-empty.
//   - transport: one of http | stdin | exec.
//   - port: required and in 1..65535 iff transport==http; must be unset (0)
//     for other transports (a set port there is almost always a copy-paste
//     bug, so it is a hard error, not a warning).
//   - idle: parses into a valid IdlePolicy (signal | http:/<path> |
//     timeout:<dur>). The parse happens in Parse; Validate reports any error.
//   - state: non-empty, and every entry an absolute path (leading "/").
//   - level: one of 0 | 1 | 2.
func (m *Manifest) Validate() error {
	var errs []error

	if m.Start == "" {
		errs = append(errs, errors.New("start: required (boot command for the brain is empty)"))
	}

	if !m.Transport.valid() {
		errs = append(errs, fmt.Errorf("transport: %q invalid, must be one of: %s | %s | %s",
			m.Transport, TransportHTTP, TransportStdin, TransportExec))
	}

	// Port is meaningful only for the http transport. We validate the coupling
	// in both directions so neither a missing nor a stray port slips through.
	if m.Transport == TransportHTTP {
		if m.Port == 0 {
			errs = append(errs, errors.New("port: required when transport=http"))
		} else if m.Port < 1 || m.Port > maxPort {
			errs = append(errs, fmt.Errorf("port: %d out of range 1..%d", m.Port, maxPort))
		}
	} else if m.Port != 0 {
		errs = append(errs, fmt.Errorf("port: %d set but transport=%q does not use a port", m.Port, m.Transport))
	}

	// Surface any idle-string parse error captured in Parse.
	if m.idleErr != nil {
		errs = append(errs, m.idleErr)
	} else if !validIdleKind(m.Idle.Kind) {
		// Defends against constructing a Manifest by hand with a zero Idle.
		errs = append(errs, fmt.Errorf("idle: kind %q invalid, must be one of: %s | %s | %s",
			m.Idle.Kind, IdleSignal, IdleHTTP, IdleTimeout))
	}

	if len(m.State) == 0 {
		errs = append(errs, errors.New("state: required and must be non-empty (paths holding all durable state)"))
	}
	for i, p := range m.State {
		// Guest paths are Linux-absolute. We check the leading "/" directly
		// rather than path/filepath so the result is the same on the darwin
		// dev host as in the Linux guest.
		if !strings.HasPrefix(p, "/") {
			errs = append(errs, fmt.Errorf("state[%d]: %q must be an absolute path (start with %q)", i, p, "/"))
		}
	}

	if !m.Level.valid() {
		errs = append(errs, fmt.Errorf("level: %d invalid, must be one of: %d | %d | %d", m.Level, Level0, Level1, Level2))
	}

	return errors.Join(errs...)
}

// validIdleKind reports whether k is one of the three idle kinds. A zero/empty
// kind is invalid — Parse always sets a concrete kind (defaulting to signal),
// so an empty kind means the manifest was hand-built without going through
// Parse.
func validIdleKind(k IdleKind) bool {
	switch k {
	case IdleSignal, IdleHTTP, IdleTimeout:
		return true
	default:
		return false
	}
}
