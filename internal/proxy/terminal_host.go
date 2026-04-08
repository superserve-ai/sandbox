package proxy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// portPrefixLabel matches labels shaped like "1234-..." which belong to
// the user-app routing format ({port}-{id}.{domain}), NOT the terminal
// format ({id}.{domain}). We reject any such label in the terminal parser
// so the two routing tables are cleanly separated and a crafted host can
// never slip a port-labelled request through the terminal path.
var portPrefixLabel = regexp.MustCompile(`^[0-9]+-`)

// ParseTerminalHost extracts the instanceID from a Host header of the form
// {instanceID}.{domain}, used by the terminal endpoint.
//
// This is intentionally a separate function from ParseHost (which expects
// {port}-{id}.{domain}) because the terminal URL has no port label — the
// edge proxy itself terminates the connection rather than forwarding to a
// VM-internal port. Mixing the two parsers would either weaken the strict
// validation we want for user app routing or special-case terminal logic
// inside ParseHost.
//
// Returns an error if the host doesn't end with the expected domain
// suffix or if the leftmost label fails the instance-ID charset check —
// same path-traversal / injection guarantees as ParseHost.
func ParseTerminalHost(host, domain string) (instanceID string, err error) {
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}

	// Same domain-suffix enforcement as ParseHost — without it, the
	// proxy would happily route Host: badbox.attacker.com.
	if !strings.HasSuffix(hostname, "."+domain) {
		return "", fmt.Errorf("proxy: terminal host %q does not end in .%s", hostname, domain)
	}

	label, _, _ := strings.Cut(hostname, ".")
	if label == "" {
		return "", fmt.Errorf("proxy: terminal host %q has empty subdomain", host)
	}

	// Reject port-prefix labels (e.g. "3000-abc") that belong to the
	// user-app routing table. The regex enforces this structurally rather
	// than relying on the coincidence that our current instance IDs happen
	// to start with hex digits.
	if portPrefixLabel.MatchString(label) {
		return "", fmt.Errorf("proxy: terminal host label %q has port prefix (user-app format)", label)
	}

	if !validInstanceID.MatchString(label) {
		return "", fmt.Errorf("proxy: terminal host instance ID %q contains invalid characters", label)
	}

	return label, nil
}
