package proxy

import (
	"fmt"
	"net"
	"strings"
)

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

	// The instance ID must NOT contain a port-style "n-..." prefix —
	// that's the user app routing format and we want a clear separation.
	// Terminal IDs are bare UUIDs (alphanumeric + hyphen, but the first
	// segment of a UUID is always 8 hex chars so it's never numeric+dash).
	if !validInstanceID.MatchString(label) {
		return "", fmt.Errorf("proxy: terminal host instance ID %q contains invalid characters", label)
	}

	return label, nil
}
