package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseHost extracts port and instanceID from a Host header of the form
// {port}-{instanceID}.sandbox.superserve.ai (or any subdomain suffix).
// Returns an error if the format doesn't match.
func ParseHost(host string) (port int, instanceID string, err error) {
	// Strip port from host if present (e.g. "49983-abc123.sandbox.superserve.ai:443")
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		// No port in host, use as-is
		hostname = host
	}

	// Take the leftmost label: "49983-abc123"
	label := strings.SplitN(hostname, ".", 2)[0]

	// Split on first "-" to get port and instanceID
	idx := strings.Index(label, "-")
	if idx < 0 {
		return 0, "", fmt.Errorf("proxy: host label %q has no '-' separator", label)
	}

	portStr := label[:idx]
	instanceID = label[idx+1:]

	if instanceID == "" {
		return 0, "", fmt.Errorf("proxy: empty instance ID in host %q", host)
	}

	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("proxy: invalid port %q in host %q", portStr, host)
	}

	return port, instanceID, nil
}
