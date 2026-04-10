package proxy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// validInstanceID restricts instance IDs to alphanumeric + hyphen, max 64 chars.
// Prevents path traversal (%2f, ..) from reaching the VMD resolver URL.
var validInstanceID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)

// ParseHost extracts port and instanceID from a Host header of the form
// {port}-{instanceID}.{domain} and validates both fields.
//
// Returns ErrInvalidHost if the host doesn't end with the expected domain suffix,
// so the proxy rejects forged Host headers pointing at arbitrary backends.
func ParseHost(host, domain string) (port int, instanceID string, err error) {
	// Strip TCP port from Host if present (e.g. "49983-abc.sandbox.superserve.ai:443")
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}

	// Validate domain suffix — prevents accepting any Host: port-id.attacker.com
	if !strings.HasSuffix(hostname, "."+domain) {
		return 0, "", fmt.Errorf("proxy: host %q does not end in .%s", hostname, domain)
	}

	// Take the leftmost label only: "49983-abc123"
	label, _, _ := strings.Cut(hostname, ".")

	// Split on the first "-" to separate port from instance ID
	portStr, instanceID, ok := strings.Cut(label, "-")
	if !ok {
		return 0, "", fmt.Errorf("proxy: host label %q has no '-' separator", label)
	}

	if instanceID == "" {
		return 0, "", fmt.Errorf("proxy: empty instance ID in host %q", host)
	}

	// Validate charset — blocks path traversal and injection into VMD URL
	if !validInstanceID.MatchString(instanceID) {
		return 0, "", fmt.Errorf("proxy: instance ID %q contains invalid characters", instanceID)
	}

	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("proxy: invalid port %q in host %q", portStr, host)
	}

	return port, instanceID, nil
}
