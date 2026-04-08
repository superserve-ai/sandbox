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

// boxdHostLabel is the reserved left-most label that addresses boxd's
// own HTTP endpoint on the edge proxy. We deliberately do NOT let
// callers reach boxd by typing its numeric port in the URL: boxd's
// internal port is an implementation detail of the VM and putting it
// in public URLs would (a) leak a magic number into every integration
// and (b) give the impression that the port itself is exposed, when
// in reality the proxy handles `boxd-...` traffic specially and never
// bounces arbitrary paths through to that port.
const boxdHostLabel = "boxd"

// ParseHost extracts the routing label and instanceID from a Host
// header of the form {label}-{instanceID}.{domain} and validates both.
//
// The label is either:
//
//   - the literal word "boxd", which maps to the boxd port
//     (boxdPort). This is the only way to address boxd through the
//     edge proxy; the numeric form is intentionally rejected.
//
//   - a decimal number in [1, 65535] above the privileged-port
//     threshold, which routes to that user-application port on the
//     VM.
//
// Returns ErrInvalidHost if the host doesn't end with the expected
// domain suffix, so the proxy rejects forged Host headers pointing at
// arbitrary backends.
func ParseHost(host, domain string) (port int, instanceID string, err error) {
	// Strip TCP port from Host if present (e.g. "boxd-abc.sandbox.superserve.ai:443")
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}

	// Validate domain suffix — prevents accepting any Host: label-id.attacker.com
	if !strings.HasSuffix(hostname, "."+domain) {
		return 0, "", fmt.Errorf("proxy: host %q does not end in .%s", hostname, domain)
	}

	// Take the leftmost label only: "boxd-abc123" or "3000-mybox"
	label, _, _ := strings.Cut(hostname, ".")

	// Split on the first "-" to separate the routing label from the
	// instance ID. Note: instance IDs themselves contain hyphens (UUIDs),
	// so we only split once.
	routing, instanceID, ok := strings.Cut(label, "-")
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

	// Reserved label for boxd.
	if routing == boxdHostLabel {
		return boxdPort, instanceID, nil
	}

	// Numeric label for user-application ports. We accept a decimal
	// in [1, 65535] but explicitly refuse the boxd port number — that
	// address form exists only under the "boxd" label.
	port, err = strconv.Atoi(routing)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("proxy: invalid label %q in host %q", routing, host)
	}
	if port == boxdPort {
		return 0, "", fmt.Errorf("proxy: boxd must be addressed as %q, not by port number", boxdHostLabel)
	}

	return port, instanceID, nil
}
