// Package preview defines the shared publication-policy vocabulary used by
// the control plane, vmd, and edge proxy.
package preview

import "fmt"

const (
	// AccessLegacyPublic preserves the pre-publication behavior where every
	// listening non-privileged port is routable.
	AccessLegacyPublic = "legacy_public"
	// AccessPublic requires explicit publication; published ports route without
	// Superserve authentication.
	AccessPublic = "public"

	// HostCapabilityPorts is advertised by a vmd/proxy build that persists and
	// enforces the explicit published-port allowlist.
	HostCapabilityPorts = "preview_ports_v1"

	// Published preview ports exclude privileged ports and boxd's reserved
	// service port. Keeping this vocabulary shared prevents the API, VMD,
	// and durable schema from disagreeing about what can be published.
	MinPublishedPort int32 = 1024
	MaxPublishedPort int32 = 65535
	ReservedBoxdPort int32 = 49983

	// ProxyProtocolHeader marks local instance lookups made by a proxy that
	// understands and enforces HostCapabilityPorts. VMD withholds strict-policy
	// instances from callers that omit the marker so rolling the proxy back
	// cannot silently restore all-port routing.
	ProxyProtocolHeader = "X-Superserve-Proxy-Protocol"

	// VMDProtocolHeader attests that a successful local instance response came
	// from a VMD which understands preview publication. A new proxy requires this
	// response marker, so rolling VMD back cannot turn an omitted strict policy
	// into the legacy all-port representation.
	VMDProtocolHeader = "X-Superserve-VMD-Protocol"
)

// ValidatePublishedPort rejects ports which cannot be governed by the public
// preview allowlist.
func ValidatePublishedPort(port int32) error {
	if port < MinPublishedPort || port > MaxPublishedPort {
		return fmt.Errorf("port must be an integer in [%d, %d]", MinPublishedPort, MaxPublishedPort)
	}
	if port == ReservedBoxdPort {
		return fmt.Errorf("port %d is reserved for Superserve's sandbox service", ReservedBoxdPort)
	}
	return nil
}
