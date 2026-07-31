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
	// AccessPrivate requires explicit publication and keeps the port closed
	// to Phase 2 proxies. The database and public API continue to use this
	// literal value after token authentication is introduced.
	AccessPrivate = "private"
	// AccessPrivateTokenV1 is a wire-only per-port mode. It is emitted to VMD
	// only after the host has attested token enforcement and must never be
	// persisted as the database access value. Older VMD/proxy generations see
	// an unknown mode and therefore fail closed.
	AccessPrivateTokenV1 = "private_token_v1"
	// AccessPrivateBrowserV1 is the Phase 4 wire-only mode for private ports
	// whose host can consume browser query/cookie carriers as well as the Phase
	// 3 header carrier. Keeping it distinct from AccessPrivateTokenV1 makes a
	// proxy rollback fail closed instead of silently accepting a signed link it
	// does not know how to scrub or bootstrap.
	AccessPrivateBrowserV1 = "private_browser_v1"

	// HostCapabilityPorts is advertised by a vmd/proxy build that persists and
	// enforces the explicit published-port allowlist.
	HostCapabilityPorts = "preview_ports_v1"
	// HostCapabilityPortAccess is advertised only when the host persists and
	// enforces the independent access mode on each published port.
	HostCapabilityPortAccess = "preview_port_access_v1"
	// HostCapabilityPortTokens is advertised only when VMD and the live proxy
	// both enforce per-port token generations and the proxy has a valid HMAC
	// seed. It is intentionally separate from per-port access so private policy
	// cannot become active during a partial fleet rollout.
	HostCapabilityPortTokens = "preview_port_tokens_v1"
	// HostCapabilityPortBrowserAuth is advertised only when VMD and the live
	// proxy understand AccessPrivateBrowserV1, including secure cookie
	// bootstrap and complete credential scrubbing. It is additive to, and
	// depends on, HostCapabilityPortTokens.
	HostCapabilityPortBrowserAuth = "preview_port_browser_auth_v1"

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

	// ProxyCapabilitiesHeader additively identifies newer proxy enforcement
	// capabilities. ProxyProtocolHeader deliberately remains the exact Phase 1
	// value so a new proxy can still query an older VMD during a rolling deploy.
	ProxyCapabilitiesHeader = "X-Superserve-Proxy-Capabilities"

	// VMDProtocolHeader attests that a successful local instance response came
	// from a VMD which understands preview publication. A new proxy requires this
	// response marker, so rolling VMD back cannot turn an omitted strict policy
	// into the legacy all-port representation.
	VMDProtocolHeader = "X-Superserve-VMD-Protocol"
)

// IsTokenizedAccess reports whether a wire-only access mode carries an exact
// positive per-port token generation. Browser auth is an additive carrier set
// over the Phase 3 token primitive, so both modes share the same durable
// generation and policy watermark.
func IsTokenizedAccess(access string) bool {
	return access == AccessPrivateTokenV1 || access == AccessPrivateBrowserV1
}

// IsPrivateAccess reports whether a database/API private value or either
// fail-closed wire sentinel represents an authenticated private port.
func IsPrivateAccess(access string) bool {
	return access == AccessPrivate || IsTokenizedAccess(access)
}

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

// RestrictiveFallback returns the sandbox-level value safe to persist on the
// Phase 1-compatible wire. A Phase 1 reader ignores per-port access, so any
// effectively non-public port hardens a strict public fallback to private.
// Empty per-port access is a Phase 1 record and inherits the sandbox default.
// Unknown sandbox modes are preserved so every generation continues to treat
// them as unsupported rather than accidentally recognizing them as private.
func RestrictiveFallback(sandboxAccess string, portAccesses ...string) string {
	for _, access := range portAccesses {
		if access != "" && access != AccessPublic {
			switch sandboxAccess {
			case "", AccessLegacyPublic, AccessPublic, AccessPrivate:
				return AccessPrivate
			default:
				return sandboxAccess
			}
		}
	}
	switch sandboxAccess {
	case "", AccessLegacyPublic:
		return sandboxAccess
	case AccessPrivate:
		return AccessPrivate
	case AccessPublic:
		return AccessPublic
	default:
		return sandboxAccess
	}
}
