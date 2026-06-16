package network

import (
	"net"

	"github.com/superserve-ai/sandbox/internal/egresspolicy"
)

// DeniedCIDRs and IsIPDenied are defined in egresspolicy so both proxies share
// one source; re-exported here to keep the network package's callers unchanged.
var DeniedCIDRs = egresspolicy.DeniedCIDRs

// IsIPDenied reports whether an IP falls within any always-denied range.
func IsIPDenied(ip net.IP) bool { return egresspolicy.IsIPDenied(ip) }
