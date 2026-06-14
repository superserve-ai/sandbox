// Package egresspolicy holds egress-policy evaluation shared by the egress
// proxy and the secrets proxy, so both enforce one set of rules. It has no
// platform-specific dependencies.
package egresspolicy

import "net"

// DeniedCIDRs are private/internal IP ranges that sandboxes must never reach,
// regardless of user configuration. IPv6 entries cover the loopback, ULA, and
// link-local ranges for the resolve-then-dial check.
var DeniedCIDRs = []string{
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

var parsedDeniedNets []*net.IPNet

func init() {
	for _, cidr := range DeniedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid denied CIDR: " + cidr)
		}
		parsedDeniedNets = append(parsedDeniedNets, ipNet)
	}
}

// IsIPDenied reports whether ip falls within any always-denied range.
func IsIPDenied(ip net.IP) bool {
	for _, ipNet := range parsedDeniedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
