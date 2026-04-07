package network

import "net"

// DeniedCIDRs are private/internal IP ranges that sandboxes must never reach.
// These are always blocked regardless of user configuration.
//
// The IPv4 entries are loaded into the nftables predefined deny set inside
// each sandbox namespace. The IPv6 entries are NOT loaded into nftables
// (our sets are IPv4-only; all v6 egress is dropped wholesale by a separate
// nfproto ipv6 drop rule) — they are kept here for the TCP egress proxy's
// DNS rebinding check, which verifies that a domain does not resolve to a
// link-local or loopback address before dialing upstream.
var DeniedCIDRs = []string{
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// IPv6 — used only by IsIPDenied (DNS rebinding check), not by nftables sets.
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// parsedDeniedNets is the parsed form of DeniedCIDRs for quick IP lookups.
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

// IsIPDenied checks if an IP falls within any of the always-denied ranges.
func IsIPDenied(ip net.IP) bool {
	for _, ipNet := range parsedDeniedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
