package network

import "net"

// DeniedCIDRs are private/internal IP ranges that sandboxes must never reach.
// These are always blocked regardless of user configuration.
var DeniedCIDRs = []string{
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// IPv6
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
