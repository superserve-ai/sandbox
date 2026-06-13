package egresspolicy

import (
	"net"
	"strings"
)

// MatchHost reports whether host matches pattern: an exact match or a
// `*.suffix` wildcard.
func MatchHost(host, pattern string) bool {
	host = strings.ToLower(host)
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return false
	}
	if p == host {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".suffix"
		if strings.HasSuffix(host, suffix) && host != suffix[1:] {
			return true
		}
	}
	return false
}

// HasCIDR reports whether any entry is an IP or CIDR rather than a domain, so
// the caller knows it must resolve the host before evaluating.
func HasCIDR(entries []string) bool {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if _, _, err := net.ParseCIDR(e); err == nil {
			return true
		}
		if net.ParseIP(e) != nil {
			return true
		}
	}
	return false
}

// EvalEgress applies allow → deny → unmatched-host-policy. CIDR/IP entries are
// matched against ip (a nil ip never matches one); domain entries against host.
func EvalEgress(host string, ip net.IP, allow, deny []string, unmatchedPolicy string) (allowed bool, reason string) {
	host = strings.ToLower(host)
	for _, a := range allow {
		if entryMatches(a, host, ip) {
			return true, ""
		}
	}
	for _, d := range deny {
		if entryMatches(d, host, ip) {
			return false, "host_denied"
		}
	}
	if len(allow) > 0 {
		return false, "host_not_allowed"
	}
	if unmatchedPolicy == "deny" {
		return false, "unmatched_host_denied"
	}
	return true, ""
}

func entryMatches(entry, host string, ip net.IP) bool {
	entry = strings.TrimSpace(entry)
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return ip != nil && ipNet.Contains(ip)
	}
	if eip := net.ParseIP(entry); eip != nil {
		return ip != nil && eip.Equal(ip)
	}
	return MatchHost(host, entry)
}
