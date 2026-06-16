package egresspolicy

import (
	"net"
	"strings"
)

// MatchHost reports whether host matches pattern: an exact match or a
// `*.suffix` wildcard that matches subdomains at any depth (but not the bare
// domain). Used for egress allow/deny rules.
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
		suffix := p[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && host != suffix[1:] {
			return true
		}
	}
	return false
}

// MatchHostStrict is like MatchHost but the wildcard matches exactly one label,
// like DNS/TLS: `*.example.com` matches `api.example.com` but not
// `a.b.example.com`. Used for credential host matching.
func MatchHostStrict(host, pattern string) bool {
	host = strings.ToLower(host)
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return false
	}
	if p == host {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) {
			label := host[:len(host)-len(suffix)]
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
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
