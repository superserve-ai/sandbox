package blocklist

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/superserve-ai/sandbox/internal/abuse"
)

const miningStateHeader = "# private-mining-policy-state-v1\n"

// MiningMatch is used only on a separately configured private mining policy.
// Generic destination denials and customer rules must never call this path.
func (b *Blocklist) MiningMatch(hostname string, ip net.IP) (abuse.MiningEvidence, bool) {
	s := b.cur.Load()
	if s == nil {
		return abuse.MiningEvidence{}, false
	}
	h := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for h != "" {
		if _, ok := s.domains[h]; ok {
			return abuse.MiningEvidence{Kind: "domain", Indicator: h, PolicyRevision: s.revision}, true
		}
		_, parent, ok := strings.Cut(h, ".")
		if !ok {
			break
		}
		h = parent
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		for _, prefix := range s.nets {
			if prefix.Contains(addr.Unmap()) {
				return abuse.MiningEvidence{Kind: "ip", Indicator: prefix.String(), PolicyRevision: s.revision}, true
			}
		}
	}
	return abuse.MiningEvidence{}, false
}

func snapshotRevision(s *blocklistSnapshot) string {
	entries := make([]string, 0, len(s.domains)+len(s.nets))
	for d := range s.domains {
		entries = append(entries, "domain:"+d)
	}
	for _, p := range s.nets {
		entries = append(entries, "ip:"+p.String())
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}
