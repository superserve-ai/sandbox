package proxy

import (
	"fmt"
	"net/netip"
)

const PeerPort = 5009

// ValidatePeerEndpoint keeps listener and advertisement configuration aligned
// with ownership routing, which derives this fixed port from the registered IP.
func ValidatePeerEndpoint(addr string) error {
	endpoint, err := netip.ParseAddrPort(addr)
	if err != nil || !PrivateBind(addr) || endpoint.Port() != PeerPort {
		return fmt.Errorf("peer endpoint must be a concrete private IP on port %d: %q", PeerPort, addr)
	}
	return nil
}
