package proxy

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/superserve-ai/sandbox/internal/db"
)

// PeerEndpointFromDiscovery validates the prerequisite database seam. The
// forwarding consumer must carry this generation unchanged into OpenStream.
func PeerEndpointFromDiscovery(row db.GetSandboxPeerEndpointRow) (PeerEndpoint, error) {
	if row.HostID == "" || row.VmdAddr == nil || !row.IncarnationID.Valid || row.PeerGeneration == nil || *row.PeerGeneration <= 0 {
		return PeerEndpoint{}, fmt.Errorf("authoritative peer endpoint unavailable")
	}
	addr, err := netip.ParseAddrPort(*row.VmdAddr)
	if err != nil || addr.Port() == 0 || !addr.Addr().IsGlobalUnicast() || addr.Addr().IsLoopback() || addr.Addr().Zone() != "" {
		return PeerEndpoint{}, fmt.Errorf("invalid registered VMD address")
	}
	host := addr.Addr().Unmap().String()
	// The advertisement gates eligibility but cannot choose the destination.
	if row.ProxyAddr == nil {
		return PeerEndpoint{}, fmt.Errorf("registered peer listener unavailable")
	}
	peerHost, peerPort, err := net.SplitHostPort(*row.ProxyAddr)
	if err != nil || peerPort != "5009" || !net.ParseIP(host).Equal(net.ParseIP(peerHost)) {
		return PeerEndpoint{}, fmt.Errorf("registered peer listener must match the VMD IP on port 5009")
	}
	return PeerEndpoint{Address: net.JoinHostPort(host, "5009"), Generation: uint64(*row.PeerGeneration)}, nil
}
