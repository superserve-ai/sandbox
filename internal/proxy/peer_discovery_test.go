package proxy

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestPeerEndpointFromDiscovery(t *testing.T) {
	addr := "192.0.2.10:50051"
	peerAddr := "192.0.2.10:5009"
	generation := int64(42)
	row := db.GetSandboxPeerEndpointRow{HostID: "example-host", VmdAddr: &addr, ProxyAddr: &peerAddr, IncarnationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PeerGeneration: &generation}
	got, err := PeerEndpointFromDiscovery(row)
	if err != nil || got.Address != "192.0.2.10:5009" || got.Generation != 42 {
		t.Fatalf("endpoint = %+v, %v", got, err)
	}
	addr = "[2001:db8::10]:50051"
	peerAddr = "[2001:0db8::10]:5009"
	got, err = PeerEndpointFromDiscovery(row)
	if err != nil || got.Address != "[2001:db8::10]:5009" {
		t.Fatalf("IPv6 endpoint = %+v, %v", got, err)
	}
	for _, invalid := range []int64{0, -1} {
		generation = invalid
		if _, err := PeerEndpointFromDiscovery(row); err == nil {
			t.Fatal("invalid generation accepted")
		}
	}
	generation = 42
	row.IncarnationID.Valid = false
	if _, err := PeerEndpointFromDiscovery(row); err == nil {
		t.Fatal("unbound host accepted")
	}
	row.IncarnationID.Valid = true
	row.PeerGeneration = nil
	if _, err := PeerEndpointFromDiscovery(row); err == nil {
		t.Fatal("missing generation accepted")
	}
	row.PeerGeneration = &generation
	addr = "example.com:50051"
	if _, err := PeerEndpointFromDiscovery(row); err == nil {
		t.Fatal("non-IP accepted")
	}
}

func TestDiscoveredGenerationReusesAndRetiresConnection(t *testing.T) {
	addr := "192.0.2.10:50051"
	peerAddr := "192.0.2.10:5009"
	generation := int64(41)
	row := db.GetSandboxPeerEndpointRow{HostID: "example-host", VmdAddr: &addr, ProxyAddr: &peerAddr, IncarnationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PeerGeneration: &generation}
	var dials atomic.Int32
	pool := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	defer pool.Close()
	open := func() {
		t.Helper()
		endpoint, err := PeerEndpointFromDiscovery(row)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := pool.OpenStream(context.Background(), row.HostID, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		stream.Close()
	}
	open()
	open()
	if dials.Load() != 1 {
		t.Fatalf("same generation dialed %d times", dials.Load())
	}
	generation++
	open()
	if dials.Load() != 2 {
		t.Fatal("same-address incarnation transition reused old connection")
	}
}

func TestPeerEndpointFromDiscoveryRejectsMismatchedListener(t *testing.T) {
	addr := "192.0.2.10:50051"
	generation := int64(42)
	row := db.GetSandboxPeerEndpointRow{HostID: "example-host", VmdAddr: &addr, IncarnationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PeerGeneration: &generation}
	for _, listener := range []string{"", "192.0.2.10:5011", "192.0.2.11:5009", "192.0.2.11:5011", "192.0.2.10:5007", "example.com:5009", "0.0.0.0:5009", "192.0.2.10", "[2001:db8::10]:5009"} {
		t.Run(listener, func(t *testing.T) {
			row.ProxyAddr = &listener
			if endpoint, err := PeerEndpointFromDiscovery(row); err == nil || endpoint != (PeerEndpoint{}) {
				t.Fatalf("mismatched listener returned endpoint: %+v, %v", endpoint, err)
			}
		})
	}
	row.ProxyAddr = nil
	if _, err := PeerEndpointFromDiscovery(row); err == nil {
		t.Fatal("missing listener accepted")
	}
}

func TestPeerEndpointFromDiscoveryRecordedAddressValidation(t *testing.T) {
	for _, tc := range []struct {
		name, vmd, peer, want string
	}{
		{name: "unspecified IPv4", vmd: "0.0.0.0:50051", peer: "0.0.0.0:5009"},
		{name: "unspecified IPv6", vmd: "[::]:50051", peer: "[::]:5009"},
		{name: "loopback IPv4", vmd: "127.0.0.2:50051", peer: "127.0.0.2:5009"},
		{name: "loopback IPv6", vmd: "[::1]:50051", peer: "[::1]:5009"},
		{name: "mapped loopback", vmd: "[::ffff:127.0.0.1]:50051", peer: "127.0.0.1:5009"},
		{name: "mapped unspecified", vmd: "[::ffff:0.0.0.0]:50051", peer: "0.0.0.0:5009"},
		{name: "multicast", vmd: "224.0.0.1:50051", peer: "224.0.0.1:5009"},
		{name: "link local", vmd: "169.254.1.1:50051", peer: "169.254.1.1:5009"},
		{name: "IPv6 zone", vmd: "[2001:db8::10%eth0]:50051", peer: "[2001:db8::10]:5009"},
		{name: "zero port", vmd: "192.0.2.10:0", peer: "192.0.2.10:5009"},
		{name: "empty port", vmd: "192.0.2.10:", peer: "192.0.2.10:5009"},
		{name: "named port", vmd: "192.0.2.10:http", peer: "192.0.2.10:5009"},
		{name: "negative port", vmd: "192.0.2.10:-1", peer: "192.0.2.10:5009"},
		{name: "out of range port", vmd: "192.0.2.10:65536", peer: "192.0.2.10:5009"},
		{name: "missing port", vmd: "192.0.2.10", peer: "192.0.2.10:5009"},
		{name: "minimum port", vmd: "192.0.2.10:1", peer: "192.0.2.10:5009", want: "192.0.2.10:5009"},
		{name: "maximum port", vmd: "192.0.2.10:65535", peer: "192.0.2.10:5009", want: "192.0.2.10:5009"},
		{name: "private IPv4", vmd: "10.0.0.10:50051", peer: "10.0.0.10:5009", want: "10.0.0.10:5009"},
		{name: "mapped IPv4", vmd: "[::ffff:192.0.2.10]:50051", peer: "192.0.2.10:5009", want: "192.0.2.10:5009"},
		{name: "IPv6", vmd: "[2001:0db8::10]:50051", peer: "[2001:db8::10]:5009", want: "[2001:db8::10]:5009"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation := int64(42)
			row := db.GetSandboxPeerEndpointRow{HostID: "example-host", VmdAddr: &tc.vmd, ProxyAddr: &tc.peer, IncarnationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PeerGeneration: &generation}
			got, err := PeerEndpointFromDiscovery(row)
			if tc.want == "" {
				if err == nil || got != (PeerEndpoint{}) {
					t.Fatalf("invalid VMD address returned endpoint: %+v, %v", got, err)
				}
			} else if err != nil || got != (PeerEndpoint{Address: tc.want, Generation: 42}) {
				t.Fatalf("endpoint = %+v, %v; want %s generation 42", got, err, tc.want)
			}
		})
	}
}
