package gateway

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func gwSock(t *testing.T, tag string) string {
	t.Helper()
	p := fmt.Sprintf("/tmp/gw-%s-%d.sock", tag, os.Getpid())
	os.Remove(p)
	t.Cleanup(func() { os.Remove(p) })
	return p
}

// A real health service behind the gateway exercises the transparent director
// end to end: unary (Check), server-streaming (Watch), metadata propagation,
// and the quiesce refusal — without the gateway compiling in any proto.
func TestGatewayTransparentProxy(t *testing.T) {
	backendSock := gwSock(t, "be")
	frontSock := gwSock(t, "fe")

	// Backend records incoming metadata so we can assert it survives the hop.
	var mdMu sync.Mutex
	var sawTest []string
	bl, err := net.Listen("unix", backendSock)
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	backend := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				mdMu.Lock()
				sawTest = md.Get("x-test")
				mdMu.Unlock()
			}
			return h(ctx, req)
		}))
	hs := health.NewServer()
	hs.SetServingStatus("svc", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(backend, hs)
	go backend.Serve(bl)
	defer backend.Stop()

	// Gateway in front, pointed at the backend.
	gw := New()
	gw.Router().SetActive(Upstream{Generation: "A", GRPCSocket: backendSock})
	defer gw.Close()
	fl, err := net.Listen("unix", frontSock)
	if err != nil {
		t.Fatalf("front listen: %v", err)
	}
	gs := gw.GRPCServer()
	go gs.Serve(fl)
	defer gs.Stop()

	cc, err := grpc.NewClient("unix://"+frontSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer cc.Close()
	client := healthpb.NewHealthClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Unary + metadata.
	resp, err := client.Check(
		metadata.NewOutgoingContext(ctx, metadata.Pairs("x-test", "1")),
		&healthpb.HealthCheckRequest{Service: "svc"})
	if err != nil {
		t.Fatalf("Check through gateway: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Check status = %v, want SERVING", resp.Status)
	}
	mdMu.Lock()
	got := sawTest
	mdMu.Unlock()
	if len(got) != 1 || got[0] != "1" {
		t.Fatalf("backend saw x-test = %v, want [1] (metadata not forwarded)", got)
	}

	// Server-streaming: Watch delivers the initial status then an update.
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	ws, err := client.Watch(wctx, &healthpb.HealthCheckRequest{Service: "svc"})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	first, err := ws.Recv()
	if err != nil || first.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Watch first = %v, %v; want SERVING", first, err)
	}
	hs.SetServingStatus("svc", healthpb.HealthCheckResponse_NOT_SERVING)
	second, err := ws.Recv()
	if err != nil || second.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("Watch update = %v, %v; want NOT_SERVING", second, err)
	}

	// Quiesce → retryable Unavailable.
	gw.Router().QuiesceGRPC(true)
	_, err = client.Check(ctx, &healthpb.HealthCheckRequest{Service: "svc"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Check while quiescing = %v, want Unavailable", err)
	}

	// Resume → serving again.
	gw.Router().QuiesceGRPC(false)
	if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: "svc"}); err != nil {
		t.Fatalf("Check after resume: %v", err)
	}
}
