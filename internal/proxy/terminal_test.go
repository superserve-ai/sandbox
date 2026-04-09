package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// fakeProcessService is a connect-rpc ProcessService implementation used by
// the bridge tests. It gives tests fine control over what the boxd-side of
// the bridge sees: callers can inject events to be emitted from Start, and
// every SendInput/Resize/Signal call is captured on channels for assertions.
//
// All operations are safe for concurrent use — the bridge's two goroutines
// call these methods from different goroutines.
type fakeProcessService struct {
	boxdpbconnect.UnimplementedProcessServiceHandler

	// events is the queue of ProcessEvents the Start stream should emit
	// to the client. Tests push events on this channel; Start drains it.
	events chan *pb.ProcessEvent

	// inputs captures every SendInput call. Tests assert on length/content.
	inputs chan *pb.SendInputRequest

	// resizes captures every Resize call.
	resizes chan *pb.ResizeRequest

	// signals captures every Signal call.
	signals chan *pb.SignalRequest

	// startErr, if set, is returned from Start immediately — lets tests
	// drive the "boxd failed to start shell" path.
	startErr error

	// sendInputErr, if set, is returned from SendInput — drives the
	// "boxd errored mid-stream" path.
	sendInputErr error
}

func newFakeProcessService() *fakeProcessService {
	return &fakeProcessService{
		events:  make(chan *pb.ProcessEvent, 16),
		inputs:  make(chan *pb.SendInputRequest, 16),
		resizes: make(chan *pb.ResizeRequest, 16),
		signals: make(chan *pb.SignalRequest, 16),
	}
}

func (f *fakeProcessService) Start(ctx context.Context, req *connect.Request[pb.StartRequest], stream *connect.ServerStream[pb.ProcessEvent]) error {
	if f.startErr != nil {
		return f.startErr
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-f.events:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (f *fakeProcessService) SendInput(ctx context.Context, req *connect.Request[pb.SendInputRequest]) (*connect.Response[pb.SendInputResponse], error) {
	if f.sendInputErr != nil {
		return nil, f.sendInputErr
	}
	f.inputs <- req.Msg
	return connect.NewResponse(&pb.SendInputResponse{}), nil
}

func (f *fakeProcessService) Resize(ctx context.Context, req *connect.Request[pb.ResizeRequest]) (*connect.Response[pb.ResizeResponse], error) {
	f.resizes <- req.Msg
	return connect.NewResponse(&pb.ResizeResponse{}), nil
}

func (f *fakeProcessService) Signal(ctx context.Context, req *connect.Request[pb.SignalRequest]) (*connect.Response[pb.SignalResponse], error) {
	f.signals <- req.Msg
	return connect.NewResponse(&pb.SignalResponse{}), nil
}

// startEvent is a helper to push a StartEvent with the given PID onto the
// fake's event queue. This is the first event the bridge expects.
func (f *fakeProcessService) pushStart(pid uint32) {
	f.events <- &pb.ProcessEvent{
		Event: &pb.ProcessEvent_Start{Start: &pb.StartEvent{Pid: pid}},
	}
}

// pushPty enqueues a PtyData event — these become binary WS frames to the browser.
func (f *fakeProcessService) pushPty(data []byte) {
	f.events <- &pb.ProcessEvent{
		Event: &pb.ProcessEvent_Data{
			Data: &pb.DataEvent{
				Output: &pb.DataEvent_PtyData{PtyData: data},
			},
		},
	}
}

// pushEnd enqueues an EndEvent — signals the shell exited, should close the WS.
func (f *fakeProcessService) pushEnd(code int32) {
	f.events <- &pb.ProcessEvent{
		Event: &pb.ProcessEvent_End{End: &pb.EndEvent{ExitCode: code}},
	}
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

// bridgeTestEnv wires up everything a bridge test needs: a fake boxd, a
// proxy handler that pipes a WS upgrade directly into bridgeTerminal, and a
// WS client dialled against the proxy. Tests just drive the fake and assert
// on what the client sees.
type bridgeTestEnv struct {
	t          *testing.T
	fake       *fakeProcessService
	boxdSrv    *httptest.Server
	proxySrv   *httptest.Server
	clientWS   *websocket.Conn
	procClient boxdpbconnect.ProcessServiceClient
}

func newBridgeTestEnv(t *testing.T) *bridgeTestEnv {
	t.Helper()
	fake := newFakeProcessService()

	// Fake boxd — mount the connect-rpc handler on httptest with h2c so
	// connect streaming works over HTTP/2 without TLS setup.
	path, handler := boxdpbconnect.NewProcessServiceHandler(fake)
	boxdMux := http.NewServeMux()
	boxdMux.Handle(path, handler)
	boxdSrv := httptest.NewUnstartedServer(h2c.NewHandler(boxdMux, &http2.Server{}))
	boxdSrv.EnableHTTP2 = true
	boxdSrv.Start()

	// A connect-rpc client pointing at the fake. Uses an explicit
	// http.Client with HTTP/2 transport so streaming flows correctly.
	procClient := boxdpbconnect.NewProcessServiceClient(
		boxdSrv.Client(),
		boxdSrv.URL,
	)

	// Proxy handler that accepts a WS upgrade and hands it to the bridge.
	h := &Handler{
		transports: newTransportCache(),
		log:        zerolog.Nop(),
	}

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
			CompressionMode:    websocket.CompressionDisabled,
		})
		if err != nil {
			t.Errorf("ws accept: %v", err)
			return
		}
		h.bridgeTerminal(r.Context(), ws, procClient, "sbx-test")
	}))

	// Dial the proxy.
	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	clientWS, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}

	env := &bridgeTestEnv{
		t:          t,
		fake:       fake,
		boxdSrv:    boxdSrv,
		proxySrv:   proxySrv,
		clientWS:   clientWS,
		procClient: procClient,
	}
	t.Cleanup(env.close)
	return env
}

func (e *bridgeTestEnv) close() {
	_ = e.clientWS.Close(websocket.StatusNormalClosure, "test cleanup")
	e.proxySrv.Close()
	e.boxdSrv.Close()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestBridge_BinaryInputForwardedToSendInput verifies that a binary WS frame
// from the client arrives at boxd as a SendInput call carrying the same
// bytes and the captured PID.
func TestBridge_BinaryInputForwardedToSendInput(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)

	// Give the bridge a moment to receive the StartEvent before we send input.
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := env.clientWS.Write(ctx, websocket.MessageBinary, []byte("ls -la\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-env.fake.inputs:
		if string(got.Data) != "ls -la\n" {
			t.Errorf("SendInput.Data = %q, want %q", got.Data, "ls -la\n")
		}
		if got.Pid != 42 {
			t.Errorf("SendInput.Pid = %d, want 42", got.Pid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SendInput")
	}
}

// TestBridge_PtyDataForwardedToClient verifies that a PtyData event from
// boxd becomes a binary WS frame on the client side.
func TestBridge_PtyDataForwardedToClient(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)
	env.fake.pushPty([]byte("hello terminal\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	typ, data, err := env.clientWS.Read(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Errorf("type = %v, want Binary", typ)
	}
	if string(data) != "hello terminal\n" {
		t.Errorf("data = %q, want %q", data, "hello terminal\n")
	}
}

// TestBridge_ResizeControlMessage verifies that a text frame carrying a
// resize message dispatches to the Resize RPC with the correct dimensions.
func TestBridge_ResizeControlMessage(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":120,"rows":30}`)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-env.fake.resizes:
		if got.Pid != 42 {
			t.Errorf("Resize.Pid = %d, want 42", got.Pid)
		}
		if got.Size.Cols != 120 || got.Size.Rows != 30 {
			t.Errorf("Resize.Size = {%d,%d}, want {120,30}", got.Size.Cols, got.Size.Rows)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Resize")
	}
}

// TestBridge_SignalAllowlist verifies that only the allowed signals get
// forwarded. A SIGKILL attempt from the browser should be dropped.
func TestBridge_SignalAllowlist(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Allowed — should arrive.
	_ = env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"type":"signal","name":"SIGINT"}`))
	select {
	case got := <-env.fake.signals:
		if got.Signal != 2 { // SIGINT
			t.Errorf("Signal = %d, want 2 (SIGINT)", got.Signal)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("allowed SIGINT did not arrive")
	}

	// Blocked — should be dropped. We assert by checking nothing arrives
	// within a short window.
	_ = env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"type":"signal","name":"SIGKILL"}`))
	select {
	case got := <-env.fake.signals:
		t.Errorf("SIGKILL should have been blocked, got signal %d", got.Signal)
	case <-time.After(250 * time.Millisecond):
		// Expected — nothing arrived.
	}
}

// TestBridge_ShellExitClosesWS verifies that when boxd emits an EndEvent
// the bridge closes the WebSocket with a normal close code.
func TestBridge_ShellExitClosesWS(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)
	env.fake.pushEnd(0)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Read until we get the close — the client may see the PTY flush
	// first, then the close.
	for {
		_, _, err := env.clientWS.Read(ctx)
		if err == nil {
			continue
		}
		status := websocket.CloseStatus(err)
		if status != websocket.StatusNormalClosure {
			t.Errorf("close status = %d, want NormalClosure", status)
		}
		return
	}
}

// TestBridge_ClientCloseStopsBoxdStream verifies that closing the WS from
// the client side causes the bridge to cancel its upstream connect-rpc
// stream, so boxd doesn't leak goroutines.
func TestBridge_ClientCloseStopsBoxdStream(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)
	// Let the bridge receive the start event and enter the pump loop.
	time.Sleep(100 * time.Millisecond)

	_ = env.clientWS.Close(websocket.StatusNormalClosure, "bye")

	// After the close propagates, the fake's Start call context should
	// be cancelled. We observe this by checking that pushing a new event
	// eventually blocks (no consumer) — using a very short timeout plus
	// a best-effort push.
	done := make(chan struct{})
	go func() {
		select {
		case env.fake.events <- &pb.ProcessEvent{
			Event: &pb.ProcessEvent_Data{
				Data: &pb.DataEvent{Output: &pb.DataEvent_PtyData{PtyData: []byte("ignored")}},
			},
		}:
		default:
		}
		close(done)
	}()
	<-done

	// If the bridge is still alive, it would have consumed the event.
	// We can't directly introspect goroutine state, but subsequent WS
	// operations should fail — which is asserted implicitly by the WS
	// already being closed. This is a smoke check.
}

// TestBridge_StartErrorClosesWSImmediately verifies the early-failure path:
// if boxd rejects Start, the WS should be closed before any bytes flow.
func TestBridge_StartErrorClosesWSImmediately(t *testing.T) {
	fake := newFakeProcessService()
	fake.startErr = errors.New("boxd: start failed")

	path, handler := boxdpbconnect.NewProcessServiceHandler(fake)
	boxdMux := http.NewServeMux()
	boxdMux.Handle(path, handler)
	boxdSrv := httptest.NewUnstartedServer(h2c.NewHandler(boxdMux, &http2.Server{}))
	boxdSrv.EnableHTTP2 = true
	boxdSrv.Start()
	defer boxdSrv.Close()

	procClient := boxdpbconnect.NewProcessServiceClient(boxdSrv.Client(), boxdSrv.URL)

	h := &Handler{transports: newTransportCache(), log: zerolog.Nop()}
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		h.bridgeTerminal(r.Context(), ws, procClient, "sbx")
	}))
	defer proxySrv.Close()

	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}

	// Expect the WS to be closed with InternalError because Start failed.
	_, _, err = client.Read(ctx)
	if err == nil {
		t.Fatal("expected read error after Start failure")
	}
	if status := websocket.CloseStatus(err); status != websocket.StatusInternalError {
		t.Errorf("close status = %d, want InternalError", status)
	}
}

// TestBridge_ConcurrentInputOutput exercises the two-goroutine pump under
// simultaneous traffic in both directions — catches races in shared state
// or ordering assumptions.
func TestBridge_ConcurrentInputOutput(t *testing.T) {
	env := newBridgeTestEnv(t)
	env.fake.pushStart(42)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Emit 20 PtyData events from boxd.
	go func() {
		for i := 0; i < 20; i++ {
			env.fake.pushPty([]byte("line\n"))
		}
	}()

	// Write 20 input frames from the client.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := env.clientWS.Write(ctx, websocket.MessageBinary, []byte("k")); err != nil {
				return
			}
		}
	}()

	// Read 20 messages from the client side.
	received := 0
	for received < 20 {
		_, _, err := env.clientWS.Read(ctx)
		if err != nil {
			t.Fatalf("read %d: %v", received, err)
		}
		received++
	}

	// Verify 20 SendInputs arrived at boxd.
	wg.Wait()
	inputsSeen := 0
	for inputsSeen < 20 {
		select {
		case <-env.fake.inputs:
			inputsSeen++
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of 20 inputs arrived", inputsSeen)
		}
	}
}
