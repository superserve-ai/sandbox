package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/superserve-ai/sandbox/internal/auth"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// pushStdout / pushStderr enqueue non-PTY data events — these become
// channel-tagged binary frames on the exec/ws client side. (pushStart/pushEnd/
// inputs/signals live on fakeProcessService in terminal_test.go.)
func (f *fakeProcessService) pushStdout(data []byte) {
	f.events <- &pb.ProcessEvent{Event: &pb.ProcessEvent_Data{
		Data: &pb.DataEvent{Output: &pb.DataEvent_Stdout{Stdout: data}},
	}}
}

func (f *fakeProcessService) pushStderr(data []byte) {
	f.events <- &pb.ProcessEvent{Event: &pb.ProcessEvent_Data{
		Data: &pb.DataEvent{Output: &pb.DataEvent_Stderr{Stderr: data}},
	}}
}

type execWSTestEnv struct {
	t        *testing.T
	fake     *fakeProcessService
	clientWS *websocket.Conn
}

func newExecWSTestEnv(t *testing.T) *execWSTestEnv {
	t.Helper()
	fake := newFakeProcessService()

	path, handler := boxdpbconnect.NewProcessServiceHandler(fake)
	boxdMux := http.NewServeMux()
	boxdMux.Handle(path, handler)
	boxdSrv := httptest.NewUnstartedServer(h2c.NewHandler(boxdMux, &http2.Server{}))
	boxdSrv.EnableHTTP2 = true
	boxdSrv.Start()

	procClient := boxdpbconnect.NewProcessServiceClient(boxdSrv.Client(), boxdSrv.URL)

	h := &Handler{transports: newTransportCache(), log: zerolog.Nop()}
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
			CompressionMode:    websocket.CompressionDisabled,
		})
		if err != nil {
			t.Errorf("ws accept: %v", err)
			return
		}
		// Mirror serveExecWS so tests exercise the production frame limit,
		// not the library's much smaller default.
		ws.SetReadLimit(maxExecReadBytes)
		h.bridgeExecWS(r.Context(), ws, procClient, "sbx-test")
	}))

	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	clientWS, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}

	t.Cleanup(func() {
		_ = clientWS.Close(websocket.StatusNormalClosure, "cleanup")
		proxySrv.Close()
		boxdSrv.Close()
	})
	return &execWSTestEnv{t: t, fake: fake, clientWS: clientWS}
}

// sendStart pushes the StartEvent (so the bridge captures the PID) and writes
// the JSON start frame that names the command.
func (e *execWSTestEnv) sendStart(pid uint32, command string) {
	e.t.Helper()
	e.fake.pushStart(pid)
	cmd, _ := json.Marshal(command)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.clientWS.Write(ctx, websocket.MessageText, []byte(`{"command":`+string(cmd)+`}`)); err != nil {
		e.t.Fatalf("send start: %v", err)
	}
	// Let the bridge consume the start frame + StartEvent and enter the pump
	// loop before the test drives traffic.
	time.Sleep(100 * time.Millisecond)
}

func (e *execWSTestEnv) readEvent(ctx context.Context) execWSEvent {
	e.t.Helper()
	typ, data, err := e.clientWS.Read(ctx)
	if err != nil {
		e.t.Fatalf("client read: %v", err)
	}
	if typ != websocket.MessageText {
		e.t.Fatalf("frame type = %v, want Text", typ)
	}
	var ev execWSEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		e.t.Fatalf("unmarshal event: %v (raw %q)", err, data)
	}
	return ev
}

// readData reads one binary output frame and returns its channel byte and
// payload. Fails if the next frame isn't binary.
func (e *execWSTestEnv) readData(ctx context.Context) (byte, []byte) {
	e.t.Helper()
	typ, data, err := e.clientWS.Read(ctx)
	if err != nil {
		e.t.Fatalf("client read: %v", err)
	}
	if typ != websocket.MessageBinary {
		e.t.Fatalf("frame type = %v, want Binary", typ)
	}
	if len(data) == 0 {
		e.t.Fatalf("binary frame missing channel byte")
	}
	return data[0], data[1:]
}

// TestExecWSStart_RequestsStdin guards that the WS bridge requests an
// interactive stdin pipe (build steps and one-shot execs don't).
func TestExecWSStart_RequestsStdin(t *testing.T) {
	if got := (&execWSStart{Command: "cat"}).toStartRequest().GetStdin(); !got {
		t.Errorf("toStartRequest().Stdin = false, want true (interactive)")
	}
}

func TestExecWS_StdoutForwarded(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "echo hi")
	env.fake.pushStdout([]byte("hello\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, payload := env.readData(ctx)
	if ch != execChStdout {
		t.Errorf("channel = %d, want %d (stdout)", ch, execChStdout)
	}
	if string(payload) != "hello\n" {
		t.Errorf("stdout = %q, want %q", payload, "hello\n")
	}
}

// TestExecWS_BinaryStdoutIsByteExact guards the whole point of the binary
// framing: non-UTF-8 output survives the round trip unmangled.
func TestExecWS_BinaryStdoutIsByteExact(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "cat image.png")
	raw := []byte{0x00, 0xff, 0xfe, 0x80, 0x01}
	env.fake.pushStdout(raw)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, payload := env.readData(ctx)
	if ch != execChStdout {
		t.Errorf("channel = %d, want %d (stdout)", ch, execChStdout)
	}
	if !bytes.Equal(payload, raw) {
		t.Errorf("stdout = %v, want %v (binary must be byte-exact)", payload, raw)
	}
}

func TestExecWS_StderrForwarded(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "ls /nope")
	env.fake.pushStderr([]byte("no such file\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, payload := env.readData(ctx)
	if ch != execChStderr {
		t.Errorf("channel = %d, want %d (stderr)", ch, execChStderr)
	}
	if string(payload) != "no such file\n" {
		t.Errorf("stderr = %q, want %q", payload, "no such file\n")
	}
}

func TestExecWS_EndClosesWithExitCode(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "false")
	env.fake.pushEnd(3)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ev := env.readEvent(ctx)
	if ev.ExitCode == nil || *ev.ExitCode != 3 {
		t.Fatalf("exit_code = %v, want 3", ev.ExitCode)
	}
	if !ev.Finished {
		t.Errorf("finished = false, want true")
	}
	// The bridge should close the WS right after the final event.
	if _, _, err := env.clientWS.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("close status = %d, want NormalClosure", websocket.CloseStatus(err))
	}
}

func TestExecWS_BinaryFrameIsStdin(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "cat")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Stdin rides channel 0; the payload follows the channel byte.
	if err := env.clientWS.Write(ctx, websocket.MessageBinary, append([]byte{execChStdin}, "piped input"...)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-env.fake.inputs:
		if string(got.Data) != "piped input" {
			t.Errorf("SendInput.Data = %q, want %q", got.Data, "piped input")
		}
		if got.Pid != 7 {
			t.Errorf("SendInput.Pid = %d, want 7", got.Pid)
		}
		if got.Eof {
			t.Errorf("Eof = true, want false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SendInput")
	}
}

// TestExecWS_LargeStdinFrameForwarded guards the exec socket's frame budget:
// a stdin frame well past the terminal bridge's 64 KiB keystroke limit must
// reach boxd intact, since exec frames carry command payloads, not keystrokes.
func TestExecWS_LargeStdinFrameForwarded(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "cat")

	payload := bytes.Repeat([]byte("x"), 128*1024)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := env.clientWS.Write(ctx, websocket.MessageBinary, append([]byte{execChStdin}, payload...)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-env.fake.inputs:
		if !bytes.Equal(got.Data, payload) {
			t.Errorf("SendInput.Data = %d bytes, want %d intact", len(got.Data), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SendInput — large frame likely rejected by read limit")
	}
}

// TestExecWS_OversizedFrameClosesTooBig pins the failure mode when a client
// exceeds maxExecReadBytes: the bridge closes with StatusMessageTooBig so the
// client sees why, instead of an unexplained drop.
func TestExecWS_OversizedFrameClosesTooBig(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "cat")

	payload := bytes.Repeat([]byte("x"), maxExecReadBytes+2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := env.clientWS.Write(ctx, websocket.MessageBinary, append([]byte{execChStdin}, payload...)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	for {
		_, _, err := env.clientWS.Read(ctx)
		if err == nil {
			continue // drain any in-flight frames until the close arrives
		}
		if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
			t.Fatalf("close status = %v (err %v), want StatusMessageTooBig", got, err)
		}
		return
	}
}

func TestExecWS_StdinClose(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "cat")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// {type:"stdin_close"} sends EOF.
	if err := env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"type":"stdin_close"}`)); err != nil {
		t.Fatalf("write stdin_close: %v", err)
	}
	gotClose := <-env.fake.inputs
	if !gotClose.Eof {
		t.Errorf("stdin_close Eof = false, want true")
	}
}

func TestExecWS_SignalForwarded(t *testing.T) {
	env := newExecWSTestEnv(t)
	env.sendStart(7, "sleep 100")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"type":"signal","name":"SIGTERM"}`)); err != nil {
		t.Fatalf("write signal: %v", err)
	}

	select {
	case got := <-env.fake.signals:
		if got.Signal != 15 { // SIGTERM
			t.Errorf("Signal = %d, want 15 (SIGTERM)", got.Signal)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Signal")
	}
}

// TestServeExecWS_ForeignOriginAccepted goes through the full serveExecWS
// handler and verifies that a connection from an origin NOT in the terminal
// allowlist is still accepted — exec/ws is gated by the access token, not by
// Origin, so customer apps on their own domains can connect.
func TestServeExecWS_ForeignOriginAccepted(t *testing.T) {
	fake := newFakeProcessService()
	path, handler := boxdpbconnect.NewProcessServiceHandler(fake)
	boxdMux := http.NewServeMux()
	boxdMux.Handle(path, handler)
	boxdSrv := httptest.NewUnstartedServer(h2c.NewHandler(boxdMux, &http2.Server{}))
	boxdSrv.EnableHTTP2 = true
	boxdSrv.Start()
	defer boxdSrv.Close()

	seedKey := []byte("test-seed-key-that-is-at-least-32-bytes-long!!")
	sandboxID := "sbx-execws-origin"
	domain := "sandbox.test"

	upURL, _ := url.Parse(boxdSrv.URL)
	resolver := &stubResolver{
		info: InstanceInfo{
			VMIP:      upURL.Hostname(),
			Status:    "running",
			StartedAt: time.Now().UnixNano(),
		},
	}

	h := NewHandler([]string{domain}, resolver, zerolog.Nop())
	// Deliberately restrict the terminal allowlist to a console origin —
	// exec/ws must ignore it and accept a different (customer) origin.
	h.WithAuth(seedKey).WithExec().WithTerminal([]string{"https://console.example.com"})

	upHost := upURL.Host
	h.transports = &transportCache{items: map[string]*transportEntry{}}
	h.transports.items[sandboxID] = &transportEntry{
		lifecycleKey: resolver.info.lifecycleKey(),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, upHost)
			},
			DisableKeepAlives: true,
		},
		lastUsed: time.Now(),
	}

	host := "boxd-" + sandboxID + "." + domain
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = host
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	token := auth.ComputeAccessToken(seedKey, sandboxID)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/exec/connect"

	fake.pushStart(99)
	fake.pushStdout([]byte("from a foreign origin\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader:   http.Header{"Origin": []string{"https://customer.example.com"}},
		Subprotocols: []string{execProtocol, "token." + token},
	})
	if err != nil {
		t.Fatalf("exec/ws dial from a foreign origin should succeed, got: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "done")

	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"command":"echo hi"}`)); err != nil {
		t.Fatalf("write start: %v", err)
	}
	typ, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("frame type = %v, want Binary", typ)
	}
	if len(data) == 0 || data[0] != execChStdout {
		t.Fatalf("frame channel = %v, want stdout", data)
	}
	if string(data[1:]) != "from a foreign origin\n" {
		t.Errorf("stdout = %q, want %q", data[1:], "from a foreign origin\n")
	}
}

func TestExecWS_PingKeepsLiveSessionAlive(t *testing.T) {
	old := execPingInterval
	execPingInterval = 50 * time.Millisecond
	t.Cleanup(func() { execPingInterval = old })

	env := newExecWSTestEnv(t)
	env.sendStart(7, "long-running")

	// Emit output only after several ping cycles have elapsed. The client is
	// blocked in Read below (so it auto-pongs), so the session must survive
	// the pings and still deliver the output.
	go func() {
		time.Sleep(300 * time.Millisecond)
		env.fake.pushStdout([]byte("still here\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, payload := env.readData(ctx)
	if ch != execChStdout || string(payload) != "still here\n" {
		t.Errorf("got channel %d %q, want stdout %q (session should survive pings)", ch, payload, "still here\n")
	}
}

// TestExecWS_StreamErrorIsGenericized verifies that a boxd/connection error
// (which can contain internal addresses) is NOT surfaced verbatim to the
// client — only a generic message is sent.
func TestExecWS_StreamErrorIsGenericized(t *testing.T) {
	fake := newFakeProcessService()
	fake.startErr = errors.New("dial tcp 10.0.0.5:49983: connection refused")

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
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
			CompressionMode:    websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		h.bridgeExecWS(r.Context(), ws, procClient, "sbx")
	}))
	defer proxySrv.Close()

	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "done")

	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"command":"echo hi"}`)); err != nil {
		t.Fatalf("write start: %v", err)
	}

	typ, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("frame type = %v, want Text error event", typ)
	}
	var ev execWSEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(ev.Error, "10.0.0.5") || strings.Contains(ev.Error, "49983") {
		t.Errorf("internal address leaked to client: %q", ev.Error)
	}
	if ev.Error != "the command failed to run" {
		t.Errorf("error = %q, want generic message", ev.Error)
	}
}

func TestExecWS_InvalidStartClosesWS(t *testing.T) {
	env := newExecWSTestEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Empty command must be rejected before any process starts.
	if err := env.clientWS.Write(ctx, websocket.MessageText, []byte(`{"command":""}`)); err != nil {
		t.Fatalf("write start: %v", err)
	}

	if _, _, err := env.clientWS.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Errorf("close status = %d, want PolicyViolation", websocket.CloseStatus(err))
	}
}
