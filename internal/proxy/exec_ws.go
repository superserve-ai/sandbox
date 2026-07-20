package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

const (
	// execConnectPath is the full-duplex counterpart to /exec/stream:
	// stdout/stderr/exit frames downstream, stdin upstream, over one socket.
	execConnectPath = "/exec/connect"

	// execProtocol is echoed on upgrade. Bump the version if the frame format
	// changes so old clients fail loudly.
	execProtocol = "superserve.exec.v1"

	// execMaxSessionDuration is the hard session ceiling; reaching it kills the
	// running command. Longer than the terminal's — agent runs are longer-lived.
	execMaxSessionDuration = 12 * time.Hour

	// I/O rides binary frames tagged with a one-byte channel, so output stays
	// byte-exact rather than being forced through a UTF-8 string.
	execChStdin  = 0x00
	execChStdout = 0x01
	execChStderr = 0x02

	// maxExecReadBytes bounds a single client frame on the exec socket. Exec
	// frames legitimately carry a whole command string (start frame) or a
	// stdin chunk — unlike the terminal's keystroke-sized maxReadBytes — so
	// this is sized for payloads, not keystrokes, while still capping what a
	// single frame can make the bridge buffer. The SDKs chunk stdin at
	// 32 KiB; never lower this below that or chunked stdin starts dying
	// with 1009 closes.
	maxExecReadBytes = 4 << 20
)

// execPingInterval is how often the bridge pings the client; a missed pong
// (within writeWait) tears the session down. Liveness is thus decoupled from
// output, so a quiet-but-running command isn't cut. A var so tests can shorten it.
var execPingInterval = 30 * time.Second

// firstFrameWait bounds how long we wait for the client's start frame before
// giving up, so a connection that upgrades but never sends one can't pin a
// goroutine.
const firstFrameWait = 10 * time.Second

// execWSStart is the first (text) frame: the command to run. Mirrors the
// /exec request body so one payload shape works across all transports.
type execWSStart struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	TimeoutS   int               `json:"timeout_s,omitempty"`
}

// execWSControl is a post-start client text frame. Binary frames carry I/O
// (channel 0 = stdin); text frames are JSON control, discriminated by Type.
type execWSControl struct {
	Type string `json:"type"`           // "stdin_close" | "signal"
	Name string `json:"name,omitempty"` // signal name when Type == "signal"
}

// execWSEvent is a server→client text frame for lifecycle and errors. Output
// itself rides binary frames, not this struct.
type execWSEvent struct {
	ExitCode *int32 `json:"exit_code,omitempty"`
	Finished bool   `json:"finished,omitempty"`
	Error    string `json:"error,omitempty"`
	Code     string `json:"code,omitempty"`
}

// toStartRequest builds the boxd StartRequest. No args → run as a shell string
// (/bin/sh -c); args → run raw, matching the /exec contract.
//
// An absent timeout means no per-command timeout (unlike /exec's 30s default):
// the long-lived session is bounded by the ping and max-session cap instead.
func (s *execWSStart) toStartRequest() *pb.StartRequest {
	var timeoutMs uint32
	if s.TimeoutS > 0 {
		timeoutMs = uint32(s.TimeoutS) * 1000
	}
	cmd, args := s.Command, s.Args
	if len(args) == 0 {
		cmd = "/bin/sh"
		args = []string{"-c", s.Command}
	}
	return &pb.StartRequest{
		Cmd:       cmd,
		Args:      args,
		Envs:      s.Env,
		Cwd:       s.WorkingDir,
		TimeoutMs: timeoutMs,
		Stdin:     true, // interactive
	}
}

// serveExecWS upgrades GET /exec/connect to a WebSocket and bridges it full-duplex
// to boxd ProcessService.Start (non-PTY). Pre-upgrade errors are HTTP
// responses; after upgrade they're WebSocket close frames.
func (h *Handler) serveExecWS(w http.ResponseWriter, r *http.Request, instanceID string) {
	// Token-gated like /exec and /files — no Origin allowlist, since customer
	// apps run on their own domains.
	if !h.execEnabled {
		http.NotFound(w, r)
		return
	}

	// Token rides in Sec-WebSocket-Protocol, never the URL. Scrub any query
	// and discourage Referer leakage, matching the terminal bridge.
	r.URL.RawQuery = ""
	w.Header().Set("Referrer-Policy", "no-referrer")

	token := extractTerminalToken(r)
	if token == "" {
		http.Error(w, "missing token (pass as Sec-WebSocket-Protocol: token.<value>)", http.StatusUnauthorized)
		return
	}

	info, fail := h.authorizeSandboxRequest(r.Context(), token, instanceID)
	if fail != nil {
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg("exec/ws: auth failed")
		fail.write(w)
		return
	}
	h.captureUsage(instanceID, "command_run", info)

	acceptOpts := &websocket.AcceptOptions{
		// Any origin: the token is the control. Auth isn't ambient (the token
		// is set explicitly, not auto-attached), so there's no cross-site
		// WS-hijacking vector to gate against.
		InsecureSkipVerify: true,
		Subprotocols:       []string{execProtocol},
		CompressionMode:    websocket.CompressionDisabled,
	}

	ws, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		h.log.Warn().Err(err).Msg("exec/ws: WS upgrade failed")
		return
	}
	ws.SetReadLimit(maxExecReadBytes)

	transport := h.transports.get(instanceID, info)
	httpClient := &http.Client{Transport: transport}
	baseURL := fmt.Sprintf("http://%s:%d", info.VMIP, boxdPort)
	procClient := boxdpbconnect.NewProcessServiceClient(httpClient, baseURL)

	h.bridgeExecWS(r.Context(), ws, procClient, instanceID)
}

// bridgeExecWS pumps frames between the WebSocket and boxd until either side
// closes. It owns the WS handle and closes it on the way out.
func (h *Handler) bridgeExecWS(ctx context.Context, ws *websocket.Conn, procClient boxdpbconnect.ProcessServiceClient, instanceID string) {
	l := h.log.With().Str("sandbox_id", instanceID).Logger()

	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The first frame must be a JSON start message naming the command.
	readCtx, readCancel := context.WithTimeout(bridgeCtx, firstFrameWait)
	typ, raw, err := ws.Read(readCtx)
	readCancel()
	if err != nil {
		logWSReadEnd(l, err, maxExecReadBytes, "exec/ws")
		_ = ws.Close(websocket.StatusPolicyViolation, "expected start message")
		return
	}
	if typ != websocket.MessageText {
		_ = ws.Close(websocket.StatusUnsupportedData, "start message must be text JSON")
		return
	}
	var start execWSStart
	if err := json.Unmarshal(raw, &start); err != nil || start.Command == "" {
		_ = ws.Close(websocket.StatusPolicyViolation, "invalid start message (command required)")
		return
	}

	stream, err := procClient.Start(bridgeCtx, connect.NewRequest(start.toStartRequest()))
	if err != nil {
		l.Error().Err(err).Msg("exec/ws: boxd Start failed")
		_ = ws.Close(websocket.StatusInternalError, "failed to start command")
		return
	}

	// First event must be StartEvent — it carries the PID needed for
	// SendInput / Signal.
	if !stream.Receive() {
		serr := stream.Err()
		l.Error().Err(serr).Msg("exec/ws: stream empty on start")
		if serr != nil {
			msg, code := clientExecError(serr)
			_ = writeExecEvent(bridgeCtx, ws, &execWSEvent{Error: msg, Code: code, Finished: true})
		}
		_ = ws.Close(websocket.StatusInternalError, "command did not start")
		return
	}
	startEvent := stream.Msg().GetStart()
	if startEvent == nil {
		l.Error().Msg("exec/ws: first event was not StartEvent")
		_ = ws.Close(websocket.StatusInternalError, "unexpected event")
		return
	}
	pid := startEvent.GetPid()
	l.Info().Uint32("pid", pid).Msg("exec/ws: bridge established")

	// Hard session ceiling, independent of activity.
	sessionDeadline := time.NewTimer(execMaxSessionDuration)
	defer sessionDeadline.Stop()

	// Liveness: ping the client; a missed pong (within writeWait) tears down,
	// so a quiet-but-running command isn't cut. Read the interval into a local
	// (not in the goroutine) so tests can override the var without a race.
	pingInterval := execPingInterval
	go func() {
		defer sentrylog.Recover("exec-ws-ping")
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-bridgeCtx.Done():
				return
			case <-sessionDeadline.C:
				l.Info().Dur("max", execMaxSessionDuration).Msg("exec/ws: max session reached, closing")
				cancel()
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(bridgeCtx, writeWait)
				err := ws.Ping(pingCtx)
				pingCancel()
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						l.Debug().Err(err).Msg("exec/ws: ping failed, tearing down")
					}
					cancel()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// ------- boxd → client -------
	// stdout/stderr go out as channel-tagged binary frames; the End event is a
	// text lifecycle frame that closes the WS.
	go func() {
		defer sentrylog.Recover("exec-ws-out")
		defer wg.Done()
		defer cancel()
		for stream.Receive() {
			msg := stream.Msg()
			if d := msg.GetData(); d != nil {
				if out := d.GetStdout(); len(out) > 0 {
					if err := writeExecData(bridgeCtx, ws, execChStdout, out); err != nil {
						if !errors.Is(err, context.Canceled) {
							l.Debug().Err(err).Msg("exec/ws: WS write failed")
						}
						return
					}
				}
				if out := d.GetStderr(); len(out) > 0 {
					if err := writeExecData(bridgeCtx, ws, execChStderr, out); err != nil {
						if !errors.Is(err, context.Canceled) {
							l.Debug().Err(err).Msg("exec/ws: WS write failed")
						}
						return
					}
				}
				continue
			}
			if e := msg.GetEnd(); e != nil {
				code := e.GetExitCode()
				if err := writeExecEvent(bridgeCtx, ws, &execWSEvent{ExitCode: &code, Finished: true}); err != nil {
					if !errors.Is(err, context.Canceled) {
						l.Debug().Err(err).Msg("exec/ws: WS write failed")
					}
					return
				}
				_ = ws.Close(websocket.StatusNormalClosure, "command exited")
				return
			}
		}
		if err := stream.Err(); err != nil && !errors.Is(err, context.Canceled) {
			l.Warn().Err(err).Msg("exec/ws: boxd stream error")
			msg, code := clientExecError(err)
			_ = writeExecEvent(bridgeCtx, ws, &execWSEvent{
				Error:    msg,
				Code:     code,
				Finished: true,
			})
			_ = ws.Close(websocket.StatusInternalError, "command error")
		}
	}()

	// ------- client → boxd -------
	// Binary frames are channel-tagged I/O (channel 0 = stdin); text frames are
	// JSON control messages.
	go func() {
		defer sentrylog.Recover("exec-ws-in")
		defer wg.Done()
		defer cancel()
		for {
			typ, data, err := ws.Read(bridgeCtx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					logWSReadEnd(l, err, maxExecReadBytes, "exec/ws")
				}
				return
			}

			// SendInput is synchronous (preserves stdin order). If the process
			// stops draining stdin, SendInput blocks and delays later control
			// frames (e.g. a signal). Acceptable for interactive stdin.
			switch typ {
			case websocket.MessageBinary:
				if len(data) == 0 || data[0] != execChStdin {
					continue // empty or unknown channel
				}
				if _, err := procClient.SendInput(bridgeCtx, connect.NewRequest(&pb.SendInputRequest{
					Pid:  pid,
					Data: data[1:],
				})); err != nil {
					l.Warn().Err(err).Msg("exec/ws: SendInput failed")
				}
			case websocket.MessageText:
				h.handleExecControl(bridgeCtx, procClient, pid, data, l)
			}
		}
	}()

	wg.Wait()
	_ = ws.Close(websocket.StatusNormalClosure, "bridge closed")
}

// handleExecControl dispatches a text control frame to the right boxd RPC.
// Unknown types are logged and dropped so a newer client can't tear down the
// session.
func (h *Handler) handleExecControl(ctx context.Context, client boxdpbconnect.ProcessServiceClient, pid uint32, data []byte, l zerolog.Logger) {
	var msg execWSControl
	if err := json.Unmarshal(data, &msg); err != nil {
		l.Warn().Err(err).Msg("exec/ws: bad control JSON")
		return
	}

	switch msg.Type {
	case "stdin_close":
		if _, err := client.SendInput(ctx, connect.NewRequest(&pb.SendInputRequest{
			Pid: pid,
			Eof: true,
		})); err != nil {
			l.Warn().Err(err).Msg("exec/ws: stdin_close failed")
		}

	case "signal":
		signum, ok := signalNameToNumber(msg.Name)
		if !ok {
			l.Warn().Str("name", msg.Name).Msg("exec/ws: unknown signal name")
			return
		}
		if _, err := client.Signal(ctx, connect.NewRequest(&pb.SignalRequest{
			Pid:    pid,
			Signal: signum,
		})); err != nil {
			l.Warn().Err(err).Msg("exec/ws: Signal failed")
		}

	default:
		l.Debug().Str("type", msg.Type).Msg("exec/ws: unknown control type")
	}
}

// clientExecError maps a boxd stream error to a safe client-facing message.
// Invalid-argument errors carry boxd's own validation text (safe to surface);
// anything else is generic, so connection details never reach the client.
func clientExecError(err error) (message, code string) {
	var ce *connect.Error
	if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
		return ce.Message(), "bad_request"
	}
	return "the command failed to run", "exec_failed"
}

// writeExecEvent marshals a lifecycle event and writes it as a single text
// frame, bounded by writeWait so a slow client can't block the bridge forever.
func writeExecEvent(ctx context.Context, ws *websocket.Conn, ev *execWSEvent) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, writeWait)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, raw)
}

// writeExecData writes one output chunk as a binary frame prefixed with its
// channel byte, keeping bytes exact end to end.
func writeExecData(ctx context.Context, ws *websocket.Conn, channel byte, data []byte) error {
	frame := make([]byte, 1+len(data))
	frame[0] = channel
	copy(frame[1:], data)
	wctx, cancel := context.WithTimeout(ctx, writeWait)
	defer cancel()
	return ws.Write(wctx, websocket.MessageBinary, frame)
}
