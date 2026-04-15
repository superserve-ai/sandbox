package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// terminalBridgeDeps holds the dependencies specific to the /terminal
// WebSocket bridge. Auth is handled by the shared HMAC seed on the
// Handler; all that remains here is the browser origin allowlist.
type terminalBridgeDeps struct {
	allowedOrigins []string
}

// terminalBoxdInterceptors injects trace context into outbound Connect calls
// to boxd. No-op when telemetry is disabled (the global tracer is the SDK
// noop). otelconnect.NewInterceptor only errors on impossible configuration,
// so a panic at startup is the right escalation.
var terminalBoxdInterceptors = func() connect.Option {
	i, err := otelconnect.NewInterceptor()
	if err != nil {
		panic("otelconnect.NewInterceptor: " + err.Error())
	}
	return connect.WithInterceptors(i)
}()

// WithAuth sets the HMAC seed used by every data-plane endpoint on the
// boxd host label (/terminal, /files). Call once at proxy startup.
func (h *Handler) WithAuth(seedKey []byte) *Handler {
	if err := auth.ValidateSeed(seedKey); err != nil {
		panic("proxy: " + err.Error())
	}
	h.seedKey = seedKey
	return h
}

// WithTerminal enables the /terminal WebSocket bridge. Requires
// WithAuth to have been called first.
func (h *Handler) WithTerminal(allowedOrigins []string) *Handler {
	if len(allowedOrigins) == 0 {
		panic("proxy: WithTerminal requires at least one allowed origin (use \"*\" for dev)")
	}
	if h.seedKey == nil {
		panic("proxy: WithTerminal requires WithAuth to be called first")
	}
	h.terminal = &terminalBridgeDeps{allowedOrigins: allowedOrigins}
	return h
}

// WithFiles enables the /files HTTP reverse proxy on boxdPort. Requires
// WithAuth to have been called first.
func (h *Handler) WithFiles() *Handler {
	if h.seedKey == nil {
		panic("proxy: WithFiles requires WithAuth to be called first")
	}
	h.filesEnabled = true
	return h
}

// Terminal bridge constants.
const (
	// boxdPort is the port boxd's connect-rpc HTTP server listens on
	// inside each VM. Terminal sessions target the same port as the
	// regular proxy path for user apps at port 49983 — boxd is the
	// single HTTP endpoint exposed by the VM.
	boxdPort = 49983

	// terminalProtocol is the identifying WebSocket subprotocol echoed
	// back on a successful upgrade. Bump the version if the wire format
	// ever changes so older clients break loudly instead of silently
	// misinterpreting frames.
	terminalProtocol = "superserve.terminal.v1"

	// tokenProtocolPrefix is how clients smuggle the auth token through
	// the WebSocket handshake without putting it in a URL query param.
	// Browser WebSocket APIs cannot set custom headers on upgrade, but
	// they CAN set the Sec-WebSocket-Protocol header via the second arg
	// of `new WebSocket(url, protocols)`. We look for an entry starting
	// with this prefix and treat the suffix as the signed token. The
	// server never echoes this value back — only terminalProtocol — so
	// the token never lands in a response header or access log.
	tokenProtocolPrefix = "token."

	// maxReadBytes bounds the size of a single WebSocket frame we will
	// accept from the browser. Terminal input frames are keystrokes,
	// typically 1-10 bytes. 64 KiB is several orders of magnitude
	// above legitimate traffic and protects boxd from a malicious
	// client asking us to forward a huge SendInput payload for every
	// "keystroke."
	maxReadBytes = 64 * 1024

	// writeWait is the max duration we wait for a WS write to complete
	// before closing the connection. If the browser side is slow or
	// unresponsive we want to free the PTY rather than block forever.
	writeWait = 10 * time.Second

	// idleCloseAfter is how long the WS can sit with no traffic in
	// either direction before we tear it down. Protects against zombie
	// connections (user closes laptop, leaves tab open, network drops
	// without FIN). Re-set on every message in either direction.
	idleCloseAfter = 10 * time.Minute

	// maxSessionDuration is a hard ceiling on a single terminal session
	// regardless of traffic. Bounds the blast radius of a hijacked WS
	// connection — even if an attacker sends just enough traffic to
	// keep the idle timer alive, the session still terminates after
	// this duration. Clients should reconnect for longer-running work.
	maxSessionDuration = 4 * time.Hour

	// initialTerminalCols / initialTerminalRows are the PTY dimensions
	// we start the shell with. The browser will almost immediately send
	// a resize message once xterm.js measures its container, so these
	// values are just placeholders that minimize visual glitches during
	// the ~100ms handshake.
	initialTerminalCols = 80
	initialTerminalRows = 24
)

// wsControlMessage is the wire format for text-frame messages on the WS.
// Binary frames are raw PTY bytes; text frames carry JSON control.
//
// We use a tagged union (discriminated by Type) so future message types
// can be added additively without breaking older clients. Unknown Type
// values are logged and dropped.
type wsControlMessage struct {
	Type string `json:"type"`

	// Resize fields — populated when Type == "resize".
	Cols uint32 `json:"cols,omitempty"`
	Rows uint32 `json:"rows,omitempty"`

	// Signal fields — populated when Type == "signal".
	// Name is a POSIX signal name ("SIGINT", "SIGTERM", "SIGKILL").
	// We translate to numeric values server-side so clients don't need
	// to hardcode Linux signal numbers.
	Name string `json:"name,omitempty"`
}

// serveTerminal handles /terminal requests for a sandbox addressed by
// the `boxd-{id}.{domain}` host label. The caller (serveBoxdPort) has
// already parsed the instance ID and confirmed the terminal feature is
// enabled; this function is responsible for:
//
//  1. Extracting the HMAC access token from the WebSocket subprotocol.
//  2. Verifying the token against the sandbox ID.
//  3. Resolving the VM IP via the resolver.
//  4. Upgrading the HTTP connection to a WebSocket.
//  5. Opening a connect-rpc stream to boxd ProcessService.Start.
//  6. Bridging bytes until either side closes.
//
// Errors before the upgrade are returned as standard HTTP error responses.
// Errors after the upgrade are sent as WebSocket close frames with codes
// from the coder/websocket library.
func (h *Handler) serveTerminal(w http.ResponseWriter, r *http.Request, instanceID string) {
	// The token is carried in the Sec-WebSocket-Protocol header, NOT the
	// URL. This keeps the token out of GCP LB access logs, browser history,
	// Referer headers on sub-resources, and any middleware request logger.
	// See extractTerminalToken for the parser.
	//
	// Defence in depth: unconditionally scrub any ?t= query param before
	// the request reaches any downstream logger, in case an older client
	// still sends one.
	r.URL.RawQuery = ""

	// Discourage browsers from sending Referer on any sub-resource the
	// handshake might spawn. Terminal upgrades don't produce sub-resources
	// but the header is cheap and matches the "token is sensitive" posture.
	w.Header().Set("Referrer-Policy", "no-referrer")

	token := extractTerminalToken(r)
	if token == "" {
		http.Error(w, "missing token (pass as Sec-WebSocket-Protocol: token.<value>)", http.StatusUnauthorized)
		return
	}

	info, fail := h.authorizeSandboxRequest(r.Context(), token, instanceID)
	if fail != nil {
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg("terminal: auth failed")
		fail.write(w)
		return
	}

	// From here on, errors go back through the WebSocket (if the upgrade
	// succeeds) because we've committed to streaming.
	//
	// Origin enforcement: Origin is a CSRF-like defense that stops a
	// malicious page in the user's browser from leveraging a leaked or
	// coerced token (e.g. via a mint-CSRF path) to open a live terminal.
	// The set is configured at proxy startup. Passing `"*"` explicitly is
	// how local dev opts out; the default is deny-unknown.
	//
	// Subprotocols: we declare terminalProtocol as the one we'll accept
	// and echo. Clients must include it in their offered list. The
	// token-carrier subprotocol (token.<value>) is NOT listed here, so
	// coder/websocket will never echo it back in the handshake response.
	acceptOpts := &websocket.AcceptOptions{
		OriginPatterns:  h.terminal.allowedOrigins,
		Subprotocols:    []string{terminalProtocol},
		CompressionMode: websocket.CompressionDisabled,
	}
	// Explicit opt-out: a single "*" entry in allowed origins disables
	// the check for dev. The config loader is responsible for only
	// allowing this via an explicit env var.
	if len(h.terminal.allowedOrigins) == 1 && h.terminal.allowedOrigins[0] == "*" {
		acceptOpts.OriginPatterns = nil
		acceptOpts.InsecureSkipVerify = true
	}

	ws, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		h.log.Warn().Err(err).Msg("terminal: WS upgrade failed")
		return
	}

	// Bound the size of any single input frame. Keystrokes are tiny;
	// anything approaching 64 KiB is either a paste (legitimate but
	// still bounded) or an attack trying to amplify into SendInput.
	ws.SetReadLimit(maxReadBytes)

	// Build the connect-rpc client to boxd. We use the transport cache so
	// the bridge benefits from the same lifecycle keying and connection
	// pooling as the generic proxy path.
	transport := h.transports.get(instanceID, info)
	httpClient := &http.Client{Transport: transport}
	baseURL := fmt.Sprintf("http://%s:%d", info.VMIP, boxdPort)
	procClient := boxdpbconnect.NewProcessServiceClient(httpClient, baseURL, terminalBoxdInterceptors)

	// Tie the bridge lifetime to the request context so shutdowns
	// propagate cleanly. The WS will be closed in bridgeTerminal.
	ctx := r.Context()
	h.bridgeTerminal(ctx, ws, procClient, instanceID)
}

// bridgeTerminal is the long-lived function that pumps bytes between the
// WebSocket and boxd until one side closes. It owns the WS handle and is
// responsible for closing it on the way out.
//
// Design: two goroutines, one per direction, plus the main goroutine that
// waits for either to finish. When either direction errors, we cancel the
// shared context and the other direction sees its read/write return, then
// exits. This is the simplest correct pattern for bidirectional bridging.
func (h *Handler) bridgeTerminal(ctx context.Context, ws *websocket.Conn, procClient boxdpbconnect.ProcessServiceClient, instanceID string) {
	l := h.log.With().
		Str("sandbox_id", instanceID).
		Logger()

	// Scoped context so either direction's failure cancels everything.
	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start a shell in PTY mode. Initial size is a placeholder — the
	// browser will resize immediately after mount.
	startReq := connect.NewRequest(&pb.StartRequest{
		Cmd: "/bin/bash",
		Pty: &pb.PtyConfig{
			Size: &pb.TerminalSize{
				Cols: initialTerminalCols,
				Rows: initialTerminalRows,
			},
		},
	})
	stream, err := procClient.Start(bridgeCtx, startReq)
	if err != nil {
		l.Error().Err(err).Msg("terminal: boxd Start failed")
		_ = ws.Close(websocket.StatusInternalError, "failed to start shell")
		return
	}

	// Read the first event — must be a StartEvent so we learn the PID
	// (needed for SendInput / Resize / Signal which all address the
	// process by PID).
	if !stream.Receive() {
		l.Error().Err(stream.Err()).Msg("terminal: boxd stream empty on start")
		_ = ws.Close(websocket.StatusInternalError, "shell did not start")
		return
	}
	startEvent := stream.Msg().GetStart()
	if startEvent == nil {
		l.Error().Msg("terminal: first event was not StartEvent")
		_ = ws.Close(websocket.StatusInternalError, "unexpected event")
		return
	}
	pid := startEvent.GetPid()
	l.Info().Uint32("pid", pid).Msg("terminal: bridge established")

	// Idle timer — reset on every message in either direction. Tears
	// down sessions that have gone quiet for idleCloseAfter.
	var idleMu sync.Mutex
	lastActivity := time.Now()
	touchIdle := func() {
		idleMu.Lock()
		lastActivity = time.Now()
		idleMu.Unlock()
	}

	// Hard session deadline — independent of activity. Bounds the
	// blast radius of a hijacked WS connection regardless of how
	// chatty the attacker is. Clients should reconnect for sessions
	// longer than this.
	sessionDeadline := time.NewTimer(maxSessionDuration)
	defer sessionDeadline.Stop()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-bridgeCtx.Done():
				return
			case <-sessionDeadline.C:
				l.Info().Dur("max", maxSessionDuration).Msg("terminal: max session reached, closing")
				cancel()
				return
			case <-ticker.C:
				idleMu.Lock()
				last := lastActivity
				idleMu.Unlock()
				if time.Since(last) > idleCloseAfter {
					l.Info().Msg("terminal: idle timeout, closing")
					cancel()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// ------- boxd → browser -------
	// Read ProcessEvents from the connect-rpc stream; write PtyData as
	// binary WebSocket frames. Non-PTY events (stdout/stderr outside
	// PTY mode, End, Keepalive) are ignored — we asked for PTY so
	// everything interactive comes through PtyData.
	go func() {
		defer wg.Done()
		defer cancel()
		for stream.Receive() {
			msg := stream.Msg()
			if d := msg.GetData(); d != nil {
				if pty := d.GetPtyData(); len(pty) > 0 {
					wctx, wcancel := context.WithTimeout(bridgeCtx, writeWait)
					if err := ws.Write(wctx, websocket.MessageBinary, pty); err != nil {
						wcancel()
						if !errors.Is(err, context.Canceled) {
							l.Debug().Err(err).Msg("terminal: WS write failed")
						}
						return
					}
					wcancel()
					touchIdle()
				}
			}
			if e := msg.GetEnd(); e != nil {
				// Shell exited — close the WS with a clean
				// code so xterm.js can show "session ended".
				l.Info().Int32("exit_code", e.GetExitCode()).Msg("terminal: shell exited")
				_ = ws.Close(websocket.StatusNormalClosure, "shell exited")
				return
			}
		}
		if err := stream.Err(); err != nil && !errors.Is(err, context.Canceled) {
			l.Warn().Err(err).Msg("terminal: boxd stream error")
		}
	}()

	// ------- browser → boxd -------
	// Read WS frames. Binary frames are PTY input (forward as SendInput
	// with the captured PID). Text frames are control JSON.
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			typ, data, err := ws.Read(bridgeCtx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					// Normal close is not an error.
					closeErr := websocket.CloseStatus(err)
					if closeErr != websocket.StatusNormalClosure && closeErr != websocket.StatusGoingAway {
						l.Debug().Err(err).Msg("terminal: WS read ended")
					}
				}
				return
			}
			touchIdle()

			switch typ {
			case websocket.MessageBinary:
				_, err := procClient.SendInput(bridgeCtx, connect.NewRequest(&pb.SendInputRequest{
					Pid:  pid,
					Data: data,
				}))
				if err != nil {
					l.Warn().Err(err).Msg("terminal: boxd SendInput failed")
					return
				}
			case websocket.MessageText:
				h.handleControlMessage(bridgeCtx, procClient, pid, data, l)
			}
		}
	}()

	wg.Wait()
	_ = ws.Close(websocket.StatusNormalClosure, "bridge closed")
}

// handleControlMessage parses a text frame as a wsControlMessage and
// dispatches to the appropriate boxd RPC. Unknown types are logged and
// dropped rather than crashing the bridge — a client speaking a newer
// protocol version shouldn't tear down the session.
func (h *Handler) handleControlMessage(ctx context.Context, client boxdpbconnect.ProcessServiceClient, pid uint32, data []byte, l zerolog.Logger) {
	var msg wsControlMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		l.Warn().Err(err).Msg("terminal: bad control JSON")
		return
	}

	switch msg.Type {
	case "resize":
		if msg.Cols == 0 || msg.Rows == 0 {
			l.Warn().Msg("terminal: resize with zero dims")
			return
		}
		_, err := client.Resize(ctx, connect.NewRequest(&pb.ResizeRequest{
			Pid:  pid,
			Size: &pb.TerminalSize{Cols: msg.Cols, Rows: msg.Rows},
		}))
		if err != nil {
			l.Warn().Err(err).Msg("terminal: boxd Resize failed")
		}

	case "signal":
		signum, ok := signalNameToNumber(msg.Name)
		if !ok {
			l.Warn().Str("name", msg.Name).Msg("terminal: unknown signal name")
			return
		}
		_, err := client.Signal(ctx, connect.NewRequest(&pb.SignalRequest{
			Pid:    pid,
			Signal: signum,
		}))
		if err != nil {
			l.Warn().Err(err).Msg("terminal: boxd Signal failed")
		}

	default:
		l.Debug().Str("type", msg.Type).Msg("terminal: unknown control type")
	}
}

// extractTerminalToken pulls the signed token out of the
// Sec-WebSocket-Protocol header. Clients include one entry of the form
// `token.<value>` alongside the main terminalProtocol entry. This keeps
// the token out of URLs, logs, and referrers.
//
// Multiple entries per header line are comma-separated per RFC 6455; we
// also accept multiple header values. Entries are trimmed and compared
// case-sensitively (the prefix is ASCII, no folding needed).
//
// Returns "" if no token entry is found. The caller logs and rejects.
func extractTerminalToken(r *http.Request) string {
	for _, hv := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(hv, ",") {
			p := strings.TrimSpace(part)
			if strings.HasPrefix(p, tokenProtocolPrefix) {
				return strings.TrimPrefix(p, tokenProtocolPrefix)
			}
		}
	}
	return ""
}

// signalNameToNumber maps POSIX signal names to their numeric values.
// Limited to signals a terminal user legitimately needs — we don't want
// browsers sending SIGKILL/SIGSTOP willy-nilly even though boxd would
// accept them.
func signalNameToNumber(name string) (int32, bool) {
	switch name {
	case "SIGINT":
		return int32(syscall.SIGINT), true
	case "SIGTERM":
		return int32(syscall.SIGTERM), true
	case "SIGHUP":
		return int32(syscall.SIGHUP), true
	case "SIGQUIT":
		return int32(syscall.SIGQUIT), true
	}
	return 0, false
}

