package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// terminalBridgeDeps groups everything the terminal handler needs so it can
// be attached to the main Handler via WithTerminal. Kept unexported because
// callers interact with it only through the Handler methods.
type terminalBridgeDeps struct {
	verifier *auth.Verifier
	nonces   *NonceCache
}

// WithTerminal installs the dependencies the /terminal WebSocket bridge
// needs. Call once at proxy startup with a verifier loaded from
// TERMINAL_TOKEN_PUBLIC_KEY and a NonceCache (DefaultNonceCache is fine).
//
// Passing nil for either argument panics — the proxy is about to bind a
// listener and we want configuration errors to surface immediately, not as
// nil-pointer crashes on the first real request.
func (h *Handler) WithTerminal(verifier *auth.Verifier, nonces *NonceCache) *Handler {
	if verifier == nil {
		panic("proxy: WithTerminal requires a non-nil Verifier")
	}
	if nonces == nil {
		panic("proxy: WithTerminal requires a non-nil NonceCache")
	}
	h.terminal = &terminalBridgeDeps{verifier: verifier, nonces: nonces}
	return h
}

// Terminal bridge constants.
const (
	// boxdPort is the port boxd's connect-rpc HTTP server listens on
	// inside each VM. Terminal sessions target the same port as the
	// regular proxy path for user apps at port 49983 — boxd is the
	// single HTTP endpoint exposed by the VM.
	boxdPort = 49983

	// writeWait is the max duration we wait for a WS write to complete
	// before closing the connection. If the browser side is slow or
	// unresponsive we want to free the PTY rather than block forever.
	writeWait = 10 * time.Second

	// idleCloseAfter is how long the WS can sit with no traffic in
	// either direction before we tear it down. Protects against zombie
	// connections (user closes laptop, leaves tab open, network drops
	// without FIN). Re-set on every message in either direction.
	idleCloseAfter = 30 * time.Minute

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

// serveTerminal is the entry point for /terminal requests. It:
//  1. Extracts and verifies the token (signature, expiry, scope)
//  2. Single-use nonce check (replay protection)
//  3. Parses the host to extract sandbox ID and matches it against the
//     token's sandbox ID
//  4. Resolves the VM IP via the normal resolver
//  5. Upgrades the HTTP connection to WebSocket
//  6. Opens a connect-rpc stream to boxd ProcessService.Start
//  7. Bridges bytes until either side closes
//
// Errors before the upgrade are returned as standard HTTP error responses.
// Errors after the upgrade are sent as WebSocket close frames with codes
// from the coder/websocket library.
func (h *Handler) serveTerminal(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	payload, err := h.terminal.verifier.Verify(token, time.Now(), auth.ScopeTerminal)
	if err != nil {
		h.log.Warn().Err(err).Msg("terminal: token verify failed")
		// Map fine-grained errors to specific statuses so the frontend
		// can show useful messages (expired = re-mint, bad sig =
		// auth failure).
		switch {
		case errors.Is(err, auth.ErrExpired), errors.Is(err, auth.ErrNotYetValid):
			http.Error(w, "token expired", http.StatusUnauthorized)
		case errors.Is(err, auth.ErrBadSignature), errors.Is(err, auth.ErrScopeMismatch):
			http.Error(w, "invalid token", http.StatusUnauthorized)
		default:
			http.Error(w, "bad token", http.StatusBadRequest)
		}
		return
	}

	if !h.terminal.nonces.CheckAndStore(payload.Nonce, time.Now()) {
		h.log.Warn().
			Str("sandbox_id", payload.SandboxID).
			Str("nonce", payload.Nonce).
			Msg("terminal: token replay rejected")
		http.Error(w, "token already used", http.StatusUnauthorized)
		return
	}

	instanceID, err := ParseTerminalHost(r.Host, h.domain)
	if err != nil {
		h.log.Warn().Err(err).Str("host", r.Host).Msg("terminal: bad host")
		http.Error(w, "invalid terminal URL", http.StatusBadRequest)
		return
	}

	if err := auth.SameSandbox(payload, instanceID); err != nil {
		// Token was minted for a different sandbox than the one being
		// addressed. Could be a misconfigured frontend or an active
		// attempt to swap sandboxes with a valid token.
		h.log.Warn().
			Str("token_sandbox", payload.SandboxID).
			Str("host_sandbox", instanceID).
			Msg("terminal: sandbox mismatch")
		http.Error(w, "token does not match sandbox", http.StatusForbidden)
		return
	}

	info, err := h.resolver.Lookup(r.Context(), instanceID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			http.Error(w, "sandbox not found", http.StatusNotFound)
			return
		}
		h.log.Error().Err(err).Str("instance", instanceID).Msg("terminal: resolver error")
		http.Error(w, "sandbox unavailable", http.StatusServiceUnavailable)
		return
	}
	if info.Status != "running" {
		http.Error(w, fmt.Sprintf("sandbox is %s", info.Status), http.StatusServiceUnavailable)
		return
	}

	// From here on, errors go back through the WebSocket (if the upgrade
	// succeeds) because we've committed to streaming. We use the coder
	// library's AcceptOptions to lock down the origin check.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// OriginPatterns: the browser sends Origin; we trust any
		// origin because the token already proves the request is
		// authorized. Origin is a CSRF defense for cookie-based auth,
		// which we don't use here.
		InsecureSkipVerify: true,
		// CompressionMode: disable because PTY output is already
		// binary and compression doesn't help terminal traffic.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		h.log.Warn().Err(err).Msg("terminal: WS upgrade failed")
		return
	}

	// Tie the bridge lifetime to the request context so shutdowns
	// propagate cleanly. The WS will be closed in bridgeTerminal.
	ctx := r.Context()
	h.bridgeTerminal(ctx, ws, instanceID, info, payload)
}

// bridgeTerminal is the long-lived function that pumps bytes between the
// WebSocket and boxd until one side closes. It owns the WS handle and is
// responsible for closing it on the way out.
//
// Design: two goroutines, one per direction, plus the main goroutine that
// waits for either to finish. When either direction errors, we cancel the
// shared context and the other direction sees its read/write return, then
// exits. This is the simplest correct pattern for bidirectional bridging.
func (h *Handler) bridgeTerminal(ctx context.Context, ws *websocket.Conn, instanceID string, info InstanceInfo, payload *auth.Payload) {
	l := h.log.With().
		Str("sandbox_id", instanceID).
		Str("team_id", payload.TeamID).
		Logger()

	// Scoped context so either direction's failure cancels everything.
	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Build a connect-rpc client to boxd over the VM's private IP.
	// We use the transport cache so we benefit from the same lifecycle
	// keying and connection pooling as the generic proxy path.
	transport := h.transports.get(instanceID, info)
	httpClient := &http.Client{Transport: transport}
	baseURL := fmt.Sprintf("http://%s:%d", info.VMIP, boxdPort)
	procClient := boxdpbconnect.NewProcessServiceClient(httpClient, baseURL)

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

	// Idle timer — reset on every message in either direction. If no
	// activity for idleCloseAfter we cancel the bridge context.
	var idleMu sync.Mutex
	lastActivity := time.Now()
	touchIdle := func() {
		idleMu.Lock()
		lastActivity = time.Now()
		idleMu.Unlock()
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-bridgeCtx.Done():
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

