// Command vmd-gateway is the stable front process that owns vmd's public
// control-plane and resolver ports and routes them to the active vmd
// generation over its private unix socket. It is the one process that must not
// blue-green: it stays up across generation cutovers so client connections and
// the kernel listen sockets survive a deploy.
//
// A local control socket accepts newline-delimited commands so the handoff
// controller (or, during bringup, an operator) can steer routing:
//
//	set-active <generation-id> <upstream-socket>
//	quiesce on|off
//	status
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/gateway"
	"github.com/superserve-ai/sandbox/internal/handoff"
)

// Generation socket/unit naming — the single source of truth shared by the
// gateway, the generation units, and the handoff controller.
func genGRPCPath(id string) string     { return "/run/vmd/gen-" + id + "-grpc.sock" }
func genResolverPath(id string) string { return "/run/vmd/gen-" + id + "-resolver.sock" }
func genControlPath(id string) string  { return "/run/vmd/gen-" + id + "-ctl.sock" }
func unitName(id string) string        { return "superserve-vmd@" + id }

// gwAdapter lets the in-process handoff controller steer routing directly, and
// persists the active generation so the gateway can rediscover it after a
// restart (its routing/controller state is otherwise only in memory).
type gwAdapter struct {
	gw        *gateway.Gateway
	statePath string
	log       zerolog.Logger
}

func (a gwAdapter) QuiesceGRPC(on bool)     { a.gw.Router().QuiesceGRPC(on) }
func (a gwAdapter) QuiesceResolver(on bool) { a.gw.Router().QuiesceResolver(on) }
func (a gwAdapter) SetActive(gen handoff.Generation) {
	up := gateway.Upstream{Generation: gen.ID, GRPCSocket: gen.GRPCSocket, ResolverSocket: gen.ResolverSocket}
	a.gw.SetActive(up)
	if err := persistActive(a.statePath, up); err != nil {
		// Non-fatal: startup discovery (probing for the live writer) recovers
		// even without the record, but a silent failure would hide a real
		// disk/permission problem — so surface it.
		a.log.Warn().Err(err).Str("generation", gen.ID).Msg("failed to persist active generation")
	}
}

// persistActive atomically records the active generation so a restarted gateway
// can restore routing (a hint; startup discovery is authoritative).
func persistActive(path string, up gateway.Upstream) error {
	if path == "" {
		return nil
	}
	data := up.Generation + "\n" + up.GRPCSocket + "\n" + up.ResolverSocket + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadActive(path string) (gateway.Upstream, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return gateway.Upstream{}, false
	}
	// Split (not TrimRight+SplitN): the record ends in a newline, so a trailing
	// empty resolver field must survive as its own segment rather than being
	// trimmed away — otherwise a valid record parses as too few fields.
	parts := strings.Split(string(b), "\n")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return gateway.Upstream{}, false
	}
	return gateway.Upstream{Generation: parts[0], GRPCSocket: parts[1], ResolverSocket: parts[2]}, true
}

// probeGenPhase returns a generation's phase ("active" or "preflight") from its
// control socket, or "" if it does not answer (dead or restarting).
func probeGenPhase(sock string, timeout time.Duration) string {
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintln(conn, "status")
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		return ""
	}
	if i := strings.Index(sc.Text(), "phase="); i >= 0 {
		return strings.TrimSpace(sc.Text()[i+len("phase="):])
	}
	return ""
}

// discoverActiveGen finds the live writer by probing every generation control
// socket for phase=active. This is authoritative — it reflects which process is
// actually serving — so it is preferred over the persisted record, which can be
// missing or stale after a restart.
func discoverActiveGen(timeout time.Duration) (gateway.Upstream, bool) {
	socks, _ := filepath.Glob("/run/vmd/gen-*-ctl.sock")
	for _, ctl := range socks {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(ctl), "gen-"), "-ctl.sock")
		if id == "" {
			continue
		}
		if probeGenPhase(ctl, timeout) == "active" {
			return gateway.Upstream{
				Generation:     id,
				GRPCSocket:     genGRPCPath(id),
				ResolverSocket: genResolverPath(id),
			}, true
		}
	}
	return gateway.Upstream{}, false
}

// controlState is the target of the gateway control socket: raw routing
// commands plus controller-driven deploys.
type controlState struct {
	gw        *gateway.Gateway
	ctrl      *handoff.Controller
	log       zerolog.Logger
	statePath string

	mu     sync.Mutex
	deploy deployStatus
}

// deployStatus is the outcome of the most recent deploy, so the trigger can
// distinguish in-progress from succeeded/failed instead of polling to a timeout.
type deployStatus struct {
	id, state, err string // state: "" (idle) | "running" | "done" | "failed"
}

func main() {
	grpcAddr := flag.String("grpc-addr", ":50051", "public control-plane gRPC listen address")
	resolverAddr := flag.String("resolver-addr", "127.0.0.1:9090", "public resolver HTTP listen address")
	controlSock := flag.String("control-sock", "/run/vmd/gateway-control.sock", "local control unix socket")
	initialID := flag.String("initial-gen-id", "", "generation id to route to at startup")
	initialGRPC := flag.String("initial-gen-grpc", "", "generation gRPC socket to route to at startup")
	initialResolver := flag.String("initial-gen-resolver", "", "generation resolver socket to route to at startup")
	statePath := flag.String("state-file", "/var/lib/sandbox/active-generation", "records the active generation for restart recovery")
	flag.Parse()

	log := zerolog.New(os.Stderr).With().Timestamp().Str("service", "vmd-gateway").Logger()

	gw := gateway.New()
	adapter := gwAdapter{gw: gw, statePath: *statePath, log: log}
	actions := handoff.NewSystemdActions(adapter, unitName, genControlPath)

	// Determine the active generation after a (re)start. Explicit flags win.
	// Otherwise DISCOVER the live writer by probing generation sockets — this is
	// authoritative even if the persisted record is missing or stale. Only if no
	// generation is actually serving do we fall back to the recorded one and
	// redeploy it (crash/reboot recovery).
	var initial gateway.Upstream
	var recoverGen *gateway.Upstream
	if *initialGRPC != "" {
		initial = gateway.Upstream{Generation: *initialID, GRPCSocket: *initialGRPC, ResolverSocket: *initialResolver}
	} else if live, ok := discoverActiveGen(2 * time.Second); ok {
		initial = live
		log.Info().Str("generation", live.Generation).Msg("discovered live generation; restoring route")
	} else if up, ok := loadActive(*statePath); ok {
		u := up
		recoverGen = &u
		log.Warn().Str("generation", up.Generation).Msg("no live generation; will redeploy the recorded one")
	}

	controller := handoff.New(actions, handoff.Generation{
		ID: initial.Generation, GRPCSocket: initial.GRPCSocket, ResolverSocket: initial.ResolverSocket,
	})
	if initial.GRPCSocket != "" {
		gw.SetActive(initial)
		persistActive(*statePath, initial)
	}

	grpcLis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", *grpcAddr).Msg("gRPC listen")
	}
	grpcSrv := gw.GRPCServer()
	go func() {
		log.Info().Str("addr", *grpcAddr).Msg("serving control-plane gRPC")
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Error().Err(err).Msg("gRPC server stopped")
		}
	}()

	resolverSrv := &http.Server{Addr: *resolverAddr, Handler: gw.ResolverHandler()}
	go func() {
		log.Info().Str("addr", *resolverAddr).Msg("serving resolver HTTP")
		if err := resolverSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("resolver server stopped")
		}
	}()

	ctlLis, err := listenControl(*controlSock)
	if err != nil {
		log.Fatal().Err(err).Str("sock", *controlSock).Msg("control socket listen")
	}
	go serveControl(ctlLis, &controlState{gw: gw, ctrl: controller, log: log, statePath: *statePath})

	// The recorded generation was gone: bring it back up via a normal deploy.
	if recoverGen != nil {
		go func(u gateway.Upstream) {
			log.Info().Str("generation", u.Generation).Msg("recovery deploy starting")
			if err := controller.Deploy(context.Background(), handoff.Generation{}, handoff.Generation{
				ID: u.Generation, GRPCSocket: u.GRPCSocket, ResolverSocket: u.ResolverSocket,
			}); err != nil {
				log.Error().Err(err).Str("generation", u.Generation).Msg("recovery deploy failed")
			}
		}(*recoverGen)
	}

	// Health monitor: recover a crashed active generation. Restart=on-failure
	// brings a crashed generation back into preflight; this detects that (or a
	// still-dead one) and re-activates it. Skipped while a deploy/recovery is in
	// flight so an intentionally-stopped generation is not mistaken for a crash.
	go monitorActiveGeneration(controller, log)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info().Msg("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = resolverSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
	gw.Close()
	_ = ctlLis.Close()
	_ = os.Remove(*controlSock)
}

// monitorActiveGeneration periodically checks the routed generation and
// re-activates it if it crashed and restarted into preflight (or logs if it is
// still down and awaiting systemd restart).
func monitorActiveGeneration(controller *handoff.Controller, log zerolog.Logger) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		if controller.Deploying() {
			continue
		}
		cur := controller.Current()
		if cur.ID == "" {
			continue
		}
		switch probeGenPhase(genControlPath(cur.ID), 2*time.Second) {
		case "active":
			// healthy
		case "preflight":
			log.Warn().Str("generation", cur.ID).Msg("active generation restarted into preflight — re-activating")
			if err := controller.Reactivate(context.Background(), cur); err != nil {
				log.Error().Err(err).Str("generation", cur.ID).Msg("re-activation failed")
			}
		default: // "" — not answering; awaiting systemd restart
			log.Warn().Str("generation", cur.ID).Msg("active generation not responding — awaiting restart")
		}
	}
}

func listenControl(path string) (net.Listener, error) {
	// The control socket is this process's own private address, so clearing a
	// stale file left by a crash is safe.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", path)
}

func serveControl(lis net.Listener, cs *controlState) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go cs.handle(conn)
	}
}

func (cs *controlState) handle(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		resp := cs.apply(strings.Fields(sc.Text()))
		fmt.Fprintln(conn, resp)
		cs.log.Info().Str("cmd", sc.Text()).Str("resp", resp).Msg("control command")
	}
}

func (cs *controlState) apply(fields []string) string {
	if len(fields) == 0 {
		return "ERR empty"
	}
	switch fields[0] {
	case "set-active":
		if len(fields) != 4 {
			return "ERR usage: set-active <generation-id> <grpc-socket> <resolver-socket>"
		}
		up := gateway.Upstream{Generation: fields[1], GRPCSocket: fields[2], ResolverSocket: fields[3]}
		cs.gw.SetActive(up)
		if err := persistActive(cs.statePath, up); err != nil {
			cs.log.Warn().Err(err).Msg("failed to persist active generation")
		}
		if cs.ctrl != nil {
			// Keep controller state in sync so a later deploy's CAS + drain
			// target reflect what is actually routed to.
			cs.ctrl.SetCurrent(handoff.Generation{ID: fields[1], GRPCSocket: fields[2], ResolverSocket: fields[3]})
		}
		return "OK"
	case "quiesce":
		if len(fields) != 2 || (fields[1] != "on" && fields[1] != "off") {
			return "ERR usage: quiesce on|off"
		}
		// Operator escape hatch: hold both paths.
		cs.gw.Router().QuiesceGRPC(fields[1] == "on")
		cs.gw.Router().QuiesceResolver(fields[1] == "on")
		return "OK"
	case "status":
		up, q := cs.gw.Router().Active()
		return fmt.Sprintf("OK generation=%q grpc=%q resolver=%q quiescing=%t",
			up.Generation, up.GRPCSocket, up.ResolverSocket, q)
	case "current":
		if cs.ctrl == nil {
			return "ERR no controller"
		}
		return "OK current=" + cs.ctrl.Current().ID
	case "deploy":
		if cs.ctrl == nil {
			return "ERR no controller"
		}
		if len(fields) != 2 {
			return "ERR usage: deploy <generation-id>"
		}
		next := handoff.Generation{
			ID:             fields[1],
			GRPCSocket:     genGRPCPath(fields[1]),
			ResolverSocket: genResolverPath(fields[1]),
		}
		expected := cs.ctrl.Current()
		cs.mu.Lock()
		cs.deploy = deployStatus{id: next.ID, state: "running"}
		cs.mu.Unlock()
		// Detached: the deploy runs to completion even if this control
		// connection drops. Poll "deploy-status" to see how it lands.
		go func() {
			err := cs.ctrl.Deploy(context.Background(), expected, next)
			cs.mu.Lock()
			if err != nil {
				cs.deploy = deployStatus{id: next.ID, state: "failed", err: err.Error()}
			} else {
				cs.deploy = deployStatus{id: next.ID, state: "done"}
			}
			cs.mu.Unlock()
			if err != nil {
				cs.log.Error().Err(err).Str("generation", next.ID).Msg("deploy failed")
			} else {
				cs.log.Info().Str("generation", next.ID).Msg("deploy complete")
			}
		}()
		return "OK deploying " + fields[1]
	case "deploy-status":
		cs.mu.Lock()
		d := cs.deploy
		cs.mu.Unlock()
		if d.state == "" {
			return "OK state=idle"
		}
		return fmt.Sprintf("OK state=%s generation=%s error=%q", d.state, d.id, d.err)
	default:
		return "ERR unknown command " + fields[0]
	}
}
