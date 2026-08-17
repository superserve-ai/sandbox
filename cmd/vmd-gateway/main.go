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
	"strings"
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

// gwAdapter lets the in-process handoff controller steer routing directly.
type gwAdapter struct{ gw *gateway.Gateway }

func (a gwAdapter) Quiesce(on bool) { a.gw.Router().Quiesce(on) }
func (a gwAdapter) SetActive(gen handoff.Generation) {
	a.gw.Router().SetActive(gateway.Upstream{
		Generation:     gen.ID,
		GRPCSocket:     gen.GRPCSocket,
		ResolverSocket: gen.ResolverSocket,
	})
}

// controlState is the target of the gateway control socket: raw routing
// commands plus controller-driven deploys.
type controlState struct {
	gw   *gateway.Gateway
	ctrl *handoff.Controller
	log  zerolog.Logger
}

func main() {
	grpcAddr := flag.String("grpc-addr", ":50051", "public control-plane gRPC listen address")
	resolverAddr := flag.String("resolver-addr", "127.0.0.1:9090", "public resolver HTTP listen address")
	controlSock := flag.String("control-sock", "/run/vmd/gateway-control.sock", "local control unix socket")
	initialID := flag.String("initial-gen-id", "", "generation id to route to at startup")
	initialGRPC := flag.String("initial-gen-grpc", "", "generation gRPC socket to route to at startup")
	initialResolver := flag.String("initial-gen-resolver", "", "generation resolver socket to route to at startup")
	flag.Parse()

	log := zerolog.New(os.Stderr).With().Timestamp().Str("service", "vmd-gateway").Logger()

	gw := gateway.New()
	if *initialGRPC != "" {
		gw.Router().SetActive(gateway.Upstream{
			Generation:     *initialID,
			GRPCSocket:     *initialGRPC,
			ResolverSocket: *initialResolver,
		})
		log.Info().Str("generation", *initialID).Str("grpc", *initialGRPC).
			Str("resolver", *initialResolver).Msg("initial upstream set")
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

	actions := handoff.NewSystemdActions(gwAdapter{gw}, unitName, genControlPath)
	controller := handoff.New(actions, handoff.Generation{
		ID:             *initialID,
		GRPCSocket:     *initialGRPC,
		ResolverSocket: *initialResolver,
	})

	ctlLis, err := listenControl(*controlSock)
	if err != nil {
		log.Fatal().Err(err).Str("sock", *controlSock).Msg("control socket listen")
	}
	go serveControl(ctlLis, &controlState{gw: gw, ctrl: controller, log: log})

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
		cs.gw.Router().SetActive(gateway.Upstream{
			Generation:     fields[1],
			GRPCSocket:     fields[2],
			ResolverSocket: fields[3],
		})
		return "OK"
	case "quiesce":
		if len(fields) != 2 || (fields[1] != "on" && fields[1] != "off") {
			return "ERR usage: quiesce on|off"
		}
		cs.gw.Router().Quiesce(fields[1] == "on")
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
		// Detached: the deploy runs to completion even if this control
		// connection drops. Poll "current" to see when it lands.
		go func() {
			if err := cs.ctrl.Deploy(context.Background(), expected, next); err != nil {
				cs.log.Error().Err(err).Str("generation", next.ID).Msg("deploy failed")
			} else {
				cs.log.Info().Str("generation", next.ID).Msg("deploy complete")
			}
		}()
		return "OK deploying " + fields[1]
	default:
		return "ERR unknown command " + fields[0]
	}
}
