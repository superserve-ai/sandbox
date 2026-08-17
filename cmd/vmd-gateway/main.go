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
)

func main() {
	grpcAddr := flag.String("grpc-addr", ":50051", "public control-plane gRPC listen address")
	resolverAddr := flag.String("resolver-addr", "127.0.0.1:9090", "public resolver HTTP listen address")
	controlSock := flag.String("control-sock", "/run/vmd/gateway-control.sock", "local control unix socket")
	initialID := flag.String("initial-gen-id", "", "generation id to route to at startup")
	initialSock := flag.String("initial-gen-sock", "", "generation upstream socket to route to at startup")
	flag.Parse()

	log := zerolog.New(os.Stderr).With().Timestamp().Str("service", "vmd-gateway").Logger()

	gw := gateway.New()
	if *initialSock != "" {
		gw.Router().SetActive(gateway.Upstream{Generation: *initialID, Socket: *initialSock})
		log.Info().Str("generation", *initialID).Str("socket", *initialSock).Msg("initial upstream set")
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
	go serveControl(ctlLis, gw, log)

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

func serveControl(lis net.Listener, gw *gateway.Gateway, log zerolog.Logger) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go handleControl(conn, gw, log)
	}
}

func handleControl(conn net.Conn, gw *gateway.Gateway, log zerolog.Logger) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		resp := applyControl(strings.Fields(sc.Text()), gw)
		fmt.Fprintln(conn, resp)
		log.Info().Str("cmd", sc.Text()).Str("resp", resp).Msg("control command")
	}
}

func applyControl(fields []string, gw *gateway.Gateway) string {
	if len(fields) == 0 {
		return "ERR empty"
	}
	switch fields[0] {
	case "set-active":
		if len(fields) != 3 {
			return "ERR usage: set-active <generation-id> <upstream-socket>"
		}
		gw.Router().SetActive(gateway.Upstream{Generation: fields[1], Socket: fields[2]})
		return "OK"
	case "quiesce":
		if len(fields) != 2 || (fields[1] != "on" && fields[1] != "off") {
			return "ERR usage: quiesce on|off"
		}
		gw.Router().Quiesce(fields[1] == "on")
		return "OK"
	case "status":
		up, q := gw.Router().Active()
		return fmt.Sprintf("OK generation=%q socket=%q quiescing=%t", up.Generation, up.Socket, q)
	default:
		return "ERR unknown command " + fields[0]
	}
}
