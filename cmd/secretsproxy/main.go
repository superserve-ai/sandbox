package main

import (
	"context"
	"encoding/base64"
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/secretsproxy"
)

const (
	defaultListenAddr = "0.0.0.0:9090"
	defaultSocketPath = "/run/secretsproxy.sock"
)

func main() {
	var (
		listenAddr = flag.String("listen", envOr("SECRETSPROXY_LISTEN", defaultListenAddr), "forward HTTP listen address")
		socketPath = flag.String("socket", envOr("SECRETSPROXY_SOCKET", defaultSocketPath), "unix socket path for control RPCs")
	)
	flag.Parse()

	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Str("svc", "secretsproxy").Logger()

	if err := run(*listenAddr, *socketPath); err != nil {
		log.Fatal().Err(err).Msg("secretsproxy exited")
	}
}

func run(listenAddr, socketPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	jwtKey, err := loadJWTKey()
	if err != nil {
		return fmt.Errorf("load JWT key: %w", err)
	}
	verifier, err := secrets.NewSigner(jwtKey, envOr("SECRETSPROXY_JWT_KID", "v1"),
		envOr("SECRETSPROXY_JWT_ISSUER", "superserve-control-plane"),
		envOr("SECRETSPROXY_JWT_AUDIENCE", "secretsproxy"),
		time.Hour)
	if err != nil {
		return fmt.Errorf("init signer: %w", err)
	}

	queries, dbCleanup, err := openDB(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("DB connection unavailable; audit writes skipped")
		queries = nil
	}
	if dbCleanup != nil {
		defer dbCleanup()
	}

	state := secretsproxy.NewState()
	registry := secretsproxy.NewRegistry(secretsproxy.AnthropicConfig)
	audit := secretsproxy.NewAuditWriter(queries)
	go audit.Run(ctx)

	server := secretsproxy.NewServer(state, verifier, registry, audit)
	control := secretsproxy.NewControlServer(state)

	forwardSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	controlSrv := &http.Server{
		Handler:           control.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	_ = os.Remove(socketPath)
	unixLn, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	log.Info().Str("listen", listenAddr).Str("socket", socketPath).Msg("secretsproxy ready")

	errCh := make(chan error, 2)
	go func() { errCh <- forwardSrv.Serve(tcpLn) }()
	go func() { errCh <- controlSrv.Serve(unixLn) }()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("server error")
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = forwardSrv.Shutdown(shutdownCtx)
	_ = controlSrv.Shutdown(shutdownCtx)
	return nil
}

// loadJWTKey reads SECRETSPROXY_JWT_KEY: raw bytes, or "base64:..."
// for binary keys.
func loadJWTKey() ([]byte, error) {
	v := os.Getenv("SECRETSPROXY_JWT_KEY")
	if v == "" {
		return nil, errors.New("SECRETSPROXY_JWT_KEY env var is required")
	}
	if strings.HasPrefix(v, "base64:") {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "base64:"))
	}
	return []byte(v), nil
}

func openDB(ctx context.Context) (*db.Queries, func(), error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, nil, errors.New("DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("parse DSN: %w", err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	return db.New(pool), pool.Close, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
