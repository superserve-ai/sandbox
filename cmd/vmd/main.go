package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/vm"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// Config holds the daemon configuration sourced from environment variables.
type Config struct {
	FirecrackerBin string
	JailerBin      string
	KernelPath     string
	BaseRootfsPath string
	SnapshotDir    string
	RunDir         string
	GRPCPort       int
	HostInterface  string

	// HostID identifies this bare-metal host in the `host` table. Used by
	// the reconciler to scope its DB queries ("sandboxes on my host").
	HostID string

	// DatabaseURL is optional. When set, the reconciler does three-way
	// reconciliation (BoltDB ↔ systemd ↔ control plane DB) and writes
	// audit log entries. When unset, the reconciler only detects drift
	// between BoltDB and systemd.
	DatabaseURL string

	// ControlPlaneURL is the base URL of the control plane API. Used by
	// the heartbeat goroutine to POST liveness. Optional — if unset,
	// heartbeat is disabled.
	ControlPlaneURL string
}

func loadConfig() (Config, error) {
	port, err := strconv.Atoi(envOrDefault("GRPC_PORT", "50051"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid GRPC_PORT: %w", err)
	}

	cfg := Config{
		FirecrackerBin: envOrDefault("FIRECRACKER_BIN", "/usr/local/bin/firecracker"),
		JailerBin:      envOrDefault("JAILER_BIN", "/usr/bin/jailer"),
		KernelPath:     requireEnv("KERNEL_PATH"),
		BaseRootfsPath: requireEnv("BASE_ROOTFS_PATH"),
		SnapshotDir:    envOrDefault("SNAPSHOT_DIR", "/var/lib/sandbox/snapshots"),
		RunDir:         envOrDefault("RUN_DIR", "/var/lib/sandbox/rundir"),
		GRPCPort:       port,
		HostInterface:  envOrDefault("HOST_INTERFACE", "eth0"),
		HostID:          envOrDefault("HOST_ID", "default"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		ControlPlaneURL: os.Getenv("CONTROL_PLANE_URL"),
	}

	if cfg.KernelPath == "" {
		return Config{}, fmt.Errorf("KERNEL_PATH environment variable is required")
	}
	if cfg.BaseRootfsPath == "" {
		return Config{}, fmt.Errorf("BASE_ROOTFS_PATH environment variable is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	return os.Getenv(key)
}

// ---------------------------------------------------------------------------
// Service lifecycle
// ---------------------------------------------------------------------------
//
// A tiny orchestration helper that manages long-running background services
// with named startup and LIFO shutdown. Every service has a name so shutdown
// logs are clear, and closers run in reverse registration order so that
// dependent services are shut down before the services they depend on.
//
// Keeps the main() flow flat: register a service, push its closer, done.
// If any service exits (successfully or with an error), shutdown is signaled
// to the rest via the shared root context.

type serviceCloser struct {
	name  string
	close func(ctx context.Context) error
}

type lifecycle struct {
	log zerolog.Logger

	mu       sync.Mutex
	closers  []serviceCloser
	firstErr error
	errName  string

	done   chan struct{}
	doneCh sync.Once
}

func newLifecycle(log zerolog.Logger) *lifecycle {
	return &lifecycle{
		log:  log,
		done: make(chan struct{}),
	}
}

// start launches fn in a background goroutine under the service name.
// If fn returns (for any reason) the lifecycle's shutdown signal is raised.
// The first non-nil error is recorded and surfaced on shutdown.
func (lc *lifecycle) start(name string, fn func() error) {
	lc.log.Info().Str("service", name).Msg("service starting")
	go func() {
		err := fn()
		lc.mu.Lock()
		if err != nil && lc.firstErr == nil {
			lc.firstErr = err
			lc.errName = name
		}
		lc.mu.Unlock()
		if err != nil {
			lc.log.Error().Err(err).Str("service", name).Msg("service exited with error")
		} else {
			lc.log.Info().Str("service", name).Msg("service exited")
		}
		lc.signalShutdown()
	}()
}

// addCloser registers a cleanup callback. Closers run on shutdown in
// reverse order of registration (LIFO) so later-started services tear
// down before earlier ones.
func (lc *lifecycle) addCloser(name string, close func(ctx context.Context) error) {
	lc.mu.Lock()
	lc.closers = append(lc.closers, serviceCloser{name: name, close: close})
	lc.mu.Unlock()
}

// signalShutdown is idempotent — closing an already-closed channel panics.
func (lc *lifecycle) signalShutdown() {
	lc.doneCh.Do(func() { close(lc.done) })
}

// wait blocks until shutdown is signaled (by a service exit, context
// cancellation, or an external caller).
func (lc *lifecycle) wait(ctx context.Context) {
	select {
	case <-lc.done:
	case <-ctx.Done():
		lc.signalShutdown()
	}
}

// shutdown runs every registered closer in reverse order, collecting
// errors but never stopping on the first failure — we want every
// resource to get a chance to clean up.
func (lc *lifecycle) shutdown(ctx context.Context) {
	lc.mu.Lock()
	closers := slices.Clone(lc.closers)
	lc.mu.Unlock()
	slices.Reverse(closers)

	for _, c := range closers {
		lc.log.Info().Str("service", c.name).Msg("closing")
		if err := c.close(ctx); err != nil {
			lc.log.Error().Err(err).Str("service", c.name).Msg("close returned error")
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// Structured logging with zerolog — unix timestamp, caller info enabled.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "vmd").
		Logger()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	log.Info().
		Str("firecracker_bin", cfg.FirecrackerBin).
		Str("kernel_path", cfg.KernelPath).
		Int("grpc_port", cfg.GRPCPort).
		Msg("starting VM daemon")

	// Validate required system tools are available.
	for _, tool := range []string{"ip", "unshare", "sh", "mount", "cp", "sysctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			log.Fatal().Str("tool", tool).Msg("required system tool not found in PATH")
		}
	}

	// Ensure required directories exist.
	for _, dir := range []string{cfg.SnapshotDir, cfg.RunDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatal().Err(err).Str("dir", dir).Msg("failed to create directory")
		}
	}

	// Root context — cancelled on signal or on the first service exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lc := newLifecycle(log)

	// ---- Network manager + host firewall ----
	netMgr, err := network.NewManager(ctx, cfg.HostInterface, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize network manager")
	}
	lc.addCloser("network manager", func(_ context.Context) error { return netMgr.Close() })

	// ---- Pre-allocate network slots ----
	// Keeps 5 ready-to-use network namespaces so sandbox creation grabs
	// one in microseconds instead of running ~11 shell commands (~10-30ms).
	netPool := netMgr.StartPool(ctx, network.PoolConfig{})
	lc.addCloser("network pool", func(_ context.Context) error { netPool.Stop(); return nil })

	// ---- VM manager ----
	mgr, err := vm.NewManager(vm.ManagerConfig{
		FirecrackerBin: cfg.FirecrackerBin,
		JailerBin:      cfg.JailerBin,
		KernelPath:     cfg.KernelPath,
		BaseRootfsPath: cfg.BaseRootfsPath,
		SnapshotDir:    cfg.SnapshotDir,
		RunDir:         cfg.RunDir,
	}, netMgr, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize VM manager")
	}

	// ---- BoltDB state store ----
	statePath := envOrDefault("VMD_STATE_PATH", filepath.Join(filepath.Dir(cfg.RunDir), "vmd.db"))
	stateStore, err := vm.OpenStateStore(statePath)
	if err != nil {
		log.Fatal().Err(err).Str("path", statePath).Msg("failed to open state store")
	}
	mgr.SetStateStore(stateStore)
	lc.addCloser("state store", func(_ context.Context) error { return stateStore.Close() })

	// ---- Reattach to running VMs from previous VMD lifetime ----
	reattached, stale := mgr.ReattachAll(ctx)
	if reattached > 0 || stale > 0 {
		log.Info().Int("reattached", reattached).Int("stale", stale).Msg("startup reattach complete")
	}

	// ---- Optional DB connection for the reconciler ----
	// VMD does not need the DB for its request path (that stays on gRPC).
	// The reconciler uses the DB for three-way drift detection and audit
	// logging. If DATABASE_URL is unset, the reconciler falls back to a
	// BoltDB ↔ systemd comparison only.
	var reconcilerDB *dbq.Queries
	if cfg.DatabaseURL != "" {
		dbPool, dbErr := pgxpool.New(ctx, cfg.DatabaseURL)
		if dbErr != nil {
			log.Fatal().Err(dbErr).Msg("failed to connect to database for reconciler")
		}
		if err := dbPool.Ping(ctx); err != nil {
			log.Fatal().Err(err).Msg("failed to ping database for reconciler")
		}
		reconcilerDB = dbq.New(dbPool)
		lc.addCloser("reconciler db pool", func(_ context.Context) error {
			dbPool.Close()
			return nil
		})
		log.Info().Msg("reconciler DB connection ready")
	} else {
		log.Warn().Msg("DATABASE_URL unset — reconciler will run in BoltDB↔systemd-only mode")
	}

	// ---- Continuous reconciler ----
	reconcilerCfg := vm.DefaultReconcilerConfig()
	reconcilerCfg.HostID = cfg.HostID
	reconcilerCfg.DB = reconcilerDB
	reconciler := vm.NewReconciler(mgr, reconcilerCfg)
	lc.start("reconciler", func() error { reconciler.Run(ctx); return nil })

	// ---- Heartbeat to control plane ----
	if cfg.ControlPlaneURL != "" {
		lc.start("heartbeat", func() error {
			vm.StartHeartbeat(ctx, vm.HeartbeatConfig{
				ControlPlaneURL: cfg.ControlPlaneURL,
				HostID:          cfg.HostID,
				Token:           os.Getenv("INTERNAL_API_TOKEN"),
			}, log)
			return nil
		})
	} else {
		log.Warn().Msg("CONTROL_PLANE_URL unset — heartbeat disabled")
	}

	lc.addCloser("vm manager: active sandboxes", func(_ context.Context) error {
		mgr.ShutdownAll()
		return nil
	})
	// Template files are NOT cleaned up on shutdown — they persist on
	// disk so the next startup can reuse them via hash caching instead
	// of cold-booting a new template (~3s saved per restart).

	// ---- TCP egress proxy ----
	// The nftables firewall in each sandbox namespace REDIRECTs TCP traffic
	// to these ports for HTTP Host header / TLS SNI inspection.
	const maxConnsPerSandbox = 256
	egressProxy := network.NewEgressProxy(
		network.DefaultHTTPProxyPort,
		network.DefaultTLSProxyPort,
		network.DefaultOtherProxyPort,
		maxConnsPerSandbox,
		log,
	)
	mgr.SetEgressProxy(egressProxy)
	netMgr.SetEgressProxy(egressProxy)
	lc.start("egress proxy", func() error { return egressProxy.Start(ctx) })

	// ---- Default template ----
	// Boot a throwaway VM from the base image, snapshot it, keep the
	// snapshot on disk. Every subsequent CreateVM restores from this
	// template snapshot instead of cold-booting (~90-200ms vs ~933ms).
	if err := mgr.InitDefaultTemplate(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize default template")
	}

	// ---- Local HTTP server (proxy resolver) ----
	// Listens on localhost:9090. The edge proxy queries this to resolve
	// instanceID → vmIP before forwarding data-plane traffic.
	localHTTP := vm.NewLocalHTTPServer(mgr, log)
	lc.start("local http server", func() error {
		return localHTTP.ListenAndServe(ctx, "localhost:9090")
	})
	lc.addCloser("local http server", func(shutdownCtx context.Context) error {
		return localHTTP.Shutdown(shutdownCtx)
	})

	// ---- gRPC server ----
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Int("port", cfg.GRPCPort).Msg("failed to listen")
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(64 << 20), // 64 MiB
	)
	vmdpb.RegisterVMDaemonServer(grpcServer, vm.NewGRPCAdapter(mgr))
	lc.start("grpc server", func() error {
		log.Info().Int("port", cfg.GRPCPort).Msg("gRPC server listening")
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			return fmt.Errorf("grpc serve: %w", err)
		}
		return nil
	})
	lc.addCloser("grpc server", func(shutdownCtx context.Context) error {
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
			log.Info().Msg("gRPC server stopped gracefully")
		case <-shutdownCtx.Done():
			log.Warn().Msg("graceful shutdown timed out, forcing stop")
			grpcServer.Stop()
		}
		return nil
	})

	// ---- Wait for signal or service failure ----
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
			lc.signalShutdown()
		case <-ctx.Done():
		}
	}()

	lc.wait(ctx)
	cancel() // propagate cancellation to any service still blocked on ctx

	// ---- Run closers in LIFO order with a hard deadline ----
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	lc.shutdown(shutdownCtx)

	if lc.firstErr != nil {
		log.Error().Err(lc.firstErr).Str("service", lc.errName).Msg("VM daemon shutdown after service error")
		os.Exit(1)
	}
	log.Info().Msg("VM daemon shutdown complete")
}
