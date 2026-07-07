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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/blocklist"
	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/vm"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// Config holds the daemon configuration sourced from environment variables.
type Config struct {
	FirecrackerBin     string
	JailerBin          string
	KernelPath         string
	BaseRootfsPath     string
	SnapshotDir        string
	RunDir             string
	GRPCPort           int
	HostInterface      string
	TemplateBuilderBin string
	BoxdBinaryPath     string

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

	// SecretsProxySocket is the local secretsproxy daemon's control-RPC unix-socket path.
	// When empty, broker registration is skipped.
	SecretsProxySocket string

	// SecretsProxySandboxAddr is the host:port the sandbox writes into HTTPS_PROXY
	// to reach the local secretsproxy daemon. When empty, no proxy env var is injected.
	SecretsProxySandboxAddr string

	// Parsed form of SecretsProxySandboxAddr; wires the host firewall REDIRECT.
	SecretsProxySandboxDst  string
	SecretsProxySandboxPort uint16
}

func loadConfig() (Config, error) {
	port, err := strconv.Atoi(envOrDefault("GRPC_PORT", "50051"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid GRPC_PORT: %w", err)
	}

	cfg := Config{
		FirecrackerBin:          envOrDefault("FIRECRACKER_BIN", "/usr/local/bin/firecracker"),
		JailerBin:               envOrDefault("JAILER_BIN", "/usr/bin/jailer"),
		KernelPath:              requireEnv("KERNEL_PATH"),
		BaseRootfsPath:          requireEnv("BASE_ROOTFS_PATH"),
		SnapshotDir:             envOrDefault("SNAPSHOT_DIR", "/var/lib/sandbox/snapshots"),
		RunDir:                  envOrDefault("RUN_DIR", "/var/lib/sandbox/rundir"),
		GRPCPort:                port,
		HostInterface:           envOrDefault("HOST_INTERFACE", "eth0"),
		TemplateBuilderBin:      envOrDefault("TEMPLATE_BUILDER_BIN", "/usr/local/bin/template-builder"),
		BoxdBinaryPath:          envOrDefault("BOXD_BINARY_PATH", "/usr/local/bin/boxd"),
		HostID:                  envOrDefault("HOST_ID", "default"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		ControlPlaneURL:         os.Getenv("CONTROL_PLANE_URL"),
		SecretsProxySocket:      os.Getenv("SECRETSPROXY_SOCKET"),
		SecretsProxySandboxAddr: os.Getenv("SECRETSPROXY_SANDBOX_ADDR"),
	}

	if cfg.KernelPath == "" {
		return Config{}, fmt.Errorf("KERNEL_PATH environment variable is required")
	}
	if cfg.BaseRootfsPath == "" {
		return Config{}, fmt.Errorf("BASE_ROOTFS_PATH environment variable is required")
	}

	if cfg.SecretsProxySandboxAddr != "" {
		host, port, err := parseSecretsProxyAddr(cfg.SecretsProxySandboxAddr)
		if err != nil {
			return Config{}, fmt.Errorf("SECRETSPROXY_SANDBOX_ADDR %q: %w", cfg.SecretsProxySandboxAddr, err)
		}
		cfg.SecretsProxySandboxDst = host
		cfg.SecretsProxySandboxPort = port
	}

	return cfg, nil
}

// parseSecretsProxyAddr parses host:port; host must be an IPv4 literal because
// the nat REDIRECT rule it feeds can't resolve DNS.
func parseSecretsProxyAddr(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		return "", 0, fmt.Errorf("host %q must be an IPv4 literal", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("port %q must be 1-65535", portStr)
	}
	return host, uint16(port), nil
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
	multi := zerolog.MultiLevelWriter(os.Stdout, &sentrylog.Writer{})
	log := zerolog.New(multi).With().
		Timestamp().
		Str("service", "vmd").
		Logger()

	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: dsn, EnableLogs: true}); err != nil {
			log.Warn().Err(err).Msg("sentry.Init failed")
		} else {
			defer sentry.Flush(2 * time.Second)
		}
	}

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

	// Trap SIGHUP before any startup work. With ExecReload=kill -HUP on a
	// Type=simple unit, a reload can arrive mid-init; without this the default
	// SIGHUP action (terminate) would kill the daemon. The buffered signal is
	// dispatched to the blocklist reload once it's up (below).
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	lc := newLifecycle(log)

	// ---- Egress blocklist (optional) ----
	// VMD_EGRESS_BLOCKLIST_CONFIG points at the operator-supplied config
	// (feeds, pinned domains/CIDRs, blocked ports). Unset = no global
	// blocklist.
	var blockList *blocklist.Blocklist
	blocklistPath := os.Getenv("VMD_EGRESS_BLOCKLIST_CONFIG")
	// vmd is the daemon, so it owns and reconciles the shared egress port
	// chain even when no ports are configured (so disabling the feature
	// clears stale drops). template-builder must not pass this.
	netMgrOpts := []network.ManagerOption{network.WithEgressPortChainOwner()}
	if blocklistPath != "" {
		blCfg, err := blocklist.LoadConfig(blocklistPath)
		if err != nil {
			log.Fatal().Err(err).Str("path", blocklistPath).Msg("failed to load egress blocklist config")
		}
		blockList = blocklist.New(blCfg, log)
		netMgrOpts = append(netMgrOpts, network.WithBlockedEgressPorts(blCfg.BlockedEgressPorts))
		log.Info().Str("path", blocklistPath).Int("feeds", len(blCfg.DomainFeeds)).Int("blocked_ports", len(blCfg.BlockedEgressPorts)).Msg("egress blocklist configured")
	} else {
		// Feature disabled — drop any host egress-block table a previous run
		// installed so its CIDR drops stop affecting sandbox egress. The
		// per-VM port-drop chain self-heals: installHostFirewall always runs
		// and ClearChain empties it when no ports are configured.
		if err := network.RemoveHostEgressBlock(); err != nil {
			log.Debug().Err(err).Msg("removing stale host egress block table")
		}
	}

	// ---- Guest DNS redirect (optional) ----
	// VMD_DNS_REDIRECT_PORT routes all sandbox DNS (TCP+UDP/53) to a
	// resolver the operator runs on that host port, regardless of the
	// nameservers configured inside the guest. Unset = guest DNS goes
	// out unmodified.
	if v := os.Getenv("VMD_DNS_REDIRECT_PORT"); v != "" {
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil || port == 0 {
			log.Fatal().Str("value", v).Msg("VMD_DNS_REDIRECT_PORT must be a port number (1-65535)")
		}
		netMgrOpts = append(netMgrOpts, network.WithDNSRedirectPort(uint16(port)))
		log.Info().Uint64("port", port).Msg("guest DNS redirect enabled")
	}

	// ---- Network manager + host firewall ----
	netMgrOpts = append(netMgrOpts,
		network.WithSecretsProxyAddr(cfg.SecretsProxySandboxDst, cfg.SecretsProxySandboxPort))
	netMgr, err := network.NewManager(ctx, cfg.HostInterface, log, netMgrOpts...)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize network manager")
	}
	lc.addCloser("network manager", func(_ context.Context) error { return netMgr.Close() })

	// ---- VM manager ----
	maxRestores, _ := strconv.Atoi(envOrDefault("VMD_MAX_CONCURRENT_RESTORES", "100"))
	uffdEnabled := envOrDefault("VMD_UFFD_ENABLED", "true") != "false"
	uffdPrefetchEnabled := envOrDefault("VMD_UFFD_PREFETCH_ENABLED", "true") != "false"
	uffdRecordMaxSeconds, _ := strconv.Atoi(envOrDefault("VMD_UFFD_RECORD_MAX_SECONDS", "10"))
	resumeUffdEnabled := envOrDefault("VMD_RESUME_UFFD", "false") == "true"
	verifySnapshotEnabled := envOrDefault("VMD_VERIFY_SNAPSHOT_ENABLED", "false") == "true"
	incrementalSnapshotEnabled := envOrDefault("VMD_INCREMENTAL_SNAPSHOT", "false") == "true"
	handlerDeathAbortEnabled := envOrDefault("VMD_HANDLER_DEATH_ABORT", "false") == "true"

	mgr, err := vm.NewManager(vm.ManagerConfig{
		FirecrackerBin:             cfg.FirecrackerBin,
		JailerBin:                  cfg.JailerBin,
		KernelPath:                 cfg.KernelPath,
		BaseRootfsPath:             cfg.BaseRootfsPath,
		SnapshotDir:                cfg.SnapshotDir,
		RunDir:                     cfg.RunDir,
		TemplateBuilderBin:         cfg.TemplateBuilderBin,
		BoxdBinaryPath:             cfg.BoxdBinaryPath,
		HostInterface:              cfg.HostInterface,
		MaxConcurrentRestores:      maxRestores,
		UffdEnabled:                uffdEnabled,
		UffdPrefetchEnabled:        uffdPrefetchEnabled,
		UffdRecordMaxSeconds:       uffdRecordMaxSeconds,
		ResumeUffdEnabled:          resumeUffdEnabled,
		VerifySnapshotEnabled:      verifySnapshotEnabled,
		IncrementalSnapshotEnabled: incrementalSnapshotEnabled,
		HandlerDeathAbortEnabled:   handlerDeathAbortEnabled,
	}, netMgr, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize VM manager")
	}

	// ---- TCP egress proxy ----
	// Must be set before ReattachAll or any VM operations so domain
	// filtering is active from the start.
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
	if blockList != nil {
		egressProxy.SetBlocklist(blockList)
		// Mirror IP/CIDR entries into a host-level nftables drop set so they
		// are enforced on every port, not just the proxied web ports.
		hostBlock, err := network.NewHostEgressBlock(log)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to install host egress block table")
		}
		blockList.SetCIDRSink(hostBlock.UpdateCIDRs)
		// Seed the host drop set from the state-seeded snapshot now, before
		// the first feed fetch (which may block up to feedFetchTimeout per
		// feed). Otherwise seeded CIDRs go unenforced on non-proxied ports
		// during the startup window.
		hostBlock.UpdateCIDRs(blockList.CIDRs())
		lc.addCloser("host egress block", func(_ context.Context) error { return hostBlock.Close() })
		lc.start("egress blocklist", func() error { return blockList.Start(ctx) })
	}
	lc.start("egress proxy", func() error { return egressProxy.Start(ctx) })

	// ---- BoltDB state store ----
	statePath := envOrDefault("VMD_STATE_PATH", filepath.Join(filepath.Dir(cfg.RunDir), "vmd.db"))
	stateStore, err := vm.OpenStateStore(statePath)
	if err != nil {
		log.Fatal().Err(err).Str("path", statePath).Msg("failed to open state store")
	}
	mgr.SetStateStore(stateStore)
	lc.addCloser("state store", func(_ context.Context) error { return stateStore.Close() })

	// ---- gRPC server ----
	// Bind and serve BEFORE the reattach so a restart doesn't refuse connections
	// during it; requests are gated Unavailable until startupReady flips.
	startupReady := &atomic.Bool{}
	notReady := func() error {
		return status.Error(codes.Unavailable, "vmd is starting up (reattaching VMs), retry shortly")
	}
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Int("port", cfg.GRPCPort).Msg("failed to listen")
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(64<<20), // 64 MiB
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if !startupReady.Load() {
				return nil, notReady()
			}
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if !startupReady.Load() {
				return notReady()
			}
			return handler(srv, ss)
		}),
	)
	adapter := vm.NewGRPCAdapter(mgr).
		WithSecretsBroker(cfg.SecretsProxySocket, cfg.SecretsProxySandboxAddr)
	vmdpb.RegisterVMDaemonServer(grpcServer, adapter)
	if cfg.SecretsProxySocket != "" {
		log.Info().
			Str("socket", cfg.SecretsProxySocket).
			Str("sandbox_addr", cfg.SecretsProxySandboxAddr).
			Msg("secretsproxy daemon integration enabled")
	}
	lc.start("grpc server", func() error {
		log.Info().Int("port", cfg.GRPCPort).Msg("gRPC server listening")
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			return fmt.Errorf("grpc serve: %w", err)
		}
		return nil
	})
	// Closer is registered later (after the manager/pool closers) so it runs
	// first on shutdown — stop accepting before those are torn down.

	// ---- Startup network prep (fast; must precede StartPool) ----
	// Reserve slots held by existing VMs (so the pool can't hand out a colliding
	// one) and sweep leaked namespaces. The per-VM reattach runs in the background
	// below; VMs it hasn't reached are loaded on-demand on first request.
	mgr.ReserveStartupSlots(ctx)
	mgr.SweepStartupOrphanNamespaces()

	// ---- Pre-allocate network slots ----
	// Warm buffer of network namespaces so creation claims off the hot path.
	// StartPool returns immediately and fills in the background, so the gate
	// below isn't held for the fill; creates fall back to on-demand until warm.
	netPoolFresh, _ := strconv.Atoi(envOrDefault("VMD_NET_POOL_FRESH_SIZE", "128"))
	netPool := netMgr.StartPool(ctx, network.PoolConfig{
		NewSize: netPoolFresh,
	})
	lc.addCloser("network pool", func(_ context.Context) error { netPool.Stop(); return nil })

	// ---- Background full reattach ----
	// Off the critical path (requests load their VM on demand); proactively
	// populates the map and GCs stale records. Plain goroutine, not an lc
	// service — a completing lc service trips lifecycle shutdown.
	go func() {
		defer sentrylog.Recover("startup reattach")
		reattached, stale := mgr.ReattachAll(ctx)
		if reattached > 0 || stale > 0 {
			log.Info().Int("reattached", reattached).Int("stale", stale).Msg("startup reattach complete")
		}
	}()

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

		// Per-connection egress logging. Drops on a full buffer rather than
		// back-pressuring the proxy's data path.
		flowSink := network.NewSQLFlowSink(reconcilerDB, network.SQLFlowSinkOptions{})
		egressProxy.SetFlowSink(flowSink)
		lc.addCloser("net_flow sink", func(closeCtx context.Context) error {
			return flowSink.Shutdown(closeCtx)
		})
		log.Info().Msg("egress flow logging enabled")
	} else {
		log.Warn().Msg("DATABASE_URL unset — reconciler will run in BoltDB↔systemd-only mode")
	}

	// ---- Continuous reconciler ----
	reconcilerCfg := vm.DefaultReconcilerConfig()
	reconcilerCfg.HostID = cfg.HostID
	reconcilerCfg.DB = reconcilerDB
	reconcilerCfg.DiskScanEnabled = envOrDefault("VMD_DISK_SCAN", "true") != "false"
	// Reclamation is opt-in: the detect-only numbers must be validated on prod
	// before this is flipped on. Defaults off.
	reconcilerCfg.DiskReclaimEnabled = envOrDefault("VMD_DISK_RECLAIM", "false") == "true"
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
	// disk so the next startup can reattach via the build pipeline's
	// on-disk snapshot layout.

	// ---- Orphan build cleanup ----
	// Orphan-build reclamation is owned by the controlplane reconciler;
	// vmd has no DB context to decide safely on its own.

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

	// Registered last so it closes first on SIGTERM: stop accepting requests
	// before the VM manager and network pool are torn down.
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

	// Fast pre-serve init is done (slots reserved, namespaces swept, pool fill
	// backgrounded). Open the gate; pool warm-up and full reattach continue in
	// the background, and requests load any not-yet-reattached VM on demand.
	startupReady.Store(true)
	log.Info().Msg("startup complete — gRPC serving requests")

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

	// SIGHUP (ExecReload, trapped above) reloads the egress blocklist config
	// without a restart — domains + CIDRs; blocked ports still need a restart.
	go func() {
		for {
			select {
			case <-hupCh:
				if blockList != nil && blocklistPath != "" {
					log.Info().Msg("SIGHUP: reloading egress blocklist config")
					blockList.Reload(blocklistPath)
				} else {
					log.Info().Msg("SIGHUP: no egress blocklist configured, nothing to reload")
				}
			case <-ctx.Done():
				return
			}
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
