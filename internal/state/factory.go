package state

import "fmt"

// Backend names a durable /state provider implementation.
type Backend string

const (
	// BackendLocal is the on-disk directory reference provider (dev/test). Default.
	BackendLocal Backend = "local"
	// BackendLocalBlock is the on-disk BLOCK-DEVICE reference provider: each
	// identity is a formatted ext4 image vmd attaches as the /state drive. This
	// is the Firecracker-native durable-disk path (vs the directory provider,
	// which has no in-VM transport on Firecracker).
	BackendLocalBlock Backend = "local-block"
	// BackendArchil is the Archil NFSv3 adapter (stub until creds land).
	BackendArchil Backend = "archil"
	// BackendMesa is the Mesa SDK/FUSE adapter (stub until creds land).
	BackendMesa Backend = "mesa"
)

// Config selects and configures a Provider. Only the fields relevant to the
// chosen Backend need be set.
type Config struct {
	// Backend selects the implementation. Empty defaults to BackendLocal.
	Backend Backend

	// BaseDir is the host directory rooting LocalProvider / LocalBlockProvider
	// state. Required for BackendLocal and BackendLocalBlock.
	BaseDir string

	// StateImageMiB sizes a fresh /state image for BackendLocalBlock.
	// <= 0 uses DefaultStateImageMiB.
	StateImageMiB int

	// Archil holds Archil adapter configuration (BackendArchil).
	Archil ArchilConfig

	// Mesa holds Mesa adapter configuration (BackendMesa).
	Mesa MesaConfig
}

// NewProvider constructs the Provider selected by cfg.Backend, defaulting to the
// local reference provider. The Archil and Mesa adapters are constructed
// (so the rest of the Actor stack can hold a stable Provider), but their
// methods return ErrNotConfigured until their credentials are wired up.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Backend {
	case "", BackendLocal:
		return NewLocalProvider(cfg.BaseDir)
	case BackendLocalBlock:
		return NewLocalBlockProvider(cfg.BaseDir, cfg.StateImageMiB)
	case BackendArchil:
		return NewArchilProvider(cfg.Archil), nil
	case BackendMesa:
		return NewMesaProvider(cfg.Mesa), nil
	default:
		return nil, fmt.Errorf("state: unknown backend %q", cfg.Backend)
	}
}
