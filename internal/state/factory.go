package state

import "fmt"

// Backend names a durable /state provider implementation.
type Backend string

const (
	// BackendLocal is the on-disk reference provider (dev/test). Default.
	BackendLocal Backend = "local"
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

	// BaseDir is the host directory rooting LocalProvider state.
	// Required for BackendLocal.
	BaseDir string

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
	case BackendArchil:
		return NewArchilProvider(cfg.Archil), nil
	case BackendMesa:
		return NewMesaProvider(cfg.Mesa), nil
	default:
		return nil, fmt.Errorf("state: unknown backend %q", cfg.Backend)
	}
}
