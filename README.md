# Superserve Sandbox

The infrastructure powering [Superserve](https://superserve.ai) sandboxes — fast, isolated VM environments for AI agents.

## Overview

Superserve Sandbox provides sub-second VM cold starts using Firecracker microVMs and copy-on-write (COW) snapshot pools. It powers the Superserve sandbox API.

**Key components:**

| Component | Description |
|-----------|-------------|
| `cmd/controlplane` | REST API server — manages sandbox lifecycle |
| `cmd/vmd` | VM daemon — runs on bare metal, orchestrates Firecracker VMs |
| `cmd/boxd` | Guest agent — runs inside each VM over vsock |
| `internal/` | Core VM, snapshot, fork, and checkpoint logic |
| `proto/` | gRPC service definitions (vmd ↔ controlplane, boxd ↔ vmd) |
| `db/` | PostgreSQL migrations and sqlc-generated queries |

## Architecture

```
SDK / CLI
    │
    ▼
Control Plane (REST API)
    │  gRPC
    ▼
VMD (bare metal)
    │  vsock
    ▼
boxd (inside VM)
```

VMD uses Firecracker to launch microVMs. Snapshot pools pre-boot VMs so sandboxes start in milliseconds. COW overlays let multiple sandboxes fork from a single snapshot without duplicating disk state.

## Getting Started

### Prerequisites

- Go 1.25+
- Docker + Docker Compose (for local dev)
- Linux host with KVM for running VMD

### Local development (control plane only)

```bash
# Start PostgreSQL
docker compose up -d db

# Apply migrations
make migrate-up

# Run control plane
make run-controlplane
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We use the Developer Certificate of Origin (DCO) — no CLA required.

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built on [Firecracker](https://github.com/firecracker-microvm/firecracker) (Apache 2.0).
