# Contributing to Superserve Sandbox

Thanks for your interest in contributing.

## Developer Certificate of Origin (DCO)

We use the DCO instead of a CLA. By contributing, you certify that you have the right to submit your contribution under the Apache 2.0 license. Sign off your commits:

```bash
git commit -s -m "your commit message"
```

## Development setup

```bash
# Prerequisites: Go 1.25+, Docker
docker compose up -d db
make migrate-up
make run-controlplane
```

VMD requires a Linux host with KVM. VMD + boxd setup docs coming soon.

### Code generation

```bash
make generate
```

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Make your changes with tests where applicable
3. Run `make lint` and `make test`
4. Sign off your commits (`git commit -s`)
5. Open a pull request

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please do not open public issues for vulnerabilities.
