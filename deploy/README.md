# Deployment registry

This directory owns **software rollout configuration**. Terraform owns infrastructure shape under `infra/`; deployment workflows own which built release is running on each API service and each ready VMD host.

The boundary is intentional:

- Terraform creates and imports durable infrastructure: networks, Cloud Run services, load balancers, buckets, service accounts, firewall rules, and host resources.
- GitHub Actions/CD builds release artifacts once and deploys the same release to every target listed in `deploy/environments.yaml`.
- Host bootstrap/config management makes a host ready. Deployment discovery must only target ready hosts.

## Release flow

On merge to `main`, deployment should follow this shape:

1. Build the release once from the commit SHA.
2. Publish immutable artifacts:
   - API container image by digest, not a mutable tag.
   - Host binaries (`vmd`, `boxd`, `proxy`, `secretsproxy`, etc.) with checksums.
   - Optional template/rootfs/kernel metadata when those are part of the release.
3. Create a release manifest that records the exact artifact versions.
4. Read `deploy/environments.yaml`.
5. Deploy that same manifest to each enabled target.
6. Verify each target.
7. Record deployment results as a GitHub Actions artifact or, later, in Postgres.

Build once, deploy many, verify all.

## Host selection

Do not deploy to a host merely because it exists. Host deployment jobs should only target hosts that are explicitly marked ready for that environment/region.

Recommended labels:

```text
environment=<environment>
region=<gcp-region>
sandbox_role=vmd
sandbox_status=ready
```

Avoid using `component=vmd` as the only selector once multiple regions or provisioning states exist. It is too broad and can pick up half-prepared hosts.

## Terraform outputs vs deployment registry

Terraform may output useful target information, but the deployment registry is the deployer's stable input. When Terraform creates a new environment, update `deploy/environments.yaml` after the infrastructure target names are reviewed.

Terraform should not:

- decide which git SHA is active;
- copy host binaries;
- restart `vmd` or `proxy`;
- write deployment success/failure records;
- put half-bootstrapped hosts into deployment discovery.

GitHub Actions should not:

- create networks or load balancers;
- create/import buckets or IAM;
- mutate Terraform state;
- route traffic to hosts that have not passed bootstrap validation.

## Deployment record

The first implementation can store deployment results as GitHub Actions artifacts. A later implementation should write them to a durable deployment ledger, for example:

```text
release_id
git_sha
environment
region
component
target
desired_version
observed_version
status
started_at
finished_at
error
```

The ledger is how operators answer:

- Which release is active in each region?
- Which hosts are stale?
- Which target failed deployment?
- Is staging/prod/new-region in sync?
