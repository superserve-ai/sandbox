# Curated public templates

Each JSON file here defines one template available to every team. The
`cmd/seed-templates` tool reads these files and INSERTs them under the
system team identified by `SYSTEM_TEAM_ID`.

Seeding is idempotent on `(team_id, alias)` — re-running is safe; existing
rows are left untouched. To rebuild a template, bump something in its
`build_spec` (so the hash differs) and `POST /templates/:id/builds`.

## Adding a new template

1. Create a new `<alias>.json` here.
2. Validate it matches the `createTemplateRequest` shape (alias, vcpu,
   memory_mib, disk_mib, build_spec with from/steps/start_cmd/ready_cmd).
3. Run `make seed-templates` on a host that can reach the DB.

## Resource defaults

| Template | vCPU | RAM | Disk |
|---|---|---|---|
| python-3.11 | 1 | 1 GiB | 4 GiB |
| python-ml | 2 | 2 GiB | 4 GiB |
| node-22 | 1 | 1 GiB | 4 GiB |
| ubuntu-24.04 | 1 | 1 GiB | 4 GiB |
| code-interpreter | 2 | 2 GiB | 8 GiB |
