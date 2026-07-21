# Security Linear importer

This tool synchronizes the August-readiness issue manifest into the **Superserve** team and
the **Security Engineering Program** project. It uses two deterministic passes:
roots are created or updated first, then children are created or updated with
their resolved parent IDs. The local state file makes repeat runs idempotent.

## Manifest

The repository includes `security-program/issues.json`. Edit that file when the
program scope changes.

Each key must be unique. `parentKey` refers to another issue in the same
manifest. The importer does not make broad workspace queries: it resolves only
the named team and project, unless IDs are supplied through environment
variables or the local state file.

## Usage

From this directory, dry-run (the default) with:

```sh
node src/index.mjs --manifest security-program/issues.json
```

Dry-run assigns in-memory `dry-run:<key>` IDs, so child payloads can be
inspected without contacting Linear. It does not write those temporary IDs to
the state file. The state file is written after an apply run and is ignored by
git.

Idempotency is based on that local state file. Preserve
`security-program/.linear-state.json` between apply runs and do not commit it;
if it is deleted or unavailable, the importer cannot identify previously
created issues and will create duplicates.

To apply changes, provide an API key and an explicit confirmation flag:

```sh
LINEAR_API_KEY=lin_api_... node src/index.mjs \
  --manifest security-program/issues.json --apply --yes
```

Optional `LINEAR_TEAM_ID` and `LINEAR_PROJECT_ID` skip name resolution. The
state file can be relocated with `--state`. Never use `--apply` unless the
target workspace and manifest have been reviewed.

## Checks

```sh
npm test
npm run check
```
