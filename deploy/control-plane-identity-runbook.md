# Control-plane identity isolation

This runbook is the operator contract for the three serving cells. Terraform
creates one Cloud Run runtime identity per cell, grants it the cell's exact
runtime secret set, and grants `roles/storage.objectViewer` on that cell's
backup bucket. The bucket is cell-local; the binding is read-only and provides
no create, overwrite, or delete access.

## Published contract

| Cell | Cloud Run identity | Backup bucket | Deployment principal (act-as + token creator) | Host identity |
| --- | --- | --- | --- | --- |
| staging | `superserve-cp-staging` | `superserve-artifact-backup-staging-usc1` | environment GitHub Actions service account | legacy `superserve-api` remains on the draining host |
| production use | `superserve-cp-use4` | `superserve-artifact-backup-use4` | environment GitHub Actions service account | dedicated `vmd-runtime-production-use4` |
| production usw2 | `superserve-cp-usw2` | `superserve-artifact-backup-usw2` | environment GitHub Actions service account | dedicated `vmd-runtime-production-usw2` |

The authoritative rendered values are the `controlplane_identity_contract`
outputs from each environment root. The output includes the runtime identity,
bucket, allowed storage permissions and object prefix, secret IDs, deployment
identity, deployment act-as and token-creation permissions, KMS grant principal
and role, and KMS owner. The KMS key is the shared credentials key for both production
cells; its `roles/cloudkms.cryptoKeyEncrypterDecrypter` grant is applied by the
central owner through the rollout workflow (outside the production Terraform
identity) before either production cutover.

The serving identities must never be attached to a VMD instance. VMD grants
remain environment-owned: staging's legacy host keeps its existing writer
grant while it drains, and the dedicated production VMD identities keep their
existing create/read grants. No new host grant or host impersonation grant is
part of this migration.

The regular production API deployment workflows update Cloud Run with
`--no-traffic`, then run `scripts/verify-control-plane-kms.sh`. That check
uses the centrally authorized owner to apply the per-runtime
`roles/cloudkms.cryptoKeyEncrypterDecrypter` binding, verifies every production
Secret Manager binding as that same runtime identity, and performs an
encrypt/decrypt round trip before the workflow routes the revision.

## Migration order

1. From each environment root, review `terraform plan` and confirm the new
   service account, exact secret set, bucket viewer grant, metric-writer grant,
   and scoped GitHub Actions act-as and token-creation grants. Confirm no VMD service account is a
   `reader_members` entry.
2. Run the manually confirmed
   `.github/workflows/control-plane-identity-rollout.yml` with `confirm=apply`.
   Production environments must provide the centrally authorized
   `KMS_POLICY_OWNER_SERVICE_ACCOUNT` secret; the deployment identity only
   impersonates that owner for the key binding. Before rollout, the central KMS
   policy owner must grant the environment deployment identity
   `roles/iam.serviceAccountTokenCreator` on that owner service account; this
   cross-root grant is out-of-band because production Terraform cannot manage
   the KMS policy owner. Terraform grants the same token-creation role on each
   dedicated runtime identity so the verifier can run its GCS, Secret Manager,
   and runtime KMS probes.
   The workflow is deliberately serial: staging, production use4, then
   production usw2. Each stage captures the serving revision before apply,
   applies and validates its Terraform plan, verifies the deployed identity,
   and uploads a private evidence artifact. A failed stage blocks later cells.
3. For each production stage, Terraform first creates the new identity and
   revision without routing traffic to it. The central KMS owner grant is then
   applied before cutover. The verifier gates the stage on a runtime-identity
   KMS encrypt/decrypt round trip as well as same-cell manifest/reference
   reads, cross-cell list denial, deterministic write/delete denial, Secret
   Manager access, effective IAM analysis, deployment act-as, and the
   centrally owned KMS binding. It also requires the latest ready revision to
   have 100% traffic under the dedicated identity.
4. Keep the old shared production runner grants until both old revisions are
   drained and the dependency audit below is complete. The workflow's failure
   trap routes traffic back to the captured revision and uploads the rollback
   result even when verification fails.
5. After the drain, remove only obsolete shared control-plane grants. Do not
   remove a grant that a legacy host, restore tool, GC job, or rollback
   revision still uses. In particular, staging's `superserve-api` host grant
   stays until that host is separately migrated.

Cloud Run rollout failure leaves the old revision serving. Do not revoke the
old identity's secret/KMS permissions until the new revision is ready and
positive checks have passed. To roll back, route traffic to the last known
good revision, restore the old identity's grants if they were already removed,
and repeat the checks before retrying the cutover.

## Durable evidence gate

The workflow artifact is the rollout record; local output or a green Terraform
plan is not deployment evidence. Every cell artifact must contain:

* `contract.json` — the applied Terraform identity/bucket/secret/KMS contract;
* `kms-grant.txt` — the central-owner grant recorded before production
  cutover, including the identity, key, and role;
* `revision-traffic.json` — the deployed runtime identity, latest-ready
  revision, and 100% traffic observation;
* `evidence.json` — an indexed PASS row for every command, including the
  positive manifest/reference reads, each negative probe, Secret Manager,
  bucket/project/service-account IAM, effective IAM analysis, KMS policy, and
  KMS encrypt/decrypt probe (where configured);
* `commands/` — stdout/stderr captured without secret values;
* `legacy-grant-audit.txt` — the dependency audit and owner decision for every
  old grant; and
* `rollback.txt` plus rollback command output. A successful stage records the
  available rollback revision; a failed stage records the revision restored by
  the trap.

Artifacts are retained privately with the workflow run. The release owner must
link the artifact, Terraform plan/apply, and UTC observation time in the change
record before declaring a cell complete. A missing artifact or any FAIL row is
an incomplete migration, even if the service health endpoint responds.
The workflow also fails closed when `evidence.json` is missing any required
PASS row, including one for every unchanged host principal's inability to
impersonate the serving identity; an uploaded artifact alone is not approval.

The verifier discovers a real generation manifest at
`templates/<template>/<build>/<generation>/manifest.json` and reads every
artifact named by its `files[*].object` entries. If a manifest uses a format
without discoverable object URIs, rerun it with one `--referenced-object`
argument per manifest reference; do not substitute a made-up path.

## Verification checklist

For each cell, record the command output and timestamp in the rollout record:

```sh
python3 scripts/verify-control-plane-identity.py \
  --cell CELL --project PROJECT --region REGION --service SERVICE \
  --contract-file CONTRACT.json --evidence-dir EVIDENCE_DIR \
  --kms-owner KMS_POLICY_OWNER_SERVICE_ACCOUNT \
  --other-bucket OTHER_CELL_BUCKET
```

The verifier discovers the actual generation `manifest.json` object, reads
each referenced artifact, creates and validates its own deterministic write
probe, and confirms that the existing manifest chosen as the delete target is
present before attempting the delete. It fails unless every negative command
returns a permission-denied response; a missing local probe or missing object
is not a negative IAM result.

Also verify that the deployment principal can update the Cloud Run service with
the new identity and mint credentials as that identity for the probes, that the
runtime can access every rendered Secret Manager secret, and that the control
plane's existing KMS-dependent operation still succeeds. Inspect effective IAM
(including inherited project/folder grants and service-account impersonation)
before declaring the negative checks complete.

For the effective audit, retain the verifier's
`gcloud asset analyze-iam-policy --scope=projects/PROJECT ...` output together
with the direct project, bucket, managed-folder, and service-account policies. In the cleanup
row, record `removed` or `retained-with-dependency`, the exact principal and
role, the dependency owner, and the observation time. Only rows marked
`removed` after the old revision is drained may be revoked; rows needed by the
staging host, restore/GC tooling, or rollback remain explicitly retained.
