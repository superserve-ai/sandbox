# Control-plane identity isolation

This runbook is the operator contract for the three serving cells. Terraform
creates one Cloud Run runtime identity per cell, grants it the cell's exact
runtime secret set, and grants `roles/storage.objectViewer` on the
`templates/` and `bases/` managed folders in that cell's backup bucket. The
managed-folder bindings provide template and shared-base object get/list; they
do not provide sandbox access, create, overwrite, or delete.

## Published contract

| Cell | Cloud Run identity | Backup bucket | Deployment principal (act-as + token creator) | Host identity |
| --- | --- | --- | --- | --- |
| staging | `superserve-cp-staging` | `superserve-artifact-backup-staging-usc1` | environment GitHub Actions service account | legacy `superserve-api` remains on the draining host |
| production use | `superserve-controlplane-use4` | `superserve-artifact-backup-use4` | environment GitHub Actions service account | dedicated `vmd-runtime-production-use4` |
| production usw2 | `superserve-controlplane-usw2` | `superserve-artifact-backup-usw2` | environment GitHub Actions service account | dedicated `vmd-runtime-production-usw2` |

The authoritative rendered values are the `controlplane_identity_contract`
outputs from each environment root. The output includes the runtime identity,
bucket, allowed storage permissions and reader object prefixes, secret IDs, deployment
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

Automatic Terraform CD runs a plan-time identity guard for all three serving
cells and refuses any control-plane service-account transition before apply.
Use the staged identity rollout for that transition; ordinary image and
infrastructure changes may resume automatically after the staged cutover.

## Migration order

1. From each environment root, review `terraform plan` and confirm the new
   service account, exact secret set, template and shared-base managed-folder viewer grants, metric-writer grant,
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
   retains the full evidence privately, and uploads only a sanitized summary.
   A failed stage blocks later cells.
3. For each production stage, Terraform first creates the new identity and
   revision without routing traffic to it. The central KMS owner grant is then
   applied before cutover. The verifier gates the stage on a runtime-identity
   KMS encrypt/decrypt round trip as well as same-cell manifest/reference
   reads, cross-cell list denial, non-mutating IAM Policy Troubleshooter
   checks for sandbox and cross-cell sandbox/template object-get denial plus create and delete denial, Secret
   Manager access, effective IAM analysis, deployment act-as, and the
   centrally owned KMS binding. It also requires the latest ready revision to
   have 100% traffic under the dedicated identity.
4. Keep the old shared production runner grants until both old revisions are
   drained and the dependency audit below is complete. The workflow's failure
   trap restores both the captured revision's traffic and the pre-migration
   Cloud Run service identity, then includes the outcome in the private
   evidence even when verification fails.
5. After the drain, remove only obsolete shared control-plane grants. Do not
   remove a grant that a legacy host, restore tool, GC job, or rollback
   revision still uses. In particular, staging's `superserve-api` host grant
   stays until that host is separately migrated.

Cloud Run rollout failure leaves the old revision serving and restores the
service template to its pre-migration identity. Do not revoke the old
identity's secret/KMS permissions until the new revision is ready and positive
checks have passed. To roll back, route traffic to the last known good
revision, restore the old identity's grants if they were already removed, and
repeat the checks before retrying the cutover.

## Durable evidence gate

The verifier keeps its full evidence directory on the runner while the stage
is executing; it includes production principals, resource names, IAM policies,
and command output and must never be uploaded. The workflow artifact contains
only `summary.json` and `summary.txt`, generated by
`scripts/sanitize-control-plane-evidence.py`. Those public-safe summaries
record the cell, overall status, and each check's name and PASS/FAIL verdict,
without command arguments, policy documents, object names, or identities.

The release owner must retain the private verifier directory through the
approved change-record process and link it with the Terraform plan/apply and
UTC observation time before declaring a cell complete. Each workflow stage
uploads that directory to the restricted bucket named by the
`CONTROL_PLANE_EVIDENCE_BUCKET` repository variable under a run- and
cell-specific prefix before the runner is torn down. Configure that bucket as
the approved private evidence store with the required retention and encryption
controls; it must not be one of the template-backup buckets. A missing summary
or any FAIL row is an incomplete migration, even if the service health endpoint
responds. The workflow also fails closed when the private `evidence.json` is
missing any required PASS row, including one for every unchanged host
principal's inability to impersonate the serving identity; an uploaded
summary alone is not approval.

The verifier discovers a real generation manifest at
`templates/<template>/<build>/<generation>/manifest.json` and reads every
artifact named by its `files[*].object` entries, including bucket-relative
`bases/` shared objects. If a manifest uses a format
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
each referenced artifact, and uses IAM Policy Troubleshooter to confirm that
the runtime identity is denied `storage.objects.get` for synthetic objects
under `sandboxes/` in its own and every other cell's bucket and under
`templates/` in every other cell's bucket. It also confirms denial of
`storage.objects.create` for a synthetic object under `templates/` and
`storage.objects.delete` on the live manifest. These checks are non-mutating,
so retries cannot turn a create check into an overwrite check or alter a
customer artifact. A missing object is not a negative IAM result.

Also verify that the deployment principal can update the Cloud Run service with
the new identity and mint credentials as that identity for the probes, that the
runtime can access every rendered Secret Manager secret, and that the control
plane's existing KMS-dependent operation still succeeds. Inspect effective IAM
(including inherited project/folder grants and service-account impersonation)
before declaring the negative checks complete.

For the effective audit, retain the verifier's
`gcloud asset analyze-iam-policy --project=PROJECT ...` output together
with the direct project, bucket, managed-folder, and service-account policies. In the cleanup
row, record `removed` or `retained-with-dependency`, the exact principal and
role, the dependency owner, and the observation time. Only rows marked
`removed` after the old revision is drained may be revoked; rows needed by the
staging host, restore/GC tooling, or rollback remain explicitly retained.
