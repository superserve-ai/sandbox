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
cells; each production Terraform root already owns its runtime identity's
`roles/cloudkms.cryptoKeyEncrypterDecrypter` grant. The shared-key bootstrap
provides the deployment principal's key-scoped IAM administration separately;
this rollout does not change that bootstrap or require another owner identity.

The serving identities must never be attached to a VMD instance. VMD grants
remain environment-owned: staging's legacy host keeps its existing writer
grant while it drains, and the dedicated production VMD identities keep their
existing create/read grants. No new host grant or host impersonation grant is
part of this migration.

The regular production API deployment workflows update Cloud Run with
`--no-traffic`, then run `scripts/verify-control-plane-kms.sh`. That check
verifies access to every production runtime secret and performs an
encrypt/decrypt round trip as the runtime identity before the workflow routes
the revision. It does not change IAM policy.

Automatic Terraform CD runs a plan-time identity guard for all three serving
cells and refuses any control-plane service-account transition before apply.
Use the staged identity rollout for that transition; ordinary image and
infrastructure changes may resume automatically after the staged cutover.
Production CD pins traffic before creating its saved plan and checks that the
plan retains 100% traffic on the captured revision. All deployment paths use
the same multi-run queue so an active identity rollout does not cause the
API and Terraform workflows waiting behind it to replace each other.

## Migration order

1. From each environment root, review `terraform plan` and confirm the new
   service account, exact secret set, template and shared-base managed-folder viewer grants, metric-writer grant,
   and scoped GitHub Actions act-as and token-creation grants. Confirm no VMD service account is a
   `reader_members` entry.
2. Run the manually confirmed
   `.github/workflows/control-plane-identity-rollout.yml` from `main` with `confirm=apply`.
   To validate a change before merge, select its branch and use
   `confirm=apply-branch`. This runs the full migration against live staging and
   both production regions using the selected commit, including identity and
   traffic changes. Tags and non-manual triggers are rejected. The same
   deployment lock, preflight checks, serial stages, and rollback apply.
   Terraform grants the deployment principal scoped token creation on each
   dedicated runtime identity so the verifier can run its GCS, Secret Manager,
   and runtime KMS probes. No separate KMS-owner secret is required.
   Before touching Cloud Run, the workflow prepares private evidence storage in
   both projects and production's key-scoped KMS metadata access.
   It then plans and checks prerequisites for all three cells as their actual
   GitHub deployment accounts. No manual bucket creation or new GitHub variable
   is needed. All prerequisite jobs must pass before the serial identity rollout:
   staging, production use4, then production usw2. Each stage captures the serving revision before apply,
   validates its saved Terraform plan, then applies it and verifies the deployed identity,
   retains the full evidence privately, and uploads only a sanitized summary.
   The plan guard rejects all VM, persistent-disk, disk-attachment, and host
   identity-adapter changes, including staging's legacy host. Handle any such
   maintenance separately; this rollout must not restart hosts. A failed stage
   blocks later cells.
3. For each production stage, Terraform first creates the new identity and
   revision without routing traffic to it and manages its existing KMS grant.
   The verifier gates the stage on a runtime-identity
   KMS encrypt/decrypt round trip as well as same-cell manifest/reference
   reads, cross-cell root and prefix list denial, own-cell sandbox list denial,
   Secret Manager access, and the Terraform-managed KMS binding. The artifact,
   secret, and encryption probes use credentials minted for the runtime identity.
   The workflow captures the latest created
   revision after apply, verifies that exact candidate's identity and Ready
   condition, then routes traffic to it by name. A retired zero-traffic candidate
   can be Ready while `latestReadyRevisionName` still names the old revision.
   The final check requires the verified candidate to have 100% traffic.
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

## Verification prerequisites

`infra/bootstrap/control-plane-evidence` manages the private evidence bucket and
its deployment-account upload grants. Production also grants its deployment
account KMS Viewer on the single credentials key so preflight can read the
primary version's state. That grant uses the existing key-scoped IAM
administration. Runtime grants remain owned by the regional roots.

The bootstrap caller must be able to manage the evidence bucket and Terraform
state. When upgrading from an audit-enabled bootstrap, it also needs project IAM
administration to remove the audit grants previously tracked in that state.
Both project bootstraps finish before the three prerequisite jobs run. Production
provides `TF_VAR_verification_kms_key`; preserve that input when running the
bootstrap outside GitHub Actions.

The prerequisite jobs read the desired contract from a fresh Terraform plan and
check the actual deployment caller, a 100% rollback revision, enabled latest
secret versions, and production KMS policy/primary-version readiness. Failed
checks retry together six times with ten seconds between rounds. Public artifacts
contain only sanitized check names and verdicts. A plan failure is incomplete.

Runtime and host account emails can still be computed in an initial plan.
Preflight does not depend on identities or managed folders the regional apply
has yet to create. The post-apply verifier uses runtime credentials for actual
artifact and secret reads, negative storage listings, and production KMS round
trips before routing the candidate. No organization policy, custom-role,
Policy Troubleshooter, or Cloud Asset inspection is required by the rollout.

After apply, runtime permission failures retry every 15 seconds within one shared
seven-minute window per cell, starting at the first denial. Each attempt remains
in private evidence. This allows newly created impersonation and resource grants
to propagate; exhausted retries still fail the stage and trigger rollback.
Credential-minting failures never count as successful negative storage checks.
See Google's [IAM propagation guidance](https://cloud.google.com/iam/docs/access-change-propagation).

### Retiring former audit setup

The next evidence bootstrap removes its tracked Cloud Asset Viewer, Role Viewer,
Service Usage Consumer, and Security Reviewer bindings. It preserves the evidence
bucket, upload grants, and KMS metadata grant at their existing state addresses.
The audit APIs are removed from Terraform management without disabling them,
since other callers may still use them.

If an administrator previously applied `infra/bootstrap/control-plane-policy-visibility`,
that root is now cleanup-only. Using its **original state bucket and prefix**, the
administrator can review and apply its plan to remove the old organization reader
bindings and custom role. It creates no permissions and is never run by the rollout.
If it was never applied, there is no organization cleanup to perform. Do not
initialize a new state location as a substitute for locating the original state.

```sh
terraform -chdir=infra/bootstrap/control-plane-policy-visibility init \
  -backend-config="bucket=ORIGINAL_ADMIN_STATE_BUCKET" \
  -backend-config="prefix=bootstrap/control-plane-policy-visibility"
terraform -chdir=infra/bootstrap/control-plane-policy-visibility plan \
  -var='organization_id=ORGANIZATION_ID' \
  -var='deployment_service_accounts=["STAGING_DEPLOYMENT_EMAIL","PRODUCTION_DEPLOYMENT_EMAIL"]' \
  -out=cleanup.tfplan
terraform -chdir=infra/bootstrap/control-plane-policy-visibility apply cleanup.tfplan
```

## Durable evidence gate

The verifier keeps its full evidence directory on the runner while the stage
is executing; it includes production principals, resource names, IAM policies,
and command output and must never be uploaded. The workflow artifact contains
only `summary.json` and `summary.txt`, generated by
`scripts/sanitize-control-plane-evidence.py`. Those public-safe summaries
record the cell, overall status, and each check's name and PASS/FAIL verdict,
without command arguments, policy documents, object names, or identities.

The preparation jobs bootstrap `infra/bootstrap/control-plane-evidence` in both
projects; each rollout stage rechecks its store before changing service identity
or traffic. State lives at
`bootstrap/control-plane-evidence` in the existing environment Terraform state
bucket. Staging uses its own store; both production regions share the production
store and state. The bucket name is `<project-id>-control-plane-evidence` and is
passed directly from Terraform to the upload steps.

Buckets enforce uniform access and public access prevention, use Google-managed
encryption at rest, prevent Terraform destruction, and retain objects for 90
days with lifecycle deletion eligible after that period. Retention is not locked.
The environment's deployment principal receives bucket-scoped object creator
and viewer grants so the CLI can discover upload destinations; no object delete
grant is added. Existing project IAM still applies. Evidence is
stored under a run-, attempt-, and cell-specific prefix. No template-backup
bucket is used. Bootstrap and an actual test upload must succeed before the
identity migration begins. The deployment principal needs permission to create
buckets and manage bucket IAM, in addition to its existing Terraform state access.

The release owner links the private evidence with the Terraform plan/apply and
UTC observation time before declaring a cell complete. A missing summary
or any FAIL row is an incomplete migration, even if the service health endpoint
responds. The workflow also fails closed when the private `evidence.json` is
missing any required runtime-access or readiness PASS row; an uploaded
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
  --other-bucket OTHER_CELL_BUCKET
```

The verifier discovers the actual generation `manifest.json` object and reads
every referenced artifact. It requires actual list denial at each cross-cell
bucket root and `templates/`, `bases/`, and `sandboxes/` prefix, plus the own-cell
`sandboxes/` prefix. These probes run as the runtime identity and do not create,
delete, or overwrite objects.

The deployment principal must be able to update Cloud Run and mint credentials
for the runtime probes. The runtime must read every rendered Secret Manager
secret and, in production, complete the existing KMS encrypt/decrypt probe.
Candidate identity, readiness, and traffic checks gate cutover; rollback remains
available for a failed stage.

The rollout does not perform a comprehensive least-privilege audit. It does not
prove the absence of object get/create/delete grants or host impersonation paths
across inherited policies. Terraform still declares the intended runtime grants,
and the plan guard still rejects changes to hosts and their identities.

For cleanup of obsolete shared runtime grants after the old revision drains,
record `removed` or `retained-with-dependency`, the exact principal and role, the
dependency owner, and observation time. Retain grants needed by the staging host,
restore/GC tooling, or rollback.
