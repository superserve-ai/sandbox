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
   `.github/workflows/control-plane-identity-rollout.yml` with `confirm=apply`.
   Terraform grants the deployment principal scoped token creation on each
   dedicated runtime identity so the verifier can run its GCS, Secret Manager,
   and runtime KMS probes. No separate KMS-owner secret is required.
   Before touching Cloud Run, the workflow bootstraps both projects' verification
   APIs, deployment-account policy inspection, and private evidence storage.
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
   reads, cross-cell root and prefix list denial, non-mutating IAM Policy
   Troubleshooter checks for own-cell sandbox reads, own-cell mutations, and
   cross-cell reads and mutations across all three prefixes, Secret Manager
   access, fully explored effective IAM analysis, deployment act-as, and the
   Terraform-managed KMS binding. The workflow captures the latest created
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

`infra/bootstrap/control-plane-evidence` enables the Cloud Asset and Policy
Troubleshooter APIs with `disable_on_destroy = false`. It grants each project's
own deployment account Cloud Asset Viewer, Role Viewer, and Service Usage
Consumer. API activation depends on the Consumer grant, which permits the
provider to poll activation operations. Partial bootstrap failures retry with a
fresh plan against saved state. Both deployment accounts receive Security Reviewer and Deny Reviewer
in each project so they can inspect cross-project policies. These grants do not
include object payload reads, secret values, runtime impersonation, or policy
modification. Production also grants its deployment account KMS Viewer on the
single credentials key so preflight can read the primary version's state. The
bootstrap relies on the existing key-scoped IAM administration for that grant.
Runtime grants remain owned by the regional roots.

The bootstrap caller must already be able to enable project services, manage
project IAM, and manage the evidence bucket and Terraform state. The workflow
provides `TF_VAR_policy_reader_service_accounts` for both existing deployment
accounts, plus `TF_VAR_verification_kms_key` in production; preserve those inputs
if running the bootstrap outside GitHub Actions.
Each project applies only its own grants. Both bootstraps finish before the
three prerequisite jobs run, with matrix fail-fast disabled to report all cells.

The prerequisite jobs read the desired contract from a fresh Terraform plan;
production does not need a previously applied contract output. They check API
availability, the actual caller, rollback revision, own/cross-project policy
visibility and complete IAM tooling analysis (including group/impersonation expansion),
enabled latest secret versions, and
production KMS policy/primary-version readiness. Failed probes retry together
six times with ten seconds between rounds, preserving private attempt evidence.
Unknown policies and incomplete analyses block migration. Public artifacts contain
only sanitized check names and verdicts. A plan failure is reported as incomplete.

Prerequisite policy probes use the existing deployment identity and accept any
definite access decision. Runtime and host account emails can still be computed
in an initial plan; preflight does not depend on identities the regional apply
has yet to create. The post-apply verifier still requires
explicit isolation denials, runtime secret/artifact reads and KMS round trips,
and scoped deployment impersonation before routing the candidate. In particular,
production's pending managed folders and token-creator grants are created by the
existing regional Terraform; the prerequisite job does not demand them early.
Template manifests and referenced artifacts are read only by the post-apply
runtime verifier, so preflight does not require deployment-account payload access.

### Inherited policy visibility

Project grants cannot provide access to ancestor policies. If private preflight
evidence reports an unreadable organization policy or custom roles, an
organization IAM administrator can apply
`infra/bootstrap/control-plane-policy-visibility` once. This separate root grants
only `resourcemanager.organizations.getIamPolicy` and `iam.roles.get` to the
deployment accounts. The role-definition read also covers known custom roles in
descendant projects; there is no role listing, descendant policy read, payload
access, or mutation. Role definitions must be readable to evaluate organization
bindings, including this reader role itself. It is never applied by the rollout, and does not give deployment
accounts organization IAM administration.

Use an existing private Terraform state bucket accessible to that administrator:

```sh
terraform -chdir=infra/bootstrap/control-plane-policy-visibility init \
  -backend-config="bucket=ADMIN_STATE_BUCKET" \
  -backend-config="prefix=bootstrap/control-plane-policy-visibility"
terraform -chdir=infra/bootstrap/control-plane-policy-visibility plan \
  -var='organization_id=ORGANIZATION_ID' \
  -var='deployment_service_accounts=["STAGING_DEPLOYMENT_EMAIL","PRODUCTION_DEPLOYMENT_EMAIL"]' \
  -out=visibility.tfplan
terraform -chdir=infra/bootstrap/control-plane-policy-visibility apply visibility.tfplan
```

This root supports projects attached directly to the organization. Any folder or
organization deny-policy visibility gap requires separately reviewed administrator
access; the root does not grant those permissions across unrelated descendants.
Unknown results remain blocking. If policies include Google Workspace groups or
domains, the corresponding
Workspace visibility is also required; the Google Cloud IAM bootstrap cannot
supply Workspace `groups.read` or domain-administrator privileges. Resolve any
such unknown result with the Workspace administrator; do not treat it as denial
or disable group expansion. Policy Analyzer also has an organization-wide daily
query allowance unless Security Command Center Premium/Enterprise is activated;
repeated preflights consume that allowance. Quota failures block the rollout.
See Google's [Policy Analyzer prerequisites](https://cloud.google.com/policy-intelligence/docs/analyze-iam-policies)
and [Policy Troubleshooter prerequisites](https://cloud.google.com/policy-intelligence/docs/troubleshoot-access).

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
  --other-bucket OTHER_CELL_BUCKET
```

The verifier discovers the actual generation `manifest.json` object, reads
each referenced artifact, and uses IAM Policy Troubleshooter to confirm that
the runtime identity is denied `storage.objects.get` under `sandboxes/` in
its own bucket and under `templates/`, `bases/`, and `sandboxes/` in every
other cell's bucket. It confirms denial of `storage.objects.create` and
`storage.objects.delete` for synthetic objects under all three prefixes in
its own and every other cell's bucket, plus deletion of the live manifest.
It also requires list denial at each cross-cell prefix, not just the bucket
root. These object-permission checks are non-mutating,
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
