# QM bootstrap and rollout

Development completion and live rollout are separate. These commands are manual
procedures, not merge gates. Do not run a live apply until the release operator
has resolved and reviewed all inputs. The administrator needs gcloud access, not
a checkout or Terraform installation. Automation performs Terraform operations.

## Resolve the administration boundary

Prepare **separate** development and production bootstrap identities and state
buckets in an existing administrator-controlled project (or separate protected
administration projects). Do not use `rayai-dev`/`rayai-prod` as an administration
project while their ordinary CI identities can change project/service-account
IAM. Such an identity could otherwise impersonate bootstrap during the grant
window. Audit inherited folder/organization access to the administration project,
QM folder, state bucket and repository before choosing this path. If no protected
administration project is available, preparation is blocked pending administrator
action; do not fall back to routine CI.

The release operator supplies actual values for the following environment
variables. Use one environment at a time and retain the resolved non-secret
manifest with the release evidence:

```bash
# Administrator supplies these from the reviewed preparation manifest.
: "${QM_ENV:?development or production}"
: "${QM_ADMIN_PROJECT:?existing protected administration project ID}"
: "${QM_FOLDER_ID:?numeric intended parent folder}"
: "${QM_BILLING_ACCOUNT:?billing account ID}"
: "${QM_BOOTSTRAP_CALLER:?authorized user:email or serviceAccount:email principal}"
: "${QM_GRANT_EXPIRY:?RFC3339 UTC end of the authorized bootstrap window}"
: "${QM_REGISTRY_LOCATION:?existing image repository region}"
: "${QM_REGISTRY_REPOSITORY:?existing image repository name}"
case "$QM_ENV" in
  development) QM_PROJECT=rayai-qm-dev; QM_PAIRED_PROJECT=rayai-dev; QM_BOOTSTRAP_ID=qm-bootstrap-dev ;;
  production) QM_PROJECT=rayai-qm-prod; QM_PAIRED_PROJECT=rayai-prod; QM_BOOTSTRAP_ID=qm-bootstrap-prod ;;
  *) echo 'Unsupported QM_ENV' >&2; exit 1 ;;
esac
QM_BOOTSTRAP_SA="${QM_BOOTSTRAP_ID}@${QM_ADMIN_PROJECT}.iam.gserviceaccount.com"
QM_BOOTSTRAP_BUCKET="${QM_ADMIN_PROJECT}-${QM_BOOTSTRAP_ID}-state"
QM_TEMP_CONDITION="expression=request.time < timestamp('${QM_GRANT_EXPIRY}'),title=qm-bootstrap-window"
export QM_ENV QM_PROJECT QM_PAIRED_PROJECT QM_BOOTSTRAP_SA QM_BOOTSTRAP_BUCKET
```

Verify the folder's parent, billing account status, existing project IDs, and
repository before granting anything:

```bash
gcloud resource-manager folders describe "$QM_FOLDER_ID"
gcloud billing accounts describe "$QM_BILLING_ACCOUNT"
gcloud projects describe "$QM_ADMIN_PROJECT"
gcloud projects describe "$QM_PAIRED_PROJECT"
gcloud projects list --filter="projectId=${QM_PROJECT}" --format='table(projectId,projectNumber,lifecycleState)'
gcloud artifacts repositories describe "$QM_REGISTRY_REPOSITORY" \
  --project="$QM_PAIRED_PROJECT" --location="$QM_REGISTRY_LOCATION"
gcloud projects get-iam-policy "$QM_ADMIN_PROJECT" --format=json
gcloud resource-manager folders get-iam-policy "$QM_FOLDER_ID" --format=json
gcloud billing accounts get-iam-policy "$QM_BILLING_ACCOUNT" --format=json
```

An empty projects-list result does not prove global project-ID availability;
project creation is the authoritative availability check. Obtain organization and
ancestor-folder policy exports from the administrator as well. Inspect effective
Owner/Editor, service-account policy/role administrators, token creators,
federation writers, IAM/custom-role writers, inherited groups, and state access.
Do not assume an unreadable ancestor policy is empty. Inspect organization
policies for service-account key creation, automatic default-account grants,
allowed regions and public ingress. Record quotas for each paired region.

## Prepare identity and temporary grants

Run creation commands once; on retry describe the exact identity/bucket and
inspect its IAM instead of ignoring arbitrary errors. These are bootstrap seed
objects in the pre-existing administration boundary, outside routine QM state.

```bash
gcloud iam service-accounts create "$QM_BOOTSTRAP_ID" \
  --project="$QM_ADMIN_PROJECT" --display-name="QM ${QM_ENV} authorized bootstrap"
gcloud storage buckets create "gs://${QM_BOOTSTRAP_BUCKET}" \
  --project="$QM_ADMIN_PROJECT" --location=US --uniform-bucket-level-access
gcloud storage buckets update "gs://${QM_BOOTSTRAP_BUCKET}" \
  --public-access-prevention --versioning
gcloud storage buckets add-iam-policy-binding "gs://${QM_BOOTSTRAP_BUCKET}" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/storage.objectAdmin

gcloud iam service-accounts add-iam-policy-binding "$QM_BOOTSTRAP_SA" \
  --project="$QM_ADMIN_PROJECT" --member="$QM_BOOTSTRAP_CALLER" \
  --role=roles/iam.serviceAccountTokenCreator --condition="$QM_TEMP_CONDITION"
gcloud resource-manager folders add-iam-policy-binding "$QM_FOLDER_ID" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/resourcemanager.projectCreator \
  --condition="$QM_TEMP_CONDITION"
gcloud billing accounts add-iam-policy-binding "$QM_BILLING_ACCOUNT" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/billing.user
gcloud artifacts repositories add-iam-policy-binding "$QM_REGISTRY_REPOSITORY" \
  --project="$QM_PAIRED_PROJECT" --location="$QM_REGISTRY_LOCATION" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/artifactregistry.admin \
  --condition="$QM_TEMP_CONDITION"
```

The [billing-account CLI](https://cloud.google.com/sdk/gcloud/reference/billing/accounts/add-iam-policy-binding)
does not accept a condition flag. Its grant requires explicit removal on every
exit path; record an administrator cleanup owner and deadline before granting it.
Do not rely on the other grants' expiry to remove Billing Account User.

The repository-scoped temporary administrator role is for adding image-reader
bindings; it includes image mutation and must expire/be removed. The bootstrap
identity gets no paired-project IAM administration. Project Creator grants do
not authorize arbitrary existing-project administration. Creating the QM project
can give bootstrap automatic Owner on that project; cleanup explicitly removes
it after scoped bindings are established. The seed project administrator must
also make enabled Service Usage/quota-project access available to the authorized
executor without granting routine jobs bootstrap impersonation.

## Automation and activation order

1. Use an isolated execution environment with source credentials for the
   authorized `QM_BOOTSTRAP_CALLER`. Both backend and providers impersonate the
   exact bootstrap identity using those source credentials. Do not supply an
   already impersonated bootstrap token: it would require a second, self-
   impersonation grant. No long-lived key file. Supply reviewed
   `environment`, `bootstrap_service_account`, `bootstrap_state_bucket`,
   `folder_id`, `billing_account`, numeric GitHub IDs/repository
   slug, and `registry` object to `infra/bootstrap/qm`. Initialize GCS using
   `-backend-config="bucket=$QM_BOOTSTRAP_BUCKET"` and
   `-backend-config="prefix=qm/$QM_ENV/bootstrap"` plus
   `-backend-config="impersonate_service_account=$QM_BOOTSTRAP_SA"`.
   Backend authentication is independent of provider authentication; see the
   [GCS backend contract](https://developer.hashicorp.com/terraform/language/backend/gcs).
   The declared bootstrap state
   bucket must match that backend input. The providers explicitly impersonate
   `bootstrap_service_account`. Keep both readiness flags false.
   Plan/apply only this environment. Capture the non-secret `contract` output.
2. Inspect the new project number, identity/tag inventory, routine state bucket,
   reader bindings and WIF conditions. Protect the output GitHub environments
   with approvals/branch protection; the provisioner deployment environment is
   privileged. Authenticate the routine network job as `qm-infra` and apply the
   matching `infra/envs/qm/...` root. No bootstrap state read is needed.
3. Database and edge owners apply their own protected states. Supply control DB
   deny CIDRs and cell endpoint maps to the network root; inspect that control
   denial has higher priority than all cell allows. Populate platform secret
   versions through the owning rotators. Provisioner DB-cell permissions must
   match its allocated cells. Apply static regional edge before tenant creation.
4. Platform-service infrastructure creates `qm-api` and `qm-provisioner` service
   shells in each supported region using the published identities and immutable
   images. They remain inaccessible to tenant provisioning. Apply bootstrap with
   `platform_services_ready=true`, `provisioning_enabled=false` to tag those
   services and grant scoped deploy access and exact tenant-subnet use. All
   tenant subnets must exist before this step. Verify tags and propagation. Refuse
   to adopt a service/account of unknown provenance that happens to have a
   reserved platform name.
5. Complete the negative checks below, using disposable tenant resources and a
   separately authorized staging verification principal where provisioning is
   not enabled yet. Verify protected tag conditions with Policy Troubleshooter
   and actual calls. Then separately apply `provisioning_enabled=true` in staging,
   run actual provisioner/tenant checks, and complete the deployment-integration
   release gates. Repeat approved production preparation. Runtime isolation is
   not proven until this evidence exists.
6. Remove all temporary grants below on success **or failure**. Later bootstrap
   changes repeat authorization. Once Owner is removed, a routine bootstrap
   refresh is intentionally unauthorized; routine CD never opens this state.

Do not keep broad rights just to let Terraform refresh project creation. A later
protected-root update requires an explicit, expiring project-level authorization
window (project IAM, service-account/custom-role administration, service enablement,
tag administration, state/secret-container/repository administration as required
by its reviewed plan). Bootstrap is a privileged administrator, not a routine
least-privilege delegate. Routine infrastructure can never obtain this window.

## Cleanup and read-only confirmation

Reuse the exact values and condition from preparation. Do not remove another
operator's unrelated binding. If creation produced an unconditional project Owner
grant, remove that exact grant. Enumerate and remove any other temporary grants
recorded in the preparation manifest, including inherited grants.

```bash
gcloud resource-manager folders remove-iam-policy-binding "$QM_FOLDER_ID" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/resourcemanager.projectCreator \
  --condition="$QM_TEMP_CONDITION"
gcloud billing accounts remove-iam-policy-binding "$QM_BILLING_ACCOUNT" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/billing.user
gcloud artifacts repositories remove-iam-policy-binding "$QM_REGISTRY_REPOSITORY" \
  --project="$QM_PAIRED_PROJECT" --location="$QM_REGISTRY_LOCATION" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/artifactregistry.admin \
  --condition="$QM_TEMP_CONDITION"
gcloud projects remove-iam-policy-binding "$QM_PROJECT" \
  --member="serviceAccount:${QM_BOOTSTRAP_SA}" --role=roles/owner --condition=None
gcloud iam service-accounts remove-iam-policy-binding "$QM_BOOTSTRAP_SA" \
  --project="$QM_ADMIN_PROJECT" --member="$QM_BOOTSTRAP_CALLER" \
  --role=roles/iam.serviceAccountTokenCreator --condition="$QM_TEMP_CONDITION"

gcloud projects get-iam-policy "$QM_PROJECT" --format=json
gcloud resource-manager folders get-iam-policy "$QM_FOLDER_ID" --format=json
gcloud billing accounts get-iam-policy "$QM_BILLING_ACCOUNT" --format=json
gcloud iam service-accounts get-iam-policy "$QM_BOOTSTRAP_SA" --project="$QM_ADMIN_PROJECT" --format=json
gcloud storage buckets get-iam-policy "gs://${QM_BOOTSTRAP_BUCKET}" --format=json
gcloud artifacts repositories get-iam-policy "$QM_REGISTRY_REPOSITORY" \
  --project="$QM_PAIRED_PROJECT" --location="$QM_REGISTRY_LOCATION" --format=json
```

A missing binding/project during failure cleanup must be confirmed by inspection,
not suppressed wholesale. Confirm default accounts have no Editor grant, no
routine identity can mutate protected role definitions or impersonation policy,
and expired bootstrap credentials cannot make privileged API calls. Bootstrap
state access remains exclusive to authorized administration; revoke it too if
the bootstrap identity is retired. Do not delete state buckets during cleanup.

## Partial failure, retries, and rollback

State and provider resource IDs are authoritative. If creation succeeded but the
response/state write was lost, stop competing jobs, inspect Cloud Audit Logs and
the exact resource, then import into the original state under renewed authorized
bootstrap credentials. Never create a second project, state prefix, service
account, secret container, or IAM owner to get past an ambiguous response. Never
import tenant resources or the previous installation. Back up versioned state
before repair; do not restore old state without reconciling actual resources.

For partial IAM/tag propagation, keep provisioning disabled, retry inspection and
bounded provider operations, and re-run negative checks. Creation success is not
permission-readiness evidence. If cleanup expires mid-apply, stop and reauthorize
only the remaining reviewed operations; never switch to ordinary CI credentials.
Disable worker intake and drain attempts before revoking permissions. Completed
tenant resources remain owned by the provisioner's persisted tenant/allocation
record, even if the worker dies before reporting success. Recovery adopts those
resources using that record; platform Terraform never cleans them up.

Network replacement/destruction and platform account/project/secret/state removal
are protected by Terraform lifecycle rules. An intentional teardown requires a
separate reviewed change, backups, dependency inspection, and an outage plan.
Rollback foundation activation by disabling provisioning and restoring the last
reviewed policy, not by destroying projects or tenant resources. Maintain control
DB denial throughout rollback. Removing a cell allow disconnects that cell's
runtimes immediately; restore its last authoritative endpoint/tag tuple before
resuming workers. Do not independently reassign a tenant to make connectivity work.

## Impact report

| Resource / path | This foundation merge | Authorized live apply / recovery |
| --- | --- | --- |
| Four existing regional Terraform roots | No resource change from these declarations; existing CD can still apply them | Inspect their independent plans; any unrelated diff requires its own owner |
| Existing API | Existing `infra/**` trigger may deploy a new revision | Normal current migration/staging/production gates; roll back image/traffic through the existing procedure |
| Existing Proxy, VMD, VM hosts | No action; no reboot/replacement planned | Stop if a plan proposes any change; explicit separate review required |
| Existing QM installation/POC | No action | No import, migration, deletion or traffic cutover in this packet |
| New QM projects, identities, protected state | Dormant declarations | Creation only; later removal/replacement requires separate approval; partial failures use import/reconciliation |
| New QM VPC/subnets/NAT/firewalls | Dormant declarations | Creation; later firewall changes take effect immediately, CIDR/VPC changes may require replacement and runtime revisions |
| Paired-project image repository IAM | No action until authorized bootstrap | Additive reader bindings, no restart; temporary admin grant removed after bootstrap |
| Platform secret containers | No values/deployment | Create containers; rotation needs coordinated consumer revisions, never log values |
| New API/provisioner services and static edge | Contract only | Downstream infrastructure/release creates new revisions after prerequisite readiness; image/traffic rollback must preserve DB compatibility |

Before each live environment apply, attach the actual plan and update this table
with every affected resource. An unexpected existing-resource replacement, VM
reboot, or Proxy/VMD change is a stop condition. Packet 2 supplies release
serialization and restart/rollback details for service deployments.

## Required live evidence

Use disposable resources, actual identities, the output project numbers and
region-specific endpoints. Perform development/staging first. Preserve request
IDs, resource IDs, IAM denial reason, timestamps and outcome; exclude credentials.
A permission failure from the test harness itself is not proof of isolation.

- As API identity, read only its two platform secrets; reject provisioner-only,
  cell-admin, tenant and opposite-environment secrets. Confirm tenant creation,
  account impersonation, IAM/tag/custom-role mutation and LB/NEG/DNS changes fail.
- As provisioner, create/read/delete a disposable tenant account, secret, bucket
  and service; verify only its exact cell-admin/platform inputs are readable.
  Test account get/update/delete/actAs and service update/delete/IAM mutation
  against protected API/deployer/Google-agent resources. Destructive negatives
  use equivalently protected disposable fixtures, never the live API identity.
  Attempt tag removal and project/custom-role/federation mutation; all must fail.
  Verify cross-project registry pull succeeds and image push fails.
- As routine network identity, plan its own root and lock its own state; deny
  bootstrap state access, secret payload access, deploying code, project IAM,
  role/federation/tag mutation, bootstrap impersonation, project creation and
  billing attachment. Repeat through inherited roles and impersonation chains.
- Deploy tenant A and B with distinct identities and persisted cell assignments.
  A can read its own secret/bucket and SQL database but not B's or the control DB.
  From A's running revision, TCP 5432 to its assigned cell succeeds; B's cell,
  control DB, and representative unrelated private Superserve targets fail.
  Repeat without a cell tag, during old/new revision overlap, and with a forged
  tenant tag request (rejected by the provisioner). Tenant identities cannot
  update Cloud Run configuration. Same-cell cross-database queries must fail too.
- Exercise required Google endpoints and legitimate public HTTPS; confirm NAT
  and private Google access without generic private reachability. Capture Direct
  VPC allocations including revision overlap/retained blocks against the budget.
- After downstream edge readiness, create/delete disposable tenants and verify
  shared wildcard routing with no per-tenant LB/NEG/DNS changes. Confirm regional
  placement and the one central coordination authority. Measure management
  request p50/p95 across project/region boundaries and verify sandbox lifecycle
  instrumentation has not changed.

Production launch remains pending until the deployment integration, auth
interface, control DB, cells, placement, provisioner, and static edge are ready
and this evidence is reviewed. Neither mocked checks nor disabled rollout is a
successful deployment report.
