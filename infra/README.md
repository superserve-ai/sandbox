# infra

Terraform skeleton layout for Superserve GCP adoption.

- `modules/` defines resource-area contracts
- `envs/` wires those contracts into staging, production, and a greenfield new-region target

The environment IAM configuration separates identities by purpose and keeps the
roles narrow enough to match the approved runtime and deployment flows.

Service account inventory:

| Service account | Environment(s) | Roles / bindings in this branch | Disposition |
| --- | --- | --- | --- |
| `superserve-api-runtime` | staging, production | `roles/logging.logWriter`, `roles/monitoring.metricWriter`, Secret Manager `roles/secretmanager.secretAccessor` on the exact API secrets used by each environment; production also keeps the key-scoped KMS grant out of band | Dedicated Cloud Run API runtime identity |
| `superserve-sandbox-runtime` | staging, production | `roles/logging.logWriter`, `roles/monitoring.metricWriter` | Dedicated VM / VMD runtime identity with no secret access |
| `superserve-deployer` | staging, production | `roles/compute.instanceAdmin.v1`, `roles/compute.networkAdmin`, `roles/compute.securityAdmin`, `roles/compute.loadBalancerAdmin`, `roles/compute.osAdminLogin`, `roles/iap.tunnelResourceAccessor`, `roles/run.admin`, `roles/artifactregistry.writer`, `roles/vpcaccess.admin`, `roles/monitoring.editor`, `roles/viewer`, `roles/secretmanager.viewer`, `roles/iam.serviceAccountViewer`, `roles/iam.serviceAccountUser` only on the runtime service accounts, GitHub sandbox `roles/iam.workloadIdentityUser`, plus bucket-scoped Terraform state access and the staging artifact bucket grant listed below | Routine Terraform and deployment identity |
| `superserve-runner` | staging, production | no new bindings in this branch | Legacy shared runtime retained only for migration safety |
| `superserve-api` / `superserve-api-runner` | staging, production | no new bindings in this branch | Legacy API runtime placeholders retained during migration |
| `superserve-build` | staging, production | no new bindings in this branch | CI / build identity kept for compatibility with existing roots |
| `superserve-github-actions` | staging, production, west2 | no bindings in staging or central production; `roles/secretmanager.secretAccessor` on the sandbox access-token seed in `production/us-west2` only | Legacy GitHub Actions identity kept until workflow authentication migrates |

The production KMS grant remains key-scoped and is managed by the central
bootstrap process. Before deploying a production revision with the new API
runtime, the bootstrap identity must run:

  ```sh
  gcloud kms keys add-iam-policy-binding credentials-kek \
    --keyring=superserve \
    --location=us-central1 \
    --project=rayai-prod \
    --member=serviceAccount:superserve-api-runtime@rayai-prod.iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyEncrypterDecrypter

  gcloud kms keys get-iam-policy credentials-kek \
    --keyring=superserve \
    --location=us-central1 \
    --project=rayai-prod \
    --flatten='bindings[].members' \
    --filter='bindings.role=roles/cloudkms.cryptoKeyEncrypterDecrypter AND bindings.members=serviceAccount:superserve-api-runtime@rayai-prod.iam.gserviceaccount.com' \
    --format='value(bindings.members)'
  ```

The existing workflows continue using `GCP_SERVICE_ACCOUNT` for this
migration phase. Do not change that secret yet. After the new identities have
been created and verified, migrate workflow authentication to the deployer in
a separate change.

The original high-privilege identity is also used to bootstrap the new
deployer and runner accounts, their bindings, and Terraform state-bucket
access.
Production regional roots depend on accounts created by
`production/us-central1`; apply that root first before applying `us-west2` or
`us-east4`, including when targeting a region manually. The production CD and
manual rollout workflows enforce this order.
The environment IAM configuration grants the sandbox repository's existing
GitHub workload identity principal `roles/iam.workloadIdentityUser` on the
new deployer. Canary remains on its separate existing identity and is not
granted access to this deployer.

The bootstrap identity remains the owner of the IAM policy resources in these
roots. The routine deployer has read-only IAM visibility, resource deployment
permissions, and narrowly scoped permission to act as the runtime account.
Apply the IAM portions once with the bootstrap identity before switching the
workflows: this establishes the bucket-scoped state grants and creates the
service accounts. Subsequent routine applies should not change those IAM
resources; IAM drift or intentional IAM changes require the bootstrap path.

Bucket-scoped deployer bindings:

- `staging/us-central1` and `production/us-central1` grant
  `roles/storage.objectAdmin` and `roles/storage.legacyBucketReader` on their
  respective Terraform state buckets to `superserve-deployer`.
- `staging/us-central1` also grants `roles/storage.admin` on
  `superserve-artifacts` to `superserve-deployer` because that root owns the
  artifact bucket used by the deploy path.

Review-only workflow:

- Run `terraform plan -input=false -no-color -out=tfplan` in the target root.
- Convert that plan to a sanitized summary with `scripts/sanitize-terraform-plan.sh tfplan > plan.txt`.
- Do not apply from this review path; production applies stay behind the
  repository rollout workflows and their approval gates.
- If the plan shows an unexpected IAM change, stop and reconcile the state or
  imported binding before any apply.
- To roll back a bad IAM change, remove the binding from Terraform, rerun
  `terraform validate`, regenerate the sanitized plan, and confirm the plan
  shows only the intended deletion before any approved rollout is retried.
- To recheck the IAM rollout after deployment, run the read-only policy checks
  below and confirm the returned role/member pairs match the table above.

Production roots configure a shared Compute Engine CPU alert for each
Terraform-managed sandbox host. The alert fires when the 60-second mean CPU
utilization is above 80% for 15 minutes, with a 15-minute notification rate
limit and 30-minute auto-close. Notifications are sent to the existing
monitored Cloud Monitoring channel names supplied through
`TF_VAR_notification_channel_ids`; the channel and its Slack credential are
owned outside this repository.

The current production host inventory is:

| Region | Instance | Alert policy key |
| --- | --- | --- |
| us-central1 | `superserve-vmd-prod` | `sandbox_host` |
| us-east4 | `superserve-vmd-use4` | `sandbox_host` |
| us-west2 | `superserve-vmd-usw2` | `sandbox_host` |

Before the first apply, the infrastructure owner must compare this inventory
with the Vanta finding and run read-only checks such as
`gcloud monitoring policies list --project PROJECT_ID` filtered for each
instance name. If an existing policy covers a host, import or correct that
policy instead of creating a duplicate. The owner must also verify the
configured channel with `gcloud monitoring channels describe CHANNEL_ID`; this
checks channel ownership and delivery configuration without exposing a Slack
webhook credential. The reusable module contains one policy per instance only
because the instance-ID filter keeps each host's Vanta evidence and response
path unambiguous.

For an existing matching policy, use its full Monitoring policy name with
`terraform import module.observability.google_monitoring_alert_policy.compute_instance_cpu[\"sandbox_host\"] POLICY_NAME`
before planning. If the policy is not a match, update it in place or remove it
from the state/configuration deliberately before creating the managed policy.

For a review-only plan, supply the same variable as a Terraform list literal,
for example:

```sh
TF_VAR_notification_channel_ids='["projects/example-project/notificationChannels/123456789"]' \
  terraform -chdir=infra/envs/production/us-central1 plan -input=false -no-color -out=tfplan
scripts/sanitize-terraform-plan.sh infra/envs/production/us-central1/tfplan > plan.txt
```

Infrastructure Operations owns these alerts. On notification, verify the
metric and active workload, inspect host and sandbox capacity, then scale or
drain the host if saturation persists. Roll back by removing the alert policy
configuration from the relevant environment and planning the deletion; do not
apply that plan until the owner confirms the channel and policy are no longer
needed. After deployment, recheck the Vanta control for every production host
and retain the sanitized plan as evidence.

For the IAM rollout itself, recheck Vanta by querying the affected service
accounts after the routine deployer is in place and confirming the resulting
policy matches the table above. Use the read-only checks for the root you are
reviewing:

```sh
# staging/us-central1
for sa in \
  superserve-api-runtime \
  superserve-sandbox-runtime \
  superserve-deployer \
  superserve-api \
  superserve-runner \
  superserve-build \
  superserve-github-actions
do
  gcloud iam service-accounts get-iam-policy \
    "${sa}@PROJECT_ID.iam.gserviceaccount.com" \
    --project=PROJECT_ID
done
gcloud storage buckets get-iam-policy gs://superserve-terraform-state
gcloud storage buckets get-iam-policy gs://superserve-artifacts

# production/us-central1
for sa in \
  superserve-api-runtime \
  superserve-sandbox-runtime \
  superserve-deployer \
  superserve-api-runner \
  superserve-runner
do
  gcloud iam service-accounts get-iam-policy \
    "${sa}@PROJECT_ID.iam.gserviceaccount.com" \
    --project=PROJECT_ID
done
gcloud storage buckets get-iam-policy gs://superserve-terraform-state-prod

# production/us-east4
for sa in \
  superserve-api-runtime \
  superserve-sandbox-runtime \
  superserve-deployer \
  superserve-api-runner \
  superserve-runner
do
  gcloud iam service-accounts get-iam-policy \
    "${sa}@PROJECT_ID.iam.gserviceaccount.com" \
    --project=PROJECT_ID
done

# production/us-west2
gcloud iam service-accounts get-iam-policy \
  superserve-github-actions@PROJECT_ID.iam.gserviceaccount.com \
  --project=PROJECT_ID
```

If a service account still carries an over-broad role, remove it in Terraform,
regenerate the sanitized plan, and re-run the Vanta check after the next
approved rollout. An empty policy for a legacy identity is acceptable when the
table marks it as migration-only.

The plan command documented here is review-only; the repository's explicitly
authorized production workflows can apply Terraform changes after their normal
approval gates.
