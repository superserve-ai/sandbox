# infra

Terraform skeleton layout for Superserve GCP adoption.

- `modules/` defines resource-area contracts
- `envs/` wires those contracts into staging, production, and a greenfield new-region target

## Runtime IAM migration

The environment IAM configuration separates routine deployment access from the
Cloud Run and sandbox runtime identities. The deployer may act only as the
dedicated API and sandbox runtime service accounts; runtime identities cannot
deploy infrastructure or modify IAM.

The production API runtime requires a key-scoped KMS grant that is intentionally
managed outside routine Terraform. Before a production regional rollout, an
authorized bootstrap identity must run:

```sh
gcloud kms keys add-iam-policy-binding credentials-kek \
  --keyring=superserve \
  --location=us-central1 \
  --project=rayai-prod \
  --member=serviceAccount:superserve-api-runtime@rayai-prod.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```

The production rollout workflows verify this grant before changing a regional
runtime identity.

Production regional roots depend on accounts and IAM bindings created by
`production/us-central1`. Apply that root before `production/us-west2` and
`production/us-east4`. The automated and manual rollout workflows enforce this
ordering and complete the west2 smoke test before beginning the east4 cutover.

Temporary legacy secret and metric-writer bindings remain during the migration
so existing revisions continue to start, serve traffic, and publish metrics.
Remove those bindings in a follow-up only after staging and every production
region have successfully migrated to the dedicated runtime identities.

The workflows continue using their existing environment-scoped
`GCP_SERVICE_ACCOUNT` identities during this migration. Do not switch workflow
authentication to `superserve-deployer` in the same rollout.

Validation commands:

```sh
infra/scripts/check-no-nonindividual-primitive-roles.sh infra

infra/scripts/verify-bootstrap-primitive-roles.sh \
  superserve-github-actions@rayai-dev.iam.gserviceaccount.com \
  rayai-dev

infra/scripts/verify-bootstrap-primitive-roles.sh \
  superserve-github-actions@rayai-prod.iam.gserviceaccount.com \
  rayai-prod

terraform fmt -check -recursive infra
```

The repository source check prevents explicit primitive Owner, Editor, or Viewer
assignments to non-individual identities. The bootstrap verification script also
checks project and ancestor policies; live IAM verification after rollout remains
the authoritative compliance result.

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
with the compliance finding and run read-only checks such as
`gcloud monitoring policies list --project PROJECT_ID` filtered for each
instance name. If an existing policy covers a host, import or correct that
policy instead of creating a duplicate. The owner must also verify the
configured channel with `gcloud monitoring channels describe CHANNEL_ID`; this
checks channel ownership and delivery configuration without exposing a Slack
webhook credential. The reusable module contains one policy per instance only
because the instance-ID filter keeps each host's compliance evidence and response
path unambiguous.

For an existing matching policy, use its full Monitoring policy name with
`terraform import module.observability.google_monitoring_alert_policy.compute_instance_cpu["sandbox_host"] POLICY_NAME`
before planning. If the policy is not a match, update it in place or remove it
from the state/configuration deliberately before creating the managed policy.

For a review-only plan, supply the same variable as a Terraform list literal,
for example:

```sh
TF_VAR_notification_channel_ids='["projects/example-project/notificationChannels/123456789"]' \
  terraform -chdir=infra/envs/production/us-central1 plan -input=false -no-color -out=tfplan
infra/scripts/sanitize-terraform-plan.sh infra/envs/production/us-central1/tfplan > plan.txt
```

Infrastructure Operations owns these alerts. On notification, verify the
metric and active workload, inspect host and sandbox capacity, then scale or
drain the host if saturation persists. Roll back by removing the alert policy
configuration from the relevant environment and planning the deletion; do not
apply that plan until the owner confirms the channel and policy are no longer
needed. After deployment, recheck the compliance control for every production host
and retain the sanitized plan as evidence.

The plan command documented here is review-only; the repository's explicitly
authorized production workflows can apply Terraform changes after their normal
approval gates.
