# Devbox

A devbox is a disposable, private, single-VM copy of the full stack built from
selected sandbox and console branches. It is reachable only through IAP SSH
forwarding and is deleted when its lifetime ends.

## Setup (one time)

These steps are done once per project by an operator with project owner (or
equivalent IAM, service usage and Compute admin) rights in the devbox project.
The workflows cannot create a box until they are complete.

### 1. Apply the shared infrastructure

`deploy/devbox/terraform` holds everything shared by all boxes:

- a dedicated VPC `superserve-devbox` and subnet `superserve-devbox-usc1`
  (`10.70.0.0/24`) with a Cloud NAT for outbound traffic. Boxes have no
  external address. The only ingress rule admits SSH from the IAP range
  `35.235.240.0/20` to VMs tagged `superserve-devbox`;
- the workflow identity `superserve-devbox-ci` and a Workload Identity
  Federation provider that only accepts GitHub Actions tokens from
  `superserve-ai/sandbox` (matched by numeric repository and owner IDs), on
  `refs/heads/main`, in the `devbox` GitHub environment, from a workflow file
  named `.github/workflows/devbox-*` triggered by `workflow_dispatch` or
  `schedule`;
- the VM identity `superserve-devbox-vm`, which has no project roles. It has
  object access in buckets named `superserve-devbox-*` (shared by all boxes)
  and read-only access to the hostprep bucket below;
- a reCAPTCHA Enterprise score key that allows `localhost` and an API key
  restricted to the reCAPTCHA Enterprise API.

The project also runs staging, so the workflow identity's rights to modify,
SSH into or delete anything are conditioned on resource names: VMs and disks
named `devbox-*` in the devbox zone, and buckets named `superserve-devbox-*`.
Listing instances, disks and buckets, following zonal operations and creating
buckets are evaluated against the project and cannot carry a name condition,
so they are granted unconditionally; none of them can change an existing
resource, but listing does return every instance's metadata, so staging
instance metadata must never hold secrets. IAP forwarding is granted for port
22 on any VM in the project, including staging hosts; logging in still needs
OS Login rights that only exist on `devbox-*` VMs.

Set `engineer_members` (for example `["group:engineers@example.com"]`) to the
principals who may open tunnels to boxes. The root has its own state prefix
(`devbox/us-central1`) and lives outside `infra/`, so no staging or production
deploy workflow runs on it. Instead, the Devbox Terraform workflow
(`.github/workflows/devbox-terraform.yml`) plans it on every pull request that
changes it and applies it when the change merges to `main`. It runs as the
staging Terraform identity, `superserve-github-actions`. An apply whose plan
would delete or replace anything stops; if that is intentional, dispatch the
workflow from `main` with `allow_destroy`.

Once, before the first apply, grant the staging Terraform identity the roles
for the resource types only this root manages:

```sh
for role in roles/iam.workloadIdentityPoolAdmin roles/recaptchaenterprise.admin roles/serviceusage.apiKeysAdmin; do
  gcloud projects add-iam-policy-binding rayai-dev --condition=None \
    --member=serviceAccount:superserve-github-actions@rayai-dev.iam.gserviceaccount.com --role="$role"
done
```

Everything else it needs it already holds. The staging root uses its rights
over service accounts, custom roles, project IAM, firewall rules, buckets,
API enablement and the state bucket, and `roles/compute.networkAdmin` covers
subnet IAM, routers and NAT. If the first apply still fails on a permission,
grant that one and rerun the workflow. These grants give every workflow that
runs as the staging Terraform identity, including pull request plans, the
same reach; that identity can already change project IAM.

Break glass: with project owner and access to the state bucket, the same root
can be applied by hand from the repository root with
`terraform -chdir=deploy/devbox/terraform init`, then `plan -out=tfplan`, then
`apply tfplan`.

Before the first box, confirm that no organization policy blocks nested
virtualization (`constraints/compute.disableNestedVirtualization`) or OS Login
for service accounts in the project. OS Login is expected to honour the
name-conditioned login grant; check it once on the first box with
`gcloud compute ssh devbox-<name> --tunnel-through-iap` as an engineer.

### 2. Seed the host artifacts

Terraform also creates `gs://rayai-dev-devbox-hostprep`, which boxes read the
guest kernel and base rootfs from at bootstrap. Its name is deliberately
outside `superserve-devbox-*`, so box destroy and the box's object grant never
match it. Boxes can only read it. Apart from principals with project-wide
storage rights, only the staging Terraform identity can write it, through the
Devbox Hostprep Seed workflow.

Dispatch Devbox Hostprep Seed (`.github/workflows/devbox-hostprep.yml`) from
`main` once, preferably while no VMD deploy is running. It copies the guest
kernel and base rootfs from staging Host 1 (the `host` input's default) over
IAP SSH, only reading the host: no staging bucket holds an established copy of
these files, so Host 1's files are the source, as the
[Host 2 identity runbook](../host2-identity-runbook.md) also directs. The
kernel is never modified and must match the SHA-256 recorded there, or the job
stops. The rootfs is rewritten with the current boxd by every VMD deploy that
changes boxd, so the copy includes that boxd and its digest can differ from
the runbook's; a box's own VMD install replaces boxd anyway. The job reads each
file once on the host, hashing exactly the bytes it sends, and accepts the
copy only if the open file was not written during that read (a deploy
renaming a new rootfs into place is fine) and the received bytes match the
digest and size. It tries up to three times, then uploads both files and
shows the rootfs digest in its summary.

Boxes verify both files against SHA-256 pins after download; the host
bootstrap keeps them as `DEVBOX_KERNEL_DIGEST` and `DEVBOX_ROOTFS_DIGEST` in
`deploy/devbox/runtime-pins.env`, added together with the box scripts. If the
summary's rootfs digest differs from that pin, update the pin to it; boxes
created before the new pin reaches `main` fail verification and should be
recreated afterwards. Each run overwrites the earlier copy; the bucket keeps
object versions, so an overwritten copy can be recovered.

### 3. Create the `devbox` GitHub environment

In `superserve-ai/sandbox` settings, create an environment named `devbox`
with deployment branches limited to `main`, no required reviewers and no wait
timer (the hourly auto-delete runs unattended). Every devbox workflow job that needs
cloud access or these values declares `environment: devbox`; no other
workflow reads them.

Values forwarded to the box follow one rule: secret `DEVBOX_SECRET_<NAME>`
becomes `<NAME>` in the box's `secrets.env`, and variable
`DEVBOX_CONFIG_<NAME>` becomes `<NAME>` in its `devbox.env`, where `<NAME>`
is the product's own setting. The runner's own cloud settings are not
forwarded and use `DEVBOX_GCP_*`, which deliberately differs from the
repository-level `GCP_*` secrets of the staging and production identity, so a
missing devbox value fails instead of falling back to that identity.

Variables:

| Variable | Value |
| --- | --- |
| `DEVBOX_GCP_PROJECT` | devbox project ID |
| `DEVBOX_GCP_WORKLOAD_IDENTITY` | full provider name, `projects/<number>/locations/global/workloadIdentityPools/superserve-devbox-github/providers/github` |
| `DEVBOX_GCP_SERVICE_ACCOUNT` | `superserve-devbox-ci@<project>.iam.gserviceaccount.com` |
| `DEVBOX_CONFIG_RECAPTCHA_SITE_KEY` | reCAPTCHA key ID |
| `DEVBOX_CONFIG_RECAPTCHA_PROJECT_ID` | devbox project ID |
| `DEVBOX_CONFIG_STRIPE_API_VERSION` | `2026-05-27.dahlia`, the version staging pins |
| `DEVBOX_CONFIG_STRIPE_CHECKOUT_PRICE_IDS` | devbox sandbox usage price IDs (step 4) |
| `DEVBOX_CONFIG_STRIPE_PRO_MONTHLY_PRICE_ID` | devbox sandbox Pro monthly price ID (step 4) |
| `DEVBOX_CONFIG_STRIPE_PRO_ANNUAL_PRICE_ID` | devbox sandbox Pro annual price ID (step 4) |
| `DEVBOX_CONFIG_BILLING_RESOURCE_CONFIG` | resource-to-meter-and-price mapping JSON (step 4) |

The first five are in the Devbox Terraform apply's job summary.

Secrets:

| Secret | Value |
| --- | --- |
| `DEVBOX_SECRET_RECAPTCHA_API_KEY` | `gcloud services api-keys get-key-string projects/rayai-dev/locations/global/keys/superserve-devbox-recaptcha` |
| `DEVBOX_SECRET_STRIPE_SECRET_KEY` | devbox Stripe sandbox secret key (step 4) |

The console repository `superserve-ai/superserve` is public, so the box
checks it out without a credential.

### 4. Create the devbox Stripe sandbox

Create a dedicated Stripe sandbox for devboxes (never the staging account).
All boxes share it; test data left by destroyed boxes is expected. Store its
standard test-mode secret key (`sk_test_...`) as the
`DEVBOX_SECRET_STRIPE_SECRET_KEY` environment secret. A standard key is used
rather than a restricted key because each box runs `stripe listen` to forward
webhooks over an outbound connection, and restricted keys may not be allowed
to open those CLI sessions; the sandbox holds nothing but devbox test data.
Webhook signing secrets come from `stripe listen` on each box and are not
stored in GitHub.

Then create the billing catalog the API expects: a meter, product and monthly
metered price for vCPU, memory and storage at the rates seeded in the
database, and a separate Pro product with the $1,200 monthly and $12,000
annual licensed prices. From the repository root, with Python 3.10 or later
and `acct_XXXXXXXX` replaced by the sandbox's account ID:

```sh
read -rs STRIPE_SECRET_KEY && export STRIPE_SECRET_KEY
python3 scripts/provision_devbox_stripe.py --expected-account acct_XXXXXXXX
python3 scripts/provision_devbox_stripe.py --expected-account acct_XXXXXXXX --apply
unset STRIPE_SECRET_KEY
```

The first run is a read-only preview of what is missing. `--apply` creates
only missing objects, verifies the whole catalog and prints the
`github_environment_variables` to store in the `devbox` environment. Reruns
reuse existing objects and print the same values; the script refuses live
keys, a key for another account, and existing objects whose shape or rate
differs, and never archives or replaces anything. The API itself creates
customers, the invoice rounding price, coupons and credit grants at runtime.

Finally, open the sandbox's customer portal settings once and save them, so
the API can create portal sessions in test mode.

### Cost

On-demand `us-central1` list prices, per box-day:

| Item | Per day |
| --- | --- |
| `n2-standard-8` VM (8 vCPU, 32 GiB) | about $9.32 |
| 50 GiB balanced boot disk | about $0.17 |
| 150 GiB balanced data disk | about $0.50 |
| Cloud NAT (per VM-hour, plus $0.045 per GiB processed) | about $0.03 plus traffic |
| Bucket, IAP | negligible |

A default 24-hour box costs roughly $10 to $11; the one-week maximum about
$70 to $75. Without boxes, the shared infrastructure costs only the few GiB of hostprep
artifacts in storage, cents per month.

### What destroy removes

Destroying a box deletes exactly its per-box resources, found by its
`devbox-id` label: the VM `devbox-<name>`, its boot disk `devbox-<name>`, its
data disk `devbox-<name>-data` and the bucket `superserve-devbox-<devbox-id>`
with its contents. Disks are not auto-deleted with the VM, so a failed or
interrupted destroy leaves labelled disks that a later run can still find.
The shared infrastructure above is untouched; removing it is a separate
`terraform destroy` of `deploy/devbox/terraform` once no boxes remain,
after deleting every object version in the hostprep bucket
(`gcloud storage rm --all-versions 'gs://rayai-dev-devbox-hostprep/**'`);
Terraform refuses to delete it while it holds objects.

## Per-box profile

`profile.json` is the shape every box is created with: an `n2-standard-8`
VM with nested virtualization on Ubuntu 24.04 LTS, a 50 GiB boot disk, a
150 GiB data disk attached with device name `devbox-data`
(`/dev/disk/by-id/google-devbox-data`), formatted XFS with reflink and
mounted at `/mnt/sandbox-data`, OS Login, the devbox network tag and VM identity, and a
private bucket with uniform access, public access prevention and no soft
delete retention. Its names, zone, region, network tag and VM identity must match the Terraform
IAM conditions and firewall; `test_profile.py` checks that.

## Create a devbox

Run **Devbox Create** (`.github/workflows/devbox-create.yml`) from `main`:

```sh
gh workflow run devbox-create.yml --repo superserve-ai/sandbox --ref main \
  -f sandbox_branch=main -f ui_branch=main -f lifetime_hours=24
```

| Input | Default | Notes |
| --- | --- | --- |
| `sandbox_branch` | `main` | Branch of `superserve-ai/sandbox` to build VMD, proxy and API from |
| `ui_branch` | `main` | Branch of `superserve-ai/superserve` to build the console from |
| `name` | generated | 2-40 lowercase letters, digits or hyphens, starting with a letter. Blank generates `<owner>-dev-<6 hex>` from your GitHub login. A name already in use is refused |
| `lifetime_hours` | `24` | 1 to 168. The box is deleted when it expires; lifetimes cannot be extended |

Each branch is resolved once to an exact commit, and every later step uses
that commit. Before taking any cloud action, the workflow checks the profile
and that the selected sandbox commit contains every box script it will run.
It then:

1. creates the data disk `devbox-<name>-data`, the VM `devbox-<name>` (boot
   disk of the same name) from `profile.json`, and the bucket
   `superserve-devbox-<devbox-id>`, all labelled `managed-by`,
   `devbox-name`, `devbox-id`, `owner` and `expires-at`;
2. writes the manifest (state `creating`) to the VM's `devbox-manifest`
   metadata key as part of creating the VM, so even a failed box can be found
   and cleaned up;
3. waits for SSH over IAP, checks out both commits on the box under
   `/opt/superserve-devbox/src/{sandbox,superserve}`, and writes
   `/etc/superserve-devbox/devbox.env` and, over SSH stdin,
   `/etc/superserve-devbox/secrets.env` (mode 0600). Each `devbox`
   environment secret `DEVBOX_SECRET_<NAME>` becomes `<NAME>` in
   `secrets.env`, and each variable `DEVBOX_CONFIG_<NAME>` becomes `<NAME>` in
   `devbox.env`. The workflow refuses to run if any value it forwards is unset;
4. runs, as root on the box and from the checked-out sandbox commit,
   `host-bootstrap.sh`, `services-up.sh`, `install-api.sh`,
   `install-vmd.sh`, `install-proxy.sh`, `seed-base.sh` and `install-ui.sh`
   (VMD needs the database and API on a fresh host), logging each to
   `/var/log/superserve-devbox/<script>.log`;
5. merges `/var/lib/superserve-devbox/runtime.json` and `services.json`
   into the manifest, sets state `ready`, and copies the manifest to
   `/etc/superserve-devbox/manifest.json`.

The run summary shows the name, zone, owner, expiry, commits, the manifest,
the port-forwarding command, log access and the destroy command. To use a
box, run the forwarding command and keep it open:

```sh
gcloud compute ssh devbox-<name> --zone=us-central1-a --project=rayai-dev \
  --tunnel-through-iap -- -N -L 3000:127.0.0.1:3000 -L 8080:127.0.0.1:8080 \
  -L 54321:127.0.0.1:54321 -L 8025:127.0.0.1:8025 -L 8090:127.0.0.1:8090
```

Then open the console at http://localhost:3000 and Mailpit at
http://localhost:8025. The API is on 8080, the auth/data gateway on 54321 and
the sandbox proxy on 8090 (sandbox hosts are `*.sandbox.localhost:8090`).

If any step fails, times out or is cancelled, the run fails, sets state
`failed` on the VM when it exists, and lists every resource of the attempt it
finds by `devbox-id` label or name. A failed box is never reported
as ready; destroy it and create a new one.

## Deploy to a devbox

Run **Devbox Deploy** (`.github/workflows/devbox-deploy.yml`) from `main` to
move an existing box to other revisions, for example to test an upgrade from
`main` to a branch:

```sh
gh workflow run devbox-deploy.yml --repo superserve-ai/sandbox --ref main \
  -f name=<name> -f sandbox_branch=my-feature -f components=all
```

| Input | Default | Notes |
| --- | --- | --- |
| `name` | required | The devbox name (without the `devbox-` prefix) |
| `sandbox_branch` | `main` | Used when `vmd`, `proxy` or `api` is selected |
| `ui_branch` | `main` | Used when `ui` is selected |
| `components` | `all` | `all`, or a comma-separated subset of `vmd`, `proxy`, `api`, `ui` |

The box is found by its labels, not by name prefix, and must be `ready` or
`failed`, have finished its first install, and not be expired. The workflow
sets state `deploying`, checks out the new commit of each repository the
selected components are built from, and reruns the same box scripts the
create workflow uses, in the production upgrade order: `install-vmd.sh`,
`install-proxy.sh`, `services-up.sh` and `install-api.sh` (both for `api`),
then `install-ui.sh`. `install-api.sh` applies pending
database migrations forward to the existing database; a failing migration
stops the deploy. There is no rollback or downgrade: deploy a fixed revision
instead. Existing sandboxes and data are kept.

Each deploy, successful or not, is appended to the manifest's `deploys` with
the actor, the requested components, the previous record (`from`) and the
targeted commits (`to`), the migration result
(`applied`, `none`, `failed` or `unknown`) and the outcome (`succeeded` or `failed`).
Only components whose install finished move in the manifest's `components`,
and `revisions` moves only for checkouts confirmed at the new commit, so a
deploy that fails partway never records progress it can't confirm. After a
failure the workflow reads the box's checkouts once: a checkout it can't read
keeps its previous revision marked `unconfirmed`, and the component whose
install was running when the deploy stopped is recorded with SHA `unknown`. The migration result
comes from the report `install-api.sh` writes for the deployed commit
(`/var/lib/superserve-devbox/api-deploy.json`). It is `none` when `install-api.sh`
didn't run, and `unknown` when it ran but left no readable report for that
commit, for example when the run was cancelled mid-migration.
`expires-at` never changes. The run summary shows previous and new commits per
component, the migration result, service readiness and log access. A failed
deploy leaves the box in state `failed`, possibly partly upgraded. Recover it
with `components=all` and the branches it should run, which reinstalls
everything and returns it to `ready`; a partial deploy to a failed box is
refused. `seed-base.sh` is not rerun.

## Workflow safety

- Create, deploy and destroy for one box share the concurrency group
  `devbox-<name>` with `queue: max`, so they run one at a time in the order
  they were started and none is cancelled for another. Each
  re-reads the box's labels before writing and stops if its `devbox-id`
  changed.
- The workflows refuse to run from any ref but `main`; the `devbox`
  environment and its Workload Identity Federation provider enforce the same.
- The runner only resolves branches, provisions, labels, writes metadata and
  connects over IAP SSH. Code from the selected branches is checked out and
  built on the box, never on the runner, and the box's service account has no
  project permissions beyond object access in devbox buckets.

### Verified only on a real box

The unit tests (`.github/workflows/scripts/test_devbox_*.py`) cover naming,
lifetime bounds, branch handling, labels, the manifest and the order of cloud
calls with `gcloud` mocked. IAP
reachability, OS Login, on-box checkouts and the box scripts themselves are
exercised by the end-to-end smoke run.
