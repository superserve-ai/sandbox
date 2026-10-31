# OS Login two-factor authentication rollout

This change declares `enable-oslogin-2fa = "TRUE"` alongside OS Login for
staging primary and standby, production east, and production west. Creation
metadata covers new instances and the existing host provisioning manifests.
The separate devbox provisioning path is outside this policy.

## Metadata ownership

Both host modules retain `ignore_changes = [metadata]`, along with all disk,
power, and destruction safeguards. Their `terraform_data.oslogin_2fa[0]`
resources reconcile the policy on existing instances using
`infra/scripts/oslogin-2fa.py`. The helper reads the current metadata, changes
only the OS Login policy keys, and submits the current fingerprint. On a
fingerprint conflict it rereads and preserves concurrent keys. It pins the
numeric instance ID, waits for the operation, and verifies the resulting
metadata. It never executes startup scripts or requests a VM stop/restart.

The helper requires OS Login to be **already effective**, either on the
instance or inherited from its project. It refuses to silently migrate a
metadata-SSH host. If OS Login is inherited, it pins `enable-oslogin=TRUE` on
the instance when enabling 2FA so a later project-policy change cannot disable
it. A disabled OS Login setting causes reconciliation to fail, requiring an
explicitly reviewed repair. An approved 2FA rollback only writes the 2FA key.

Replacement of the Terraform data resource runs the helper; it does not
replace the VM. Triggers include the instance incarnation, desired 2FA value,
helper revision, and both refreshed OS Login values. After a metadata update,
the next refreshed plan normally proposes one **no-op reconciliation** to
record the new observed values. Complete that reviewed apply and require a
subsequent refreshed plan with no policy changes before declaring convergence.
Until this step, a reversion to the original observed value can escape trigger
comparison. Terraform is not continuous enforcement: future drift requires a
refreshed plan/apply. Do not disable refresh when checking this policy.

Deleting the policy key from Terraform does **not** roll back live metadata:
there is deliberately no destroy-time authentication side effect.

## Pre-apply gates

- Verify current Google 2-Step Verification enrollment for every intended human.
  Connected identity evidence is useful but a fresh SSH second-factor challenge
  after rollout is the acceptance test. Do not collect recovery codes.
- Inventory the live fleet against Terraform, including standby hosts and
  replacement templates. As of October 31, 2026, the two staging hosts lack
  instance-level OS Login and their project does not enable it either. They
  use metadata SSH keys. **Staging is blocked until a separately approved OS
  Login migration establishes working human and automation access.** Production
  east/west have OS Login enabled. No access migration is performed by this PR.
- Keep a working recovery session open. Verify guest-agent and OS Login package
  health, PAM configuration, and effective sshd settings for the actual human
  and service-account users (`sshd -T -C ...`, including Match overrides).
  Production currently reports keyboard-interactive authentication disabled.
  The Google guest agent normally reconfigures SSH for OS Login 2FA, but that
  behavior must be confirmed on the installed version and configuration. A
  conflicting override is a stop condition, not permission to change sshd.
- Inventory local/root accounts and `authorized_keys` fallback paths without
  copying key material. OS Login MFA does not cover every local-account path.
  Review service-account impersonation and attached-service-account privileges;
  a human using an exempt service-account identity is not human MFA proof.
  Preserve findings for the access-policy owner instead of changing IAM here.
- Confirm the deployment identity from the selected environment's
  `google-github-actions/auth` WIF/service-account configuration. VMD, proxy,
  Firecracker and collector workflows use `gcloud compute ssh/scp` over IAP.
  `DEPLOY_TRANSPORT=local` executes on the host without SSH. Operator scripts
  use the active gcloud identity; unattended human-account SSH needs migration
  or a deliberate interactive procedure. The service-account 2FA exemption
  does not prove every deployment path works.
- The local-exec helper requires Python 3 and authenticated gcloud with
  `compute.instances.get`, `compute.instances.setMetadata`, and operation-read
  access (plus `compute.projects.get` for inherited OS Login). Confirm gcloud
  and Terraform use the reviewed identity and project. No IAM grants are added.

## Plan, apply and verify

Each stage requires separate approval: **staging, then production east, then
production west**. The existing production rollout workflow does not expose
an east target; do not dispatch a different region as a substitute.

**Keep the PR draft and unmerged until the staged rollout is complete.** A merge
touching infrastructure triggers automatic Terraform CD; its regional jobs do
not enforce these separate approvals or the human challenge gate. Perform the
approved saved-plan applies below from the exact reviewed PR revision, including
convergence and access verification in every region, before merging. If the
source or base changes, revalidate the combined revision and refresh the plans.
Alternatively, separately review and implement a gated CD path before merging.
The existing automatic workflow must not perform the initial MFA activation.

| Root | Policy resources |
| --- | --- |
| `infra/envs/staging/us-central1` | `module.sandbox_host.terraform_data.oslogin_2fa[0]`, `module.sandbox_host_b.terraform_data.oslogin_2fa[0]` |
| `infra/envs/production/us-east4` | `module.sandbox_host_c.terraform_data.oslogin_2fa[0]` |
| `infra/envs/production/us-west2` | `module.sandbox_host_b.terraform_data.oslogin_2fa[0]` |

1. Supply the environment's real Terraform inputs, initialize its correct
   backend, validate, and generate a refreshed saved plan. Keep state, plan
   JSON, and unsanitized output private. A plan containing placeholder inputs
   or unrelated drift is not deployable. If a targeted plan is needed, inspect
   every dependency action too; targeting a data resource does not isolate it
   from upstream IAM or instance changes.
2. Review policy resource triggers, exact project/zone/instance IDs, and the
   helper source. Terraform's plan displays the reconciler action rather than
   an API metadata diff. Reject any VM replacement, stop, disk operation, IAM
   change, or unrelated metadata/startup change. Obtain approval for this plan.
3. Keep recovery access open and apply the reviewed plan. Verify the policy
   keys and effective guest-agent/PAM/sshd configuration. Any required restart
   or authentication repair requires separate approval.
4. Make a fresh SSH connection as a named human with connection reuse disabled
   (`ControlMaster=no`, `ControlPath=none`). The human must complete an actual
   second-factor challenge. Record identity, UTC time, target incarnation and
   result, but no factor contents. Metadata alone is not challenge proof.
5. Verify each applicable deployment transport with its real service-account
   identity, then complete the no-op convergence apply described above and
   require a clean refreshed policy plan. Record readiness and any residual
   local-account or impersonation exceptions privately. Only then seek the
   next region's approval.

## Rollback

Keep `enable-oslogin=TRUE`. Change `enable-oslogin-2fa` to `"FALSE"` in the
specific affected environment module call, generate and approve a refreshed
plan, and apply its reconciler. It changes only that key and preserves other
metadata. Verify fresh human access and automation, settle the observed-value
record with a reviewed no-op apply, and require a clean policy plan. Stop the
remaining regional rollout. Do not remove the Terraform key/resource, destroy
the VM, or use a broad metadata replacement as rollback.

No infrastructure apply, merge, host restart, credential, IAM, or authentication
configuration change is authorized by this document.

References: [Google OS Login setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin),
[guest OS Login components](https://github.com/GoogleCloudPlatform/guest-oslogin),
[GCE metadata fingerprint semantics](https://docs.cloud.google.com/compute/docs/metadata/setting-custom-metadata).
