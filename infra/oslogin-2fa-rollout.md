# OS Login 2FA rollout readiness

This document describes the approval gates for enabling the managed host
metadata policy. Terraform metadata is policy evidence only; it does not prove
that a named human receives a second-factor challenge.

## Scope and ownership

The staging primary host, staging managed-identity standby, production east
host, production west host, and their Terraform replacement paths provide
`enable-oslogin=TRUE` and `enable-oslogin-2fa=TRUE`. The host modules continue
to own startup metadata, disks, scheduling, and lifecycle safeguards. GCE
instance metadata remains runtime authority, and the intended ownership key is
the project/zone/instance/metadata-key tuple.

The current modules still protect the complete metadata map with
`ignore_changes = [metadata]`. A provider-backed proof that a single metadata
key can be reconciled while preserving unrelated live keys is required before
that protection is changed. Until that evidence exists, existing-host
enforcement is an unresolved implementation gate; no broad metadata ownership
change is authorized.

## Readiness gates

Before any apply, operators must obtain fresh, read-only evidence that:

1. each intended named human has Google 2-Step Verification enabled;
2. OS Login, the guest agent, PAM, and sshd permit the required keyboard-
   interactive flow; and
3. deployment transport uses its documented workload-identity or service
   account path, with impersonation boundaries reviewed separately from human
   access.

Unavailable identity, guest-agent, PAM, sshd, or transport evidence remains a
blocking gate. Service-account automation is not human 2FA proof and must be
validated on its own path. Recovery access and local or fallback-user bypasses
must be checked before rollout; no credentials, enrollment, IAM, or
authentication settings are changed by this procedure.

## Staged apply and rollback

Each stage requires a separate approval and a retained recovery session:

1. **Staging:** approve the staging state, apply only the reviewed metadata
   change, then perform a fresh named-human SSH attempt and confirm the actual
   second-factor challenge. Validate the deployment automation path before
   proceeding.
2. **Production east:** approve the east state independently and repeat the
   recovery, named-human, second-factor, and automation checks.
3. **Production west:** approve the west state independently and repeat the
   same checks.

If a gate fails, stop before the next stage. Rollback requires separate
approval and removes only the managed `enable-oslogin-2fa` key; it must not
restart or replace a host, detach disks, weaken `prevent_destroy`, or alter
unrelated metadata. Any rollback of an existing host remains blocked until the
same provider ownership and fingerprint/update semantics are evidenced.

No apply, restart, IAM change, credential change, enrollment change, or
authentication configuration change is authorized by this document.
