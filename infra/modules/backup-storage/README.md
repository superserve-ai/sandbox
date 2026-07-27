# backup-storage

Regional GCS bucket that is the durability/DR tier for host-local VM
artifacts. Hosts keep the hot copy on ephemeral local SSD; this bucket holds
the only copy that survives host loss.

## What lives here

One bucket per cell, in the cell's home region (backup data never leaves the
cell — same residency posture as the rest of the cell). Object layout is keyed
by database IDs, never by host-local absolute paths, so a restore can land the
files on any replacement host:

```
sandboxes/<sandbox_id>/<generation>/            vmstate.snap, mem.snap|mem.diff, disk files, manifest
templates/<template_id>/<build_id>/             vmstate.snap, mem.snap, *.delta, base.ext4, build.meta.json, manifest
```

`<generation>` is a monotonically increasing per-sandbox backup counter so
re-uploads never overwrite (writers cannot overwrite — see below); the current
generation is recorded in the control-plane database.

## Access model

| Identity | Roles | Can |
| --- | --- | --- |
| vmd host SA (`writer_members`) | `objectCreator` + `objectViewer` | create new objects, read/list for idempotency and restore |
| dedicated GC SA (created by this module) | `objectAdmin` | delete objects past the retention window |

Writers cannot delete **or overwrite** (overwriting an existing object name
requires `storage.objects.delete`), so a compromised host cannot destroy or
corrupt existing backups. The GC service account is control-plane-only: no
host or runtime service may run as it.

## Retention model (layered)

1. **Control-plane GC job** (runs as the GC SA): deletes a destroyed artifact's
   objects 30 days after the artifact's deletion, driven by the database.
2. **Lifecycle**: noncurrent versions reaped after
   `noncurrent_version_retention_days`; abandoned resumable uploads aborted
   after 7 days.
3. **Soft delete** (`soft_delete_retention_seconds`): recovery window under
   bugs in the GC job itself.
4. `prevent_destroy` + `force_destroy = false` on the bucket resource.

## Encryption

Google-managed by default. The shared credentials KEK cannot be used: it lives
in us-central1 and a bucket's default CMEK key must match the bucket's
location. Pass a per-region key via `kms_key_name` to enable CMEK.

CMEK prerequisite: before setting `kms_key_name`, grant the project's Cloud
Storage service agent (`service-<project_number>@gs-project-accounts.iam.gserviceaccount.com`)
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key, or bucket creation
and object writes will be rejected. This module does not create that binding:
KMS IAM grants are managed out-of-band in this repo because the CD Terraform
SA cannot set KMS IAM policy (same pattern as the credentials-KEK grants).
