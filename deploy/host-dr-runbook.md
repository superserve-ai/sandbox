# Host disaster recovery: retired replacement procedure

**Do not execute the former rebuild/remap procedure.** It reused the destroyed
host's full `HOST_ID` on a replacement VM and is incompatible with authoritative
incarnation fencing. This runbook is retired; it does not provide an executable
end-to-end replacement recovery procedure.

A replacement VM must receive a new full host ID and its own installation
incarnation, even when it reuses the same regional slot. Its heartbeat cannot
claim the destroyed host's bound row. Copying the old incarnation, authorizing a
rebind of the old row for a replacement VM, or directly rewriting the old row's
address is not a recovery workaround. Rebind is reserved for reinstalling the
same provisioned VM. See [authoritative peer identity rollout](host-generation-rollout.md)
for identity installation, fencing, and rollback requirements.

## Requirements before replacement recovery can reopen

A replacement recovery runbook must define and validate all of the following
before this procedure can be reinstated:

- Fence the lost VM and prevent client operations and reconciliation from racing
  recovery. Keep the replacement out of scheduling until recovery is validated;
  host `draining` alone does not block sandbox resumes.
- Provision and bind the replacement under its new full host ID. Preserve the
  old host's identity history and tombstone; never reuse its ID or remove fencing
  records to permit recovery.
- Enumerate backups using the **old** host ID before changing ownership. The
  `backup-restore -host-restore` mode restores files and produces a coverage
  ledger; it does not remap sandbox ownership or make sandboxes resumable.
- Define an explicit, guarded remap of each successfully recovered sandbox's
  `sandbox.host_id` from the old ID to the replacement's new ID. Specify expected
  ownership/status checks, handling of concurrent operations, retry behavior,
  and partial failures. Retain the old host row while sandbox references still
  require it; changing the old host's address is not a remap.
- Validate filesystem restoration and cold boot, restore required configuration
  and policy, and reconcile snapshot references before permitting client use.
  File restoration alone does not supply a memory image for the normal resume
  path. Define the resulting sandbox status and verify routing to the new host
  before reopening each recovered sandbox. Uncovered or failed restores must
  remain unavailable and be recorded in the recovery ledger.
- Reopen scheduling only after recovery gates pass, and document retirement of
  the old host without deleting its durable identity history.

Until that replacement procedure is available, treat backup materialization as
file recovery only. Do not use the former HOST_ID substitution or status-flip
instructions to return recovered sandboxes to service.
