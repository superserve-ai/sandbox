#!/usr/bin/env python3
"""Validate the reviewed staging standby replacement plan without applying it."""
import json
import sys


HOST = 'module.sandbox_host_b.google_compute_instance.this'
DISK = 'google_compute_disk.sandbox_data_b'
ATTACHMENT = 'google_compute_attached_disk.sandbox_data_b'
ATTESTATION = 'module.peer_identity.terraform_data.managed_identity'


def validate(plan):
    changes = {r['address']: r['change'] for r in plan['resource_changes']}
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(changes[HOST]['actions'] == ['delete', 'create'], 'Host 2 must be replaced, not updated in place')
    allowed_destroy = {HOST, ATTACHMENT, ATTESTATION}
    for address, change in changes.items():
        require('delete' not in change['actions'] or address in allowed_destroy,
                f'unexpected destruction: {address}')
        if address.startswith('module.sandbox_host.'):
            require(change['actions'] == ['no-op'], 'serving Host 1 must remain unchanged')
    disk = changes[DISK]
    require(disk['actions'] == ['no-op'], 'sandbox-data disk must be a no-op')
    require(disk['before']['id'] == disk['after']['id'] and disk['after']['size'] == 500,
            'the existing 500 GB disk must be preserved')
    attach = changes[ATTACHMENT]
    require(attach['before']['disk'] == disk['after']['id'], 'old attachment must reference the preserved disk')
    require(attach['actions'] == ['forget'], 'old attachment must be forgotten without destructive operations')
    host = changes[HOST]['after']
    require(len(host['attached_disk']) == 1 and host['attached_disk'][0]['source'] == disk['after']['id'],
            'VM creation must reattach the preserved disk')
    require(changes[HOST]['before']['labels']['component'] == 'vmd-staging-standby'
            and changes[HOST]['before']['labels'].get('sandbox_status') != 'ready', 'existing host must still be standby')
    require(host['labels']['component'] == 'vmd-staging-standby'
            and host['labels'].get('sandbox_status') != 'ready', 'replacement must remain standby/non-ready')
    require(host['service_account'] == changes[HOST]['before']['service_account'],
            'dedicated runtime account must be retained')
    require(host['boot_disk'][0]['auto_delete'] and host['boot_disk'][0]['initialize_params'][0]['size'] == 200,
            'replacement must create its own 200 GB boot disk')
    identity = host['workload_identity_config']
    require(len(identity) == 1 and identity[0]['identity'] and identity[0]['identity_certificate_enabled'],
            'creation request must enable the managed identity and certificates')
    require(changes[HOST]['after_unknown'].get('instance_id') is True, 'replacement must get a new instance ID')
    require(changes[ATTESTATION]['actions'] == ['delete', 'create'], 'attestation must be regenerated')
    refs = plan['configuration']['root_module']['module_calls']['peer_identity']['expressions']['instance_id']['references']
    require('module.sandbox_host_b.instance_id' in refs, 'attestation must reference the replacement instance ID')


if __name__ == '__main__':
    validate(json.load(sys.stdin))
    print('Replacement plan verified: standby VM replacement, existing 500 GB disk preserved, new-ID attestation.')
