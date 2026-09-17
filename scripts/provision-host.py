#!/usr/bin/env python3
"""Plan and apply one operator-approved host operation; never admit a host."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REGIONS = {
    'us-central1': ('staging', 'superserve-terraform-state'),
    'us-west2': ('production', 'superserve-terraform-state-prod'),
    'us-east4': ('production', 'superserve-terraform-state-prod'),
}
HOSTS = {
    'us-central1': {'sandbox_host', 'sandbox_host_b'},
    'us-west2': {'sandbox_host_b'},
    'us-east4': {'sandbox_host_c'},
}


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def resource_values(module):
    result = {r['address']: r['values'] for r in module.get('resources', [])}
    for child in module.get('child_modules', []):
        result.update(resource_values(child))
    return result


def disk_address_for(region, host):
    suffix = '' if region == 'us-east4' and host == 'sandbox_host_b' else host.removeprefix('sandbox_host')
    return 'google_compute_disk.sandbox_data'+suffix


def validate_monitoring_update(change, vm_change, references, host, condition_type):
    require(change['actions'] == ['update'], 'Creating monitoring infrastructure is unsupported: existing policies may only update in place')
    old_id = (vm_change.get('before') or {}).get('instance_id')
    require(f'module.{host}.instance_id' in references,
            'Monitoring policy must follow the selected VM identity')
    before, after = change.get('before') or {}, change.get('after') or {}
    conditions = before.get('conditions') or []
    require(len(conditions) == 1, 'Unexpected monitoring conditions')
    blocks = conditions[0].get(condition_type) or []
    if vm_change['actions'] == ['create']:
        # The VM is absent, but the existing policy retains its last instance ID.
        prior_ids = re.findall(r'resource\.labels\.instance_id\s*=\s*"([0-9]+)"',
                               blocks[0].get('filter', '')) if len(blocks) == 1 else []
        require(len(prior_ids) == 1, 'Monitoring filter must select one previous VM')
        old_id = prior_ids[0]
    require(old_id and len(blocks) == 1 and re.search(
        r'resource\.labels\.instance_id\s*=\s*"' + re.escape(str(old_id)) + r'"',
        blocks[0].get('filter', '')), 'Monitoring filter must select the previous VM')
    filter_path = ('conditions', 0, condition_type, 0, 'filter')

    def unchanged(old, new, unknown, path=()):
        # The replacement ID makes only the filter unknown. Provider-owned
        # mutation metadata and condition names may also be recomputed.
        computed = path[:1] == ('mutation_record',) or path == ('conditions', 0, 'name')
        if path == filter_path or computed:
            if unknown is True:
                return
        require(unknown is not True, 'Unexpected unknown monitoring field: ' + str(path))
        if isinstance(old, dict) and isinstance(new, dict):
            for key in old.keys() | new.keys() | (unknown or {}).keys():
                unchanged(old.get(key), new.get(key), (unknown or {}).get(key), path + (key,))
        elif isinstance(old, list) and isinstance(new, list):
            require(len(old) == len(new), 'Monitoring block count changed')
            for i, (left, right) in enumerate(zip(old, new)):
                unchanged(left, right, unknown[i] if unknown else None, path + (i,))
        else:
            require(old == new, 'Unrelated monitoring change: ' + str(path))

    unchanged(before, after, change.get('after_unknown'))


def validate_identity_replacement(change, vm_change, references, host):
    require(change['actions'] == ['delete', 'create'],
            'Creating identity infrastructure is unsupported: restore the existing identity adapter before host provisioning')
    old_id = (vm_change.get('before') or {}).get('instance_id')
    require(f'module.{host}.instance_id' in references,
            'Identity adapter must follow the selected VM identity')
    before = (change.get('before') or {}).get('triggers_replace')
    after = (change.get('after') or {}).get('triggers_replace')
    unknown = (change.get('after_unknown') or {}).get('triggers_replace')
    if vm_change['actions'] == ['create']:
        # Retain the applied trust configuration while recovering a missing VM.
        old_id = (before[0].get('instance_id')
                  if isinstance(before, list) and before and isinstance(before[0], dict) else None)
    require(old_id and isinstance(before, list) and len(before) == 2 and
            isinstance(before[0], dict) and before[0].get('instance_id') == old_id,
            'Identity adapter must select the previous VM')

    def unchanged(old, new, pending, path=()):
        # Only the VM ID may be recomputed; trust inputs and the provisioner
        # script must retain their previously applied values.
        if path == (0, 'instance_id'):
            require(pending is True and new is None, 'Expected an unknown replacement VM ID')
            return
        require(pending is not True, 'Unexpected unknown identity trigger: ' + str(path))
        if isinstance(old, dict) and isinstance(new, dict):
            require(pending is None or pending is False or isinstance(pending, dict),
                    'Unexpected identity trigger shape')
            for key in old.keys() | new.keys() | (pending or {}).keys():
                unchanged(old.get(key), new.get(key), (pending or {}).get(key), path + (key,))
        elif isinstance(old, list) and isinstance(new, list):
            require(len(old) == len(new) and
                    (pending is None or pending is False or
                     isinstance(pending, list) and len(pending) == len(old)),
                    'Identity trigger count changed')
            for i, (left, right) in enumerate(zip(old, new)):
                unchanged(left, right, pending[i] if pending else None, path + (i,))
        else:
            require(not pending and old == new, 'Unrelated identity trigger change: ' + str(path))

    unchanged(before, after, unknown)


def validate_plan(plan, host, image, operation, region, run_id=None):
    """Reject mutations outside the selected host and its validated dependencies."""
    require(plan.get('errored') is not True, 'Terraform plan errored')
    address = f'module.{host}.google_compute_instance.this'
    disk_address = disk_address_for(region, host)
    attachment = disk_address.replace('google_compute_disk.', 'google_compute_attached_disk.')
    changes = {r['address']: r for r in plan.get('resource_changes', [])}
    require(address in changes, 'Target VM missing from full plan')
    change = changes[address]['change']
    expected = ['create'] if operation == 'create' else ['delete', 'create']
    require(change['actions'] == expected, f'Expected {operation} of exactly the target VM')
    after = change['after']
    if run_id is not None:
        require(after.get('metadata', {}).get('host-provisioning-run') == run_id, 'Missing creation-time retry marker')
    require(after['boot_disk'][0]['initialize_params'][0]['image'] == image,
            'Planned image does not match requested override')
    require(after.get('labels', {}).get('component') == 'vmd-provisioning' and
            after['labels'].get('sandbox_status') == 'provisioning',
            'Commit the target to provisioning_hosts before running this workflow')
    require(host in plan.get('variables', {}).get('provisioning_hosts', {}).get('value', []),
            'Target must remain excluded in the regional configuration')
    require(after.get('desired_status') != 'TERMINATED', 'Target configuration prevents identity installation')
    require(all(after.get(k) for k in ('project', 'zone', 'name')), 'Target coordinates must be known')
    require(disk_address in changes, 'Target retained disk missing from full plan')
    disk_change = changes[disk_address]['change']
    disk_creation = operation == 'create' and disk_change['actions'] == ['create']
    require(disk_creation or disk_change['actions'] == ['no-op'] and disk_change.get('before', {}).get('id'),
            'Existing data disks must not change; only create may allocate a new disk')
    disk = disk_change['after']
    config = plan.get('configuration', {}).get('root_module', {})
    attachment_config = next((r for r in config.get('resources', []) if r['address'] == attachment), {})
    disk_refs = attachment_config.get('expressions', {}).get('disk', {}).get('references', [])
    inline_refs = config.get('module_calls', {}).get(host, {}).get('expressions', {}).get('sandbox_data_disk', {}).get('references', [])
    if attachment in changes:
        attachment_change = changes[attachment]['change']
        require(attachment_change['actions'] in (['create'], ['delete', 'create']),
                'Replacement requires reattaching the data disk')
        value = attachment_change['after']
        instance_refs = attachment_config.get('expressions', {}).get('instance', {}).get('references', [])
        require(f'module.{host}.instance_self_link' in instance_refs,
                'Attachment must reference the selected VM')
        require((value.get('disk') or '').split('/')[-1] == disk['name'] or
                disk_creation and disk_address+'.id' in disk_refs, 'Wrong attachment disk')
        require(value.get('device_name') == 'superserve-sandbox-data', 'Wrong data device')
        require(value.get('mode') == 'READ_WRITE', 'Wrong disk attachment mode')
    for addr, item in changes.items():
        actions = item['change']['actions']
        if actions in (['no-op'], ['read']) or addr == address or addr == disk_address and disk_creation:
            continue
        if addr == attachment:
            continue
        # Reconcile the existing provider identity adapter only for Host 2.
        if host == 'sandbox_host_b' and addr == 'module.peer_identity.terraform_data.managed_identity':
            references = config.get('module_calls', {}).get('peer_identity', {}).get(
                'expressions', {}).get('instance_id', {}).get('references', [])
            validate_identity_replacement(item['change'], change, references, host)
            continue
        policies = {
            'compute_instance_cpu': ('compute_instance_cpu_alerts', 'condition_threshold'),
            'host_maintenance_events': ('host_maintenance_event_alerts', 'condition_matched_log'),
        }
        if region in ('us-west2', 'us-east4'):
            policy = next((name for name in policies if addr ==
                           f'module.observability.google_monitoring_alert_policy.{name}["{host}"]'), None)
            if policy:
                variable, condition_type = policies[policy]
                references = config.get('module_calls', {}).get('observability', {}).get(
                    'expressions', {}).get(variable, {}).get('references', [])
                validate_monitoring_update(item['change'], change, references, host, condition_type)
                continue
        raise ValueError(f'Unrelated mutation in full plan: {addr}: {actions}')
    inline = after.get('attached_disk') or []
    require(any((d.get('source') or '').split('/')[-1] == disk['name'] for d in inline) or
            disk_creation and disk_address+'.id' in inline_refs or
            attachment in changes, 'Plan does not attach the retained data disk')
    return {'address': address, 'disk_address': disk_address, 'disk_name': disk['name'], 'disk_creation': disk_creation,
            'project': after['project'], 'zone': after['zone'], 'instance': after['name'],
            'image': image, 'operation': operation, 'host': host}


def inventory(target):
    flags = ['--project='+target['project'], '--zones='+target['zone'], '--format=json']
    vms = json.loads(run('gcloud', 'compute', 'instances', 'list', *flags))
    vm = next((v for v in vms if v['name'] == target['instance']), None)
    disks = json.loads(run('gcloud', 'compute', 'disks', 'list', *flags))
    disk = next((d for d in disks if d['name'] == target['disk_name']), None)
    return vm, disk


def check_inventory(target, vm, disk):
    require((disk is None) == target['disk_creation'], 'Data disk existence differs from the reviewed plan')
    require(not (disk or {}).get('users') or vm and disk['users'] == [vm['selfLink']],
            'Retained disk is attached to another VM')
    if target['operation'] == 'create':
        require(vm is None, 'Create refuses an existing VM; reconcile state first')
    else:
        require(vm is not None, 'Replace refuses a missing VM; reconcile state first')
        require(vm['status'] == 'TERMINATED', 'Evacuate and stop the target before replacement')
        require(vm.get('labels', {}).get('component') != 'vmd',
                'Exclude the old target from deployment before replacement')
        require(vm.get('labels', {}).get('sandbox_status') != 'ready',
                'Clear operator-controlled admission before replacement: after evacuation, set '
                'sandbox_status=provisioning on the stopped VM. Adding provisioning_hosts does '
                'not clear an existing ready label because Terraform preserves admission status.')
        attached = [d for d in vm.get('disks', []) if not d.get('boot') and d.get('source')]
        require(len(attached) == 1 and attached[0]['source'].split('/')[-1] == target['disk_name']
                and attached[0].get('autoDelete') is False,
                'Replacement requires exactly the retained non-auto-deleting data disk')
    return {'instance_id': str(vm['id']) if vm else None, 'disk_id': str(disk['id']) if disk else None}


def prepare(directory, host, image, operation, run_id=""):
    # Copy only the selected module; never weaken the shared module for other hosts.
    source = 'managed-identity-host' if directory.parts[-2:] == ('staging', 'us-central1') and host == 'sandbox_host_b' else 'sandbox-host'
    copied = directory / '.provision-host-module'
    override = directory / 'operation_override.tf.json'
    require(not copied.exists() and not override.exists(), 'Provisioning scratch paths already exist')
    shutil.copytree(ROOT / 'infra/modules' / source, copied,
                    ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', 'tests', '.terraform.lock.hcl'))
    if operation == 'replace':
        # A lifecycle override replaces the whole block, losing ignore_changes.
        main = copied / 'main.tf'
        configuration = main.read_text()
        configuration, count = re.subn(r'(?m)^([ \t]*prevent_destroy[ \t]*=[ \t]*)true([ \t]*)$',
                                       r'\g<1>false\2', configuration)
        require(count == 1, 'Expected exactly one host destruction protection')
        main.write_text(configuration)
    override.write_text(json.dumps({'module': {host: {'source': './.provision-host-module', 'boot_disk_image': image, 'provisioning_run_id': run_id}}}))


def cleanup(directory):
    (directory / 'operation_override.tf.json').unlink(missing_ok=True)
    shutil.rmtree(directory / '.provision-host-module', ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['plan', 'apply'])
    p.add_argument('--region', choices=REGIONS, required=True)
    p.add_argument('--host', required=True, help='Configured Terraform host module name')
    p.add_argument('--image', required=True)
    p.add_argument('--operation', choices=['create', 'replace'], required=True)
    a = p.parse_args()
    require(a.host in HOSTS[a.region], 'Host is not configured in this region')
    require(a.image.strip() and not any(c in a.image for c in '\r\n\x00'), 'Supply an image reference')
    environment, bucket = REGIONS[a.region]
    directory = ROOT / 'infra/envs' / environment / a.region
    work = ROOT / '.host-provisioning'
    work.mkdir(exist_ok=True)
    revision = os.environ['GITHUB_SHA']
    run_id = os.environ['GITHUB_RUN_ID']
    attempt = os.environ['PLAN_ATTEMPT']
    require(run_id.isdigit() and attempt.isdigit(), 'Invalid run identity')
    uri = f'gs://{bucket}/manual-host-provisioning/{run_id}/{attempt}'
    binding = dict(region=a.region, host=a.host, image=a.image, operation=a.operation, revision=revision)
    planfile = work / 'approved.tfplan'
    receiptfile = work / 'receipt.json'
    require(not any(k.startswith('TF_CLI_ARGS') for k in os.environ), 'Terraform CLI overrides are not supported')
    require(not (directory / '.provision-host-module').exists() and
            not (directory / 'operation_override.tf.json').exists(), 'Provisioning scratch paths already exist')
    try:
        prepare(directory, a.host, a.image, a.operation, run_id)
        run('terraform', 'init', '-input=false', '-lockfile=readonly', cwd=directory)
        if a.phase == 'plan':
            args = ['terraform', 'plan', '-input=false', '-lock-timeout=5m', '-out='+str(planfile)]
            if a.operation == 'replace':
                args.append('-replace=module.'+a.host+'.google_compute_instance.this')
                if not (a.region == 'us-central1' and a.host == 'sandbox_host_b'):
                    args.append('-replace='+disk_address_for(a.region, a.host).replace('google_compute_disk.', 'google_compute_attached_disk.'))
            # Full plan is private; only a bounded summary goes into Actions logs.
            run(*args, cwd=directory)
            plan = json.loads(run('terraform', 'show', '-json', str(planfile), cwd=directory))
            target = validate_plan(plan, a.host, a.image, a.operation, a.region, run_id)
            vm, disk = inventory(target)
            before = check_inventory(target, vm, disk)
            receipt = dict(binding=binding, target=target, before=before, plan_sha256=digest(planfile))
            receiptfile.write_text(json.dumps(receipt, indent=2))
            for file in (planfile, receiptfile):
                run('gcloud', 'storage', 'cp', '--if-generation-match=0', str(file), uri+'/'+file.name)
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
                f.write('## Host provisioning plan\n\n```json\n'+json.dumps(receipt, indent=2)+'\n```\n')
                f.write(f'Private saved plan: `{uri}/approved.tfplan`. Review with `terraform show` using this revision before approving the environment. Only the selected VM, its attachment, existing identity adapter and validated CPU/maintenance monitoring updates may mutate. Existing data disk is unchanged; a new disk is allowed only for create. Host stays provisioning.\n')
        else:
            for file in (planfile, receiptfile):
                run('gcloud', 'storage', 'cp', uri+'/'+file.name, str(file))
            receipt = json.loads(receiptfile.read_text())
            require(receipt['binding'] == binding and digest(planfile) == receipt['plan_sha256'],
                    'Approved plan does not match this operation')
            plan = json.loads(run('terraform', 'show', '-json', str(planfile), cwd=directory))
            target = validate_plan(plan, a.host, a.image, a.operation, a.region, run_id)
            require(target == receipt['target'], 'Plan target differs from review')
            vm, disk = inventory(target)
            # Retrying a completed apply resumes identity installation, never replacement.
            marker = {i['key']: i['value'] for i in (vm or {}).get('metadata', {}).get('items', [])}
            resumed = marker.get('host-provisioning-run') == run_id
            if resumed:
                state = json.loads(run('terraform', 'show', '-json', cwd=directory))
                held = resource_values(state['values']['root_module']).get(target['address'], {})
                require(str(held.get('instance_id')) == str(vm['id']), 'Reconcile incomplete apply before retrying identity installation')
            if not resumed:
                require(check_inventory(target, vm, disk) == receipt['before'],
                        'Provider identity changed after planning; replan for review')
                run('terraform', 'apply', '-input=false', '-lock-timeout=5m', str(planfile), cwd=directory)
                vm, disk = inventory(target)
            require(vm and disk and (target['disk_creation'] or str(disk['id']) == receipt['before']['disk_id']), 'Retained disk identity changed')
            require(str(vm['id']) != receipt['before']['instance_id'], 'Replacement VM identity did not change')
            require(vm.get('labels', {}).get('component') == 'vmd-provisioning' and
                    vm['labels'].get('sandbox_status') == 'provisioning', 'Target is not excluded')
            attached = [d for d in vm.get('disks', []) if not d.get('boot') and d.get('source')]
            require(len(attached) == 1 and attached[0]['source'].split('/')[-1] == target['disk_name']
                    and attached[0].get('autoDelete') is False, 'Data disk attachment is unsafe')
            # A failed/partial apply must not be reported as a completed handoff.
            result = subprocess.run(['terraform', 'plan', '-input=false', '-lock-timeout=5m', '-detailed-exitcode'],
                                    cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            require(result.returncode == 0, 'Provisioning has pending changes; reconcile and review a new plan before handoff')
            flags = ['--project='+target['project'], '--zone='+target['zone'], '--quiet']
            run('gcloud', 'compute', 'ssh', target['instance'], *flags,
                '--tunnel-through-iap',
                '--command=sudo sh -c '+shlex.quote((ROOT/'deploy/host-provisioning-hold.sh').read_text()))
            run('python3', str(ROOT/'deploy/install-host-identity.py'),
                '--project', target['project'], '--zone', target['zone'], '--instance', target['instance'],
                '--slot', target['instance'], '--new-machine', '--fencing-control-plane-ready')
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
                f.write('## Provisioned; not admitted\n\n```json\n'+json.dumps({**target,
                    'instance_id': str(vm['id']), 'disk_id': str(disk['id'])}, indent=2)+'\n```\n')
                f.write('Host identity installed. VMD and socket remain held stopped; placement and routine deployment remain excluded by provisioning_hosts. Restore runtime/artifacts and existing cell CA, prepare peer credentials, then follow existing runtime deployment and validation. Remove the maintenance exclusion and run deploy/release-host-provisioning.sh only through the approved readiness/admission procedure.\n')
    finally:
        cleanup(directory)


if __name__ == '__main__':
    main()
