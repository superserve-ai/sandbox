"""Regional defaults and the manual provisioning contract."""
import copy
import importlib.util
import json
import os
import re
import textwrap
import subprocess
import sys
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('provision_host', ROOT/'scripts/provision-host.py')
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


def fixture(operation='replace', region='us-central1', host='sandbox_host_b'):
    disk = dict(id='projects/example-project/zones/example-a/disks/data', name='data')
    vm = dict(project='example-project', zone='example-a', name='example-host',
              labels=dict(component='vmd-provisioning', sandbox_status='provisioning'),
              boot_disk=[dict(initialize_params=[dict(image='opaque-image')])],
              attached_disk=[dict(source=disk['id'])])
    return dict(variables={'provisioning_hosts': {'value': [host]}}, resource_changes=[
        dict(address=f'module.{host}.google_compute_instance.this', change=dict(
            actions=['delete', 'create'] if operation == 'replace' else ['create'], after=vm)),
        dict(address=provision.disk_address_for(region, host), change=dict(
            actions=['no-op'], before=disk, after=disk)),
    ])


class ProvisionPlanTests(unittest.TestCase):
    def validate(self, plan, operation='replace'):
        return provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', operation, 'us-central1')

    def test_create_and_replace(self):
        for operation in ('create', 'replace'):
            self.assertEqual(self.validate(fixture(operation), operation)['image'], 'opaque-image')

    def identity_plan(self, region):
        plan = fixture(region=region)
        plan['resource_changes'][0]['change']['before'] = {'instance_id': '123456'}
        configuration = dict(project_id='example-project', project_number='123', region=region,
                             pool_id='example-pool', ca_pool='example-ca', namespace='vmd',
                             identity='example-peer', spiffe_uri='spiffe://example.test/peer',
                             identity_at_creation=True, instance_name='example-host',
                             instance_id='123456', zone='example-a', internal_ip='192.0.2.1',
                             host_id='example-host-id', runtime_email='runtime@example.test')
        before = {'triggers_replace': [configuration, 'script-hash']}
        after = copy.deepcopy(before)
        del after['triggers_replace'][0]['instance_id']
        plan['resource_changes'].append(dict(
            address='module.peer_identity.terraform_data.managed_identity',
            change=dict(actions=['delete', 'create'], before=before, after=after,
                        after_unknown={'id': True, 'triggers_replace': [{'instance_id': True}, False]})))
        plan['configuration'] = {'root_module': {'module_calls': {'peer_identity': {
            'expressions': {'instance_id': {'references': ['module.sandbox_host_b.instance_id']}}
        }}}}
        return plan

    def test_create_recovers_existing_identity_with_retained_disk(self):
        plan = self.identity_plan('us-central1')
        plan['resource_changes'][0]['change'].update(actions=['create'], before=None)
        result = self.validate(plan, 'create')
        self.assertFalse(result['disk_creation'])
        for mutation in ('trust', 'unknown_trust', 'script', 'reference', 'new_adapter'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(plan)
                change = bad['resource_changes'][-1]['change']
                if mutation == 'trust':
                    change['after']['triggers_replace'][0]['ca_pool'] = 'other-ca'
                elif mutation == 'unknown_trust':
                    change['after_unknown']['triggers_replace'][0]['ca_pool'] = True
                elif mutation == 'script':
                    change['after']['triggers_replace'][1] = 'new-script'
                elif mutation == 'reference':
                    bad['configuration']['root_module']['module_calls']['peer_identity']['expressions']['instance_id']['references'] = ['module.other.instance_id']
                else:
                    change.update(actions=['create'], before=None)
                with self.assertRaises(ValueError):
                    self.validate(bad, 'create')

    def test_production_create_recovers_existing_monitoring(self):
        for region in ('us-west2', 'us-east4'):
            for host in provision.HOSTS[region]:
                for retained in (True, False):
                    with self.subTest(region=region, host=host, retained=retained):
                        plan = self.monitoring_plan(region, host)
                        plan['resource_changes'][0]['change'].update(actions=['create'], before=None)
                        if not retained:
                            plan['resource_changes'][1]['change'].update(actions=['create'], before=None)
                        provision.validate_plan(plan, host, 'opaque-image', 'create', region)
                        for mutation in ('channels', 'reference', 'unknown_conditions', 'other_host', 'new_policy'):
                            bad = copy.deepcopy(plan)
                            item = bad['resource_changes'][2]
                            if mutation == 'channels':
                                item['change']['after']['notification_channels'] = ['other']
                            elif mutation == 'reference':
                                bad['configuration']['root_module']['module_calls']['observability']['expressions']['compute_instance_cpu_alerts']['references'] = ['module.other.instance_id']
                            elif mutation == 'unknown_conditions':
                                item['change']['after_unknown']['conditions'] = True
                            elif mutation == 'new_policy':
                                item['change'].update(actions=['create'], before=None)
                            else:
                                item['address'] = item['address'].replace(host, 'other_host')
                            with self.assertRaises(ValueError):
                                provision.validate_plan(bad, host, 'opaque-image', 'create', region)

    def test_identity_replacement_allows_only_instance_dependency(self):
        for region in provision.REGIONS:
            with self.subTest(region=region):
                provision.validate_plan(self.identity_plan(region), 'sandbox_host_b',
                                        'opaque-image', 'replace', region)

    def test_identity_replacement_rejects_changed_or_unknown_inputs(self):
        fields = self.identity_plan('us-central1')['resource_changes'][-1]['change'][
            'before']['triggers_replace'][0].keys() - {'instance_id'}
        for region in provision.REGIONS:
            for field in sorted(fields) + ['script_hash']:
                for unknown in (False, True):
                    with self.subTest(region=region, field=field, unknown=unknown):
                        plan = self.identity_plan(region)
                        change = plan['resource_changes'][-1]['change']
                        triggers = change['after']['triggers_replace']
                        pending = change['after_unknown']['triggers_replace']
                        if field == 'script_hash':
                            triggers[1] = None if unknown else 'new-script-hash'
                            pending[1] = unknown
                        elif unknown:
                            del triggers[0][field]
                            pending[0][field] = True
                        else:
                            triggers[0][field] = 'changed'
                        with self.assertRaises(ValueError):
                            provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', 'replace', region)

    def test_identity_replacement_requires_existing_selected_vm_dependency(self):
        for mutation in ('wrong_reference', 'missing_reference', 'wrong_old_id', 'known_id',
                         'unknown_configuration', 'unknown_triggers', 'missing_triggers',
                         'extra_trigger', 'create_adapter', 'update_adapter'):
            with self.subTest(mutation=mutation):
                plan = self.identity_plan('us-central1')
                change = plan['resource_changes'][-1]['change']
                expression = plan['configuration']['root_module']['module_calls']['peer_identity']['expressions']
                operation = 'replace'
                if mutation == 'wrong_reference':
                    expression['instance_id']['references'] = ['module.sandbox_host.instance_id']
                elif mutation == 'missing_reference':
                    expression.clear()
                elif mutation == 'wrong_old_id':
                    change['before']['triggers_replace'][0]['instance_id'] = '654321'
                elif mutation == 'known_id':
                    change['after']['triggers_replace'][0]['instance_id'] = '654321'
                    change['after_unknown']['triggers_replace'][0] = {}
                elif mutation == 'unknown_configuration':
                    change['after_unknown']['triggers_replace'][0] = True
                elif mutation == 'unknown_triggers':
                    change['after_unknown']['triggers_replace'] = True
                elif mutation == 'missing_triggers':
                    del change['before']['triggers_replace']
                elif mutation == 'extra_trigger':
                    change['after']['triggers_replace'].append('extra')
                elif mutation == 'create_adapter':
                    change.update(actions=['create'], before=None)
                elif mutation == 'update_adapter':
                    change['actions'] = ['update']
                with self.assertRaises(ValueError):
                    self.validate(plan, operation)

    def monitoring_plan(self, region, host):
        plan = fixture(region=region, host=host)
        plan['resource_changes'][0]['change']['before'] = {'instance_id': '123456'}
        expressions = {}
        for policy, variable, block in (
            ('compute_instance_cpu', 'compute_instance_cpu_alerts', 'condition_threshold'),
            ('host_maintenance_events', 'host_maintenance_event_alerts', 'condition_matched_log'),
        ):
            before = dict(project='example-project', enabled=True, notification_channels=['channel'],
                          conditions=[dict(display_name='example-host', name='condition-name', **{
                              block: [dict(filter='resource.labels.instance_id="123456"', duration='60s')]
                          })])
            after = copy.deepcopy(before)
            del after['conditions'][0][block][0]['filter']
            plan['resource_changes'].append(dict(
                address=f'module.observability.google_monitoring_alert_policy.{policy}["{host}"]',
                change=dict(actions=['update'], before=before, after=after,
                            after_unknown={'conditions': [{block: [{'filter': True}]}]})))
            expressions[variable] = {'references': [f'module.{host}.instance_id']}
        plan['configuration'] = {'root_module': {'module_calls': {
            'observability': {'expressions': expressions}}}}
        return plan

    def test_production_replacement_allows_selected_host_monitoring(self):
        for region in ('us-west2', 'us-east4'):
            for host in provision.HOSTS[region]:
                with self.subTest(region=region, host=host):
                    plan = self.monitoring_plan(region, host)
                    provision.validate_plan(plan, host, 'opaque-image', 'replace', region)

    def test_monitoring_exception_remains_scoped(self):
        for policy_index in (2, 3):
            for mutation in ('other_host', 'other_policy', 'delete', 'create', 'replace',
                             'enabled', 'channels', 'threshold', 'unknown_conditions',
                             'unknown_enabled', 'wrong_old_id', 'wrong_reference', 'known_filter'):
                with self.subTest(policy=policy_index, mutation=mutation):
                    plan = self.monitoring_plan('us-west2', 'sandbox_host_b')
                    item = plan['resource_changes'][policy_index]
                    change = item['change']
                    block = 'condition_threshold' if policy_index == 2 else 'condition_matched_log'
                    if mutation == 'other_host':
                        item['address'] = item['address'].replace('["sandbox_host_b"]', '["sandbox_host"]')
                    elif mutation == 'other_policy':
                        item['address'] = 'module.observability.google_monitoring_alert_policy.backup["other"]'
                    elif mutation in ('delete', 'create', 'replace'):
                        change['actions'] = ['delete', 'create'] if mutation == 'replace' else [mutation]
                    elif mutation == 'enabled':
                        change['after']['enabled'] = False
                    elif mutation == 'channels':
                        change['after']['notification_channels'] = ['other']
                    elif mutation == 'threshold':
                        change['after']['conditions'][0][block][0]['duration'] = '0s'
                    elif mutation == 'unknown_conditions':
                        change['after_unknown']['conditions'] = True
                    elif mutation == 'unknown_enabled':
                        change['after_unknown']['enabled'] = True
                    elif mutation == 'wrong_old_id':
                        plan['resource_changes'][0]['change']['before']['instance_id'] = '654321'
                    elif mutation == 'wrong_reference':
                        plan['configuration']['root_module']['module_calls']['observability']['expressions'] = {}
                    elif mutation == 'known_filter':
                        change['after_unknown'] = {}
                        change['after']['conditions'][0][block][0]['filter'] = 'resource.labels.instance_id="654321"'
                    with self.assertRaises(ValueError):
                        provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', 'replace', 'us-west2')

    def test_rejects_other_resources_and_disk_mutations(self):
        for address in ['module.sandbox_host.google_compute_instance.this', 'google_compute_disk.other',
                        'google_project_iam_member.other']:
            plan = fixture()
            plan['resource_changes'].append(dict(address=address, change=dict(actions=['delete'])))
            with self.assertRaises(ValueError): self.validate(plan)
        plan = fixture(); plan['resource_changes'][1]['change']['actions'] = ['delete', 'create']
        with self.assertRaises(ValueError): self.validate(plan)

    def test_rejects_wrong_operation_image_and_admission(self):
        mutations = [lambda p: p['resource_changes'][0]['change'].update(actions=['create']),
                     lambda p: p['resource_changes'][0]['change']['after']['labels'].update(component='vmd'),
                     lambda p: p['resource_changes'][0]['change']['after']['boot_disk'][0]['initialize_params'][0].update(image='wrong'),
                     lambda p: p['variables']['provisioning_hosts'].update(value=[])]
        for mutate in mutations:
            plan = fixture(); mutate(plan)
            with self.assertRaises(ValueError): self.validate(plan)

    def test_external_attachment_and_east_address(self):
        self.assertEqual(provision.disk_address_for('us-east4', 'sandbox_host_b'), 'google_compute_disk.sandbox_data')
        plan = fixture(); plan['resource_changes'][0]['change']['after']['attached_disk'] = []
        disk = plan['resource_changes'][1]['change']['after']
        plan['resource_changes'].append(dict(address='google_compute_attached_disk.sandbox_data_b',
            change=dict(actions=['delete', 'create'], after=dict(disk=disk['id'], device_name='superserve-sandbox-data', mode='READ_WRITE'))))
        plan['configuration'] = {'root_module': {'resources': [dict(
            address='google_compute_attached_disk.sandbox_data_b',
            expressions={'instance': {'references': ['module.sandbox_host_b.instance_self_link']}})]}}
        self.validate(plan)
        plan['resource_changes'][-1]['change']['after']['disk'] = 'wrong'
        with self.assertRaises(ValueError): self.validate(plan)

    def test_inventory_requires_explicit_release_of_existing_admission(self):
        target = self.validate(fixture())
        vm = dict(id='123', selfLink='vm', status='TERMINATED',
                  labels=dict(component='vmd-provisioning', sandbox_status='ready'),
                  disks=[dict(boot=False, source='disks/data', autoDelete=False)])
        disk = dict(id='456', users=['vm'])
        with self.assertRaisesRegex(ValueError, 'set sandbox_status=provisioning'):
            provision.check_inventory(target, vm, disk)
        vm['labels']['sandbox_status'] = 'provisioning'
        self.assertEqual(provision.check_inventory(target, vm, disk),
                         dict(instance_id='123', disk_id='456'))

    def test_inventory_refuses_serving_wrong_disk_or_existing_create(self):
        target = self.validate(fixture())
        vm = dict(id='123', selfLink='vm', status='TERMINATED', labels={'component': 'vmd-provisioning'},
                  disks=[dict(boot=False, source='disks/data', autoDelete=False), dict(type='SCRATCH')])
        disk = dict(id='456', users=['vm'])
        self.assertEqual(provision.check_inventory(target, vm, disk)['disk_id'], '456')
        for field, value in [('status', 'RUNNING'), ('labels', {'component': 'vmd'}),
                             ('disks', [dict(boot=False, source='disks/data', autoDelete=True)])]:
            bad = copy.deepcopy(vm); bad[field] = value
            with self.assertRaises(ValueError): provision.check_inventory(target, bad, disk)
        with self.assertRaises(ValueError): provision.check_inventory({**target, 'operation': 'create'}, vm, disk)
        with self.assertRaises(ValueError): provision.check_inventory(target, None, disk)
        self.assertIsNone(provision.check_inventory({**target, 'operation': 'create'}, None, {'id': '456'})['instance_id'])

    def test_new_disk_only_for_create(self):
        plan = fixture('create')
        plan['resource_changes'][1]['change'].update(actions=['create'], before=None)
        self.assertTrue(self.validate(plan, 'create')['disk_creation'])
        with self.assertRaises(ValueError): self.validate(plan)

    def test_unknown_new_disk_requires_configuration_reference(self):
        plan = fixture('create')
        plan['resource_changes'][1]['change'].update(actions=['create'], before=None)
        plan['resource_changes'][1]['change']['after'].pop('id')
        plan['resource_changes'][0]['change']['after']['attached_disk'] = [{'source': None}]
        with self.assertRaises(ValueError): self.validate(plan, 'create')
        plan['configuration'] = {'root_module': {'module_calls': {'sandbox_host_b': {
            'expressions': {'sandbox_data_disk': {'references': ['google_compute_disk.sandbox_data_b.id']}}
        }}}}
        self.assertTrue(self.validate(plan, 'create')['disk_creation'])

    def test_prepare_preserves_preexisting_override(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            override = directory/'operation_override.tf.json'
            override.write_text('existing')
            with self.assertRaises(ValueError):
                provision.prepare(directory, 'sandbox_host_b', 'opaque-image', 'replace')
            self.assertEqual(override.read_text(), 'existing')
            self.assertFalse((directory/'.provision-host-module').exists())

    def test_retry_marker_must_match_plan(self):
        plan = fixture()
        with self.assertRaises(ValueError):
            provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', 'replace', 'us-central1', '123')
        plan['resource_changes'][0]['change']['after']['metadata'] = {'host-provisioning-run': '123'}
        provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', 'replace', 'us-central1', '123')

    def test_wrong_disk_user_rejected(self):
        target = self.validate(fixture('create'), 'create')
        with self.assertRaises(ValueError):
            provision.check_inventory(target, None, {'id': '456', 'users': ['another-vm']})

    def test_hold_script_matches_rendered_modules(self):
        hold = (ROOT/'deploy/host-provisioning-hold.sh').read_text().split('\n', 1)[1].strip()
        for name in ('sandbox-host', 'managed-identity-host'):
            text = (ROOT/'infra/modules'/name/'main.tf').read_text()
            rendered = text.split('host_provisioning_hold = <<-EOT\n')[1].split('  EOT')[0]
            self.assertEqual('\n'.join(line[4:] for line in rendered.splitlines()).strip(), hold)

    def test_scoped_lifecycle_override(self):
        for environment, region, module in (
            ('production', 'us-west2', 'sandbox-host'),
            ('staging', 'us-central1', 'managed-identity-host'),
        ):
            for operation in ('create', 'replace'):
                with self.subTest(module=module, operation=operation), tempfile.TemporaryDirectory() as temp:
                    directory = Path(temp)/environment/region; directory.mkdir(parents=True)
                    source = ROOT/'infra/modules'/module/'main.tf'
                    original = source.read_text()
                    provision.prepare(directory, 'sandbox_host_b', 'opaque-image', operation)
                    override = json.loads((directory/'operation_override.tf.json').read_text())
                    self.assertEqual(list(override['module']), ['sandbox_host_b'])
                    self.assertEqual(override['module']['sandbox_host_b']['boot_disk_image'], 'opaque-image')
                    copied = directory/'.provision-host-module'
                    expected = original.replace('prevent_destroy = true', 'prevent_destroy = false') if operation == 'replace' else original
                    self.assertEqual((copied/'main.tf').read_text(), expected)
                    self.assertFalse((copied/'operation_override.tf.json').exists())
                    self.assertEqual(source.read_text(), original)
                    provision.cleanup(directory)
                    self.assertFalse((directory/'operation_override.tf.json').exists())


class ProvisionReleaseTests(unittest.TestCase):
    def test_release_survives_both_boot_hooks(self):
        for name in ('sandbox-host', 'managed-identity-host'):
            with self.subTest(module=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                text = (ROOT/'infra/modules'/name/'main.tf').read_text()
                def heredoc(local):
                    return textwrap.dedent(text.split(local + ' = <<-EOT\n')[1].split('  EOT')[0])
                hold = heredoc('host_provisioning_hold')
                identity = heredoc('host_identity_prerequisite')
                prefix = json.loads(re.search(r'(\["sh", "-c", .*"provisioning-boot"\])', text)[1])
                startup = text.split('var.provisioning ? "if [ -f ')[1].split(' : lookup')[0]
                startup = 'if [ -f ' + startup[:-1]
                startup = startup.replace('${lookup(var.metadata, "startup-script", ":")}', 'echo startup >> "$CALLS"')
                startup = startup.replace('\\n', '\n')
                def relocate(script):
                    return script.replace('/etc/', str(root/'etc') + '/')
                bindir = root/'bin'; bindir.mkdir()
                systemctl = bindir/'systemctl'
                systemctl.write_text('#!/bin/sh\necho "$*" >> "$SYSTEMCTL"\n')
                systemctl.chmod(0o755)
                env = {**os.environ, 'PATH': str(bindir) + ':' + os.environ['PATH'],
                       'SYSTEMCTL': str(root/'systemctl'), 'CALLS': str(root/'calls')}
                def run(script):
                    return subprocess.run(['sh', '-c', relocate(script)], env=env, check=True)
                def boot():
                    run(identity)
                    run(hold)
                    for command in (['sh', '-c', 'echo boot-string >> "$CALLS"'],
                                    ['sh', '-c', 'echo "boot-argv:$1" >> "$CALLS"', 'sh', 'two words']):
                        subprocess.run([relocate(arg) for arg in prefix] + command, env=env, check=True)
                    run(hold + startup)
                hold_path = root/'etc/sandbox/provisioning-hold'
                complete = root/'etc/sandbox/provisioning-complete'
                boot()
                boot()
                self.assertTrue(hold_path.exists())
                self.assertFalse(complete.exists())
                self.assertFalse((root/'calls').exists())
                release = (ROOT/'deploy/release-host-provisioning.sh').read_text()
                with self.assertRaises(subprocess.CalledProcessError):
                    run(release)
                self.assertFalse(complete.exists())
                for filename in ('host-identity.json', 'host-identity.env'):
                    (root/'etc/sandbox'/filename).write_text('installed')
                run(release)
                run(release)
                self.assertTrue(complete.exists())
                self.assertFalse(hold_path.exists())
                (root/'systemctl').write_text('')
                boot()
                self.assertFalse(hold_path.exists())
                self.assertNotIn('stop ', (root/'systemctl').read_text())
                self.assertEqual((root/'calls').read_text().splitlines(),
                                 ['boot-string', 'boot-argv:two words', 'startup'])
                for unit in ('superserve-vmd.service', 'superserve-vmd.socket'):
                    gate = root/'etc/systemd/system'/f'{unit}.d/10-identity-required.conf'
                    self.assertIn('host-identity', gate.read_text())
                (root/'etc/sandbox/host-identity.env').unlink()
                boot()
                self.assertIn('stop superserve-vmd.socket', (root/'systemctl').read_text())
                self.assertIn('stop superserve-vmd.service', (root/'systemctl').read_text())


class ApplyTests(unittest.TestCase):
    def exercise(self, *, resumed=False, bad_binding=False, changed_disk=False, pending=False):
        plan = fixture()
        plan['resource_changes'][0]['change']['after']['metadata'] = {'host-provisioning-run': '123'}
        target = provision.validate_plan(plan, 'sandbox_host_b', 'opaque-image', 'replace', 'us-central1', '123')
        old_vm = dict(id='100', selfLink='vm', status='TERMINATED', labels={'component': 'vmd-provisioning'},
                      disks=[dict(boot=False, source='disks/data', autoDelete=False)])
        new_vm = {**old_vm, 'id': '101', 'status': 'RUNNING',
                  'labels': dict(component='vmd-provisioning', sandbox_status='provisioning'),
                  'metadata': {'items': [dict(key='host-provisioning-run', value='123')]}}
        disk = dict(id='999' if changed_disk else '456', users=['vm'])
        calls = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'deploy').mkdir()
            (root/'deploy/host-provisioning-hold.sh').write_text('set -eu')
            receipt = dict(binding=dict(region='us-central1', host='sandbox_host_b', image='opaque-image',
                                        operation='replace', revision='wrong' if bad_binding else 'revision'),
                           target=target, before=dict(instance_id='100', disk_id='456'),
                           plan_sha256=provision.hashlib.sha256(b'saved-plan').hexdigest())

            def fake_run(*args, **kwargs):
                calls.append(args)
                if args[:3] == ('gcloud', 'storage', 'cp'):
                    Path(args[-1]).write_bytes(b'saved-plan' if args[-1].endswith('.tfplan') else json.dumps(receipt).encode())
                if args[:3] == ('terraform', 'show', '-json'):
                    if len(args) > 3: return json.dumps(plan)
                    return json.dumps({'values': {'root_module': {'resources': [dict(
                        address=target['address'], values={'instance_id': '101'})]}}})
                return ''

            env = dict(GITHUB_SHA='revision', GITHUB_RUN_ID='123', PLAN_ATTEMPT='1', GITHUB_STEP_SUMMARY=str(root/'summary'))
            argv = ['provision-host.py', 'apply', '--region', 'us-central1', '--host', 'sandbox_host_b',
                    '--image', 'opaque-image', '--operation', 'replace']
            with patch.object(provision, 'ROOT', root), patch.object(provision, 'prepare'), \
                 patch.object(provision, 'cleanup'), patch.object(provision, 'run', side_effect=fake_run), \
                 patch.object(provision, 'inventory', side_effect=[(new_vm if resumed else old_vm, disk), (new_vm, disk)]), \
                 patch.object(provision.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2 if pending else 0)), \
                 patch.dict(os.environ, env), patch('sys.argv', argv):
                if bad_binding or changed_disk or pending:
                    with self.assertRaises(ValueError): provision.main()
                else:
                    provision.main()
        return calls

    def test_apply_uses_saved_plan_and_installs_identity(self):
        calls = self.exercise()
        apply = [c for c in calls if c[:2] == ('terraform', 'apply')]
        self.assertEqual(len(apply), 1)
        self.assertTrue(apply[0][-1].endswith('/approved.tfplan'))
        self.assertTrue(any(c[0] == 'python3' and '--new-machine' in c for c in calls))

    def test_retry_resumes_identity_without_replacing_again(self):
        calls = self.exercise(resumed=True)
        self.assertFalse(any(c[:2] == ('terraform', 'apply') for c in calls))
        self.assertTrue(any(c[0] == 'python3' and '--new-machine' in c for c in calls))

    def test_post_apply_hold_uses_iap(self):
        for resumed in (False, True):
            with self.subTest(resumed=resumed):
                calls = self.exercise(resumed=resumed)
                ssh = [c for c in calls if c[:3] == ('gcloud', 'compute', 'ssh')]
                self.assertEqual(len(ssh), 1)
                self.assertIn('--tunnel-through-iap', ssh[0])

    def test_binding_and_provider_drift_stop_before_apply(self):
        for kwargs in ({'bad_binding': True}, {'changed_disk': True}):
            calls = self.exercise(**kwargs)
            self.assertFalse(any(c[:2] == ('terraform', 'apply') for c in calls))

    def test_partial_apply_cannot_handoff(self):
        calls = self.exercise(resumed=True, pending=True)
        self.assertFalse(any(c[0] == 'python3' for c in calls))


class WiringTests(unittest.TestCase):
    def test_defaults_and_no_new_github_variables(self):
        expected = {'staging/us-central1': 'superserve-vmd-20260401-224137',
                    'production/us-west2': 'ubuntu-2404-lts-amd64', 'production/us-east4': 'ubuntu-2204-lts'}
        for root, image in expected.items():
            variables = (ROOT/'infra/envs'/root/'variables.tf').read_text()
            self.assertIn(image, variables)
            main = (ROOT/'infra/envs'/root/'main.tf').read_text()
            self.assertIn('lookup(var.host_image_overrides,', main)
            self.assertIn('contains(var.provisioning_hosts,', main)
        for name in ('terraform-plans.yml', 'terraform-cd.yml', 'terraform-rollout-staging.yml', 'terraform-rollout-production.yml'):
            text = (ROOT/'.github/workflows'/name).read_text()
            self.assertNotIn('TF_VAR_BOOT_DISK_IMAGE', text)
            self.assertNotIn('terraform-require-boot-image.sh', text)

    def test_protection_lookup_fails_closed(self):
        workflow = (ROOT/'.github/workflows/host-provision.yml').read_text()
        script = textwrap.dedent(workflow.split('        run: |\n', 1)[1].split('\n  plan:', 1)[0])
        for token, api_status, reviewers, success in (
                ('', 0, True, False), ('test-token', 1, True, False),
                ('test-token', 0, False, False), ('test-token', 0, True, True)):
            with self.subTest(token=bool(token), api_status=api_status, reviewers=reviewers), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                gh = root/'gh'
                gh.write_text(f'#!{sys.executable}\n' +
                    'import json, os, sys\n'
                    'assert os.environ["GH_TOKEN"] == "test-token"\n'
                    'assert sys.argv[1:] == ["api", "repos/example/repository/environments/host-provision-staging"]\n'
                    'print(json.dumps({"protection_rules": [{"type": "required_reviewers", "reviewers": ["reviewer"] if os.environ["REVIEWERS"] == "true" else []}]}))\n'
                    'sys.exit(int(os.environ["API_STATUS"]))\n')
                gh.chmod(0o755)
                output = root/'output'
                result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env={
                    **os.environ, 'PATH': str(root) + ':' + os.environ['PATH'],
                    'GH_TOKEN': token, 'API_STATUS': str(api_status), 'REVIEWERS': str(reviewers).lower(),
                    'REPOSITORY': 'example/repository', 'SOURCE_REF': 'refs/heads/main', 'READY': 'true',
                    'REGION': 'us-central1', 'HOST': 'sandbox_host_b',
                    'GITHUB_OUTPUT': str(output), 'GITHUB_RUN_ATTEMPT': '1'})
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual(output.exists(), success)
                if success:
                    self.assertIn('environment=staging', output.read_text())

    def test_workflow_binds_approval_and_private_plan(self):
        text = (ROOT/'.github/workflows/host-provision.yml').read_text()
        self.assertIn('needs: [preflight, plan, approve]', text)
        self.assertIn('environment: host-provision-${{ needs.preflight.outputs.environment }}', text)
        self.assertIn('required_reviewers', text)
        self.assertIn('GH_TOKEN: ${{ secrets.HOST_PROVISION_ENVIRONMENT_READ_TOKEN }}', text)
        self.assertNotIn('GH_TOKEN: ${{ github.token }}', text)
        self.assertIn('ref: ${{ github.sha }}', text)
        self.assertNotIn('actions/upload-artifact', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('test "$SOURCE_REF" = refs/heads/main', text)


if __name__ == '__main__': unittest.main()
