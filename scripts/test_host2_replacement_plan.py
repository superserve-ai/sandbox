import copy
import unittest
from check_host2_replacement_plan import validate, HOST, DISK, ATTACHMENT, ATTESTATION


class ReplacementPlanTest(unittest.TestCase):
    def plan(self):
        account = [{'email': 'runtime@example-project.iam.gserviceaccount.com'}]
        disk = {'id': 'projects/example-project/zones/us-central1-a/disks/example-data', 'size': 500}
        host = {'labels': {'component': 'vmd-staging-standby', 'sandbox_status': 'provisioning'},
                'service_account': account, 'attached_disk': [{'source': disk['id']}],
                'boot_disk': [{'auto_delete': True, 'initialize_params': [{'size': 200}]}],
                'workload_identity_config': [{'identity': 'example.test/ns/vmd/sa/peer', 'identity_certificate_enabled': True}]}
        changes = {
            HOST: {'actions': ['delete', 'create'], 'before': {'service_account': account, 'labels': {'component': 'vmd-staging-standby'}},
                   'after': host, 'after_unknown': {'instance_id': True}},
            DISK: {'actions': ['no-op'], 'before': disk, 'after': copy.deepcopy(disk)},
            ATTACHMENT: {'actions': ['forget'], 'before': {'disk': disk['id']}},
            ATTESTATION: {'actions': ['delete', 'create']},
            'module.sandbox_host.google_compute_instance.this': {'actions': ['no-op']},
        }
        return {'resource_changes': [{'address': a, 'change': c} for a, c in changes.items()],
                'configuration': {'root_module': {'module_calls': {'peer_identity': {'expressions': {
                    'instance_id': {'references': ['module.sandbox_host_b.instance_id']}}}}}}}

    def test_preserved_disk_and_new_identity_plan_passes(self):
        validate(self.plan())

    def test_rejects_disk_replacement_admission_missing_mwi_and_stale_attestation(self):
        for case in ('disk', 'ready', 'serving', 'mwi', 'stale-id', 'host1', 'attachment', 'unrelated-destroy', 'before-serving', 'before-ready'):
            with self.subTest(case=case):
                plan = self.plan()
                changes = {r['address']: r['change'] for r in plan['resource_changes']}
                if case == 'disk': changes[DISK]['actions'] = ['delete', 'create']
                if case == 'before-serving': changes[HOST]['before']['labels']['component'] = 'vmd'
                if case == 'before-ready': changes[HOST]['before']['labels']['sandbox_status'] = 'ready'
                if case == 'ready': changes[HOST]['after']['labels']['sandbox_status'] = 'ready'
                if case == 'serving': changes[HOST]['after']['labels']['component'] = 'vmd'
                if case == 'mwi': changes[HOST]['after']['workload_identity_config'][0]['identity_certificate_enabled'] = False
                if case == 'stale-id': plan['configuration']['root_module']['module_calls']['peer_identity']['expressions']['instance_id']['references'] = []
                if case == 'host1': changes['module.sandbox_host.google_compute_instance.this']['actions'] = ['update']
                if case == 'attachment': changes[ATTACHMENT]['before']['disk'] = 'another-disk'
                if case == 'unrelated-destroy': plan['resource_changes'].append({'address': 'example.other', 'change': {'actions': ['delete']}})
                with self.assertRaises(ValueError): validate(plan)


if __name__ == '__main__':
    unittest.main()
