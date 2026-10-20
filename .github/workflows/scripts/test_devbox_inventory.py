"""Devbox destroy must select by label identity in the dev project and never broaden its approved set."""
from datetime import datetime, timezone
import json
import unittest

import devbox_contract as contract
import devbox_inventory as inv

PROJECT = contract.PROJECT
ZONE = contract.ZONE
NOW = 1_800_000_000
CREATED = '2027-01-15T06:00:00+00:00'


def link(kind, name, project=PROJECT, zone=ZONE):
    return f'https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/{kind}/{name}'


def at(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


def labels(name, devbox_id, owner='alice', expires_at=NOW + 3600, **extra):
    return {**contract.labels(name, devbox_id, owner, at(expires_at)), **extra}


def gce(name, devbox_id='3f9c0a1b2c4d'):
    """Return the contract's (instance, boot disk, data disk) names for a box."""
    by_type = {}
    for resource in contract.resources(name, devbox_id):
        by_type.setdefault(resource['type'], []).append(resource['name'])
    [instance], disks = by_type['instance'], by_type['disk']
    return instance, *sorted(disks, key=len)


class FakeCloud:
    def __init__(self):
        self.instances_, self.disks_, self.buckets_ = [], [], []
        self.calls, self.fail = [], set()

    def add_box(self, name, devbox_id, *, vm=True, disks=True, bucket=True, project=PROJECT, zone=ZONE,
                manifest=None, unlabelled=(), **label_args):
        tags = labels(name, devbox_id, **label_args)
        instance, boot, data = gce(name, devbox_id)
        if manifest is None:
            manifest = contract.with_state(contract.new_manifest(
                name=name, devbox_id=devbox_id, owner=tags['owner'], actor=tags['owner'],
                created_at=at(NOW - 26 * 3600), expires_at=at(int(tags['expires-at'])),
                revisions={'sandbox': {'branch': 'main', 'sha': 'a' * 40},
                           'ui': {'branch': 'feature-x', 'sha': 'b' * 40}}), 'ready')
        if vm:
            self.instances_.append({'name': instance, 'zone': f'projects/{project}/zones/{zone}', 'status': 'RUNNING',
                                    'labels': dict(tags), 'selfLink': link('instances', instance, project, zone),
                                    'creationTimestamp': '2027-01-15T06:00:00.000-00:00',
                                    'metadata': {'items': [{'key': contract.MANIFEST_METADATA_KEY,
                                                            'value': json.dumps(manifest)}]}})
        if disks:
            for disk in (boot, data):
                self.disks_.append({'name': disk, 'zone': f'projects/{project}/zones/{zone}', 'creationTimestamp': CREATED,
                                    'labels': {} if disk == boot and 'boot' in unlabelled else dict(tags),
                                    'selfLink': link('disks', disk, project, zone),
                                    'users': [link('instances', instance, project, zone)] if vm else []})
        if bucket:
            self.buckets_.append({'name': contract.bucket_name(devbox_id), 'creation_time': CREATED,
                                  'labels': {} if 'bucket' in unlabelled else dict(tags)})

    def instances(self):
        return [dict(i) for i in self.instances_]

    def disks(self):
        return [dict(d) for d in self.disks_]

    def buckets(self):
        return [dict(b) for b in self.buckets_]

    def _delete(self, kind, collection, name):
        self.calls.append((kind, name))
        if (kind, name) in self.fail:
            return f'{kind} {name}: permission denied'
        collection[:] = [item for item in collection if item['name'] != name]
        return None

    def label(self, resource, labels):
        self.calls.append(('label', resource.name))
        if ('label', resource.name) in self.fail:
            return f'{resource.name}: permission denied'
        for item in self.disks_ + self.buckets_:
            if item['name'] == resource.name:
                item['labels'] = {**item['labels'], **labels}
        return None

    def set_metadata(self, name, zone, key, value):
        self.calls.append(('metadata', name, json.loads(value)['state']))

    def delete_instance(self, name, zone):
        for disk in self.disks_:
            disk['users'] = [u for u in disk['users'] if u != link('instances', name)]
        return self._delete('instance', self.instances_, name)

    def delete_disk(self, name, zone):
        return self._delete('disk', self.disks_, name)

    def delete_bucket(self, name):
        return self._delete('bucket', self.buckets_, name)


def boxes(cloud):
    return inv.inventory(inv.collect(cloud), PROJECT)


class EligibilityTest(unittest.TestCase):
    def test_complete_box_groups_all_four_resources(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        [box], ignored = boxes(cloud)
        instance, boot, data = gce('alice-dev-a7f3c9')
        self.assertEqual(ignored, [])
        self.assertEqual(sorted((r.kind, r.name) for r in box.resources), [
            ('bucket', 'superserve-devbox-3f9c0a1b2c4d'), ('disk', boot), ('disk', data), ('instance', instance)])
        self.assertEqual((box.zone, box.owner, box.missing), (ZONE, 'alice', []))
        self.assertEqual(box.state, 'RUNNING / ready')

    def test_prefix_lookalikes_and_unlabelled_resources_are_never_selected(self):
        instance, _, data = gce('alice-dev-a7f3c9')
        cloud = FakeCloud()
        cloud.instances_.append({'name': instance, 'zone': ZONE, 'labels': {},
                                 'selfLink': link('instances', instance)})
        cloud.disks_.append({'name': data, 'zone': ZONE,
                             'labels': {'devbox-name': 'alice-dev-a7f3c9', 'devbox-id': '3f9c0a1b2c4d'},
                             'selfLink': link('disks', data)})
        cloud.buckets_.append({'name': 'superserve-devbox-3f9c0a1b2c4d', 'labels': {}})
        lookalike = labels('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        cloud.disks_.append({'name': data + '2', 'zone': ZONE, 'labels': lookalike,
                             'selfLink': link('disks', data + '2')})
        cloud.buckets_.append({'name': 'superserve-devbox-3f9c0a1b2c4d-backup', 'labels': lookalike})
        found, ignored = boxes(cloud)
        self.assertEqual(found, [])
        self.assertEqual(sorted(r.name for r, _ in ignored), [data + '2', 'superserve-devbox-3f9c0a1b2c4d-backup'])

    def test_missing_or_invalid_identity_labels_are_ignored(self):
        for missing in ('devbox-id', 'devbox-name'):
            for value in (None, '', 'NOT-VALID'):
                with self.subTest(missing=missing, value=value):
                    cloud = FakeCloud()
                    cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
                    for item in cloud.instances_ + cloud.disks_ + cloud.buckets_:
                        if value is None:
                            del item['labels'][missing]
                        else:
                            item['labels'][missing] = value
                    found, ignored = boxes(cloud)
                    self.assertEqual(found, [])
                    self.assertEqual(len(ignored), 4)

    def test_wrong_project_zone_and_staging_discovery_labels_are_ignored(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', project='example-other-project', bucket=False)
        cloud.add_box('bob-dev-0d1e2f', '0d1e2f3a4b5c', sandbox_role='vmd')
        cloud.add_box('carol-dev-1f2a3b', '1f2a3b4c5d6e', zone='us-east1-b', bucket=False)
        found, ignored = boxes(cloud)
        self.assertEqual(found, [])
        reasons = {r.name: reason for r, reason in ignored}
        self.assertIn(f'not in project {PROJECT}', reasons[gce('alice-dev-a7f3c9')[0]])
        self.assertIn('sandbox_role', reasons[gce('bob-dev-0d1e2f')[0]])
        self.assertIn(f'not in zone {ZONE}', reasons[gce('carol-dev-1f2a3b')[0]])
        self.assertEqual(len(ignored), 10)

    def test_orphan_disks_and_buckets_remain_eligible_without_vm(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False)
        cloud.add_box('bob-dev-0d1e2f', '0d1e2f3a4b5c', vm=False, disks=False)
        found, _ = boxes(cloud)
        self.assertEqual([(b.name, b.state) for b in found],
                         [('alice-dev-a7f3c9', 'orphaned (no VM)'), ('bob-dev-0d1e2f', 'orphaned (no VM)')])
        self.assertEqual(found[0].missing, [f'instance {gce("alice-dev-a7f3c9")[0]}'])
        self.assertEqual(len(found[1].resources), 1)


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeCloud()
        self.cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', expires_at=NOW - 1)
        self.cloud.add_box('alice-dev-b8e4d0', '4a0d1b2c3d4e', expires_at=NOW)
        self.cloud.add_box('bob-dev-0d1e2f', '0d1e2f3a4b5c', owner='bob', expires_at=NOW + 1, vm=False)
        self.cloud.add_box('carol-dev-1f2a3b', '1f2a3b4c5d6e', owner='carol')
        for item in self.cloud.instances_ + self.cloud.disks_ + self.cloud.buckets_:
            if item['labels']['devbox-name'] == 'carol-dev-1f2a3b':
                del item['labels']['expires-at']

    def names(self, action, **kwargs):
        targets, _ = inv.plan(self.cloud, PROJECT, action, now=NOW, **kwargs)
        return [t['name'] for t in targets]

    def test_expiry_selects_passed_boxes_including_orphans_and_skips_unset(self):
        self.assertEqual(self.names('auto-delete'), ['alice-dev-a7f3c9', 'alice-dev-b8e4d0'])
        self.cloud.buckets_[2]['labels']['expires-at'] = str(NOW - 5)
        self.assertIn('bob-dev-0d1e2f', self.names('auto-delete'))

    def test_malformed_manifest_does_not_block_auto_delete(self):
        valid = json.loads(self.cloud.instances_[0]['metadata']['items'][0]['value'])
        for manifest in ({'schema_version': 1, 'revisions': {'sandbox': {'sha': None}}},
                         {**valid, 'revisions': {'sandbox': 'abc'}}, {**valid, 'components': ['api']}):
            with self.subTest(manifest=manifest):
                cloud = FakeCloud()
                cloud.add_box('dave-dev-2a3b4c', '2a3b4c5d6e7f', expires_at=NOW - 1, manifest=manifest)
                targets, _ = inv.plan(cloud, PROJECT, 'auto-delete', now=NOW)
                self.assertEqual([t['name'] for t in targets], ['dave-dev-2a3b4c'])

    def test_named_mine_and_list(self):
        self.assertEqual(self.names('destroy-named', name='bob-dev-0d1e2f'), ['bob-dev-0d1e2f'])
        self.assertEqual(self.names('destroy-named', name='bob-dev'), [])
        self.assertEqual(self.names('destroy-mine', actor='Alice'), ['alice-dev-a7f3c9', 'alice-dev-b8e4d0'])
        self.assertEqual(self.names('list'), [])
        with self.assertRaises(SystemExit):
            inv.plan(self.cloud, PROJECT, 'destroy-named', name='Bad_Name', now=NOW)

    def test_destroy_all_requires_confirmation_bound_to_the_exact_set(self):
        targets, report = inv.plan(self.cloud, PROJECT, 'destroy-all', now=NOW)
        self.assertEqual(targets, [])
        token = inv.set_token([b.target() for b in boxes(self.cloud)[0]])
        self.assertIn(token, report)
        self.assertEqual(len(self.names('destroy-all', confirm=token)), 4)
        self.cloud.add_box('dave-dev-2a3b4c', '2a3b4c5d6e7f', owner='dave')
        with self.assertRaises(SystemExit) as stop:
            inv.plan(self.cloud, PROJECT, 'destroy-all', confirm=token, now=NOW)
        self.assertIn('dave-dev-2a3b4c', stop.exception.code)
        with self.assertRaises(SystemExit):
            inv.plan(self.cloud, PROJECT, 'destroy-all', confirm='0' * 16, now=NOW)

    def test_token_binds_zone_and_identity_not_order(self):
        a = {'name': 'alice-dev-a7f3c9', 'zone': ZONE, 'devbox_id': '3f9c0a1b2c4d'}
        b = {'name': 'bob-dev-0d1e2f', 'zone': '', 'devbox_id': '0d1e2f3a4b5c'}
        self.assertEqual(inv.set_token([a, b]), inv.set_token([b, a]))
        self.assertNotEqual(inv.set_token([a]), inv.set_token([{**a, 'zone': 'us-east1-b'}]))
        self.assertNotEqual(inv.set_token([a]), inv.set_token([{**a, 'devbox_id': '000000000000'}]))
        self.assertNotEqual(inv.set_token([a]), inv.set_token([a, b]))

    def test_same_name_identities_share_one_matrix_entry(self):
        targets = [{'name': 'alice-dev-a7f3c9', 'zone': ZONE, 'devbox_id': '3f9c0a1b2c4d'},
                   {'name': 'alice-dev-a7f3c9', 'zone': '', 'devbox_id': '5b6c7d8e9f0a'},
                   {'name': 'bob-dev-0d1e2f', 'zone': ZONE, 'devbox_id': '0d1e2f3a4b5c'}]
        self.assertEqual(inv.by_name(targets), [
            {'name': 'alice-dev-a7f3c9', 'devbox_ids': '3f9c0a1b2c4d,5b6c7d8e9f0a'},
            {'name': 'bob-dev-0d1e2f', 'devbox_ids': '0d1e2f3a4b5c'}])


class DestroyTest(unittest.TestCase):
    def test_removes_exactly_the_box_and_marks_it_destroying_first(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        cloud.add_box('alice-dev-a7f3c9x', '5b6c7d8e9f0a')
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        instance, boot, data = gce('alice-dev-a7f3c9')
        self.assertEqual(cloud.calls, [
            ('metadata', instance, 'destroying'), ('instance', instance),
            ('bucket', 'superserve-devbox-3f9c0a1b2c4d'), ('disk', boot), ('disk', data)])
        [left], _ = boxes(cloud)
        self.assertEqual((left.name, len(left.resources)), ('alice-dev-a7f3c9x', 4))

    def test_recreated_name_with_new_identity_is_left_alone(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '5b6c7d8e9f0a')
        self.assertIn('already gone', inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d'))
        self.assertEqual(cloud.calls, [])

    def test_orphans_are_removed_and_rerun_is_success(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False)
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertEqual([c[0] for c in cloud.calls], ['bucket', 'disk', 'disk'])
        self.assertIn('already gone', inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d'))

    def test_partial_failure_lists_remaining_and_retry_finishes(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        cloud.fail = {('bucket', 'superserve-devbox-3f9c0a1b2c4d')}
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn('bucket superserve-devbox-3f9c0a1b2c4d', stop.exception.code)
        self.assertIn('permission denied', stop.exception.code)
        cloud.fail, cloud.calls = set(), []
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertEqual(cloud.calls, [('bucket', 'superserve-devbox-3f9c0a1b2c4d')])

    def test_recorded_resource_destroy_cannot_handle_is_not_reported_as_success(self):
        for invalid in (False, True):
            with self.subTest(invalid_manifest=invalid):
                self.check_unhandled_refusal(invalid)

    def check_unhandled_refusal(self, invalid):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        manifest = json.loads(cloud.instances_[0]['metadata']['items'][0]['value'])
        manifest['resources'].append({'type': 'disk', 'name': 'devbox-alice-dev-a7f3c9-scratch', 'zone': ZONE})
        if invalid:
            del manifest['created_at']
        cloud.instances_[0]['metadata']['items'][0]['value'] = json.dumps(manifest)
        for _ in range(2):
            with self.assertRaises(SystemExit) as stop:
                inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
            self.assertIn('disk devbox-alice-dev-a7f3c9-scratch', stop.exception.code)
        self.assertEqual(cloud.calls, [])

    def test_disk_attached_to_another_instance_is_not_deleted(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False)
        _, _, data = gce('alice-dev-a7f3c9')
        cloud.disks_[1]['users'] = [link('instances', 'staging-vmd-1')]
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn('attached to staging-vmd-1', stop.exception.code)
        self.assertNotIn(('disk', data), cloud.calls)

    def test_auto_delete_rechecks_expiry_before_deleting(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', expires_at=NOW + 60)
        self.assertIn('no longer expired', inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d',
                                                         require_expired_at=NOW))
        self.assertEqual(cloud.calls, [])


class UnlabelledResourceTest(unittest.TestCase):
    def test_unlabelled_boot_disk_and_bucket_join_their_box_by_exact_name(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', unlabelled=('boot', 'bucket'))
        [box], _ = boxes(cloud)
        _, boot, _ = gce('alice-dev-a7f3c9')
        self.assertEqual(sorted(r.name for r in box.resources if r.adopted), [boot, 'superserve-devbox-3f9c0a1b2c4d'])
        self.assertEqual((box.missing, box.owner), ([], 'alice'))
        self.assertIn(f'unlabelled bucket superserve-devbox-3f9c0a1b2c4d, disk {boot}', inv.render([box], [], NOW))

    def test_unlabelled_resources_without_a_single_labelled_anchor_are_never_selected(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, unlabelled=('boot', 'bucket'))
        cloud.disks_ = [d for d in cloud.disks_ if d['labels']]
        cloud.disks_.append({'name': gce('alice-dev-a7f3c9')[1], 'zone': ZONE, 'labels': {'sandbox_role': 'vmd'},
                             'selfLink': link('disks', gce('alice-dev-a7f3c9')[1])})
        [box], _ = boxes(cloud)
        self.assertEqual([r.adopted for r in box.resources], [True, False])
        cloud.disks_ = []
        self.assertEqual(boxes(cloud), ([], []))

    def test_unlabelled_boot_disk_goes_to_the_identity_whose_vm_it_is_attached_to(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '5b6c7d8e9f0a', vm=False, disks=False)
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', unlabelled=('boot',))
        found, ignored = boxes(cloud)
        self.assertEqual(ignored, [])
        self.assertEqual([(b.devbox_id, any(r.adopted for r in b.resources)) for b in found],
                         [('3f9c0a1b2c4d', True), ('5b6c7d8e9f0a', False)])
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '5b6c7d8e9f0a')
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertEqual((cloud.instances_, cloud.disks_, cloud.buckets_), ([], [], []))

    def test_detached_unlabelled_boot_disk_claimed_by_two_identities_is_refused(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, disks=False)
        cloud.add_box('alice-dev-a7f3c9', '5b6c7d8e9f0a', vm=False, unlabelled=('boot',))
        found, ignored = boxes(cloud)
        self.assertFalse(any(r.adopted for b in found for r in b.resources))
        self.assertIn('claimed by 2 devboxes', ignored[0][1])

    def test_unlabelled_leftovers_are_labelled_first_so_a_failed_delete_stays_findable(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', unlabelled=('boot', 'bucket'))
        cloud.disks_ = [d for d in cloud.disks_ if not d['name'].endswith('-data')]
        instance, boot, _ = gce('alice-dev-a7f3c9')
        cloud.fail = {('bucket', 'superserve-devbox-3f9c0a1b2c4d')}
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn('bucket superserve-devbox-3f9c0a1b2c4d', stop.exception.code)
        self.assertEqual(sorted(cloud.calls[:2]), [('label', boot), ('label', 'superserve-devbox-3f9c0a1b2c4d')])
        [box], _ = boxes(cloud)
        self.assertEqual([(r.kind, r.adopted) for r in box.resources], [('bucket', False)])
        cloud.fail = set()
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertEqual((cloud.instances_, cloud.disks_, cloud.buckets_), ([], [], []))

    def test_failed_labelling_deletes_nothing(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', unlabelled=('boot',))
        cloud.fail = {('label', gce('alice-dev-a7f3c9')[1])}
        with self.assertRaises(SystemExit):
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertEqual([c[0] for c in cloud.calls], ['label'])

    def test_unlabelled_disk_named_like_a_data_disk_is_never_adopted(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', disks=False)
        _, _, data = gce('alice-dev-a7f3c9')
        cloud.disks_.append({'name': data, 'zone': f'projects/{PROJECT}/zones/{ZONE}', 'labels': {},
                             'creationTimestamp': CREATED, 'selfLink': link('disks', data), 'users': []})
        [box], _ = boxes(cloud)
        self.assertNotIn(('disk', data), [(r.kind, r.name) for r in box.resources])
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn(f'{data}: is not labelled as this devbox', stop.exception.code)
        self.assertEqual(cloud.calls, [])

    def test_blocked_remnant_is_not_reported_gone_when_nothing_else_remains(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, bucket=False, environment='staging')
        cloud.disks_ = cloud.disks_[:1]
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn(f'disk {gce("alice-dev-a7f3c9")[1]}', stop.exception.code)
        self.assertEqual(cloud.calls, [])

    def test_refused_resources_of_another_identity_do_not_block_destroy(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, disks=False, expires_at=NOW - 1)
        cloud.add_box('alice-dev-a7f3c9', '5b6c7d8e9f0a', vm=False, bucket=False, environment='staging')
        inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d', require_expired_at=NOW)
        self.assertEqual(cloud.calls, [('bucket', 'superserve-devbox-3f9c0a1b2c4d')])
        self.assertEqual(len(cloud.disks_), 2)

    def test_remnants_not_attributable_to_another_identity_still_block(self):
        _, boot, _ = gce('alice-dev-a7f3c9')
        for kind, change in (('disk', {'devbox-id': 'BADID'}), ('bucket', {'devbox-id': 'ffffffffffff'}),
                             ('disk', {'devbox-id': 'ffffffffffff', 'devbox-name': 'bob-dev-0d1e2f'}),
                             ('disk', {'devbox-id': 'ffffffffffff', 'devbox-name': ''}),
                             ('disk', {'devbox-id': 'ffffffffffff', 'managed-by': 'someone-else'})):
            with self.subTest(kind=kind, change=change):
                cloud = FakeCloud()
                cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, environment='staging')
                cloud.disks_ = cloud.disks_[:1] if kind == 'disk' else []
                cloud.buckets_ = cloud.buckets_ if kind == 'bucket' else []
                (cloud.disks_ or cloud.buckets_)[0]['labels'].update(change)
                with self.assertRaises(SystemExit):
                    inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
                self.assertEqual(cloud.calls, [])

    def test_resource_labelled_as_the_box_under_another_name_blocks_destroy(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
        extra = gce('alice-dev-a7f3c9')[2] + '2'
        cloud.disks_.append({'name': extra, 'zone': f'projects/{PROJECT}/zones/{ZONE}', 'creationTimestamp': CREATED,
                             'labels': labels('alice-dev-a7f3c9', '3f9c0a1b2c4d'), 'selfLink': link('disks', extra)})
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn(extra, stop.exception.code)
        self.assertEqual(cloud.calls, [])

    def test_unlabelled_disk_newer_than_the_box_is_not_adopted(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, unlabelled=('boot',))
        cloud.disks_[0]['creationTimestamp'] = '2027-03-01T00:00:00+00:00'
        [box], _ = boxes(cloud)
        self.assertFalse(any(r.adopted for r in box.resources))
        with self.assertRaises(SystemExit) as stop:
            inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
        self.assertIn('newer than the create run', stop.exception.code)
        self.assertEqual(cloud.calls, [])

    def test_unreadable_manifest_refuses_destroy(self):
        for value in ('{"resources": [', '{}', 'null', '[]', '{"resources": null}'):
            with self.subTest(value=value):
                cloud = FakeCloud()
                cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d')
                cloud.instances_[0]['metadata']['items'][0]['value'] = value
                with self.assertRaises(SystemExit) as stop:
                    inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
                self.assertIn(inv.UNREADABLE, stop.exception.code)
                self.assertEqual(cloud.calls, [])

    def test_doubly_claimed_leftover_goes_to_the_only_box_whose_create_window_fits(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '5b6c7d8e9f0a', vm=False, disks=False)
        cloud.buckets_[0]['creation_time'] = '2026-12-01T00:00:00+00:00'
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False, unlabelled=('boot',))
        found, ignored = boxes(cloud)
        self.assertEqual(ignored, [])
        self.assertEqual([(b.devbox_id, any(r.adopted for r in b.resources)) for b in found],
                         [('3f9c0a1b2c4d', True), ('5b6c7d8e9f0a', False)])

    def test_old_partially_labelled_or_foreign_attached_resources_are_not_adopted(self):
        _, boot, _ = gce('alice-dev-a7f3c9')
        cases = {'older than the devbox': {'creationTimestamp': '2027-01-15T04:59:59+00:00'},
                 'devbox-name': {'labels': {'devbox-name': 'bob-dev-0d1e2f', 'env': 'staging'}},
                 'attached to staging-vmd-1': {'users': [link('instances', 'staging-vmd-1')]}}
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                cloud = FakeCloud()
                cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', unlabelled=('boot',))
                cloud.disks_[0].update(change)
                [box], ignored = boxes(cloud)
                self.assertNotIn(('disk', boot), [(r.kind, r.name) for r in box.resources])
                if reason != 'devbox-name':
                    self.assertIn(reason, ignored[0][1])
                with self.assertRaises(SystemExit) as stop:
                    inv.destroy(cloud, PROJECT, 'alice-dev-a7f3c9', '3f9c0a1b2c4d')
                self.assertIn(boot, stop.exception.code)
                self.assertEqual(cloud.calls, [])


class DestroyNameTest(unittest.TestCase):
    def test_one_identity_failing_does_not_skip_the_others(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', vm=False)
        original = inv.destroy

        def flaky(cloud_, project, name, devbox_id, **kwargs):
            if devbox_id == '5b6c7d8e9f0a':
                raise RuntimeError('gcloud compute disks list failed: backend error')
            return original(cloud_, project, name, devbox_id, **kwargs)
        inv.destroy = flaky
        try:
            with self.assertRaises(SystemExit) as stop:
                inv.destroy_name(cloud, PROJECT, 'alice-dev-a7f3c9', '5b6c7d8e9f0a,3f9c0a1b2c4d')
        finally:
            inv.destroy = original
        self.assertIn('Destroyed `alice-dev-a7f3c9` (3f9c0a1b2c4d)', stop.exception.code)
        self.assertIn('Destroy incomplete for alice-dev-a7f3c9: 5b6c7d8e9f0a', stop.exception.code)

    def test_invalid_identity_inputs_are_rejected_not_reported_gone(self):
        for name, ids in (('alice-dev-a7f3c9', ''), ('alice-dev-a7f3c9', 'XYZ'), ('Bad_Name', '3f9c0a1b2c4d')):
            with self.subTest(name=name, ids=ids), self.assertRaises(SystemExit):
                inv.destroy_name(FakeCloud(), PROJECT, name, ids)


class RenderTest(unittest.TestCase):
    def test_revisions_group_partially_upgraded_components_and_escape_cells(self):
        box = inv.Box('alice-dev-a7f3c9', '3f9c0a1b2c4d', [inv.Resource('instance', 'x', ZONE, {}, manifest={
            'components': {'vmd': {'branch': 'main', 'sha': 'a' * 40}, 'proxy': {'branch': 'main', 'sha': 'a' * 40},
                           'api': {'branch': 'fix|y', 'sha': 'c' * 40}, 'ui': {'branch': 'main', 'sha': 'b' * 40}},
            'revisions': {'sandbox': {'branch': 'main', 'sha': 'a' * 40}}})])
        self.assertEqual(inv._revisions(box), 'main @ aaaaaaaaaaaa (vmd, proxy); fix\\|y @ cccccccccccc (api); '
                                              'main @ bbbbbbbbbbbb (ui)')

    def test_list_shows_partial_boxes_revisions_and_ignored_resources(self):
        cloud = FakeCloud()
        cloud.add_box('alice-dev-a7f3c9', '3f9c0a1b2c4d', bucket=False)
        cloud.buckets_.append({'name': 'superserve-devbox-ffffffffffff', 'labels': labels('bob-dev-0d1e2f', '0d1e2f3a4b5c')})
        found, ignored = boxes(cloud)
        report = inv.render(found, ignored, NOW)
        self.assertIn('partial: missing bucket superserve-devbox-3f9c0a1b2c4d', report)
        self.assertIn('feature-x @ bbbbbbbbbbbb', report)
        self.assertIn('1d 2h', report)
        self.assertIn(contract.forwarding_command('alice-dev-a7f3c9', ZONE), report)
        self.assertIn('superserve-devbox-ffffffffffff', report)


if __name__ == '__main__':
    unittest.main()
