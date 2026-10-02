"""Reject incomplete, stale or unauthenticated recovery observations."""

import copy
import datetime
import hashlib
import io
import json
import time
import unittest
from unittest.mock import patch
import zipfile

import recovery_evidence as evidence
from migrate_database import MigrationError


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        def stamp(seconds):
            return datetime.datetime.fromtimestamp(self.now + seconds, datetime.timezone.utc).isoformat()
        self.revision, self.plan, self.database = 'a' * 40, 'b' * 64, 'example-project'
        self.current = {'service': {}, 'revisions': [{'metadata': {'name': 'api-v1'},
                        'status': {'imageDigest': 'sha256:' + 'c' * 64}, 'spec': {'containers': [{}]}}],
                        'instances': [{'id': '1', 'name': 'host', 'zone': 'example-zone'}]}
        service = {'service_id': 'vmd', 'source_commit': evidence.AUDITED_SOURCE,
                   'build_provenance_verified': True, 'automatic_downloads': False, 'in_progress_rollout': False,
                   'executable_sha256': 'd' * 64, 'unit_sha256': 'e' * 64, 'configuration_sha256': 'f' * 64}
        process = {'service_id': 'vmd', 'source_commit': evidence.AUDITED_SOURCE,
                   'build_provenance_verified': True, 'executable_sha256': 'd' * 64,
                   'start_time': stamp(-60), 'incarnation_id': 'instance-1', 'destination_database': self.database}
        host = {'instance_id': '1', 'instance_name': 'host', 'zone': 'example-zone',
                'authenticated_read_route': 'existing-observer', 'key_or_metadata_mutation': False,
                'complete_process_inventory': True, 'report_services': [service], 'report_processes': [process],
                'spools': {name: {'retained_payloads': 0, 'complete_scan': True} for name in
                           ('.storage-report-queue', '.storage-report-queue.v2', '.storage-report-queue.migrating/state.json')}}
        self.document = {'schema': 1, 'target': 'usw2', 'recovery_revision': self.revision,
                         'collector_revision': self.revision, 'plan_hash': self.plan, 'database_project': self.database,
                         'started_at': stamp(-10), 'completed_at': stamp(-1), 'project': evidence.PROJECT,
                         'region': evidence.REGION, 'service': evidence.SERVICE,
                         'inventory_before': evidence.sha(self.current), 'inventory_after': evidence.sha(self.current),
                         'revisions': [{'name': 'api-v1', 'source_commit': evidence.AUDITED_SOURCE,
                                        'image_digest': 'sha256:' + 'c' * 64, 'build_provenance_verified': True}],
                         'revision_lifecycle_audit': {'started_at': stamp(-700), 'completed_at': stamp(-1),
                                                      'complete': True, 'deleted_revisions': []},
                         'hosts': [host], 'alternate_producers': [], 'complete_writer_inventory': True,
                         'deployment_and_toggle_hold': {'revision': self.revision, 'active': True}}

    def validate(self, document=None, current=None, now=None):
        evidence.validate(document or self.document, revision=self.revision, plan_hash=self.plan,
                          database_project=self.database, current=current or self.current,
                          now=self.now if now is None else now)

    def test_incomplete_or_capable_producer_fails_closed(self):
        self.validate()
        changes = [(['hosts', 0, 'report_processes'], None), (['hosts', 0, 'report_services'], None),
                   (['hosts', 0, 'key_or_metadata_mutation'], True),
                   (['hosts', 0, 'report_services', 0, 'automatic_downloads'], True),
                   (['hosts', 0, 'report_services', 0, 'executable_sha256'], '1' * 64),
                   (['hosts', 0, 'report_processes', 0, 'source_commit'], '1' * 40),
                   (['hosts', 0, 'spools', '.storage-report-queue', 'retained_payloads'], 1),
                   (['hosts', 0, 'spools', '.storage-report-queue.v2', 'complete_scan'], False),
                   (['revision_lifecycle_audit', 'deleted_revisions'], ['deleted']),
                   (['revisions', 0, 'build_provenance_verified'], False),
                   (['hosts'], []), (['alternate_producers'], ['other']),
                   (['deployment_and_toggle_hold', 'active'], False)]
        for path, value in changes:
            with self.subTest(path=path):
                doc = copy.deepcopy(self.document)
                target = doc
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(MigrationError):
                    self.validate(doc)
        for now in (self.now + 121, self.now - 20):
            with self.assertRaises(MigrationError):
                self.validate(now=now)

    def test_changed_inventory_sidecars_and_overrides_fail(self):
        for containers in ([{}, {}], [{'command': ['override']}], [{'args': ['override']}], []):
            current = copy.deepcopy(self.current)
            current['revisions'][0]['spec']['containers'] = containers
            doc = copy.deepcopy(self.document)
            doc['inventory_before'] = doc['inventory_after'] = evidence.sha(current)
            with self.assertRaises(MigrationError):
                self.validate(doc, current)
        current = copy.deepcopy(self.current)
        current['instances'].append({'id': '2', 'name': 'standby', 'zone': 'example-zone'})
        with self.assertRaises(MigrationError):
            self.validate(current=current)

    def observation(self, run_id='12'):
        return evidence.Observation(repository='example/project', revision=self.revision, run_id=run_id,
                                    plan_hash=self.plan, database_project=self.database, deadline=time.monotonic() + 60)

    def test_authenticated_artifact_and_refresh_preserve_stable_state(self):
        def archive():
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as file:
                file.writestr('evidence.json', json.dumps(self.document))
            return buffer.getvalue()
        data = archive()
        run = {'head_sha': self.revision, 'head_branch': 'main', 'event': 'workflow_dispatch',
               'path': evidence.COLLECTOR_WORKFLOW, 'status': 'completed', 'conclusion': 'success',
               'repository': {'full_name': 'example/project'}}
        def api(path, binary=False):
            if '/artifacts?' in path:
                return json.dumps({'artifacts': [{'id': 1, 'name': 'retained-recovery-evidence-usw2',
                                  'expired': False, 'size_in_bytes': len(data),
                                  'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}]})
            return data if binary else json.dumps(run)
        with patch.object(evidence, 'inventory', return_value=self.current):
            first = self.observation()
            first.api = api
            first.verify()
            self.document['completed_at'] = datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc).isoformat()
            self.document['revision_lifecycle_audit']['completed_at'] = self.document['completed_at']
            data = archive()
            refreshed = self.observation('13')
            refreshed.api = api
            refreshed.verify()
            self.assertEqual(first.state_digest, refreshed.state_digest)
            with self.assertRaisesRegex(MigrationError, 'integrity changed'):
                first.verify()
            for key, wrong in [('head_sha', '1' * 40), ('path', '.github/workflows/other.yml'),
                               ('conclusion', 'failure'), ('repository', {'full_name': 'other/project'})]:
                original = run[key]
                run[key] = wrong
                with self.subTest(key=key), self.assertRaises(MigrationError):
                    refreshed.verify()
                run[key] = original


if __name__ == '__main__':
    unittest.main(verbosity=2)
