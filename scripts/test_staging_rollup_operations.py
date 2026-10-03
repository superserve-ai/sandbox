import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import staging_rollup_diagnostic as diagnostic
import staging_rollup_pause as pause


class StagingRollupOperationsTest(unittest.TestCase):
    def test_wrong_database_project_never_connects(self):
        for value in ('postgresql://user:example@db.other.supabase.co/postgres',
                      'postgresql://user:example@db.rifhalqzxgskwajjgipj.supabase.co/postgres?host=other'):
            with self.subTest(value=value), patch.dict(os.environ, DATABASE_URL=value), patch.object(diagnostic, 'command') as command:
                with self.assertRaisesRegex(diagnostic.DiagnosticError, 'staging_database_identity_unverified'):
                    diagnostic.sql(diagnostic.Reader(time.monotonic()+30), 'SELECT 1')
                command.assert_not_called()

    def test_unarmed_baseline_does_not_deploy_during_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory)/'baseline.json'
            baseline.write_text(json.dumps({'mutation_started': False}))
            with patch.object(pause, 'BASELINE', baseline), patch.object(pause, 'RESULT', Path(directory)/'result.json'), \
                 patch.dict(os.environ, GCP_PROJECT=pause.PROJECT), patch('sys.argv', ['pause', '--restore']), \
                 patch.object(pause, 'gate', return_value='a'*40), patch.object(pause, 'restore') as restore, \
                 patch.object(pause, 'service') as service:
                self.assertEqual(pause.main(), 0)
                restore.assert_not_called()
                service.assert_not_called()

    def test_ready_unrouted_revision_does_not_require_serving_pointer(self):
        service = {'metadata': {'generation': 2}, 'status': {'observedGeneration': 2,
                   'latestCreatedRevisionName': 'new', 'latestReadyRevisionName': 'old'}}
        revision = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                    'imageDigest': pause.IMAGE, 'conditions': [{'type': 'Ready', 'status': 'True', 'reason': 'Retired'}]}}
        with patch.object(pause, 'service', return_value=service), patch.object(pause, 'same_configuration', return_value=True), \
             patch.object(pause, 'flag', return_value='true'), patch.object(diagnostic, 'cloud', return_value=revision):
            self.assertEqual(pause.wait_ready(pause.Reader(time.monotonic()+30), 'new', {}, 'true'), service)

    def test_inactive_and_unreconciled_are_not_retired(self):
        row = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
               'conditions': [{'type': 'Active', 'status': 'False', 'reason': 'Retired'}]}}
        self.assertTrue(pause.retired(row))
        changed = copy.deepcopy(row)
        changed['status']['observedGeneration'] = 0
        self.assertFalse(pause.retired(changed))
        row['status']['conditions'][0]['reason'] = 'Retiring'
        self.assertFalse(pause.retired(row))


if __name__ == '__main__':
    unittest.main()
