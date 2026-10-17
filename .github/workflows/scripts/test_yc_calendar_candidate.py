import copy
import os
import unittest
from unittest.mock import Mock, patch

import yc_calendar_candidate as candidate


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.drain = Mock()
        self.drain.pause.side_effect = lambda: self.events.append('pause')
        self.drain.barrier.side_effect = lambda: self.events.append('retired')
        self.drain.resume.side_effect = lambda **_: self.events.append('resume')
        self.before = {'active_leases': 1, 'history_hash': 'original', 'base_history_hash': 'original',
                       'cohort': {'synthetic': 'unchanged'}, 'policy_hash': 'reviewed'}
        self.drained = dict(self.before, active_leases=0)
        self.after = dict(self.drained, history_hash='migrated')
        self.inspect = Mock(side_effect=lambda applied: copy.deepcopy(self.after if applied else self.drained))
        self.migrate = Mock(side_effect=lambda: self.events.append('migrate'))
        self.recheck = Mock(side_effect=lambda: self.events.append('recheck'))
        self.audit = patch.object(candidate, 'audit')
        self.audit.start()
        self.addCleanup(self.audit.stop)

    def run_transition(self):
        candidate.transition(self.drain, self.before, self.inspect, self.migrate, self.recheck)

    def test_migration_requires_drain_and_resume_requires_schema_verification(self):
        self.run_transition()
        self.assertEqual(self.events, ['pause', 'retired', 'recheck', 'retired', 'migrate', 'recheck', 'resume'])
        self.drain.resume.assert_called_once_with(migrated=True)

    def test_unexpired_lease_or_changed_financial_authority_stops_before_migration(self):
        for changed in ({'active_leases': 1}, {'cohort': {'synthetic': 'new-export'}}):
            with self.subTest(changed=changed):
                self.inspect.side_effect = lambda applied: dict(self.drained, **changed)
                with self.assertRaises(candidate.common.GateError):
                    self.run_transition()
                self.migrate.assert_not_called()
                self.drain.resume.assert_not_called()

    def test_failed_retirement_prevents_sql(self):
        self.drain.barrier.side_effect = candidate.common.GateError('old revision still executing')
        with self.assertRaises(candidate.common.GateError):
            self.run_transition()
        self.inspect.assert_not_called()
        self.migrate.assert_not_called()

    def test_migration_failure_never_restores_old_runtime(self):
        self.migrate.side_effect = candidate.common.GateError('synthetic migration failure')
        with self.assertRaises(candidate.common.GateError):
            self.run_transition()
        self.drain.resume.assert_not_called()
        self.assertEqual(self.drain.method_calls, [unittest.mock.call.pause(), unittest.mock.call.barrier(), unittest.mock.call.barrier()])

    def test_schema_or_history_verification_failure_prevents_application_start(self):
        self.after['base_history_hash'] = 'changed-history'
        with self.assertRaisesRegex(candidate.common.GateError, 'prior history'):
            self.run_transition()
        self.drain.resume.assert_not_called()

    def test_approval_change_after_migration_leaves_service_parked(self):
        self.recheck.side_effect = [None, candidate.common.GateError('main changed')]
        with self.assertRaises(candidate.common.GateError):
            self.run_transition()
        self.migrate.assert_called_once()
        self.drain.resume.assert_not_called()


class PolicyTests(unittest.TestCase):
    def test_apply_inputs_cannot_bypass_missing_persistent_retry_fence(self):
        for mode, env in [('apply', {}), ('gate', {'VALIDATION_MODE': 'apply'})]:
            with self.subTest(mode=mode), patch('sys.argv', ['candidate', mode]), patch.dict(os.environ, env), \
                    patch.object(candidate, 'provenance') as provenance, patch.object(candidate, 'audit'), \
                    patch.object(candidate.common, 'staging_credentials') as credentials:
                self.assertEqual(candidate.main(), 1)
                credentials.assert_not_called()
                provenance.assert_not_called()

    def test_credit_runner_receipt_is_not_calendar_approval(self):
        run = {'head_sha': 'a' * 40, 'event': 'workflow_dispatch', 'path': candidate.common.WORKFLOW,
               'head_branch': 'main', 'repository': {'full_name': candidate.common.REPOSITORY},
               'head_repository': {'full_name': candidate.common.REPOSITORY},
               'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
        with patch.object(candidate.common, 'api', return_value=run), patch.object(candidate.common, 'command') as command:
            with self.assertRaisesRegex(candidate.common.GateError, 'calendar preflight'):
                candidate.fetch_receipt({'PREFLIGHT_RUN_ID': '123', 'GITHUB_SHA': 'a' * 40})
            command.assert_not_called()

    def test_history_uses_post_credit_function_and_exact_calendar_bytes(self):
        manifest, history = candidate.load_policy()
        spec = history['functions']['enqueue_billing_entitlement']
        self.assertEqual(candidate.common.file_hash(candidate.ROOT / spec['source']), spec['source_sha256'])
        sql = (candidate.ROOT / spec['source']).read_text()
        body = candidate.re.search(r'FUNCTION enqueue_billing_entitlement\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;', sql, candidate.re.S).group(1)
        self.assertEqual(candidate.digest(body), spec['body_sha256'])
        self.assertEqual(history['candidate_migrations'], manifest['migrations'])


if __name__ == '__main__':
    unittest.main()
