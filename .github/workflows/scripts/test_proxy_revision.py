import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


class ProxyRevisionTests(unittest.TestCase):
    def test_schema_gate_waits_for_successful_same_release_migration(self):
        for name in ('deploy-proxy.yml', 'deploy-api.yml', 'terraform-cd.yml'):
            with self.subTest(workflow=name):
                self.check_schema_gate(name)

    def check_schema_gate(self, name):
        workflow = Path(__file__).parents[1].joinpath(name).read_text()
        step = workflow.split('      - name: Wait for same-SHA CD Migrate to succeed\n', 1)[1].split('\n  deploy-staging:', 1)[0].split('\n  build-api-image:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        substitutions = {'github.event_name': 'push', 'github.event.before': 'before',
                         'github.sha': 'release', 'github.repository': 'example/repo',
                         'steps.revision.outputs.revision': 'release'}
        for key, value in substitutions.items():
            script = script.replace('${{ ' + key + ' }}', value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for command, body in {
                'git': 'case "$1" in fetch) exit "${FETCH_FAILURE:-0}";; diff) printf "%s\\n" "$CHANGED_PATH";; checkout) test "$3" = release;; esac',
                'gh': 'case "$2" in *head_sha=release*) printf "%s\\n" "$MIGRATION_RESULT";; *) exit 9;; esac',
                'sleep': 'exit 0',
            }.items():
                path = root / command
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                       CHANGED_PATH='supabase/migrations/test.sql', MIGRATION_RESULT='completed success')
            for result, success in [('completed success', True), ('completed failure', False),
                                    ('completed cancelled', False), ('in_progress pending', False),
                                    ('absent absent', False)]:
                with self.subTest(result=result):
                    proc = subprocess.run(['bash', '-c', script], env=dict(env, MIGRATION_RESULT=result),
                                          capture_output=True, text=True)
                    self.assertEqual(proc.returncode == 0, success, proc.stderr)
            for path in ('supabase/shared-auth-history/setup.sql', 'scripts/migrate_database.py',
                         '.github/workflows/cd.yml'):
                for result, success in [('completed success', True), ('completed failure', False)]:
                    with self.subTest(path=path, result=result):
                        proc = subprocess.run(['bash', '-c', script],
                                              env=dict(env, CHANGED_PATH=path, MIGRATION_RESULT=result),
                                              capture_output=True, text=True)
                        self.assertEqual(proc.returncode == 0, success, proc.stderr)
            proc = subprocess.run(['bash', '-c', script], env=dict(env, CHANGED_PATH='internal/proxy/router.go',
                                  MIGRATION_RESULT='completed failure'), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            for result, success in [('completed success', True), ('absent absent', name != 'deploy-proxy.yml')]:
                proc = subprocess.run(['bash', '-c', script], env=dict(env, FETCH_FAILURE='1',
                                      MIGRATION_RESULT=result), capture_output=True, text=True)
                self.assertEqual(proc.returncode == 0, success, proc.stderr)
            manual = script.replace('if [ "push" != "push" ]', 'if [ "workflow_dispatch" != "push" ]')
            proc = subprocess.run(['bash', '-c', manual], env=dict(env, MIGRATION_RESULT='completed failure'),
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode == 0, name != "terraform-cd.yml", proc.stderr)
        if name == "deploy-proxy.yml":
            self.assertIn("      - 'supabase/migrations/**'", workflow)

    def test_revision_gate_accepts_only_main_history_and_matching_original_run(self):
        workflow = Path(__file__).parents[1].joinpath('deploy-proxy.yml').read_text()
        step = workflow.split('      - name: Validate deployment revision\n', 1)[1].split('      - name:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True).strip()
            git('init', '-q', '-b', 'main')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.test',
                'commit', '-q', '--allow-empty', '-m', 'main')
            approved = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', approved)
            git('checkout', '-q', '-b', 'unreviewed')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.test',
                'commit', '-q', '--allow-empty', '-m', 'unreviewed')
            unreviewed = git('rev-parse', 'HEAD')
            fake = root / 'gh'
            fake.write_text('#!/bin/sh\nprintf "%s" "$RUN_METADATA"\n')
            fake.chmod(0o755)
            metadata = dict(head_sha=approved, head_branch='main',
                            path='.github/workflows/deploy-proxy.yml', event='workflow_dispatch')
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                       GH_REPO='example/repo', CURRENT_REF='refs/heads/main', CURRENT_SHA=approved,
                       REQUESTED_REVISION='', REQUESTED_ROLLOUT_ID='', GITHUB_OUTPUT=str(root / 'output'),
                       RUN_METADATA=json.dumps(metadata))
            cases = [({}, True),
                     ({'REQUESTED_REVISION': approved, 'REQUESTED_ROLLOUT_ID': '123'}, True),
                     ({'CURRENT_REF': 'refs/heads/unreviewed'}, False),
                     ({'CURRENT_SHA': unreviewed}, False),
                     ({'REQUESTED_REVISION': 'main', 'REQUESTED_ROLLOUT_ID': '123'}, False),
                     ({'REQUESTED_REVISION': approved}, False),
                     ({'REQUESTED_ROLLOUT_ID': '123'}, False),
                     ({'REQUESTED_REVISION': approved, 'REQUESTED_ROLLOUT_ID': '123',
                       'RUN_METADATA': json.dumps(dict(metadata, head_sha=unreviewed))}, False),
                     ({'REQUESTED_REVISION': approved, 'REQUESTED_ROLLOUT_ID': '123',
                       'RUN_METADATA': json.dumps(dict(metadata, path='.github/workflows/other.yml'))}, False),
                     ({'REQUESTED_REVISION': unreviewed, 'REQUESTED_ROLLOUT_ID': '123',
                       'RUN_METADATA': json.dumps(dict(metadata, head_sha=unreviewed))}, False)]
            staging_validation = dict(CURRENT_REF='refs/heads/unreviewed', CURRENT_SHA=unreviewed,
                                      DEPLOY_EVENT='workflow_dispatch', VALIDATION_ENVIRONMENT='staging',
                                      PROXY_DEPLOYMENT_MODE='legacy')
            cases.extend([
                (staging_validation, True),
                (dict(staging_validation, VALIDATION_ENVIRONMENT='production'), False),
                (dict(staging_validation, PROXY_DEPLOYMENT_MODE='generation'), False),
                (dict(staging_validation, DEPLOY_EVENT='push'), False),
                (dict(staging_validation, REQUESTED_REVISION=approved, REQUESTED_ROLLOUT_ID='123'), False),
            ])
            for override, success in cases:
                with self.subTest(override=override):
                    (root / 'output').unlink(missing_ok=True)
                    result = subprocess.run(['bash', '-c', script], cwd=root,
                                            env=dict(env, **override), capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    if success:
                        expected_revision = unreviewed if override == staging_validation else approved
                        self.assertEqual((root / 'output').read_text(), f'revision={expected_revision}\n')
                    else:
                        self.assertFalse((root / 'output').exists())
        self.assertEqual(workflow.count('ref: ${{ needs.migration-gate.outputs.revision }}'), 2)
        self.assertIn('needs: [migration-gate, deploy-staging]', workflow)
