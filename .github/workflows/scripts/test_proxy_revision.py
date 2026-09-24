import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


class ProxyRevisionTests(unittest.TestCase):
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
            for override, success in cases:
                with self.subTest(override=override):
                    (root / 'output').unlink(missing_ok=True)
                    result = subprocess.run(['bash', '-c', script], cwd=root,
                                            env=dict(env, **override), capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    if success:
                        self.assertEqual((root / 'output').read_text(), f'revision={approved}\n')
                    else:
                        self.assertFalse((root / 'output').exists())
        self.assertEqual(workflow.count('ref: ${{ needs.migration-gate.outputs.revision }}'), 2)
        self.assertIn('needs: [migration-gate, deploy-staging]', workflow)
