"""Identity rollout failures must leave the target's running deployment intact."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('deploy_vmd_identity', Path(__file__).with_name('deploy-vmd.py'))
deploy_vmd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy_vmd)

IDENTITY = dict(host_id='example-host', project_id='example-project', instance_id='100',
                incarnation_id='73863d7a-26f8-4a41-9d89-d458421935e7')
ENV = 'HOST_ID=example-host\nHOST_IDENTITY_FILE=/etc/sandbox/host-identity.json\n'


class IdentityPreflightTests(unittest.TestCase):
    def exercise(self, state, env):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if state is not None:
                (root / 'host-identity.json').write_text(state)
            if env is not None:
                (root / 'host-identity.env').write_text(env)
            # Substitute only file locations, preserving the required env value.
            script = deploy_vmd.host_identity_preflight()
            for name in ('host-identity.json', 'host-identity.env'):
                script = script.replace("Path('/etc/sandbox/" + name + "')", 'Path(' + repr(str(root / name)) + ')')
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            result = subprocess.run(['bash', '-c', 'sudo() { "$@"; }\n' + script],
                                    capture_output=True, text=True)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            return result

    def test_installed_identity_passes_without_changes(self):
        result = self.exercise(json.dumps(IDENTITY), ENV)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_empty_corrupt_or_mismatched_identity_fails_without_changes(self):
        valid = json.dumps(IDENTITY)
        cases = [(None, None), (None, ENV), (valid, None), ('', ENV), (valid, ''),
                 ('{', ENV), ('null', ENV), ('{}', ENV),
                 (json.dumps(dict(IDENTITY, incarnation_id='invalid')), ENV),
                 (json.dumps(dict(IDENTITY, incarnation_id='00000000-0000-0000-0000-000000000000')), ENV),
                 (valid, ENV.replace('example-host', 'another-host')),
                 (valid, ENV.replace('/etc/sandbox/host-identity.json', '/tmp/other.json')),
                 (valid, ENV + 'HOST_ID=another-host\n')]
        for state, env in cases:
            with self.subTest(state=state, env=env):
                result = self.exercise(state, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('complete deploy/host-generation-rollout.md', result.stderr)

    def test_deploy_checks_identity_before_upload_even_with_all_inputs(self):
        for supplied in (False, True):
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                if args[0] == 'tar':
                    return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
                if args[1:4] == ['compute', 'instances', 'list']:
                    return subprocess.CompletedProcess(args, 0, stdout='example-host,us-central1-a\n')
                if args[1:3] == ['compute', 'ssh']:
                    return subprocess.CompletedProcess(args, 1, stdout='', stderr='identity not installed')
                self.fail(f'unexpected command after failed preflight: {args[:3]}')

            env = dict(GCP_PROJECT='example-project', SHA='12345678')
            if supplied:
                env.update(CONTROL_PLANE_URL='https://example.test', DATABASE_URL='postgres://example.test/db',
                           INTERNAL_API_TOKEN='example-token')
            with self.subTest(supplied=supplied), patch.dict(os.environ, env, clear=True), \
                    patch.object(deploy_vmd.subprocess, 'run', side_effect=run), \
                    patch.object(deploy_vmd.os.path, 'getsize', return_value=100), \
                    patch.object(deploy_vmd.os.path, 'exists', return_value=True), patch('builtins.print'):
                self.assertEqual(deploy_vmd.main(), 1)
            self.assertEqual(len(calls), 3)
            probe = calls[-1]
            self.assertEqual(probe[1:3], ['compute', 'ssh'])
            self.assertIn(deploy_vmd.host_identity_preflight(), probe[probe.index('--command') + 1])

    def test_remote_script_rechecks_before_mutations(self):
        source = Path(deploy_vmd.__file__).read_text()
        self.assertIn('input_preflight = host_identity_preflight() + runtime_input_preflight(', source)
        self.assertIn('inject_script = input_preflight + legacy_vmd_enrollment()', source)


if __name__ == '__main__':
    unittest.main()
