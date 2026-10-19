"""Execute capacity configuration and rollout checks against a fake host env."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from shell_test_support import linux_shell_prelude

spec = importlib.util.spec_from_file_location('deploy_vmd_egress', Path(__file__).with_name('deploy-vmd.py'))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class EgressCapacityDeploymentTest(unittest.TestCase):
    def exercise(self, existing='', **overrides):
        env = {'SHA': 'a' * 40, 'DEPLOY_CELL': 'use4'}
        env.update(overrides)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'vmd.env'
            path.write_text('UNRELATED=preserve\n' + existing)
            script = deploy.egress_capacity_preflight(env) + '\n' + deploy.egress_capacity_update(env)
            script = script.replace('/etc/sandbox/vmd.env', str(path))
            result = subprocess.run(['bash', '-c', linux_shell_prelude() + '\nsudo() { "$@"; }\n' + script], text=True, capture_output=True)
            return result, path.read_text()


    def test_reruns_preserve_optional_settings(self):
        result, contents = self.exercise(VMD_EGRESS_ENFORCE='true', VMD_EGRESS_MAX_CONNECTIONS='8')
        self.assertEqual(result.returncode, 0, result.stderr)
        result, again = self.exercise(contents.removeprefix('UNRELATED=preserve\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(contents, again)


    def test_explicit_disable_preserves_capacity(self):
        result, contents = self.exercise('VMD_EGRESS_ENFORCE=true\nVMD_EGRESS_MAX_CONNECTIONS=8\n', VMD_EGRESS_ENFORCE='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(contents.count('VMD_EGRESS_ENFORCE='), 1)
        self.assertIn('VMD_EGRESS_ENFORCE=false', contents)
        self.assertIn('VMD_EGRESS_MAX_CONNECTIONS=8', contents)

    def test_invalid_inputs_fail_before_remote_execution(self):
        for value in ('0', '-1', 'oops', '8\nINJECT=1', '999999999999999999999999', '８'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy.egress_capacity_settings({'VMD_EGRESS_MAX_CONNECTIONS': value})
        with self.assertRaises(ValueError):
            deploy.egress_capacity_settings({'VMD_EGRESS_ENFORCE': '1'})

    def test_inherited_whitespace_quotes_and_last_assignment(self):
        existing = 'VMD_EGRESS_ENFORCE=false\n  VMD_EGRESS_ENFORCE = "true"\n\tVMD_EGRESS_MAX_CONNECTIONS = \'8\'\n'
        result, _ = self.exercise(existing)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_inherited_overflow_and_unsupported_syntax_fail_before_updates(self):
        for existing in ('VMD_EGRESS_MAX_CONNECTIONS=999999999999999999999999\n',
                         'VMD_EGRESS_ENFORCE=tr"ue"\n',
                         'VMD_EGRESS_ENFORCE=tr' + chr(92) + '\nue\n'):
            with self.subTest(existing=existing):
                result, contents = self.exercise(existing)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(contents, 'UNRELATED=preserve\n' + existing)
        result, _ = self.exercise('VMD_EGRESS_MAX_CONNECTIONS=999999999999999999999999\n',
                                  VMD_EGRESS_MAX_CONNECTIONS='8', VMD_EGRESS_ENFORCE='false')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_comments_cannot_hide_enforcement_and_multiline_context_fails_closed(self):
        cases = [
            '# a comment' + chr(92) + '\nVMD_EGRESS_ENFORCE=true\n',
            'UNRELATED=path' + chr(92) * 2 + '\nVMD_EGRESS_ENFORCE=true\n',
            'VMD_EGRESS_ENFORCE=true\nOTHER="first line\nVMD_EGRESS_ENFORCE=false\nlast line"\n',
            'VMD_EGRESS_ENFORCE=true\n# a comment' + chr(92) + '\nVMD_EGRESS_ENFORCE=false\n',
        ]
        for existing in cases:
            with self.subTest(existing=existing):
                result, contents = self.exercise(existing)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(contents, 'UNRELATED=preserve\n' + existing)
        # Explicit overrides may not rewrite apparent keys inside another value.
        result, contents = self.exercise(cases[2], VMD_EGRESS_ENFORCE='false', VMD_EGRESS_MAX_CONNECTIONS='8')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(contents, 'UNRELATED=preserve\n' + cases[2])
