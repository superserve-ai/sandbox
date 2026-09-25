"""Production custom roles require effective CI permissions before region applies."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).parents[1] / 'terraform-cd.yml'


class CustomRoleBootstrapTests(unittest.TestCase):
    def test_effective_permissions_gate_regional_applies(self):
        text = WORKFLOW.read_text()
        job = text.split('  production-us-central1-bootstrap:\n')[1].split('\n  production-us-west2-infra:')[0]
        self.assertIn('-target=\'module.iam.google_project_iam_member.project_bindings["cd_role_admin"]\'', job)
        script = job.split('      - name: Wait for custom role management permissions\n')[1].split('        run: |\n')[1]
        for cell in ('us-east4', 'us-west2'):
            region = text.split('  production-' + cell + '-infra:\n')[1].split('    steps:')[0]
            self.assertIn('production-us-central1-bootstrap', region)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                'gcloud': '#!/bin/sh\nprintf "example-token\\n"\n',
                'sleep': '#!/bin/sh\nexit 0\n',
                'curl': '''#!/bin/sh
count=$(cat "$ROLE_TEST_COUNT" 2>/dev/null || echo 0)
count=$((count+1))
echo "$count" > "$ROLE_TEST_COUNT"
case "$ROLE_TEST_MODE" in
  error) exit 22 ;;
  partial) printf '{"permissions":["iam.roles.get"]}' ;;
  eventual) if [ "$count" -lt 2 ]; then printf '{}'; else printf '%s' "$ROLE_TEST_PERMISSIONS"; fi ;;
  *) printf '%s' "$ROLE_TEST_PERMISSIONS" ;;
esac
''',
            }
            for name, contents in commands.items():
                path = root / name
                path.write_text(contents)
                path.chmod(0o755)
            for mode, expected, calls in (('ready', 0, 1), ('eventual', 0, 2), ('partial', 1, 30), ('error', 1, 30)):
                counter = root / 'count'
                counter.unlink(missing_ok=True)
                env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                           GCP_PROJECT='example-project', ROLE_TEST_MODE=mode, ROLE_TEST_COUNT=str(counter),
                           ROLE_TEST_PERMISSIONS='{"permissions":["iam.roles.create","iam.roles.get","iam.roles.update","iam.roles.delete"]}')
                result = subprocess.run(['bash', '-eu', '-c', script], env=env, capture_output=True, text=True)
                with self.subTest(mode=mode):
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(int(counter.read_text()), calls)


if __name__ == '__main__':
    unittest.main()
