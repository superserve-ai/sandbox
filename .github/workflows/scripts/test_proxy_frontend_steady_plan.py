"""Ordinary applies must preserve live proxy traffic before migration."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('steady', ROOT / 'scripts/check_proxy_frontend_steady_plan.py')
steady = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steady)


class SteadyFrontendTests(unittest.TestCase):
    def test_noop_adoption_is_allowed_but_traffic_changes_are_refused(self):
        for cell, addresses in (('staging', steady.STAGING_FRONTENDS), ('production', steady.FRONTENDS)):
            items = [dict(address=address, change=dict(actions=['no-op'], before={'id': address},
                          after={'id': address}, importing={'id': address})) for address in addresses]
            steady.validate(dict(resource_changes=items), cell)
            for mutation in ('update', 'create', 'delete', 'replace', 'changed', 'unknown', 'moved', 'missing', 'duplicate'):
                changed = copy.deepcopy(items)
                item = changed[0]
                if mutation in ('update', 'create', 'delete'):
                    item['change']['actions'] = [mutation]
                elif mutation == 'replace':
                    item['change']['actions'] = ['delete', 'create']
                elif mutation == 'changed':
                    item['change']['after']['backend_service'] = 'example-replacement'
                elif mutation == 'unknown':
                    item['change']['after_unknown'] = {'backend_service': True}
                elif mutation == 'moved':
                    item['previous_address'] = 'example.previous'
                elif mutation == 'missing':
                    changed.pop()
                else:
                    changed.append(copy.deepcopy(item))
                with self.subTest(cell=cell, mutation=mutation), self.assertRaises(ValueError):
                    steady.validate(dict(resource_changes=changed), cell)
        with self.assertRaises(ValueError):
            steady.validate({}, 'unknown')

    def test_guard_runs_before_both_automatic_applies(self):
        workflow = (ROOT / '.github/workflows/terraform-cd.yml').read_text()
        for cell in ('staging/us-central1', 'production/us-east4'):
            step = re.split(r'^  [a-z][a-z0-9-]*:\n',
                            workflow.split('- name: Terraform apply ' + cell + '\n', 1)[1],
                            maxsplit=1, flags=re.M)[0]
            guard = step.index('check_proxy_frontend_steady_plan.py')
            self.assertLess(guard, step.index('terraform apply -input=false'))
            if cell.startswith('staging'):
                self.assertIn('check_proxy_frontend_steady_plan.py" staging', step[:guard + 80])

    def test_manual_staging_apply_preserves_setting_and_refuses_traffic_changes(self):
        workflow = (ROOT / '.github/workflows/terraform-rollout-staging.yml').read_text()
        step = workflow.split('      - name: Terraform apply staging/us-central1\n')[1].split('\n      - name:')[0]
        expression = re.search(r'TF_VAR_proxy_generation_frontends_enabled: \$\{\{ (.+) \}\}', step)[1]
        script = step.split('        run: |\n')[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'infra/envs/staging/us-central1').mkdir(parents=True)
            shim = root / 'terraform'
            shim.write_text('''#!/bin/sh
case "$1" in
 plan) printf '%s' "$TF_VAR_proxy_generation_frontends_enabled" > "$PLAN_SETTING" ;;
 show) cat "$PLAN_FIXTURE" ;;
 apply) touch "$APPLY_RECEIPT" ;;
esac
''')
            shim.chmod(0o755)
            for setting in ('', 'false', 'true', 'TRUE'):
                selected = eval(expression.replace('&&', ' and ').replace('||', ' or '),
                                {'__builtins__': {}},
                                {'vars': SimpleNamespace(PROXY_STAGING_FRONTEND_MIGRATED=setting)})
                for mutation in (None, 'backend_service', 'certificate_map'):
                    items = [dict(address=address, type=address.split('.')[0], change=dict(actions=['no-op'],
                                  before={'id': address}, after={'id': address}))
                             for address in steady.STAGING_FRONTENDS]
                    if mutation:
                        items[0]['change']['actions'] = ['update']
                        items[0]['change']['after'][mutation] = 'example-unintended-change'
                    fixture = root / 'plan.json'
                    fixture.write_text(json.dumps({'format_version': '1.2', 'resource_changes': items}))
                    applied = root / 'applied'
                    applied.unlink(missing_ok=True)
                    env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                               GITHUB_WORKSPACE=str(ROOT), GITHUB_STEP_SUMMARY=str(root / 'summary'),
                               PLAN_FIXTURE=str(fixture), APPLY_RECEIPT=str(applied),
                               PLAN_SETTING=str(root / 'setting'), TF_VAR_proxy_generation_frontends_enabled=selected)
                    result = subprocess.run(['bash', '-eu', '-c', script], cwd=root, env=env,
                                            capture_output=True, text=True)
                    with self.subTest(setting=setting, mutation=mutation):
                        self.assertEqual((root / 'setting').read_text(), 'true' if setting == 'true' else 'false')
                        self.assertEqual(result.returncode == 0, mutation is None, result.stderr)
                        self.assertEqual(applied.exists(), mutation is None)
                        if mutation:
                            self.assertIn('Use the explicit proxy migration for frontend changes', result.stderr)


if __name__ == '__main__':
    unittest.main()
