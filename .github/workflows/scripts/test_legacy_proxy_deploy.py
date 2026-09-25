import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load('legacy_guard', SCRIPTS / 'legacy_proxy_preflight.py')
deploy = load('legacy_deploy', SCRIPTS / 'deploy-proxy-legacy.py')
steady = load('production_steady', SCRIPTS.parents[2] / 'scripts/check_proxy_frontend_steady_plan.py')


class LegacyProxyTests(unittest.TestCase):
    def test_unfinished_or_active_generations_block_legacy_deployment(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, 'command', return_value=''):
            root = Path(directory)
            marker = root / 'hold'
            guard.check_state(root, marker)
            good = dict(phase='rolled_back', active=guard.LEGACY)
            for mutation in ('hold', 'phase', 'bootstrap', 'generation', 'ports', 'credentials', 'private', 'running'):
                state = copy.deepcopy(good)
                if mutation == 'hold':
                    marker.touch()
                elif mutation == 'phase':
                    state['phase'] = 'rollback_withdrawing'
                elif mutation == 'bootstrap':
                    state.update(phase='complete', bootstrap=True)
                elif mutation == 'generation':
                    state['active']['id'] = 'a' * 20
                elif mutation == 'ports':
                    state['active']['ports']['public'] = 5100
                elif mutation == 'credentials':
                    state['_credential_recovery'] = {'pending': True}
                elif mutation == 'private':
                    (root / 'private.json').write_text(json.dumps(dict(guard.LEGACY, id='a' * 20)))
                (root / 'state.json').write_text(json.dumps(state))
                units = 'proxy-' + 'a' * 20 + '.service loaded active running' if mutation == 'running' else ''
                with self.subTest(mutation=mutation), patch.object(guard, 'command', return_value=units):
                    with self.assertRaises(RuntimeError):
                        guard.check_state(root, marker)
                marker.unlink(missing_ok=True)
                (root / 'private.json').unlink(missing_ok=True)
            (root / 'state.json').write_text(json.dumps(good))
            (root / 'private.json').write_text(json.dumps(guard.LEGACY))
            guard.check_state(root, marker)

    def test_advertisement_must_match_saved_and_running_vmd(self):
        enabled = {'PEER_PROXY_LISTEN_ADDR': '192.0.2.10:5009'}
        self.assertEqual(guard.resolve_listener('auto', enabled, enabled, '192.0.2.10'), '192.0.2.10:5009')
        self.assertEqual(guard.resolve_listener('', {}, {}, ''), '')
        for requested, running, saved in (('auto', {}, enabled), ('auto', enabled, {}), ('', enabled, enabled)):
            with self.subTest(requested=requested), self.assertRaises(RuntimeError):
                guard.resolve_listener(requested, running, saved, '192.0.2.10')

    def test_generated_deployment_locks_before_preflight_and_never_mutates_vmd(self):
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            output = 'example-host,us-central1-a\n' if args[:4] == ['gcloud', 'compute', 'instances', 'list'] else ''
            return subprocess.CompletedProcess(args, 0, output, '')
        env = dict(GCP_PROJECT='example-project', GCP_REGION='us-central1', SHA='12345678',
                   PROXY_DOMAIN='sandbox.example.test', PEER_PROXY_LISTEN_ADDR='auto')
        with patch.dict(os.environ, env, clear=True), patch.object(deploy.subprocess, 'run', side_effect=run), \
                patch.object(deploy.os.path, 'exists', return_value=True):
            self.assertEqual(deploy.main(), 0)
        outer = commands[-1][-1]
        self.assertIn('flock -n /var/lib/proxy-rollout/lock bash -c', outer)
        inner = shlex.split(outer)[-1]
        syntax = subprocess.run(['bash', '-n'], input=inner, text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertLess(inner.index('sudo python3 /tmp/legacy-proxy-preflight-'), inner.index('sudo mv /tmp/proxy-'))
        for line in inner.splitlines():
            if 'vmd.env' in line and not line.lstrip().startswith('#'):
                self.assertIn("sed -n 's/^HOST_ID=//p'", line)
        self.assertNotRegex(inner, r'systemctl (restart|stop|start) superserve-vmd')
        self.assertIn('systemctl restart proxy', inner)
        self.assertIn('InvocationID', inner)

    def test_legacy_mode_bypasses_only_generation_promotion(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        step = workflow.split('      - name: Require host identity readiness for automatic rollout\n')[1].split('\n  deploy-staging:')[0]
        script = step.split('        run: |\n')[1]
        for ready in ('', 'true'):
            env = dict(os.environ, PROXY_DEPLOYMENT_MODE='legacy', DEPLOY_EVENT='push', ROLLOUT_READY=ready)
            result = subprocess.run(['bash', '-eu', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0 if ready == 'true' else 1, result.stderr)
        production = workflow.split('  deploy-production:\n')[1]
        expression = re.search(r'^    if: (.+)$', production, re.M)[1]
        for environment in ('staging', 'production'):
            context = dict(github=SimpleNamespace(event_name='workflow_dispatch', event=SimpleNamespace(
                inputs=SimpleNamespace(environment=environment))),
                needs={'migration-gate': SimpleNamespace(outputs=SimpleNamespace(mode='legacy'))})
            self.assertEqual(eval(expression.replace('&&', ' and ').replace('||', ' or '),
                                  {'__builtins__': {}}, context), environment == 'production')

    def test_retry_mode_controls_manifest_loading_and_production_gate(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        selector = re.search(r'^  PROXY_DEPLOYMENT_MODE: \$\{\{ (.+) \}\}$', workflow, re.M)[1]
        manifest_step = workflow.split('      - name: Read applied proxy manifests from the owning state\n')[1]
        manifest_gate = re.search(r'^        if: (.+)$', manifest_step, re.M)[1]
        production = workflow.split('  deploy-production:\n')[1]
        production_gate = re.search(r'^    if: (.+)$', production, re.M)[1]
        for requested in ('legacy', 'generation'):
            for rollout_id in ('', '123'):
                for ready in ('', 'true'):
                    with self.subTest(requested=requested, rollout_id=rollout_id, ready=ready):
                        context = dict(
                            inputs=SimpleNamespace(operation='deploy', rollout_id=rollout_id,
                                                   revision='a' * 40 if rollout_id else '',
                                                   deployment_mode=requested),
                            github=SimpleNamespace(event_name='workflow_dispatch', event=SimpleNamespace(
                                inputs=SimpleNamespace(environment='production'))),
                            vars=SimpleNamespace(PROXY_GENERATION_PROMOTION_READY=ready,
                                                 PROXY_GENERATION_PROMOTION_EVIDENCE_STATUS='passed',
                                                 PROXY_GENERATION_RUNBOOK_URL='https://example.test/runbook',
                                                 PROXY_GENERATION_PROMOTION_EVIDENCE_URL='https://example.test/evidence'))
                        def evaluate(expression):
                            return eval(expression.replace('&&', ' and ').replace('||', ' or '),
                                        {'__builtins__': {}}, context)
                        selected = evaluate(selector)
                        self.assertEqual(selected, requested)
                        context['env'] = SimpleNamespace(PROXY_DEPLOYMENT_MODE=selected)
                        context['needs'] = {'migration-gate': SimpleNamespace(outputs=SimpleNamespace(mode=selected))}
                        self.assertEqual(evaluate(manifest_gate), requested == 'generation')
                        self.assertEqual(evaluate(production_gate), requested == 'legacy' or ready == 'true')

    def test_full_production_apply_cannot_change_frontends(self):
        items = [dict(address=address, change=dict(actions=['no-op'], before={'id': address},
                                                  after={'id': address}, importing={'id': address}))
                 for address in steady.FRONTENDS]
        steady.validate(dict(resource_changes=items))
        for action in (['update'], ['create'], ['delete', 'create']):
            changed = copy.deepcopy(items)
            changed[0]['change']['actions'] = action
            with self.assertRaises(ValueError):
                steady.validate(dict(resource_changes=changed))
        with self.assertRaises(ValueError):
            steady.validate(dict(resource_changes=items[:-1]))


if __name__ == '__main__':
    unittest.main()
