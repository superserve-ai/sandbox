"""Exercise manual selection and production step guards without cloud access."""

import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).parent


class DeployTargetTests(unittest.TestCase):
    def test_staging_migration_shares_proxy_deployment_queue(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        expression = re.search(r'^  group: \$\{\{ (.+) \}\}$', workflow, re.M)[1]
        expression = expression.replace('&&', 'and').replace('||', 'or')
        proxy_group = re.search(r'^  group: (.+)$', (SCRIPTS.parent / 'deploy-proxy.yml').read_text(), re.M)[1]
        terraform_group = re.search(r'^  group: (.+)$', (SCRIPTS.parent / 'terraform-cd.yml').read_text(), re.M)[1]
        for mode in ('', 'none', 'hold', 'cutover', 'rollback', 'release', 'abort', 'expedite-abort'):
            actual = eval(expression, {'__builtins__': {}}, {'inputs': SimpleNamespace(proxy_migration=mode)})
            self.assertEqual(actual, terraform_group if mode in ('', 'none', 'expedite-abort') else proxy_group, mode)

    def test_staging_migration_conflicts_fail_before_authentication(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        for name in ('smoke', 'privateca-bootstrap', 'proxy-prepare', 'proxy-runtime-iam'):
            job = re.split(r'^  [a-z][a-z-]*:\n', workflow.split(f'  {name}:\n', 1)[1],
                           maxsplit=1, flags=re.M)[0]
            script = job.split('        run: |\n', 1)[1].split('\n      - uses:', 1)[0]
            for mode in ('hold', 'cutover', 'rollback', 'release', 'abort', 'expedite-abort'):
                result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                        env=dict(os.environ, CONFIRM='smoke' if name == 'smoke' else 'apply',
                                                 PRIVATECA_BOOTSTRAP='false', PROXY_PREPARE='false',
                                                 PROXY_RUNTIME_IAM='false', PROXY_MIGRATION=mode))
                self.assertNotEqual(result.returncode, 0, (name, mode))

    def test_staging_smoke_selection_excludes_infrastructure_jobs(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        jobs = {}
        for name in ('smoke', 'privateca-bootstrap', 'proxy-prepare', 'proxy-runtime-iam', 'proxy-migration', 'staging'):
            job = re.split(r'^  [a-z][a-z-]*:\n', workflow.split(f'  {name}:\n', 1)[1],
                           maxsplit=1, flags=re.M)[0]
            jobs[name] = job
        for smoke, bootstrap, proxy, runtime, migration in itertools.product((False, True), (False, True), (False, True), (False, True), ('none', 'hold', 'cutover', 'rollback', 'release', 'abort')):
            with self.subTest(smoke=smoke, bootstrap=bootstrap, proxy=proxy, runtime=runtime):
                selected = []
                for name, job in jobs.items():
                    guard = re.search(r'^    if: \$\{\{ (.+) \}\}$', job, re.M)[1]
                    guard = guard.replace('&&', 'and').replace('!=', '<>').replace('!', 'not ').replace('<>', '!=')
                    if eval(guard, {'__builtins__': {}},
                            {'inputs': SimpleNamespace(smoke_only=smoke,
                                                       privateca_bootstrap=bootstrap,
                                                       proxy_prepare=proxy,
                                                       proxy_runtime_iam=runtime,
                                                       proxy_migration=migration)}):
                        selected.append(name)
                expected = ('smoke' if smoke else 'privateca-bootstrap' if bootstrap
                            else 'proxy-prepare' if proxy else 'proxy-runtime-iam' if runtime else 'proxy-migration' if migration != 'none' else 'staging')
                self.assertEqual(selected, [expected])
        self.assertIn('environment: staging', jobs['smoke'])
        self.assertIn('secrets.SS_TEST_API_KEY_STAGING', jobs['smoke'])
        self.assertNotIn('id-token:', jobs['smoke'])
        self.assertNotIn('terraform ', jobs['smoke'])
        self.assertNotIn('google-github-actions/auth', jobs['smoke'])

    def test_staging_smoke_confirmation_rejects_conflicting_modes(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        job = workflow.split('  smoke:\n', 1)[1].split('  privateca-bootstrap:\n', 1)[0]
        script = job.split('        run: |\n', 1)[1].split('\n      - uses:', 1)[0]
        for confirm in ('smoke', 'apply', '', 'invalid'):
            for bootstrap, proxy, runtime in itertools.product(('true', 'false'), repeat=3):
                with self.subTest(confirm=confirm, bootstrap=bootstrap, proxy=proxy):
                    result = subprocess.run(['bash', '-eu', '-c', script],
                                            capture_output=True, text=True,
                                            env=dict(os.environ, CONFIRM=confirm,
                                                     PRIVATECA_BOOTSTRAP=bootstrap,
                                                     PROXY_PREPARE=proxy, PROXY_RUNTIME_IAM=runtime, PROXY_MIGRATION="none"))
                    self.assertEqual(result.returncode == 0,
                                     confirm == 'smoke' and bootstrap == proxy == runtime == 'false')

    def test_privateca_bootstrap_rejects_proxy_preparation(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        job = workflow.split('  privateca-bootstrap:\n', 1)[1].split('  proxy-prepare:\n', 1)[0]
        script = job.split('        run: |\n', 1)[1].split('\n      - uses:', 1)[0]
        for confirm, proxy, runtime in itertools.product(('apply', 'smoke', ''), ('true', 'false'), ('true', 'false')):
            result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                    env=dict(os.environ, CONFIRM=confirm, PROXY_PREPARE=proxy, PROXY_RUNTIME_IAM=runtime, PROXY_MIGRATION="none"))
            self.assertEqual(result.returncode == 0, confirm == 'apply' and proxy == runtime == 'false')

    def test_proxy_preparation_plan_guards_reject_unrelated_changes(self):
        workflow = (SCRIPTS.parent / 'terraform-rollout-staging.yml').read_text()
        job = workflow.split('  proxy-prepare:\n', 1)[1].split('  staging:\n', 1)[0]
        self.assertIn('environment: staging', job)
        self.assertNotIn('smoke-test-region.sh', job)
        self.assertNotIn('terraform -chdir=infra/envs/production', job)
        self.assertLess(job.index('terraform apply -input=false -lock-timeout=5m role-plan'),
                        job.index('- name: Wait for role-management permissions'))
        self.assertLess(job.index('- name: Wait for role-management permissions'),
                        job.index('terraform plan -input=false -lock-timeout=5m "${targets[@]}"'))
        targets_script = job.split('          targets=()', 1)[1].split('          terraform plan', 1)[0]
        targets_result = subprocess.run(['bash', '-eu', '-c', 'targets=()\n' + targets_script + '\nprintf "%s\\n" "${targets[@]}"'],
                                        capture_output=True, text=True, check=True)
        targets = targets_result.stdout.splitlines()
        self.assertEqual(len(targets), 10)
        self.assertNotIn('-target=module.proxy_generations["staging"].google_project_iam_member.generation', targets)
        self.assertIn('-target=module.proxy_generations["staging"].google_project_iam_custom_role.generation', targets)
        self.assertNotIn('-target=module.proxy_generations', targets)
        script = job.split('- name: Apply CI role-management grant', 1)[1]
        role_guard = script.split("jq -e --arg target \"$target\" '", 1)[1].split("\n          '", 1)[0]
        proxy_guard = script.split("terraform show -json proxy-plan | jq -e '", 1)[1].split("\n          '", 1)[0]
        role_guard = role_guard.replace('rayai-dev', 'example-project').replace(
            'superserve-github-actions', 'example-deployer')
        proxy_guard = proxy_guard.replace('rayai-dev', 'example-project')
        target = 'module.iam.google_project_iam_member.project_bindings["cd_role_admin"]'
        grant = dict(address=target, type='google_project_iam_member',
                     change=dict(actions=['create'], after=dict(
                         project='example-project', role='roles/iam.roleAdmin', condition=[],
                         member='serviceAccount:example-deployer@example-project.iam.gserviceaccount.com')))

        def accepted(guard, changes):
            result = subprocess.run(['jq', '-e', '--arg', 'target', target, guard],
                                    input=json.dumps(dict(resource_changes=changes)),
                                    capture_output=True, text=True)
            return result.returncode == 0

        self.assertTrue(accepted(role_guard, [grant]))
        self.assertTrue(accepted(role_guard, []))
        for key, value in (
            ('project', 'example-production'), ('role', 'roles/owner'),
            ('member', 'user:operator@example.com'), ('condition', [{'expression': 'true'}]),
        ):
            changed = json.loads(json.dumps(grant))
            changed['change']['after'][key] = value
            self.assertFalse(accepted(role_guard, [changed]), key)
        for actions in (['delete'], ['update'], ['delete', 'create']):
            changed = json.loads(json.dumps(grant))
            changed['change']['actions'] = actions
            self.assertFalse(accepted(role_guard, [changed]), actions)
        unrelated = json.loads(json.dumps(grant))
        unrelated['address'] = 'google_project_iam_member.unrelated'
        self.assertFalse(accepted(role_guard, [unrelated]))

        generation = dict(address='module.proxy_generations["staging"].google_project_iam_custom_role.generation[0]',
                          type='google_project_iam_custom_role',
                          change=dict(actions=['create'], after=dict(project='example-project')))
        self.assertTrue(accepted(proxy_guard, [generation]))
        endpoint_binding = dict(address='module.proxy_generations["staging"].google_project_iam_member.generation[0]',
                                type='google_project_iam_member',
                                change=dict(actions=['create'], after=dict(project='example-project', condition=[])))
        self.assertFalse(accepted(proxy_guard, [endpoint_binding]))
        endpoint_binding['change']['actions'] = ['no-op']
        self.assertTrue(accepted(proxy_guard, [endpoint_binding]))
        for address, project, actions in (
            ('google_compute_url_map.proxy', 'example-project', ['create']),
            (generation['address'], 'example-production', ['create']),
            (generation['address'], 'example-project', ['update']),
            (generation['address'], 'example-project', ['delete']),
        ):
            changed = dict(address=address, type=generation['type'],
                           change=dict(actions=actions, after=dict(project=project)))
            self.assertFalse(accepted(proxy_guard, [changed]))
        bucket = dict(address='module.proxy_generations["staging"].google_storage_bucket_iam_member.generation_ownership[0]',
                      type='google_storage_bucket_iam_member',
                      change=dict(actions=['create'], after=dict(bucket='example-project-proxy-staging-ownership')))
        self.assertTrue(accepted(proxy_guard, [bucket]))
        bucket['change']['after']['bucket'] = 'example-unrelated-bucket'
        self.assertFalse(accepted(proxy_guard, [bucket]))

    def test_frontend_owning_states_keep_migration_explicit(self):
        workflow = (SCRIPTS.parent / 'terraform-cd.yml').read_text()
        deploy = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        for name, gate in (
            ('staging/us-central1', 'PROXY_STAGING_FRONTEND_MIGRATED'),
            ('production/us-east4', 'PROXY_PRODUCTION_FRONTEND_MIGRATED'),
        ):
            with self.subTest(state=name):
                step = workflow.split(f'- name: Terraform apply {name}\n', 1)[1]
                self.assertIn(f'vars.{gate}', step.split('        run: |', 1)[0])
                guard = step.split('        run: |\n', 1)[1].split('          echo "## Terraform rollout:', 1)[0]
                for value in ('', 'false', 'true'):
                    result = subprocess.run(['bash', '-eu', '-c', guard],
                                            capture_output=True, text=True,
                                            env=dict(os.environ, PROXY_FRONTEND_MIGRATED=value))
                    self.assertEqual(result.returncode, 0)
        for state in ('staging/us-central1', 'production/us-east4', 'production/us-west2'):
            with self.subTest(bootstrap_output=state):
                generations = (SCRIPTS.parent.parent.parent / 'infra' / 'envs' / state
                               / 'proxy-generations.tf').read_text()
                self.assertIn('output "proxy_generation_bootstrap"', generations)
                self.assertIn('key => cell.generation_rollout', generations)
                self.assertIn(f'terraform -chdir=infra/envs/{state} output -json |', deploy)

    def test_automatic_rollouts_enforce_identity_gates(self):
        for kind in ('vmd', 'proxy'):
            workflow = (SCRIPTS.parent / f'deploy-{kind}.yml').read_text()
            # Read the gate up to the next job, preserving its nested steps.
            gate = re.split(r'^  [a-z][a-z-]*:\n', workflow.split('  migration-gate:\n', 1)[1], maxsplit=1, flags=re.M)[0]
            self.assertIn('ROLLOUT_READY: ${{ vars.HOST_IDENTITY_ROLLOUT_READY }}', gate)
            script = gate.rsplit('        run: |\n', 1)[1]
            staging = workflow.split('  deploy-staging:\n', 1)[1].split('    steps:', 1)[0]
            self.assertRegex(staging, r'needs: \[[^\]]*migration-gate[^\]]*\]')
            cases = [(event, ready, int(event == 'push' and ready != 'true'))
                     for event in ('push', 'workflow_dispatch')
                     for ready in (None, '', 'false', 'true', 'TRUE', '1', 'tru', ' true ')]
            for event, ready, expected in cases:
                with self.subTest(kind=kind, event=event, ready=ready):
                    env = dict(os.environ, DEPLOY_EVENT=event, GENERATION_READY='true')
                    if kind == 'proxy':
                        env.update(RUNBOOK_URL='https://www.notion.so/example-team/proxy-generation',
                                   EVIDENCE_URL='https://evidence.example/proxy-generation/2026-09-21',
                                   EVIDENCE_STATUS='passed')
                    env.pop('ROLLOUT_READY', None)
                    if ready is not None:
                        env['ROLLOUT_READY'] = ready
                    result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                            env=env, text=True)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected:
                        if kind == 'proxy' or ready is not None:
                            self.assertIn('use the coordinated manual rollout procedure', result.stderr)

    def test_proxy_automatic_rollouts_require_generation_promotion(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        gate = re.split(r'^  [a-z][a-z-]*:\n', workflow.split('  migration-gate:\n', 1)[1],
                        maxsplit=1, flags=re.M)[0]
        self.assertIn('GENERATION_READY: ${{ vars.PROXY_GENERATION_PROMOTION_READY }}', gate)
        script = gate.rsplit('        run: |\n', 1)[1]
        for event in ('push', 'workflow_dispatch'):
            for ready in (None, '', 'false', 'true', 'TRUE', '1', 'tru', ' true '):
                with self.subTest(event=event, ready=ready):
                    env = dict(os.environ, DEPLOY_EVENT=event, ROLLOUT_READY='true',
                               RUNBOOK_URL='https://www.notion.so/example-team/proxy-generation',
                               EVIDENCE_URL='https://evidence.example/proxy-generation/2026-09-21',
                               EVIDENCE_STATUS='passed')
                    env.pop('GENERATION_READY', None)
                    if ready is not None:
                        env['GENERATION_READY'] = ready
                    result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                            env=env, text=True)
                    expected = int(event == 'push' and ready != 'true')
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected:
                        self.assertIn('Generation migration and staging promotion evidence', result.stderr)

    def test_proxy_automatic_rollouts_require_linked_runbook_and_recorded_evidence(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        gate = re.split(r'^  [a-z][a-z-]*:\n', workflow.split('  migration-gate:\n', 1)[1],
                        maxsplit=1, flags=re.M)[0]
        self.assertIn('RUNBOOK_URL: ${{ vars.PROXY_GENERATION_RUNBOOK_URL }}', gate)
        self.assertIn('EVIDENCE_URL: ${{ vars.PROXY_GENERATION_PROMOTION_EVIDENCE_URL }}', gate)
        self.assertIn('EVIDENCE_STATUS: ${{ vars.PROXY_GENERATION_PROMOTION_EVIDENCE_STATUS }}', gate)
        production = workflow.split('  deploy-production:\n', 1)[1]
        self.assertIn('Validate linked staging promotion evidence', production)
        self.assertIn('echo "- Evidence status: $EVIDENCE_STATUS"', production)
        self.assertNotIn('echo "- Executable runbook: $RUNBOOK_URL"', production)
        self.assertNotIn('echo "- Recorded staging evidence: $EVIDENCE_URL"', production)
        self.assertIn("vars.PROXY_GENERATION_PROMOTION_EVIDENCE_STATUS == 'passed'", production)
        script = gate.rsplit('        run: |\n', 1)[1]
        cases = (
            ('https://www.notion.so/example-team/page', 'https://evidence.example/run-1', 'passed', 0),
            ('https://app.notion.com/example-team/page', 'https://evidence.example/run-1', 'passed', 0),
            ('', 'https://evidence.example/run-1', 'passed', 1),
            ('http://runbook.example/page', 'https://evidence.example/run-1', 'passed', 1),
            ('https://runbook.example/page', 'https://evidence.example/run-1', 'passed', 1),
            ('https://www.notion.so/example-team/page', '', 'passed', 1),
            ('https://www.notion.so/example-team/page', 'https://evidence.example/run-1', 'pending', 1),
        )
        for runbook, evidence, status, expected in cases:
            with self.subTest(runbook=runbook, evidence=evidence, status=status):
                env = dict(os.environ, DEPLOY_EVENT='push', ROLLOUT_READY='true',
                           GENERATION_READY='true', RUNBOOK_URL=runbook,
                           EVIDENCE_URL=evidence, EVIDENCE_STATUS=status)
                result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                        env=env, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertIn('published Notion runbook', result.stderr)

    def test_proxy_bootstrap_uses_applied_manifests_and_promoted_staging(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        staging, production = workflow.split('  deploy-staging:\n',1)[1].split('  deploy-production:\n',1)
        for job, root in ((staging,'staging/us-central1'),(production,'production/us-east4')):
            output = f'terraform -chdir=infra/envs/{root} output -json |'
            self.assertLess(job.index(output),job.index('python3 .github/workflows/scripts/deploy-proxy.py'))
        self.assertIn("PROXY_OPERATION: ${{ inputs.environment == 'production' && 'deploy' || inputs.operation || 'deploy' }}",staging)
        self.assertIn("PROXY_OPERATION: ${{ inputs.operation || 'deploy' }}",workflow)

    def test_production_proxy_loads_each_cells_own_manifest(self):
        workflow = (SCRIPTS.parent / 'deploy-proxy.yml').read_text()
        production = workflow.split('  deploy-production:\n', 1)[1]
        steps = re.split(r'^      - ', production, flags=re.M)
        for region, deploy_name in (
            ('us-east4', 'Deploy proxy to us-east4 use-cell VMD instance'),
            ('us-west2', 'Deploy proxy to usw cell VMD instances'),
        ):
            with self.subTest(region=region):
                index = next(i for i, step in enumerate(steps)
                             if step.startswith(f'name: {deploy_name}\n'))
                load, deploy = steps[index - 1:index + 1]
                load_guard = re.search(r'^        if: (.+)$', load, re.M).group(1)
                deploy_guard = re.search(r'^        if: (.+)$', deploy, re.M).group(1)
                self.assertEqual(load_guard, "env.PROXY_DEPLOYMENT_MODE == 'generation' && (" + deploy_guard + ")")
                root = f'infra/envs/production/{region}'
                self.assertIn(f'terraform -chdir={root} init -input=false', load)
                self.assertIn(f'terraform -chdir={root} output -json |', load)
                self.assertEqual(load.count(' output -json'), 1)

    def test_each_proxy_environment_commits_a_cell_for_rollout_manifests(self):
        cells = (
            ('staging/us-central1', 'staging'),
            ('production/us-east4', 'use4'),
            ('production/us-west2', 'usw2'),
        )
        for root, cell in cells:
            with self.subTest(root=root):
                tfvars = (SCRIPTS.parent.parent.parent / 'infra' / 'envs' / root / 'terraform.tfvars').read_text()
                self.assertNotIn('proxy_generation_cells = {}', tfvars)
                self.assertIn(f'proxy_generation_cells = {{\n  {cell} = {{', tfvars)
                self.assertRegex(tfvars, r'(?m)^    instance\s*=\s*"[^"]+"$')
                if cell == 'usw2':
                    # The west public route is the adopted regional URL map;
                    # the east-owned SSL/redirect frontends must not be
                    # represented as west cutover routes.
                    self.assertIn('"public-http" = {', tfvars)
                    self.assertNotIn('"public-tcp" = {', tfvars)
                    self.assertNotIn('redirect = {', tfvars)

                generations = (SCRIPTS.parent.parent.parent / 'infra' / 'envs' / root / 'proxy-generations.tf').read_text()
                self.assertNotRegex(generations, r'(?m)^\s*default\s*=\s*\{\}\s*$')
                self.assertIn('output "proxy_generation_rollout"', generations)
                self.assertIn('serving_host', generations)

    def test_generation_manifest_keeps_serving_identity_for_standby_resolution(self):
        module = (SCRIPTS.parent.parent.parent / 'infra' / 'modules' / 'proxy-lb' / 'generations.tf').read_text()
        self.assertIn('serving_host = {', module)
        self.assertIn('instance = var.generation_cell.instance', module)
        self.assertIn('ip       = var.generation_cell.ip', module)

    def test_generation_backends_are_attached_to_owned_frontends(self):
        root = SCRIPTS.parent.parent.parent / 'infra' / 'envs'
        owned_frontends = {
            'staging/us-central1': ('staging', ('public-http', 'public-tcp', 'redirect')),
            'production/us-east4': ('use4', ('public-http', 'public-tcp', 'redirect')),
        }
        for environment, (cell, routes) in owned_frontends.items():
            with self.subTest(environment=environment):
                generations = (root / environment / 'proxy-generations.tf').read_text()
                frontends = (root / environment / 'proxy-frontends.tf').read_text()
                for route in routes:
                    backend_expression = (
                        f'module.proxy_generations["{cell}"].generation_backend_services.redirect'
                        if route == 'redirect' else
                        f'module.proxy_generations["{cell}"].generation_backend_services["{route}"]'
                    )
                    self.assertIn(
                        backend_expression,
                        generations if route != 'redirect' else frontends,
                    )
                self.assertIn('frontend_backend_references', generations)
                self.assertIn('migration_complete', generations)

        # The west backend is owned by its regional state, while the global
        # URL map is owned by east; both sides must retain the same explicit
        # backend identity for the cross-state route.
        west = (root / 'production/us-west2/proxy-generations.tf').read_text()
        east = (root / 'production/us-east4/proxy-frontends.tf').read_text()
        backend = 'proxy-usw2-public-http-generations'
        self.assertIn(backend, east)
        self.assertIn('module.proxy_generations["usw2"].generation_backend_services["public-http"]', west)
        self.assertIn('data "terraform_remote_state" "use4"', west)
        self.assertIn('data.terraform_remote_state.use4.outputs.proxy_west_frontend_backend_references', west)
        self.assertIn('url-map:sandbox-dataplane', west)
        self.assertIn('target-https-proxy:dp-https', west)
        self.assertIn('frontend_backend_references', west)
        self.assertIn('migration_complete', west)

    def deploy_selection(self, rows, region="us-central1", expected="example-standby"):
        spec = importlib.util.spec_from_file_location("deploy_selection", SCRIPTS / "deploy-vmd.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        selected = []

        class Executor:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, instance):
                selected.append(instance["name"])
                future = Future()
                future.set_result(None)
                return future

        env = dict(GCP_PROJECT="example-project", GCP_REGION=region, SHA="12345678",
                   VMD_LABEL="component=vmd-staging-standby", EXPECTED_STANDBY_HOST=expected)
        with patch.dict(os.environ, env, clear=True), \
             patch.object(module, "run_or_die"), \
             patch.object(module.os.path, "getsize", return_value=0), \
             patch.object(module.os.path, "exists", return_value=True), \
             patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, rows, "")) as run, \
             patch.object(module, "ThreadPoolExecutor", Executor):
            result = module.main()
        self.assertEqual(len(run.call_args_list), 1, "selection must not contact any host")
        self.assertEqual(run.call_args.args[0][:4], ["gcloud", "compute", "instances", "list"])
        return result, selected

    def test_standby_discovery_rejects_unexpected_ambiguous_or_unscoped_hosts(self):
        for rows, region in (
            ("", "us-central1"),
            ("other-host,us-central1-a\n", "us-central1"),
            ("example-standby,us-central1-a\nother-host,us-central1-b\n", "us-central1"),
            ("example-standby,us-west2-a\n", "us-central1"),
            ("example-standby,us-central1-a\n", ""),
        ):
            with self.subTest(rows=rows, region=region):
                self.assertEqual(self.deploy_selection(rows, region), (1, []))

    def test_standby_discovery_accepts_only_expected_host_in_selected_region(self):
        rows = "example-standby,projects/example-project/zones/us-central1-a\nother-host,us-west2-a\n"
        self.assertEqual(self.deploy_selection(rows), (0, ["example-standby"]))

    def test_serving_discovery_retains_multiple_host_fanout(self):
        rows = "example-primary,us-central1-a\nexample-secondary,us-central1-b\n"
        self.assertEqual(self.deploy_selection(rows, expected=""),
                         (0, ["example-primary", "example-secondary"]))

    def select(self, **overrides):
        env = dict(os.environ, DEPLOY_EVENT="workflow_dispatch", DEPLOY_TARGET="",
                   DEPLOY_PRODUCTION_CELL="", DEPLOY_CELL="staging",
                   GCP_PROJECT="example-project", MOCK_ROLE_ROWS="", GCP_REGION="us-central1",
                   VMD_LABEL="component=legacy",
                   PEER_IDENTITY_HOSTS="legacy-host", EXPECTED_STANDBY_HOST="",
                   PEER_ROUTING_ENABLED="0", PEER_PROXY_LISTEN_ADDR="auto")
        env.update(overrides)
        return subprocess.run(
            ["bash", "-ec", 'gcloud() { '
             '[ "$*" = "compute instances list --project=$GCP_PROJECT --filter=labels.component=vmd-$DEPLOY_CELL-standby --format=csv[no-heading](name,zone)" ] || return 2; '
             'printf "%s" "$MOCK_ROLE_ROWS"; return ${MOCK_ROLE_STATUS:-0}; }; '
             'source "$1"; printf "%s\\n" "$VMD_LABEL" '
             '"$PEER_IDENTITY_HOSTS" "$EXPECTED_STANDBY_HOST" '
             '"$PEER_ROUTING_ENABLED" "$PEER_PROXY_LISTEN_ADDR"',
             "select", str(SCRIPTS / "select-deploy-target.sh")],
            env=env, capture_output=True, text=True,
        )

    def test_exact_standby_mappings_and_defaults(self):
        for cell, region, host in (
            ("staging", "us-central1", "superserve-vmd-staging-2"),
            ("usw2", "us-west2", "superserve-vmd-usw2-2"),
        ):
            for target in ("", "standby"):
                with self.subTest(cell=cell, target=target):
                    result = self.select(DEPLOY_CELL=cell, GCP_REGION=region,
                                         DEPLOY_PRODUCTION_CELL="",
                                         DEPLOY_TARGET=target, MOCK_ROLE_ROWS=f"{host},{region}-a\n")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(),
                                     [f"component=vmd-{cell}-standby",
                                      host if cell == "staging" else "legacy-host", host, "0", "auto"])

    def test_serving_preserves_existing_peer_configuration(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_TARGET="serving", DEPLOY_CELL=cell,
                                 DEPLOY_PRODUCTION_CELL="use4" if cell == "use4" else "usw2")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=vmd", "legacy-host", "", "0", "auto"])

    def test_missing_standby_role_blocks_deployment(self):
        for target in ("", "standby"):
            result = self.select(DEPLOY_TARGET=target, DEPLOY_CELL="use4",
                                 DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4",
                                 EXPECTED_STANDBY_HOST="legacy-host")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Standby role requires exactly one host", result.stderr)
            # Nothing after sourcing the selector may run, even with a stale host override.
            self.assertEqual(result.stdout, "")

    def test_push_ignores_selectors_and_preserves_environment(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_EVENT="push", DEPLOY_TARGET="invalid", DEPLOY_CELL=cell,
                                 GCP_REGION="", PEER_ROUTING_ENABLED="1",
                                 MOCK_ROLE_ROWS="example-replacement,us-east4-a\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=legacy", "legacy-host", "", "1", "auto"])

    def test_use4_standby_uses_live_role(self):
        result = self.select(DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4",
                             GCP_REGION="us-east4", MOCK_ROLE_ROWS="example-replacement,us-east4-a\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["component=vmd-use4-standby", "legacy-host",
                          "example-replacement", "0", "auto"])

    def test_promotion_and_rollback_follow_roles_in_both_cells(self):
        for cell, region in (("usw2", "us-west2"), ("use4", "us-east4")):
            for serving, inactive in (("example-host-1", "example-host-2"),
                                      ("example-host-2", "example-host-1")):
                with self.subTest(cell=cell, serving=serving):
                    result = self.select(DEPLOY_CELL=cell, DEPLOY_PRODUCTION_CELL=cell,
                                         GCP_REGION=region, MOCK_ROLE_ROWS=f"{inactive},{region}-a\n",
                                         PEER_IDENTITY_HOSTS="example-host-2")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines()[1:3], ["example-host-2", inactive])
                    self.assertEqual(self.deploy_selection(f"{inactive},{region}-a\n", region, inactive),
                                     (0, [inactive]))
                    # A role change between selection and discovery must fail closed.
                    self.assertEqual(self.deploy_selection(f"{serving},{region}-a\n", region, inactive), (1, []))
                    result = self.select(DEPLOY_TARGET="serving", DEPLOY_CELL=cell,
                                         DEPLOY_PRODUCTION_CELL=cell, GCP_REGION=region)
                    self.assertEqual(result.stdout.splitlines()[0], "component=vmd")
                    self.assertEqual(self.deploy_selection(f"{serving},{region}-a\n", region, ""), (0, [serving]))

    def test_role_discovery_rejects_ambiguous_wrong_region_and_failed_queries(self):
        for rows, status in (("", "0"), ("example-a,us-west2-a\nexample-b,us-west2-b\n", "0"),
                             ("example-a,us-east4-a\n", "0"), ("example-a,us-west2-a\n", "1")):
            result = self.select(DEPLOY_CELL="usw2", GCP_REGION="us-west2",
                                 MOCK_ROLE_ROWS=rows, MOCK_ROLE_STATUS=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_manual_rejects_invalid_or_unscoped_selection(self):
        for override in ({"DEPLOY_TARGET": "component=vmd"}, {"DEPLOY_PRODUCTION_CELL": "all"},
                         {"GCP_REGION": ""}, {"DEPLOY_CELL": "other"},
                         {"DEPLOY_CELL": "use4", "DEPLOY_PRODUCTION_CELL": "usw2"}):
            with self.subTest(override=override):
                result = self.select(**override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_workflow_cell_guards_and_staging_dependency(self):
        for kind in ("vmd", "proxy"):
            workflow = (SCRIPTS.parent / f"deploy-{kind}.yml").read_text()
            production = workflow.split("  deploy-production:\n", 1)[1]
            self.assertRegex(production, r"needs: \[[^\]]*deploy-staging[^\]]*\]")
            condition = re.search(r'^    if: (.+)$', production, re.M)[1]
            for event in ('push', 'workflow_dispatch'):
                for environment in ('', 'staging', 'production'):
                    for ready in ('', 'false', 'true', 'TRUE', '1', 'tru', ' true '):
                        with self.subTest(kind=kind, event=event, environment=environment, ready=ready):
                            context = dict(
                                needs={'migration-gate': SimpleNamespace(outputs=SimpleNamespace(mode='generation'))},
                                github=SimpleNamespace(event_name=event, event=SimpleNamespace(
                                    inputs=SimpleNamespace(environment=environment))),
                                vars=SimpleNamespace(
                                    PROXY_GENERATION_PROMOTION_READY=ready,
                                    PROXY_GENERATION_PROMOTION_EVIDENCE_STATUS='passed',
                                    PROXY_GENERATION_RUNBOOK_URL='https://www.notion.so/example-team/page',
                                    PROXY_GENERATION_PROMOTION_EVIDENCE_URL='https://evidence.example/run-1'))
                            selected = eval(condition.replace('&&', ' and ').replace('||', ' or '),
                                            {'__builtins__': {}}, context)
                            expected = ((event == 'push' or environment == 'production')
                                        and (kind != 'proxy' or ready == 'true'))
                            self.assertEqual(selected, expected)
            steps = [s for s in re.split(r"^      - name: ", workflow, flags=re.M)
                     if f"python3 .github/workflows/scripts/deploy-{kind}.py" in s]
            self.assertEqual(len(steps), 3)
            for step in steps:
                self.assertLess(step.index("source .github/workflows/scripts/select-deploy-target.sh"),
                                step.index(f"python3 .github/workflows/scripts/deploy-{kind}.py"))
            for event in ("push", "workflow_dispatch"):
                for target in ("serving", "standby"):
                    for cell in ("", "use4", "usw2"):
                        for enabled in ("", "configured"):
                            selected = []
                            for step in steps[1:]:
                                condition = re.search(r"^        if: (.+)$", step, re.M)[1]
                                context = dict(github=SimpleNamespace(event_name=event),
                                               inputs=SimpleNamespace(production_cell=cell, cell=cell, target=target),
                                               vars=SimpleNamespace(CLOUD_RUN_SERVICE_USW=enabled))
                                if eval(condition.replace("&&", " and ").replace("||", " or "),
                                        {"__builtins__": {}}, context):
                                    selected.append(re.search(r"DEPLOY_CELL: (\w+)", step)[1])
                            expected = ([cell or "usw2"] if event == "workflow_dispatch"
                                        else (["use4", "usw2"] if enabled else ["use4"]))
                            self.assertEqual(selected, expected, (kind, event, target, cell, enabled))

    def test_zero_matches_never_retry_serving_or_upload(self):
        for kind in ("vmd", "proxy"):
            spec = importlib.util.spec_from_file_location("deploy_under_test", SCRIPTS / f"deploy-{kind}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            env = dict(GCP_PROJECT="example-project", GCP_REGION="us-east4", SHA="12345678",
                       VMD_LABEL="component=vmd-use4-standby", PROXY_DOMAIN="sandbox.example.test")
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                self.assertEqual(args[:4], ["gcloud", "compute", "instances", "list"])
                self.assertIn("--filter=labels.component=vmd-use4-standby AND status=RUNNING", args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with patch.dict(os.environ, env, clear=True), patch.object(module.subprocess, "run", side_effect=run):
                if kind == "vmd":
                    with patch.object(module, "run_or_die"), patch.object(module.os.path, "getsize", return_value=0):
                        self.assertEqual(module.main(), 1)
                else:
                    self.assertEqual(module.main(), 1)
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
