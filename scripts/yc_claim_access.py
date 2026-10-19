"""Prepare or apply only the two staging YC API credential grants."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'infra/envs/staging/us-central1'
REPOSITORY = 'superserve-ai/sandbox'
WORKFLOW = '.github/workflows/terraform-rollout-staging.yml'
BUCKET = 'rayai-dev-control-plane-evidence'
DEPLOYER = 'superserve-github-actions@rayai-dev.iam.gserviceaccount.com'
MEMBER = 'serviceAccount:superserve-cp-staging@rayai-dev.iam.gserviceaccount.com'
TERRAFORM_VERSION = '1.16.6'
TARGETS = {
    f'google_secret_manager_secret_iam_member.controlplane_runtime["yc-claim-{kind}-token-staging-usc1"]':
    f'yc-claim-{kind}-token-staging-usc1'
    for kind in ('capture', 'console')
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def diagnostic_metadata(output, directory):
    sources = {p.resolve(): (p.relative_to(ROOT).as_posix(), len(p.read_text().splitlines()))
               for p in (ROOT / 'infra').rglob('*.tf') if '.terraform' not in p.parts}
    diagnostics = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get('type') != 'diagnostic':
            continue
        diagnostic = event.get('diagnostic')
        if not isinstance(diagnostic, dict):
            continue
        severity = diagnostic.get('severity')
        safe = {'severity': severity if severity in ('error', 'warning') else 'unknown'}
        address = diagnostic.get('address')
        if isinstance(address, str) and address in TARGETS:
            safe['address'] = address
        location = diagnostic.get('range')
        if isinstance(location, dict):
            filename = location.get('filename')
            start = location.get('start')
            number = start.get('line') if isinstance(start, dict) else None
            if isinstance(filename, str) and len(filename) <= 4096:
                try:
                    source = sources.get((directory / filename).resolve())
                except (ValueError, OSError):
                    source = None
                if source:
                    safe['file'] = source[0]
                    if type(number) is int and 1 <= number <= source[1]:
                        safe['line'] = number
        diagnostics.append(safe)
        if len(diagnostics) == 100:
            break
    return diagnostics


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        failure = {'command': ' '.join(args[:2]), 'exit_status': result.returncode}
        if args[:2] == ('terraform', 'plan') and '-json' in args:
            failure['diagnostics'] = diagnostic_metadata(result.stdout, Path(cwd))
        raise ValueError(json.dumps(failure))
    return result.stdout


def validate_inputs(env):
    mode = env.get('YC_CLAIM_ACCESS')
    require(mode in ('plan', 'apply'), 'Unsupported claim access mode')
    require(env.get('CONFIRM') == mode, 'Confirmation must match claim access mode')
    require(all(env.get(k) == 'false' for k in (
        'PRIVATECA_BOOTSTRAP', 'SMOKE_ONLY', 'PROXY_PREPARE', 'PROXY_RUNTIME_IAM'))
        and env.get('PROXY_MIGRATION') == 'none', 'Claim access cannot mix rollout modes')
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY, 'Unexpected repository')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Manual dispatch required')
    require(env.get('DEPLOYMENT_SERVICE_ACCOUNT') == DEPLOYER, 'Unexpected deployment identity')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'Reruns require a new reviewed plan')
    sha = env.get('YC_CLAIM_SOURCE_SHA', '')
    require(re.fullmatch('[a-f0-9]{40}', sha) and sha == env.get('GITHUB_SHA'), 'Source SHA mismatch')
    require(not any(k.startswith('TF_CLI_ARGS') for k in env), 'Terraform CLI overrides forbidden')
    if mode == 'plan':
        require(not env.get('YC_CLAIM_PLAN_RUN_ID') and not env.get('YC_CLAIM_PLAN_SHA256'),
                'Plan mode cannot reference another plan')
    else:
        require(re.fullmatch('[1-9][0-9]*', env.get('YC_CLAIM_PLAN_RUN_ID', '')),
                'Plan run ID required')
        require(re.fullmatch('[a-f0-9]{64}', env.get('YC_CLAIM_PLAN_SHA256', '')),
                'Reviewed plan hash required')


def validate_plan(plan):
    require(plan.get('errored') is False and plan.get('applyable') is True,
            'Plan must be applyable without errors')
    require(plan.get('terraform_version') == TERRAFORM_VERSION, 'Terraform version mismatch')
    require(not plan.get('deferred_changes'), 'Deferred changes forbidden')
    changes = []
    for resource in plan.get('resource_changes', []):
        change = resource.get('change', {})
        require(not change.get('importing') and not change.get('replace_paths')
                and not resource.get('previous_address'), 'Imports, moves and replacements forbidden')
        actions = change.get('actions')
        if actions == ['no-op']:
            continue
        if resource.get('mode') == 'data' and actions == ['read']:
            continue
        address = resource.get('address')
        require(address in TARGETS and resource.get('mode') == 'managed'
                and resource.get('type') == 'google_secret_manager_secret_iam_member'
                and resource.get('provider_name') == 'registry.terraform.io/hashicorp/google'
                and actions == ['create'], 'Plan contains an unapproved resource mutation')
        after = change.get('after') or {}
        expected = dict(project='rayai-dev', secret_id=TARGETS[address],
                        role='roles/secretmanager.secretAccessor', member=MEMBER)
        require(change.get('before') is None, 'Grant must not replace existing state')
        require(all(after.get(k) == v and not change.get('after_unknown', {}).get(k)
                    for k, v in expected.items()) and after.get('condition') == []
                and not change.get('after_unknown', {}).get('condition'),
                'Secret IAM identity or condition differs from approved grant')
        changes.append(dict(address=address, **expected))
    require(len(changes) == 2 and {c['address'] for c in changes} == set(TARGETS),
            'Exactly the two credential grants must be created')
    return sorted(changes, key=lambda c: c['address'])


def validate_run(metadata, jobs, run_id, sha):
    require(str(metadata.get('id')) == run_id and metadata.get('head_sha') == sha
            and metadata.get('path') == WORKFLOW and metadata.get('event') == 'workflow_dispatch'
            and metadata.get('repository', {}).get('full_name') == REPOSITORY
            and metadata.get('conclusion') == 'success' and metadata.get('run_attempt') == 1,
            'Plan run provenance mismatch')
    require(any(j.get('name') == 'Staging YC claim credential access'
                and j.get('conclusion') == 'success'
                and any(s.get('name') == 'Save reviewed claim access plan'
                        and s.get('conclusion') == 'success' for s in j.get('steps', []))
                for j in jobs.get('jobs', [])), 'Successful plan step required')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prefix(sha, run_id):
    return f'gs://{BUCKET}/yc-claim-access/{REPOSITORY}/{sha}/{run_id}/1'


def validate_receipt(receipt, sha, run_id, expected_hash):
    require(receipt.get('source_sha') == sha and receipt.get('run_id') == run_id
            and receipt.get('run_attempt') == 1 and receipt.get('repository') == REPOSITORY
            and receipt.get('workflow') == WORKFLOW and receipt.get('phase') == 'plan'
            and receipt.get('terraform_version') == TERRAFORM_VERSION
            and receipt.get('plan_sha256') == expected_hash
            and receipt.get('plan_uri') == prefix(sha, run_id) + '/approved.tfplan'
            and re.fullmatch('[1-9][0-9]*', str(receipt.get('plan_generation', ''))),
            'Saved plan receipt differs from reviewed inputs')


def main(phase):
    env = os.environ
    validate_inputs(env)
    if phase == 'check':
        return
    require(phase == env['YC_CLAIM_ACCESS'], 'Workflow phase mismatch')
    require(env.get('DEPLOYMENT_SERVICE_ACCOUNT') == DEPLOYER, 'Unexpected deployment identity')
    require(run('git', 'rev-parse', 'HEAD', cwd=ROOT).strip() == env['GITHUB_SHA'], 'Checkout mismatch')
    bucket = json.loads(run('gcloud', 'storage', 'buckets', 'describe', 'gs://' + BUCKET, '--format=json'))
    require(bucket.get('public_access_prevention') == 'enforced'
            and bucket.get('uniform_bucket_level_access') is True
            and str(bucket.get('retention_policy', {}).get('retentionPeriod')) == '7776000',
            'Private evidence storage controls differ')
    require(json.loads(run('terraform', 'version', '-json'))['terraform_version'] == TERRAFORM_VERSION,
            'Terraform executable version mismatch')
    run('terraform', 'init', '-input=false', '-lockfile=readonly', cwd=DIRECTORY)
    work = Path(env['RUNNER_TEMP']) / 'yc-claim-access'
    work.mkdir(exist_ok=False)
    planfile, receiptfile = work / 'approved.tfplan', work / 'receipt.json'
    sha = env['GITHUB_SHA']
    try:
        if phase == 'plan':
            run_id = env['GITHUB_RUN_ID']
            require(re.fullmatch('[1-9][0-9]*', run_id), 'Invalid run ID')
            run('terraform', 'plan', '-json', '-input=false', '-lock-timeout=5m',
                *(f'-target={address}' for address in TARGETS), '-out=' + str(planfile), cwd=DIRECTORY)
            changes = validate_plan(json.loads(run('terraform', 'show', '-json', str(planfile), cwd=DIRECTORY)))
            uri = prefix(sha, run_id) + '/approved.tfplan'
            run('gcloud', 'storage', 'cp', '--if-generation-match=0', str(planfile), uri)
            generation = str(json.loads(run('gcloud', 'storage', 'objects', 'describe', uri, '--format=json'))['generation'])
            receipt = dict(repository=REPOSITORY, workflow=WORKFLOW, source_sha=sha,
                           run_id=run_id, run_attempt=1, phase='plan', terraform_version=TERRAFORM_VERSION,
                           plan_uri=uri, plan_generation=generation, plan_sha256=digest(planfile), changes=changes)
            receiptfile.write_text(json.dumps(receipt, indent=2))
            run('gcloud', 'storage', 'cp', '--if-generation-match=0', str(receiptfile), prefix(sha, run_id) + '/receipt.json')
            with open(env['GITHUB_STEP_SUMMARY'], 'a') as f:
                f.write('## Staging claim access plan\n\n```json\n' + json.dumps(receipt, indent=2) + '\n```\n')
                f.write('Two grants only. No apply performed. Private evidence is retained for 90 days, then lifecycle deletion applies.\n')
        else:
            run_id, expected_hash = env['YC_CLAIM_PLAN_RUN_ID'], env['YC_CLAIM_PLAN_SHA256']
            base = f'repos/{REPOSITORY}/actions/runs/{run_id}'
            validate_run(json.loads(run('gh', 'api', base)), json.loads(run('gh', 'api', base + '/jobs')), run_id, sha)
            run('gcloud', 'storage', 'cp', prefix(sha, run_id) + '/receipt.json', str(receiptfile))
            receipt = json.loads(receiptfile.read_text())
            validate_receipt(receipt, sha, run_id, expected_hash)
            run('gcloud', 'storage', 'cp', receipt['plan_uri'] + '#' + receipt['plan_generation'], str(planfile))
            require(digest(planfile) == expected_hash, 'Saved plan checksum mismatch')
            changes = validate_plan(json.loads(run('terraform', 'show', '-json', str(planfile), cwd=DIRECTORY)))
            require(changes == receipt['changes'], 'Saved plan grants differ from reviewed receipt')
            run('terraform', 'apply', '-input=false', '-lock-timeout=5m', str(planfile), cwd=DIRECTORY)
            with open(env['GITHUB_STEP_SUMMARY'], 'a') as f:
                f.write(f'Applied the exact two-grant plan from run {run_id}, source {sha}, SHA256 {expected_hash}.\n')
    finally:
        planfile.unlink(missing_ok=True)
        receiptfile.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f'Claim access stopped: {error}', file=sys.stderr)
        sys.exit(1)
