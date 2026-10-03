#!/usr/bin/env python3
"""Read-only branch diagnostic; never produces production recovery evidence."""

import argparse
import json
import os
from pathlib import Path
import re
import time

from collect_recovery_evidence import Reader, guest_observation, require
from migrate_database import MigrationError
from recovery_evidence import sha


PROJECT = 'rayai-dev'
REGION = 'us-central1'
HOSTS = {'superserve-vmd-staging', 'superserve-vmd-staging-2'}


def check_dispatch(reader, env):
    revision = env.get('GITHUB_SHA', '')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == 'superserve-ai/sandbox'
            and env.get('GITHUB_REF', '').startswith('refs/heads/')
            and re.fullmatch(r'[a-f0-9]{40}', revision)
            and env.get('APPROVED_REVISION') == revision
            and env.get('DEPLOY_ENVIRONMENT') == 'staging'
            and env.get('RECEIVER_DIAGNOSTIC') == 'true'
            and env.get('SMOKE_PREFLIGHT') == 'true'
            and env.get('FORCE_REBUILD') == 'false',
            'Diagnostic requires an exact reviewed branch revision and staging-only read inputs')
    require(reader.command(['git', 'rev-parse', 'HEAD']).strip() == revision,
            'Checked-out diagnostic source differs from the approved revision')
    return revision


def observe(reader, result):
    queries = {
        'services': ('run', 'services', 'list', '--region='+REGION),
        'revisions': ('run', 'revisions', 'list', '--service=superserve-api', '--region='+REGION),
        'instances': ('compute', 'instances', 'list'),
        'routes': ('compute', 'url-maps', 'list'),
        'backends': ('compute', 'backend-services', 'list'),
        'negs': ('compute', 'network-endpoint-groups', 'list'),
        'forwarders': ('compute', 'forwarding-rules', 'list'),
        'https_proxies': ('compute', 'target-https-proxies', 'list'),
    }
    inventory = {}
    for name, args in queries.items():
        result['step'] = name
        # Do not call the production Reader.cloud method: this project is fixed
        # independently of workflow vars, provider defaults or caller input.
        rows = json.loads(reader.command(['gcloud', *args, '--project='+PROJECT, '--limit=1000',
                                         '--format=json', '--quiet', '--verbosity=warning'], reject_stderr=True))
        require(isinstance(rows, list) and len(rows) < 1000, 'Staging inventory is incomplete')
        inventory[name] = rows
        result['inventory'][name] = {'count': len(rows), 'sha256': sha(rows)}
    result['metadata_status'] = 'passed'
    result['step'] = 'guest_observation'
    result['service_names'] = sorted(row['metadata']['name'] for row in inventory['services'])
    hosts = [row for row in inventory['instances'] if row.get('name') in HOSTS]
    require({row['name'] for row in hosts} == HOSTS and len(hosts) == len(HOSTS)
            and all(row.get('zone', '').endswith('/us-central1-a') for row in hosts),
            'Expected staging host inventory is missing or changed')
    if not (os.environ.get('RECOVERY_SSH_USER') and (Path.home()/'.ssh/google_compute_engine').is_file()
            and (Path.home()/'.ssh/known_hosts').is_file()):
        result.update(status='blocked', reason='Existing staging SSH user, identity and verified known_hosts are required; no access was provisioned')
        return
    for host in hosts:
        result['guests'].append(guest_observation(reader, host, project=PROJECT))
    result.update(status='passed', step='complete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-dispatch', action='store_true')
    args = parser.parse_args()
    reader = Reader(time.monotonic()+360)
    result = {'schema': 1, 'kind': 'staging-access-diagnostic', 'project': PROJECT,
              'region': REGION, 'status': 'failed', 'step': 'dispatch',
              'metadata_status': 'not-completed', 'inventory': {}, 'guests': [],
              'production_evidence': False}
    try:
        result['revision'] = check_dispatch(reader, os.environ)
        result['run_id'] = os.environ.get('GITHUB_RUN_ID', '')
        if args.check_dispatch:
            return 0
        observe(reader, result)
    except MigrationError as error:
        result['reason'] = str(error)
    except Exception:
        result['reason'] = 'Staging observation failed; provider and configuration details suppressed'
    if not args.check_dispatch:
        path = Path('staging-receiver-diagnostic/result.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, sort_keys=True)+'\n')
    print(json.dumps({key: result[key] for key in ('status', 'step', 'metadata_status')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
