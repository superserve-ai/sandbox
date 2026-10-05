#!/usr/bin/env python3
"""Collect read-only, revision-bound receiver evidence; never execute recovery."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import tarfile
import time
import urllib.request
import zipfile

from migrate_database import MigrationError, PROJECTS
import recovery_database_binding as binding
import recovery_evidence as evidence


ROOT = Path(__file__).resolve().parent.parent
PROJECT = "rayai-prod"
REGISTRY = "us-central1-docker.pkg.dev"
IMAGE = REGISTRY + "/rayai-prod/superserve/controlplane"
CANARY_IMAGE = REGISTRY + "/rayai-prod/superserve/api-canary"
# The artifact/config/layer comparison for this separate repository is pinned
# by review. Runtime tags alone are never used as build provenance.
CANARY = {"source": "cb9ea82f6ea62f422ab499c4055fe0208def8467",
          "image": "sha256:2c7a5388df0a3372b6c47f61246132f6d59ee9b14d42858aafb44a593caeabfc",
          "config": "sha256:eee0e18454a7877b36254bcc86c88f51e1ecc722d0e14d9af1db4e7b36532f46",
          "artifact": 10420173312,
          "archive": "sha256:e313cbd398a5e738007abdcefba10c5b36d3cb7246225afca9988b92a687344a"}
MAX_ITEMS = 1000
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
CELLS = {'us-west2': 'superserve-api-usw2', 'us-east4': 'superserve-api-use4'}
HOST_SOURCE = 'b7ea7b9b2f663f2e1ba318a92d8d511c6542acb6'
HOST_BINARIES = {
    'vmd': 'c935a32171af63ea99fd2c52d84ff355c2b750b318c7825007c2a87756f63bc3',
    'secretsproxy': '24dc59dc86b13ffa7780fa722a7e71052eb117b2a1598fac7fc1f2208e43351c',
}
# Reviewed metadata only; no historical command, environment or image payloads.
RETIRED_RECEIVERS = json.loads(Path(__file__).with_name('recovery_retired_receivers.json').read_text())


def deletion_history(reader, earliest, cutoff=None):
    query = ('log_id("cloudaudit.googleapis.com/activity") AND protoPayload.serviceName="run.googleapis.com" '
             'AND (protoPayload.methodName:"DeleteRevision" OR protoPayload.methodName:"DeleteService" '
             'OR protoPayload.methodName:"DeleteJob") AND timestamp>="' + earliest + '"')
    if cutoff:
        query += ' AND (timestamp>="' + cutoff + '" OR receiveTimestamp>="' + cutoff + '")'
    return reader.cloud('logging', 'read', query, '--limit=1000',
                        fields='timestamp,receiveTimestamp,protoPayload.methodName,protoPayload.resourceName,protoPayload.status')


def mutable_inventory(reader):
    queries = {
        'services': ('run', 'services', 'list', '--platform=managed', '--limit=1000'),
        'jobs': ('run', 'jobs', 'list', '--limit=1000'),
        'instances': ('compute', 'instances', 'list', '--limit=1000'),
        'routes': ('compute', 'url-maps', 'list', '--limit=1000'),
        'backends': ('compute', 'backend-services', 'list', '--limit=1000'),
        'negs': ('compute', 'network-endpoint-groups', 'list', '--limit=1000'),
        'forwarders': ('compute', 'forwarding-rules', 'list', '--limit=1000'),
        'https_proxies': ('compute', 'target-https-proxies', 'list', '--limit=1000'),
        'workers': ('run', 'worker-pools', 'list', '--limit=1000'),
    }
    for region, service in CELLS.items():
        queries['revisions_' + region] = ('run', 'revisions', 'list', '--service=' + service,
                                         '--region=' + region, '--limit=1000')
    for secret in binding.BINDINGS:
        queries['versions_' + secret] = ('secrets', 'versions', 'list', secret, '--limit=1000')
    def query(item):
        key, args = item
        rows = reader.cloud(*args)
        require(isinstance(rows, list), 'Cloud inventory is not a complete list')
        return key, sorted(rows, key=lambda r: str(r.get('name', r.get('metadata', {}).get('name', r.get('id', '')))))
    with ThreadPoolExecutor(max_workers=8) as executor:
        state = dict(executor.map(query, queries.items()))
    # Compute returns consumer references in varying order. Preserve every
    # reference/value while canonicalizing this unordered metadata list.
    for backend in state['backends']:
        if 'usedBy' in backend:
            require(isinstance(backend['usedBy'], list), 'Backend consumer references are malformed')
            backend['usedBy'] = sorted(backend['usedBy'], key=evidence.sha)
    state['canary_image'] = reader.cloud('artifacts', 'docker', 'images', 'describe',
                                         CANARY_IMAGE + ':' + CANARY['source'])['image_summary']['digest']
    # Also enumerate the retired job's region even without a current job there.
    job_regions = {job.get('metadata', {}).get('labels', {}).get('cloud.googleapis.com/location', '')
                   for job in state['jobs']}
    live_job_regions = set(job_regions)
    job_regions.add('us-central1')
    require(all(re.fullmatch(r'[a-z]+-[a-z]+[0-9]', region) for region in job_regions),
            'Job region is missing from the global inventory')
    def executions(region):
        # Cloud SDK treats completionTime as a date and rejects a wildcard.
        # Negating an epoch comparison retains missing/null completion times.
        # An empty retired region produces an SDK "filter keys not present"
        # warning. Enumerate it without a filter; retain the completeness bound
        # and classify completed executions locally instead of ignoring warnings.
        filters = ['--filter=NOT status.completionTime>=1970-01-01T00:00:00Z'] if region in live_job_regions else []
        rows = reader.cloud('run', 'jobs', 'executions', 'list', '--region='+region, *filters, '--limit=1000')
        require(isinstance(rows, list), 'Job execution inventory is incomplete')
        if not filters:
            active = []
            for row in rows:
                completed = row.get('status', {}).get('completionTime')
                if completed is None:
                    active.append(row)
                else:
                    require(isinstance(completed, str) and evidence.timestamp(completed) <= time.time(),
                            'Retired-region execution completion is invalid')
            rows = active
        return rows
    with ThreadPoolExecutor(max_workers=8) as executor:
        state['active_job_executions'] = sorted(sum(executor.map(executions, sorted(job_regions)), []),
                                               key=lambda row: row.get('metadata', {}).get('name', ''))
    # Job executions are not another receiver: the fixed API-only image is
    # checked separately. Changing execution timestamps are not writer config.
    for job in state['jobs']:
        job.pop('status', None)
    state['dns'] = {host: sorted({row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
                    for host in ('api.superserve.ai', 'api-usw.superserve.ai')}
    from urllib.parse import urlsplit
    state['service_dns'] = {s['status']['url']: sorted({row[4][0] for row in socket.getaddrinfo(
        urlsplit(s['status']['url']).hostname, 443, type=socket.SOCK_STREAM)}) for s in state['services']}
    return state


def receiver_inventory(reader):
    state = mutable_inventory(reader)
    earliest = min(r['metadata']['creationTimestamp'] for region in CELLS for r in state['revisions_'+region])
    state['deleted_receivers'] = deletion_history(reader, earliest)
    return state


def check_deletion_delta(reader, history):
    delta = deletion_history(reader, history['earliest'], history['cutoff'])
    require(all(event in history['events'] for event in delta),
            'New or late receiver deletion observed; recollect complete history')


def attach_history(current, history):
    earliest = min(r['metadata']['creationTimestamp'] for region in CELLS for r in current['revisions_'+region])
    require(earliest == history['earliest'], 'Historical revision coverage changed')
    current['deleted_receivers'] = history['events']
    return current


def guest_failure_reason(output):
    from recovery_guest_probe import CHECKS, ERROR_TYPES
    generic = 'Guest observation failed; inspect the fixed redacted probe requirements'
    try:
        value = json.loads(output)
        require(isinstance(value, dict) and 'error' in value, generic)
        check, service, kind = (value.get(name) for name in ('check', 'service', 'error_type'))
        require(isinstance(check, str) and check in CHECKS
                and (service is None or isinstance(service, str) and service in {'vmd', 'secretsproxy'})
                and isinstance(kind, str) and kind in ERROR_TYPES, generic)
        return 'Guest observation incomplete: ' + json.dumps({'check': check, 'service': service, 'error_type': kind})
    except Exception:
        return generic


def guest_observation(reader, instance, *, project=PROJECT):
    require(project in {PROJECT, 'rayai-dev'}, 'Guest observation project is not allowed')
    name, zone = instance['name'], instance['zone'].rsplit('/', 1)[-1]
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name)
            and re.fullmatch(r'[a-z]+-[a-z0-9]+[0-9]-[a-z]', zone), 'Guest identity is invalid')
    user = os.environ.get('RECOVERY_SSH_USER', '')
    key = Path.home() / '.ssh/google_compute_engine'
    known = Path.home() / '.ssh/known_hosts'
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) and key.is_file() and known.is_file(),
            'Existing authenticated guest route is missing: require an existing SSH identity/user and verified known_hosts; no keys will be registered')
    source = (ROOT / 'scripts/recovery_guest_probe.py').read_text()
    proxy = shlex.join(['gcloud', 'compute', 'start-iap-tunnel', name, '22', '--listen-on-stdin',
                        '--project=' + project, '--zone=' + zone, '--quiet'])
    alias = f"{project}.{zone}.{instance['id']}"
    args = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'UpdateHostKeys=no', '-o', 'ControlMaster=no',
            '-o', 'UserKnownHostsFile=' + str(known), '-o', 'HostKeyAlias=' + alias,
            '-o', 'ProxyCommand=' + proxy, '-i', str(key), user + '@' + name,
            'sudo -n /usr/bin/python3 -']
    output = reader.command(args, input=source, guest_diagnostic=True)
    observed = json.loads(output)
    require(isinstance(observed, dict) and 'error' not in observed, guest_failure_reason(output))
    return {'instance_id': str(instance['id']), 'instance_name': name, 'zone': instance['zone'],
            'route': 'existing-ssh-identity-over-iap', 'host_key_alias': alias,
            'probe_sha256': hashlib.sha256(source.encode()).hexdigest(), 'observation': observed}


def host_provenance(reader):
    # The workflow builds these binaries from a second, exact-source checkout
    # with the original compiler/flags before the fresh observation window.
    source = ROOT / 'audited-host-source'
    require(reader.command(['git', '-C', str(source), 'rev-parse', 'HEAD']).strip() == HOST_SOURCE,
            'Audited host source checkout is missing or changed')
    result = {}
    for binary in ('vmd', 'secretsproxy'):
        data = (source / 'bin' / binary).read_bytes()
        unit = (source / 'deploy' / f'superserve-{binary}.service').read_bytes()
        result[binary] = {'source': HOST_SOURCE, 'binary': hashlib.sha256(data).hexdigest(),
                          'unit': hashlib.sha256(unit).hexdigest()}
        result[binary]['dropins'], result[binary]['guards'] = {}, {}
        result[binary]['optional_dropins'] = {}
        if binary == 'vmd':
            from recovery_guest_probe import DROPINS, EXTRA_DROPINS
            result[binary]['optional_dropins'] = {name: hashlib.sha256(text.encode()).hexdigest()
                                                  for name, text in EXTRA_DROPINS.items()}
            for name, guard in DROPINS.items():
                suffix = name.split('-', 1)[1]
                path = source / 'deploy' / ('superserve-vmd-' + suffix)
                result[binary]['dropins'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
                if guard:
                    result[binary]['guards'][guard] = hashlib.sha256((source/'deploy'/guard).read_bytes()).hexdigest()
    require(all(result[name]['binary'] == expected for name, expected in HOST_BINARIES.items()),
            'Audited host build is not reproducible')
    return result


def active_mutations(reader, own_run):
    runs = []
    statuses = ('in_progress', 'queued', 'waiting', 'pending', 'requested')
    with ThreadPoolExecutor(max_workers=len(statuses)) as executor:
        for page in executor.map(lambda status: reader.pages('actions/runs?status='+status, 'workflow_runs'), statuses):
            runs.extend(page)
    readonly = {'.github/workflows/ci.yml', '.github/workflows/terraform-checks.yml', evidence.COLLECTOR_WORKFLOW}
    require(not [r for r in runs if str(r['id']) != own_run and r.get('path') not in readonly],
            'Another workflow may mutate deployment state; complete operator coordination first')


def collect(reader, revision, env):
    # Checkpoint precedes the full scan. Later reads include late-arriving events
    # by receiveTimestamp; an acknowledged hold still covers audit delivery lag.
    cutoff = utc()
    preliminary = receiver_inventory(reader)
    history = {'cutoff': cutoff,
               'catalog_sha256': evidence.sha(RETIRED_RECEIVERS),
               'earliest': min(r['metadata']['creationTimestamp'] for region in CELLS
                               for r in preliminary['revisions_'+region]),
               'events': preliminary['deleted_receivers']}
    revisions = sum((preliminary['revisions_' + region] for region in CELLS), [])
    provenance = receiver_provenance(reader, revisions)
    canary = verify_canary(reader)
    hosts = host_provenance(reader)
    # Access prerequisites are checked before requesting either URL payload.
    manual = load_manual_guests(env)
    require(manual is not None or os.environ.get('RECOVERY_SSH_USER') and (Path.home()/'.ssh/google_compute_engine').is_file()
            and (Path.home()/'.ssh/known_hosts').is_file(), 'Existing hosted guest read route has not been established')
    active_mutations(reader, env['GITHUB_RUN_ID'])
    started = utc()
    reader.deadline = min(reader.deadline, time.monotonic() + evidence.MAX_AGE_SECONDS)
    with ThreadPoolExecutor(max_workers=1) as audit_executor:
        audit = audit_executor.submit(check_deletion_delta, reader, history)
        before = attach_history(mutable_inventory(reader), history)
        require(before == preliminary, 'Inventory changed during provenance preparation; recollect')
        if manual is not None:
            guests = manual['hosts']
            evidence.validate_manual_guests(manual, revision, evidence.sha(json.loads(
                (ROOT/'supabase/recovery/retained-storage-v1.json').read_text())), before, time.time())
            require(manual['operator'] == env['GITHUB_ACTOR'], 'Manual capture operator must dispatch collection')
        else:
            with ThreadPoolExecutor(max_workers=4) as executor:
                guests = list(executor.map(lambda instance: guest_observation(reader, instance), before['instances']))
        bindings = {}
        for region, secret in [('us-west2', 'database-url-usw2'), ('us-east4', 'database-url')]:
            # All historical executables are proved incapable. Bind every active
            # instance lifetime; its original latest version may remain loaded.
            active = [r for r in before['revisions_'+region] if any(c.get('type') == 'Active' and c.get('status') == 'True'
                             for c in r.get('status', {}).get('conditions', []))]
            require(active, 'No active receiver was observed')
            earliest = min(r['metadata']['creationTimestamp'] for r in active)
            bindings[secret] = private_binding(reader, secret, earliest, utc())
        audit.result()
        after = attach_history(mutable_inventory(reader), history)
        require(after == before, 'Inventory changed during observation; no evidence issued')
    verify_dispatch(reader, env)
    active_mutations(reader, env['GITHUB_RUN_ID'])
    completed = utc()
    manifest = json.loads((ROOT/'supabase/recovery/retained-storage-v1.json').read_text())
    document = {'schema': 3, 'policy': 'incapable-receivers-v1', 'target': 'usw2',
                'recovery_revision': revision, 'collector_revision': revision,
                'plan_hash': evidence.sha(manifest), 'database_project': PROJECTS['usw2'],
                'started_at': started, 'completed_at': completed,
                'inventory_before': evidence.sha(before), 'inventory_after': evidence.sha(after),
                'receiver_provenance': provenance, 'canary_provenance': canary,
                'host_provenance': hosts, 'hosts': guests, 'database_bindings': bindings,
                'deletion_history': history,
                'coordinated_assumption': {'actor': env['GITHUB_ACTOR'], 'run_id': env['GITHUB_RUN_ID'],
                    'revision': revision, 'target': 'usw2', 'plan_hash': evidence.sha(manifest),
                    'acknowledgment': 'accepted', 'started_at': started,
                    'scope': evidence.COORDINATION_SCOPE}}
    if manual is not None:
        document['manual_guests'] = manual
    evidence.validate_receivers(document, revision=revision, plan_hash=document['plan_hash'],
                                database_project=PROJECTS['usw2'], current=after, now=time.time())
    return document


def load_manual_guests(env):
    raw, digest = env.get('MANUAL_GUESTS_JSON', ''), env.get('MANUAL_GUESTS_SHA256', '')
    if not raw and not digest:
        return None
    require(0 < len(raw.encode()) <= 60000 and re.fullmatch(r'[a-f0-9]{64}', digest)
            and hashlib.sha256(raw.encode()).hexdigest() == digest,
            'Manual guest input is missing, oversized or differs from the approved digest')
    value = json.loads(raw)
    require(isinstance(value, dict), 'Manual guest input must be an object')
    return value


def require(ok, reason):
    evidence.require(ok, reason)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Reader:
    """Fixed read commands with bounded output, time and sanitized failures."""
    def __init__(self, deadline):
        self.deadline = deadline
        self._registry_token = None

    def command(self, args, *, binary=False, input=None, reject_stderr=False, guest_diagnostic=False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "Collection deadline expired")
        try:
            child_env = dict(os.environ, CLOUDSDK_CORE_LOG_HTTP='false',
                             CLOUDSDK_CORE_DISABLE_FILE_LOGGING='true', CLOUDSDK_CORE_VERBOSITY='error',
                             CLOUDSDK_COMPUTE_ALLOW_PARTIAL_ERROR='false')
            result = subprocess.run(args, input=input, capture_output=True, env=child_env,
                                    timeout=min(60, remaining), text=not binary)
            require(len(result.stdout) <= MAX_ARCHIVE, "Read-only provider output exceeded its bound")
            if result.returncode != 0 and guest_diagnostic:
                raise MigrationError(guest_failure_reason(result.stdout))
            require(result.returncode == 0, "Read-only provider failed; provider output suppressed")
            require(not reject_stderr or not result.stderr,
                    "Cloud inventory reported a warning; completeness is unproved and provider output suppressed")
            require(len(result.stdout) <= MAX_ARCHIVE, "Read-only provider output exceeded its bound")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise MigrationError("Read-only provider unavailable or timed out") from None

    def cloud(self, *args, fields=None):
        # Both Cloud Run and Compute can return successful partial inventories
        # with only a warning. Require all-or-nothing Compute responses above,
        # and reject diagnostics for every cloud read before accepting its rows.
        output_format = 'json(' + fields + ')' if fields else 'json'
        value = json.loads(self.command(["gcloud", *args, "--project=" + PROJECT, "--format=" + output_format, "--quiet",
                                         "--verbosity=warning"], reject_stderr=True))
        if isinstance(value, list):
            require(len(value) < MAX_ITEMS, "Cloud inventory reached its completeness bound")
        return value

    def github(self, path, *, binary=False):
        return self.command(["gh", "api", "repos/superserve-ai/sandbox/" + path], binary=binary)

    def pages(self, path, key):
        rows = []
        for page in range(1, 11):
            separator = '&' if '?' in path else '?'
            data = json.loads(self.github(f'{path}{separator}per_page=100&page={page}'))
            batch = data[key]
            require(isinstance(batch, list), "GitHub inventory shape is invalid")
            rows.extend(batch)
            if len(batch) < 100:
                require(data.get('total_count', len(rows)) == len(rows), "GitHub inventory is incomplete")
                return rows
        raise MigrationError("GitHub inventory reached its completeness bound")

    def registry(self, image, path):
        require(image in {IMAGE, CANARY_IMAGE}, "Unaudited registry repository")
        require(re.fullmatch(r'(manifests|blobs)/sha256:[a-f0-9]{64}', path), "Registry digest is invalid")
        if self._registry_token is None:
            self._registry_token = self.command(['gcloud', 'auth', 'print-access-token']).strip()
        request = urllib.request.Request('https://' + REGISTRY + '/v2/' + image.split('/', 1)[1] + '/' + path,
                                         headers={'Authorization': 'Bearer ' + self._registry_token,
                                                  'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'})
        try:
            with urllib.request.urlopen(request, timeout=min(15, max(1, self.deadline-time.monotonic()))) as response:
                data = response.read(MAX_CONFIG + 1)
            require(len(data) <= MAX_CONFIG and 'sha256:' + hashlib.sha256(data).hexdigest() == path.split('/')[-1],
                    "Registry content does not match its immutable digest")
            return data
        except Exception:
            raise MigrationError("Immutable registry observation failed") from None


def artifact_config(data):
    """Read the config in a docker-save artifact without extracting/executing it."""
    require(len(data) <= MAX_ARCHIVE, "Build artifact is oversized")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) == 1 and archive.infolist()[0].file_size <= MAX_ARCHIVE,
                "Build artifact archive shape is invalid")
        with tarfile.open(fileobj=io.BytesIO(archive.read(archive.namelist()[0])), mode='r:gz') as tar:
            manifest_file = tar.getmember('manifest.json')
            require(manifest_file.isfile() and manifest_file.size <= MAX_CONFIG, "Image manifest is invalid")
            manifest = json.load(tar.extractfile(manifest_file))
            require(len(manifest) == 1, "Build artifact must contain one image")
            config_file = tar.getmember(manifest[0]['Config'])
            require(config_file.isfile() and config_file.size <= MAX_CONFIG, "Image config is invalid")
            return tar.extractfile(config_file).read()


def receiver_provenance(reader, revisions):
    """Authenticate old image builds before starting the short evidence window."""
    sources = set(reader.command(['git', '-C', str(ROOT), 'rev-list', '--first-parent', evidence.AUDITED_SOURCE]).split())
    require(evidence.AUDITED_SOURCE in sources, "Audited receiver source history is unavailable")
    images = reader.cloud('artifacts', 'docker', 'images', 'list', IMAGE, '--include-tags', '--limit=1000')
    by_digest = {row['version']: row for row in images}
    result = {}
    for revision in revisions:
        digest = revision.get('status', {}).get('imageDigest', '').rsplit('@', 1)[-1]
        if digest in result:
            continue
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', digest), "Receiver immutable image is unavailable")
        tags = set(by_digest.get(digest, {}).get('tags', [])) & sources
        require(len(tags) == 1, "Historical receiver needs authenticated pre-retained build provenance: " + digest)
        source = tags.pop()
        runs = reader.pages(f'actions/runs?head_sha={source}&event=push', 'workflow_runs')
        matches = []
        for run in runs:
            if (run.get('head_sha') != source or run.get('head_branch') != 'main'
                    or run.get('path') != '.github/workflows/deploy-api.yml'
                    or run.get('conclusion') != 'success'):
                continue
            for item in reader.pages(f"actions/runs/{run['id']}/artifacts", 'artifacts'):
                if item.get('name') == 'controlplane-image-' + source and not item.get('expired'):
                    matches.append((run['id'], item))
        require(len(matches) == 1, "Historical receiver build artifact is unavailable or ambiguous: " + digest)
        run_id, item = matches[0]
        require(0 < item.get('size_in_bytes', 0) <= MAX_ARCHIVE, "Build artifact size is invalid")
        data = reader.github(f"actions/artifacts/{item['id']}/zip", binary=True)
        require('sha256:' + hashlib.sha256(data).hexdigest() == item.get('digest'), "Build artifact integrity mismatch")
        config = artifact_config(data)
        manifest = json.loads(reader.registry(IMAGE, 'manifests/' + digest))
        config_digest = 'sha256:' + hashlib.sha256(config).hexdigest()
        require(manifest.get('config', {}).get('digest') == config_digest, "Registry image does not match its source build")
        built = json.loads(config)
        require(built.get('config', {}).get('Entrypoint') == ['controlplane']
                and not built['config'].get('Cmd'), "Receiver executable override is not audited")
        result[digest] = {'source': source, 'lineage_boundary': evidence.AUDITED_SOURCE,
                          'build_run': run_id, 'artifact': item['id'],
                          'archive_digest': item['digest'], 'config_digest': config_digest}
    return result


def verify_canary(reader):
    manifest = json.loads(reader.registry(CANARY_IMAGE, 'manifests/' + CANARY['image']))
    require(manifest.get('config', {}).get('digest') == CANARY['config'], "Canary image provenance changed")
    config = json.loads(reader.registry(CANARY_IMAGE, 'blobs/' + CANARY['config']))
    require(config.get('config', {}).get('Entrypoint') == ['/api-canary'], "Canary entrypoint changed")
    return dict(CANARY)


def verify_dispatch(reader, env):
    revision = env.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[a-f0-9]{40}', revision) and env.get('GITHUB_REF') == 'refs/heads/main'
            and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == 'superserve-ai/sandbox'
            and env.get('APPROVED_REVISION') == revision,
            "Collection requires an explicitly approved exact main revision")
    require(json.loads(reader.github('git/ref/heads/main'))['object']['sha'] == revision,
            "Main advanced; collection must be re-approved")
    require(re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ID', ''))
            and env.get('GITHUB_ACTOR') and env.get('COORDINATION_ACK') == 'accepted',
            "A named operator must acknowledge the coordinated no-change window")
    return revision


def private_binding(reader, secret, start, end):
    def versions(name):
        return reader.cloud('secrets', 'versions', 'list', name, '--limit=1000')
    def payload(name):
        version = name.rsplit('/', 1)[-1]
        # This is executed only inside an explicitly released hosted collector.
        # stdout is captured privately; no provider error or payload is logged.
        encoded = reader.command(['gcloud', 'secrets', 'versions', 'access', version,
                                  '--secret=' + secret, '--project=' + PROJECT,
                                  '--format=get(payload.data)', '--quiet'], binary=True).strip()
        require(len(encoded) <= 32768, 'Private database binding exceeded its size bound')
        return base64.b64decode(encoded, altchars=b'-_', validate=True)
    return binding.classify(secret, earliest_start=start, observed_at=end,
                            list_versions=versions, read_payload=payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-dispatch', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('recovery-evidence/evidence.json'))
    args = parser.parse_args()
    reader = Reader(time.monotonic() + 1800)
    try:
        revision = verify_dispatch(reader, os.environ)
        if args.check_dispatch:
            return 0
        document = collect(reader, revision, os.environ)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        require(not args.output.exists(), "Evidence output already exists")
        args.output.write_text(json.dumps(document, sort_keys=True) + '\n')
        print('Read-only receiver evidence collected; recovery has not been executed')
    except MigrationError as error:
        print(str(error))
        return 1
    except Exception:
        print('Read-only collection failed; provider and configuration details suppressed')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
