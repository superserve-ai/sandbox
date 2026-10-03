"""Verify an authenticated read-only observation before retained recovery.

The collector is a separate operational prerequisite. This verifier never
registers SSH keys, provisions access, or treats a sampling flag as exclusion.
"""

import datetime
import hashlib
import io
import json
import re
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from migrate_database import MigrationError

COLLECTOR_WORKFLOW = ".github/workflows/recovery-evidence.yml"
MAX_AGE_SECONDS = 120
MAX_BYTES = 2_000_000
# This source has neither the retained API receiver nor the retained publisher
# field. Adding an admitted build requires source and persisted-replay review.
AUDITED_SOURCE = "7bfa1da7f8b18ccf7bc25feaf3fc8640ae2cc690"
PROJECT = "rayai-prod"
REGION = "us-west2"
SERVICE = "superserve-api-usw2"
COORDINATION_SCOPE = ["api-worker-deployments-and-rollbacks", "host-binaries-services-and-restarts",
                      "routing-dns-and-proxies", "database-secret-rotation", "retained-activation",
                      "manual-and-alternate-writers", "already-in-flight-automation"]


def require(condition, message):
    if not condition:
        raise MigrationError(message)


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(args, deadline, *, binary=False):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Recovery evidence deadline exceeded")
    result = subprocess.run(args, capture_output=True, timeout=min(remaining, 15), text=not binary)
    require(result.returncode == 0, "Authenticated read-only observation failed; no output logged")
    return result.stdout


def timestamp(value):
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(dt.tzinfo is not None, "Evidence timestamps must include a timezone")
    return dt.timestamp()


def inventory(deadline):
    # Inspect every revision, including tagged, draining and zero-traffic ones.
    # The conservative admission below requires every observed revision to be
    # an audited incapable build, rather than inferring absence from traffic.
    queries = [
        ["gcloud", "run", "services", "describe", SERVICE,
         "--project", PROJECT, "--region", REGION, "--format=json"],
        ["gcloud", "run", "revisions", "list", "--service", SERVICE,
         "--project", PROJECT, "--region", REGION, "--format=json"],
        ["gcloud", "compute", "instances", "list", "--project", PROJECT, "--format=json"],
    ]
    with ThreadPoolExecutor(max_workers=3) as executor:
        service, revisions, hosts = list(executor.map(lambda args: json.loads(command(args, deadline)), queries))
    require(isinstance(service, dict) and isinstance(revisions, list) and revisions and isinstance(hosts, list),
            "Cloud observation is incomplete")
    # Use the complete project instance inventory so an unlabelled/standby host
    # cannot disappear through a deployment script's narrower label filter.
    return {"service": service, "revisions": revisions, "instances": hosts}


def validate(document, *, revision, plan_hash, database_project, current, now):
    if document.get('schema') == 2:
        return validate_receivers(document, revision=revision, plan_hash=plan_hash,
                                  database_project=database_project, current=current, now=now)
    require(document.get("schema") == 1 and document.get("target") == "usw2"
            and document.get("recovery_revision") == revision and document.get("plan_hash") == plan_hash
            and document.get("database_project") == database_project,
            "Evidence does not identify this recovery revision, plan and database")
    start, end = timestamp(document["started_at"]), timestamp(document["completed_at"])
    require(now - MAX_AGE_SECONDS <= start <= end <= now, "Deployment evidence is stale or future dated")
    require(document.get("collector_revision") == revision, "Collector revision mismatch")
    require(document.get("inventory_before") == document.get("inventory_after") == sha(current),
            "Deployment inventory changed or evidence coverage is incomplete")
    require(document.get("project") == PROJECT and document.get("region") == REGION
            and document.get("service") == SERVICE, "Evidence cloud target mismatch")
    revisions = document.get("revisions", [])
    observed = {r["metadata"]["name"] for r in current["revisions"]}
    require({r.get("name") for r in revisions} == observed and len(revisions) == len(observed),
            "Evidence must cover every revision, including background and tagged revisions")
    for item in revisions:
        require(item.get("source_commit") == AUDITED_SOURCE
                and re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("image_digest", ""))
                and item.get("build_provenance_verified") is True,
                "Revision is not an authenticated audited incapable build")
        actual = next(r for r in current["revisions"] if r["metadata"]["name"] == item["name"])
        actual_image = actual.get("status", {}).get("imageDigest", "")
        require(actual_image.rsplit("@", 1)[-1] == item["image_digest"], "Revision image changed")
        containers = actual.get("spec", {}).get("containers", [])
        require(len(containers) == 1 and not containers[0].get("command") and not containers[0].get("args"),
                "Unaudited sidecars or command overrides prevent writer exclusion")
    lifecycle = document.get("revision_lifecycle_audit", {})
    require(timestamp(lifecycle["started_at"]) <= start - 600
            and timestamp(lifecycle["completed_at"]) >= end
            and lifecycle.get("complete") is True and lifecycle.get("deleted_revisions") == [],
            "Recent revision deletion or incomplete drain coverage prevents recovery")
    hosts = document.get("hosts", [])
    instances = {str(item["id"]): item for item in current["instances"]}
    require({str(h.get("instance_id")) for h in hosts} == set(instances) and len(hosts) == len(instances),
            "Host evidence must cover the full instance inventory")
    for host in hosts:
        instance = instances[str(host["instance_id"])]
        require(host.get("instance_name") == instance["name"] and host.get("zone") == instance["zone"],
                "Host identity changed")
        require(host.get("authenticated_read_route") and host.get("key_or_metadata_mutation") is False
                and host.get("complete_process_inventory") is True,
                "Host observation requires established non-mutating authenticated access")
        services = host.get("report_services")
        require(isinstance(services, list), "Restart-capable report services were not inventoried")
        by_service = {s["service_id"]: s for s in services}
        require(len(by_service) == len(services), "Ambiguous report service inventory")
        for service in services:
            require(service.get("source_commit") == AUDITED_SOURCE
                    and service.get("build_provenance_verified") is True
                    and service.get("automatic_downloads") is False and service.get("in_progress_rollout") is False
                    and all(re.fullmatch(r"[a-f0-9]{64}", service.get(key, ""))
                            for key in ("executable_sha256", "unit_sha256", "configuration_sha256")),
                    "A restart source may introduce a retained-capable writer")
        processes = host.get("report_processes")
        require(isinstance(processes, list), "Running report process inventory is missing")
        for process in processes:
            require(process.get("source_commit") == AUDITED_SOURCE
                    and re.fullmatch(r"[a-f0-9]{64}", process.get("executable_sha256", ""))
                    and process.get("build_provenance_verified") is True
                    and process.get("start_time") and process.get("incarnation_id")
                    and process.get("destination_database") == database_project
                    and process.get("service_id") in by_service
                    and process.get("executable_sha256") == by_service[process["service_id"]]["executable_sha256"],
                    "A host process may produce or replay retained reports")
        require(set(host.get("spools", {})) == {".storage-report-queue", ".storage-report-queue.v2", ".storage-report-queue.migrating/state.json"}
                and all(s.get("retained_payloads") == 0 and s.get("complete_scan") is True
                        for s in host["spools"].values()),
                "Retained spool coverage is missing or contains retained payloads")
    require(document.get("alternate_producers") == [] and document.get("complete_writer_inventory") is True,
            "Alternate or unobserved writers prevent recovery")
    require(document.get("deployment_and_toggle_hold", {}).get("revision") == revision
            and document["deployment_and_toggle_hold"].get("active") is True,
            "The separately coordinated deployment and configuration hold is missing")


def public_api_routes(current):
    """Resolve the two report hostnames through the observed load-balancer graph."""
    from collect_recovery_evidence import CELLS
    proxies = {row['selfLink']: row for row in current['https_proxies']}
    maps = {row['selfLink']: row for row in current['routes']}
    backends = {row['selfLink']: row for row in current['backends']}
    negs = {row['selfLink']: row for row in current['negs']}
    destinations = {}
    for host, addresses in current['dns'].items():
        require(addresses, 'Report hostname has no observed destination')
        matched = []
        for address in addresses:
            forwarders = [f for f in current['forwarders'] if f.get('IPAddress') == address
                          and f.get('target') in proxies]
            require(len(forwarders) == 1, 'Report hostname does not resolve to one audited HTTPS route')
            route = maps[proxies[forwarders[0]['target']]['urlMap']]
            require(not route.get('routeRules') and not route.get('defaultUrlRedirect'), 'Unknown report routing rule')
            matches = [r for r in route.get('hostRules', []) if any(
                pattern == host or pattern == '*' or (pattern.startswith('*.') and host.endswith(pattern[1:]))
                for pattern in r.get('hosts', []))]
            require(len(matches) <= 1, 'Ambiguous report host route')
            selected = route
            if matches:
                choices = [m for m in route['pathMatchers'] if m['name'] == matches[0]['pathMatcher']]
                require(len(choices) == 1, 'Missing report path matcher')
                selected = choices[0]
            require(not any(selected.get(k) for k in ('pathRules', 'routeRules', 'defaultRouteAction', 'headerAction')),
                    'Report routes require a simple audited backend')
            backend = backends[selected['defaultService']]
            groups = backend.get('backends', [])
            require(groups and not backend.get('customRequestHeaders'), 'Report backend is incomplete or rewritten')
            services = []
            for group in groups:
                neg = negs.get(group['group'], {})
                target = neg.get('cloudRun', {})
                require(neg.get('networkEndpointType') == 'SERVERLESS' and set(target) == {'service'}
                        and target['service'] in CELLS.values(), 'Report backend is not an audited API service')
                services.append(target['service'])
            require(len(set(services)) == 1, 'Report backend has mixed destinations')
            matched.append(services[0])
        require(len(set(matched)) == 1, 'DNS addresses route to different receivers')
        destinations['https://' + host] = matched[0]
    return destinations


def stable_guest(value):
    copy = json.loads(json.dumps(value))
    for service in copy['observation']['services']:
        service['process'].pop('established_peers', None)
    return copy


def receiver_state(document):
    assumption = {key: document['coordinated_assumption'][key]
                  for key in ('actor', 'scope', 'target', 'revision', 'plan_hash', 'acknowledgment')}
    bindings = {name: {key: value for key, value in proof.items() if key != 'observed_at'}
                for name, proof in document['database_bindings'].items()}
    return {'inventory_after': document['inventory_after'], 'provenance': document['receiver_provenance'],
            'hosts': sorted(map(stable_guest, document['hosts']), key=lambda h: h['instance_id']),
            'database_bindings': bindings, 'coordinated_assumption': assumption}


def validate_receivers(document, *, revision, plan_hash, database_project, current, now):
    from collect_recovery_evidence import CANARY, CANARY_IMAGE, CELLS, HOST_SOURCE
    from recovery_database_binding import BINDINGS, candidate_versions
    require(document.get('schema') == 2 and document.get('policy') == 'incapable-receivers-v1'
            and document.get('target') == 'usw2' and document.get('database_project') == database_project
            and document.get('recovery_revision') == document.get('collector_revision') == revision
            and document.get('plan_hash') == plan_hash, 'Receiver evidence identity mismatch')
    start, end = timestamp(document['started_at']), timestamp(document['completed_at'])
    require(now-MAX_AGE_SECONDS <= start <= end <= now, 'Receiver evidence is stale or future dated')
    require(document.get('inventory_before') == document.get('inventory_after') == sha(current),
            'Receiver, routing or binding inventory changed')
    assumption = document.get('coordinated_assumption', {})
    require(assumption.get('revision') == revision and assumption.get('plan_hash') == plan_hash
            and assumption.get('target') == 'usw2' and assumption.get('acknowledgment') == 'accepted'
            and assumption.get('scope') == COORDINATION_SCOPE and assumption.get('actor')
            and re.fullmatch(r'[1-9][0-9]*', assumption.get('run_id', ''))
            and assumption.get('started_at') == document['started_at'],
            'Explicit coordinated-window acknowledgment is missing')
    services = {s['metadata']['name']: s for s in current['services']}
    require(set(services) == set(CELLS.values()) and len(current['services']) == len(services),
            'Additional or missing API receiver service')
    destinations = public_api_routes(current)
    require(current.get('workers') == [],
            'An alternate worker pool requires source and binding review')
    require(current.get('deleted_receivers') == [],
            'Deleted receiver history needs source provenance or affirmative termination review')
    certificates = document.get('receiver_provenance', {})
    for region, name in CELLS.items():
        service = services[name]
        destinations[service['status']['url']] = name
        rows = current['revisions_'+region]
        require(rows and len({r['metadata']['name'] for r in rows}) == len(rows), 'Revision coverage is incomplete')
        for row in rows:
            image = row.get('status', {}).get('imageDigest', '').rsplit('@', 1)[-1]
            proof = certificates.get(image, {})
            require(proof.get('lineage_boundary') == AUDITED_SOURCE
                    and re.fullmatch(r'[a-f0-9]{40}', proof.get('source', ''))
                    and proof.get('artifact') and proof.get('build_run')
                    and re.fullmatch(r'sha256:[a-f0-9]{64}', proof.get('config_digest', '')),
                    'A receiver revision lacks authenticated pre-retained provenance')
            containers = row.get('spec', {}).get('containers', [])
            require(len(containers) == 1 and not containers[0].get('command') and not containers[0].get('args'),
                    'Receiver executable/sidecar override is not audited')
        secret = 'database-url-usw2' if region == 'us-west2' else 'database-url'
        active = [r for r in rows if any(c.get('type') == 'Active' and c.get('status') == 'True'
                                         for c in r.get('status', {}).get('conditions', []))]
        require(active, 'Active receiver inventory is missing')
        earliest = min(r['metadata']['creationTimestamp'] for r in active)
        proof = document.get('database_bindings', {}).get(secret, {})
        require(proof.get('earliest_revision_start') == earliest and timestamp(proof['observed_at']) <= end,
                'Database binding does not cover active receiver lifetime')
        expected = candidate_versions(secret, current['versions_'+secret], earliest, proof['observed_at'])
        require(proof.get('versions') == [{'name': v['name'], 'created_at': v['createTime'],
                                          'expected_project_match': True} for v in expected],
                'Database binding versions are incomplete')
        for row in active:
            env = row['spec']['containers'][0].get('env', [])
            refs = [e for e in env if e['name'] == 'DATABASE_URL']
            require(len(refs) == 1 and refs[0].get('valueFrom', {}).get('secretKeyRef') == {'name': secret, 'key': 'latest'}
                    and not any(e['name'].startswith('PG') for e in env),
                    'API database binding is not the privately verified reference')
            aliases = row['metadata'].get('annotations', {}).get('run.googleapis.com/secrets', '')
            mapping = {}
            for item in aliases.split(',') if aliases else []:
                parts = item.split(':', 1)
                require(len(parts) == 2 and parts[0] not in mapping, 'Database secret alias mapping is ambiguous')
                mapping[parts[0]] = parts[1]
            require(secret not in mapping or mapping[secret] in {
                f'projects/{project}/secrets/{secret}' for project in ('rayai-prod', '887554770957')},
                'Database secret alias resolves to another resource')
    require(document.get('canary_provenance') == CANARY, 'Canary provenance changed')
    require(current.get('canary_image') == CANARY['image'], 'Canary image tag changed')
    for execution in current.get('active_job_executions', []):
        containers = execution.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        require(len(containers) == 1 and containers[0].get('image') == CANARY_IMAGE + '@' + CANARY['image']
                and not containers[0].get('command')
                and containers[0].get('args') in (['-mode', 'lifecycle'], ['-mode', 'janitor']),
                'An active job execution has unreviewed executable provenance')
    expected_jobs = {f'{prefix}-production-{region}' for prefix in ('api-canary', 'api-canary-janitor') for region in CELLS}
    require({j['metadata']['name'] for j in current['jobs']} == expected_jobs and len(current['jobs']) == 4,
            'Unknown alternate job consumer')
    for job in current['jobs']:
        spec = job['spec']['template']['spec']['template']['spec']
        containers = spec.get('containers', [])
        require(len(containers) == 1 and not spec.get('volumes'), 'Canary sidecar/volume is not audited')
        container = containers[0]
        mode = 'janitor' if 'janitor' in job['metadata']['name'] else 'lifecycle'
        require(not container.get('command') and container.get('args') == ['-mode', mode]
                and container.get('image') in {CANARY_IMAGE + ':' + CANARY['source'], CANARY_IMAGE + '@' + CANARY['image']},
                'Alternate consumer image/entrypoint is not audited')
        env = container.get('env', [])
        endpoint = [e.get('value') for e in env if e['name'] == 'API_BASE_URL']
        require(len(endpoint) == 1 and endpoint[0].rstrip('/') in destinations
                and not any(e['name'] == 'DATABASE_URL' or e['name'].startswith('PG') for e in env),
                'Canary destination or database configuration is not audited')
    hosts = {str(h['id']): h for h in current['instances']}
    observed = document.get('hosts', [])
    require(len(observed) == len(hosts) and {h.get('instance_id') for h in observed} == set(hosts),
            'Guest observation must cover the complete host inventory')
    for guest in observed:
        host = hosts[guest['instance_id']]
        require(guest.get('instance_name') == host['name'] and guest.get('zone') == host['zone']
                and guest.get('route') == 'existing-ssh-identity-over-iap', 'Guest identity or authenticated route changed')
        observation = guest['observation']
        require(observation.get('boot_id') and observation.get('additional_managed_reporters') == [],
                'Guest process inventory is incomplete')
        entries = observation.get('services', [])
        require(len(entries) == 2 and {entry['binary'] for entry in entries} == {'vmd', 'secretsproxy'},
                'Managed guest reporter inventory is incomplete')
        for entry in entries:
            build = document['host_provenance'][entry['binary']]
            require(build.get('source') == HOST_SOURCE and entry['installed_sha256'] == build['binary']
                    and entry['process']['executable_sha256'] == build['binary'] and entry['unit_sha256'] == build['unit']
                    and entry.get('dropins') == build.get('dropins') and entry.get('guards') == build.get('guards'),
                    'Running or restart guest executable/configuration is not audited')
            route = entry['process']['routing']
            require(route['origin'] in destinations and entry['restart_routing']['origin'] == route['origin'],
                    'Guest effective or restart report destination is not audited')
            addresses = current['service_dns'].get(route['origin'], current['dns'].get(route['origin'].removeprefix('https://'), []))
            require(addresses and route.get('resolved_addresses') and entry['restart_routing'].get('resolved_addresses')
                    and set(route['resolved_addresses']) <= set(addresses)
                    and set(entry['restart_routing']['resolved_addresses']) <= set(addresses),
                    'Guest DNS differs from the audited receiver route')
            # The audited publisher fixes its report URL at startup; replay
            # cannot replace it, and audited receivers do not redirect it.
            # Other TLS clients (including backups) share this process. Their
            # socket addresses are diagnostics, not report-receiver identity.


class Observation:
    def __init__(self, *, repository, revision, run_id, plan_hash, database_project, deadline):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or "")
                and re.fullmatch(r"[a-f0-9]{40}", revision or "")
                and re.fullmatch(r"[1-9][0-9]*", run_id or ""),
                "Recovery is blocked: supply a successful authenticated read-only evidence collection run")
        self.repository, self.revision, self.run_id = repository, revision, run_id
        self.plan_hash, self.database_project, self.deadline = plan_hash, database_project, deadline
        self.artifact_digest = None
        self.state_digest = None
        self.valid_until = None
        self._document = None
        self._identity = (repository, revision, run_id, plan_hash, database_project)

    def api(self, path, binary=False):
        return command(["gh", "api", f"repos/{self.repository}/{path}"], self.deadline, binary=binary)

    def load_artifact(self):
        run = json.loads(self.api(f"actions/runs/{self.run_id}"))
        require(run.get("head_sha") == self.revision and run.get("head_branch") == "main"
                and run.get("path") == COLLECTOR_WORKFLOW and run.get("event") == "workflow_dispatch"
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                and run.get("repository", {}).get("full_name") == self.repository,
                "Evidence must come from the reviewed same-revision read-only collection workflow")
        artifacts = json.loads(self.api(f"actions/runs/{self.run_id}/artifacts?per_page=100"))
        matching = [a for a in artifacts["artifacts"] if a.get("name") == "retained-recovery-evidence-usw2"]
        require(len(matching) == 1, "A unique recovery evidence artifact is required")
        artifact = matching[0]
        require(not artifact.get("expired") and 0 < artifact.get("size_in_bytes", 0) <= MAX_BYTES,
                "Recovery evidence artifact is unavailable or oversized")
        data = self.api(f"actions/artifacts/{int(artifact['id'])}/zip", binary=True)
        require(len(data) <= MAX_BYTES, "Recovery evidence download is oversized")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        require(digest == artifact.get("digest"),
                "Recovery evidence artifact integrity changed")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            require(archive.namelist() == ["evidence.json"] and archive.getinfo("evidence.json").file_size <= MAX_BYTES,
                    "Recovery evidence archive shape is invalid")
            document = json.loads(archive.read("evidence.json"))
        return document, digest

    def verify(self):
        require(self._identity == (self.repository, self.revision, self.run_id, self.plan_hash, self.database_project),
                "Recovery evidence identity changed")
        # Keep the authenticated bytes only for this Observation. A fresh run
        # requires a new instance; mutable cloud inventory is never cached.
        if self._document is None:
            document, digest = self.load_artifact()
        else:
            document, digest = self._document, self.artifact_digest
        require(time.time() < timestamp(document["started_at"]) + MAX_AGE_SECONDS,
                "Deployment evidence is stale")
        if document.get('schema') == 2:
            from collect_recovery_evidence import Reader, receiver_inventory, guest_observation, active_mutations
            reader = Reader(self.deadline)
            current = receiver_inventory(reader)
            import os
            active_mutations(reader, os.environ.get('GITHUB_RUN_ID', ''))
            with ThreadPoolExecutor(max_workers=4) as executor:
                guests = list(executor.map(lambda host: guest_observation(reader, host), current['instances']))
            require(sorted(map(stable_guest, guests), key=lambda h: h['instance_id']) ==
                    sorted(map(stable_guest, document['hosts']), key=lambda h: h['instance_id']),
                    'Guest process, executable or effective destination changed')
            require(document['coordinated_assumption']['run_id'] == self.run_id,
                    'Coordination acknowledgment belongs to another collection run')
            fresh = dict(document, hosts=guests)
            validate_receivers(fresh, revision=self.revision, plan_hash=self.plan_hash,
                               database_project=self.database_project, current=current, now=time.time())
        else:
            current = inventory(self.deadline)
        validate(document, revision=self.revision, plan_hash=self.plan_hash, database_project=self.database_project,
                 current=current, now=time.time())
        state_digest = sha(receiver_state(document)) if document.get('schema') == 2 else sha({key: document[key] for key in (
            "inventory_after", "revisions", "hosts", "alternate_producers", "deployment_and_toggle_hold")})
        require(self.state_digest is None or self.state_digest == state_digest,
                "Observed writer state changed during recovery")
        self.valid_until = timestamp(document["started_at"]) + MAX_AGE_SECONDS
        self.state_digest = state_digest
        self.artifact_digest = digest
        self._document = document
