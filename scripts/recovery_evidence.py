"""Verify an authenticated read-only observation before retained recovery.

The collector is a separate operational prerequisite. This verifier never
registers SSH keys, provisions access, or treats a sampling flag as exclusion.
"""

import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from migrate_database import MigrationError

COLLECTOR_WORKFLOW = ".github/workflows/recovery-evidence.yml"
MAX_AGE_SECONDS = 120
MANUAL_MAX_AGE_SECONDS = 1800
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
    if document.get('schema') in (2, 3):
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


def forwards_https(rule):
    protocol = rule.get('IPProtocol')
    require(protocol in {'TCP', 'UDP', 'ESP', 'AH', 'SCTP', 'ICMP', 'ICMPV6', 'L3_DEFAULT'},
            'Forwarding-rule protocol is missing or unknown')
    if protocol not in {'TCP', 'L3_DEFAULT'}:
        return False
    selectors = [key for key in ('portRange', 'ports', 'allPorts') if rule.get(key)]
    require(len(selectors) == 1, 'Forwarding-rule port coverage is ambiguous')
    if selectors[0] == 'allPorts':
        require(rule['allPorts'] is True, 'Forwarding-rule allPorts is invalid')
        return True
    if selectors[0] == 'ports':
        ports = rule['ports']
        require(isinstance(ports, list) and all(isinstance(port, str) and re.fullmatch(r'[0-9]{1,5}', port)
                                               and 1 <= int(port) <= 65535 for port in ports),
                'Forwarding-rule ports are invalid')
        return any(int(port) == 443 for port in ports)
    value = rule['portRange']
    match = re.fullmatch(r'([0-9]{1,5})(?:-([0-9]{1,5}))?', value) if isinstance(value, str) else None
    require(match is not None, 'Forwarding-rule port range is invalid')
    first, last = int(match[1]), int(match[2] or match[1])
    require(1 <= first <= last <= 65535, 'Forwarding-rule port range is invalid')
    return first <= 443 <= last


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
            forwarders = [f for f in current['forwarders'] if f.get('IPAddress') == address and forwards_https(f)]
            require(len(forwarders) == 1 and forwarders[0].get('target') in proxies,
                    'Report hostname does not resolve to one audited TCP port 443 route')
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
            'database_bindings': bindings, 'coordinated_assumption': assumption,
            **({'manual_guests': document['manual_guests']} if 'manual_guests' in document else {}),
            **({'host_provenance': document['host_provenance'],
                'canary_provenance': document['canary_provenance']} if document['schema'] == 3 else {})}


def validate_manual_guests(manual, revision, plan_hash, current, now):
    from pathlib import Path
    require(manual.get('authority') == 'operator-supplied-coordinated-window'
            and manual.get('revision') == revision and manual.get('plan_hash') == plan_hash
            and manual.get('project') == PROJECT and manual.get('target') == 'usw2'
            and manual.get('acknowledgment') == 'accepted' and manual.get('scope') == COORDINATION_SCOPE
            and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', manual.get('operator', '')),
            'Manual guest authority, recovery identity or continuity acknowledgment is invalid')
    start, end = timestamp(manual['started_at']), timestamp(manual['completed_at'])
    require(now-MANUAL_MAX_AGE_SECONDS <= start <= end <= now,
            'Manual guest capture is stale or future dated; acknowledgment cannot reset capture time')
    probe_hash = hashlib.sha256(Path(__file__).with_name('recovery_guest_probe.py').read_bytes()).hexdigest()
    instances = {str(instance['id']): instance for instance in current['instances']}
    hosts = manual.get('hosts', [])
    require(len(hosts) == len(instances) == 2 and {h.get('instance_id') for h in hosts} == set(instances),
            'Manual capture must cover both immutable host identities')
    for host in hosts:
        instance = instances[host['instance_id']]
        require(host.get('instance_name') == instance['name'] and host.get('zone') == instance['zone']
                and host.get('probe_sha256') == probe_hash and host.get('route') == 'operator-supplied'
                and instance.get('status') == 'RUNNING'
                and instance.get('lastStartTimestamp')
                and timestamp(instance['lastStartTimestamp']) <= start
                and host.get('instance_sha256') == sha(instance),
                'Manual host identity, restart state, metadata or probe differs from current inventory')
    return start + MANUAL_MAX_AGE_SECONDS


def canary_configuration(spec, destinations):
    containers = spec.get('containers', [])
    require(len(containers) == 1 and not spec.get('volumes') and not containers[0].get('volumeMounts'),
            'Canary sidecar/volume is not audited')
    container = containers[0]
    env = container.get('env', [])
    endpoint = [e.get('value') for e in env if e['name'] == 'API_BASE_URL']
    require(len(endpoint) == 1 and isinstance(endpoint[0], str) and endpoint[0].rstrip('/') in destinations
            and not any(e['name'] == 'DATABASE_URL' or e['name'].startswith('PG') for e in env),
            'Canary destination or database configuration is not audited')
    return container


def retired_receiver_history_safe(current):
    from collect_recovery_evidence import RETIRED_RECEIVERS
    events = current.get('deleted_receivers')
    if events == []:
        return True
    if not isinstance(events, list) or len(events) > len(RETIRED_RECEIVERS['events']):
        return False
    seen = set()
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get('protoPayload'), dict):
            return False
        payload = event['protoPayload']
        status = payload.get('status')
        if not isinstance(status, dict) or type(status.get('code', 0)) is not int:
            return False
        identity = {'timestamp': event.get('timestamp'), 'receiveTimestamp': event.get('receiveTimestamp'),
                    'method': payload.get('methodName'), 'resource': payload.get('resourceName'),
                    'status_code': status.get('code', 0)}
        if identity not in RETIRED_RECEIVERS['events'] or sha(identity) in seen:
            return False
        seen.add(sha(identity))
        deleted_at = timestamp(identity['timestamp'])
        if deleted_at >= timestamp(RETIRED_RECEIVERS['retained_introduction_at']):
            return False
        if identity['status_code'] == 5:
            # Exact reviewed NOT_FOUND event: no deletion occurred.
            continue
        if identity['status_code'] != 0:
            return False
        name = identity['resource'].rsplit('/', 1)[-1]
        if identity['method'].endswith('.Jobs.DeleteJob'):
            rows = [(row, None) for row in current['jobs']]
            rows += [(row, 'run.googleapis.com/job') for row in current['active_job_executions']]
        elif identity['method'].endswith('.Services.DeleteService'):
            rows = [(row, None) for row in current['services']]
            rows += [(row, 'serving.knative.dev/service') for key, values in current.items()
                     if key.startswith('revisions_') for row in values]
        else:
            return False
        for row, owner_label in rows:
            metadata = row.get('metadata', {})
            actual = metadata.get('name', '').rsplit('/', 1)[-1]
            labels = metadata.get('labels', {})
            owner = labels.get(owner_label) if owner_label else None
            matches = (actual == name if owner_label is None else
                       owner == name if owner else actual.startswith(name+'-'))
            if matches:
                created = metadata.get('creationTimestamp')
                if not metadata.get('uid') or not created or timestamp(created) <= deleted_at:
                    return False
                # New identities still pass the complete current source/config
                # policy below; historical classification grants no runtime trust.
    return True


def validate_receivers(document, *, revision, plan_hash, database_project, current, now, provenance_only=False):
    from collect_recovery_evidence import CANARY, CANARY_IMAGE, CELLS, HOST_SOURCE
    from recovery_database_binding import BINDINGS, candidate_versions
    require(document.get('schema') in (2, 3) and document.get('policy') == 'incapable-receivers-v1'
            and document.get('target') == 'usw2' and document.get('database_project') == database_project
            and document.get('recovery_revision') == document.get('collector_revision') == revision
            and document.get('plan_hash') == plan_hash, 'Receiver evidence identity mismatch')
    start, end = timestamp(document['started_at']), timestamp(document['completed_at'])
    require(start <= end <= now and end-start <= MAX_AGE_SECONDS,
            'Receiver collection window is invalid')
    # Only schema 3 separates authenticated provenance from live authorization.
    # This mode validates historical facts and never grants a mutation lease.
    require((provenance_only and document['schema'] == 3) or now-MAX_AGE_SECONDS <= start,
            'Receiver evidence is stale or future dated')
    require(document.get('inventory_before') == document.get('inventory_after') == sha(current),
            'Receiver, routing or binding inventory changed')
    if 'deletion_history' in document:
        from collect_recovery_evidence import RETIRED_RECEIVERS
        history = document['deletion_history']
        earliest = min(r['metadata']['creationTimestamp'] for region in CELLS for r in current['revisions_'+region])
        require(history.get('earliest') == earliest and history.get('events') == current['deleted_receivers']
                and timestamp(history['cutoff']) <= start
                and history.get('catalog_sha256') == sha(RETIRED_RECEIVERS),
                'Authenticated receiver history checkpoint differs from the reviewed policy')
    if 'manual_guests' in document:
        manual = document['manual_guests']
        validate_manual_guests(manual, revision, plan_hash, current, now)
        require(document['hosts'] == manual['hosts']
                and manual['operator'] == document['coordinated_assumption']['actor'],
                'Manual host authority differs from the authenticated collection input')
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
    require(retired_receiver_history_safe(current),
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
        # An execution retains its task configuration when its job is updated.
        container = canary_configuration(execution.get('spec', {}).get('template', {}).get('spec', {}), destinations)
        require(container.get('image') == CANARY_IMAGE + '@' + CANARY['image']
                and not container.get('command')
                and container.get('args') in (['-mode', 'lifecycle'], ['-mode', 'janitor']),
                'An active job execution has unreviewed executable provenance')
    expected_jobs = {f'{prefix}-production-{region}' for prefix in ('api-canary', 'api-canary-janitor') for region in CELLS}
    require({j['metadata']['name'] for j in current['jobs']} == expected_jobs and len(current['jobs']) == 4,
            'Unknown alternate job consumer')
    for job in current['jobs']:
        spec = job['spec']['template']['spec']['template']['spec']
        container = canary_configuration(spec, destinations)
        mode = 'janitor' if 'janitor' in job['metadata']['name'] else 'lifecycle'
        require(not container.get('command') and container.get('args') == ['-mode', mode]
                and container.get('image') in {CANARY_IMAGE + ':' + CANARY['source'], CANARY_IMAGE + '@' + CANARY['image']},
                'Alternate consumer image/entrypoint is not audited')
    hosts = {str(h['id']): h for h in current['instances']}
    observed = document.get('hosts', [])
    require(len(observed) == len(hosts) and {h.get('instance_id') for h in observed} == set(hosts),
            'Guest observation must cover the complete host inventory')
    for guest in observed:
        host = hosts[guest['instance_id']]
        expected_route = 'operator-supplied' if 'manual_guests' in document else 'existing-ssh-identity-over-iap'
        require(guest.get('instance_name') == host['name'] and guest.get('zone') == host['zone']
                and guest.get('route') == expected_route, 'Guest identity or declared observation authority changed')
        observation = guest['observation']
        require(observation.get('boot_id') and observation.get('additional_managed_reporters') == [],
                'Guest process inventory is incomplete')
        entries = observation.get('services', [])
        require(len(entries) == 2 and {entry['binary'] for entry in entries} == {'vmd', 'secretsproxy'},
                'Managed guest reporter inventory is incomplete')
        for entry in entries:
            build = document['host_provenance'][entry['binary']]
            required_dropins, optional_dropins = build.get('dropins', {}), build.get('optional_dropins', {})
            actual_dropins = entry.get('dropins', {})
            dropins_match = (set(required_dropins) <= set(actual_dropins)
                and set(actual_dropins) <= set(required_dropins) | set(optional_dropins)
                and all(value == {**optional_dropins, **required_dropins}[name] for name, value in actual_dropins.items()))
            require(build.get('source') == HOST_SOURCE and entry['installed_sha256'] == build['binary']
                    and entry['process']['executable_sha256'] == build['binary'] and entry['unit_sha256'] == build['unit']
                    and dropins_match and entry.get('guards') == build.get('guards'),
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
        self._document_hash = None
        self._artifact_digest = None
        self._consumer_identity = None
        self._identity = (repository, revision, run_id, plan_hash, database_project)
        self._lease = None

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

    def consumer_identity(self):
        env = os.environ
        require(env.get('RECOVERY_COORDINATION_ACK') == 'accepted'
                and env.get('GITHUB_ACTIONS') == 'true'
                and env.get('GITHUB_REPOSITORY') == self.repository
                and env.get('GITHUB_SHA') == self.revision
                and env.get('GITHUB_REF') == 'refs/heads/main'
                and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and env.get('GITHUB_ACTOR')
                and re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ID', '')),
                'Fresh consumer coordination acknowledgment and workflow identity are required')
        identity = (env['GITHUB_RUN_ID'], env['GITHUB_ACTOR'])
        require(self._consumer_identity is None or self._consumer_identity == identity,
                'Consumer coordination identity changed during recovery')
        return identity

    def verify(self):
        try:
            self._verify()
        except Exception:
            self.valid_until = self._lease = None
            raise

    def _verify(self):
        # A failed refresh cannot leave a previously issued lease usable.
        previous_until = self.valid_until
        self.valid_until = None
        require(self._identity == (self.repository, self.revision, self.run_id, self.plan_hash, self.database_project),
                "Recovery evidence identity changed")
        if self._document is None:
            document, digest = self.load_artifact()
        else:
            document, digest = self._document, self.artifact_digest
            require(sha(document) == self._document_hash and digest == self._artifact_digest,
                    'Authenticated provenance changed during recovery')
        renewable = document.get('schema') == 3
        mode = 'manual' if 'manual_guests' in document else 'automated'
        require(os.environ.get('RECOVERY_GUEST_MODE', 'automated') == mode,
                'Consumer guest authority mode differs from the authenticated collection')
        if renewable:
            consumer = self.consumer_identity()
            started = time.time()
            mono = time.monotonic()
            require(mono < self.deadline, 'Recovery evidence deadline exceeded')
            if self._lease is not None:
                wall_start, mono_start, wall_end, mono_end, last_wall = self._lease
                require(started >= last_wall and mono >= mono_start,
                        'Observation clock moved backwards')
                require(previous_until is None or previous_until == wall_end,
                        'Observation authorization changed')
                require(self.state_digest == sha(receiver_state(document)), 'Observed writer state changed during recovery')
                if min(wall_end-started, mono_end-mono, self.deadline-mono) >= 6:
                    self._lease = (wall_start, mono_start, wall_end, mono_end, started)
                    self.valid_until = wall_end
                    return
            self._lease = None
            observation_deadline = min(self.deadline, mono + MAX_AGE_SECONDS)
            require(time.monotonic() < observation_deadline, 'Recovery evidence deadline exceeded')
        else:
            require(time.time() < timestamp(document["started_at"]) + MAX_AGE_SECONDS,
                    "Deployment evidence is stale")
            observation_deadline = self.deadline
        if document.get('schema') in (2, 3):
            from collect_recovery_evidence import Reader, receiver_inventory, guest_observation, active_mutations
            reader = Reader(observation_deadline)
            if renewable:
                active_mutations(reader, consumer[0])
            history = document.get('deletion_history')
            current = receiver_inventory(reader, history) if history else receiver_inventory(reader)
            if not renewable:
                active_mutations(reader, os.environ.get('GITHUB_RUN_ID', ''))
            if 'manual_guests' in document:
                validate_manual_guests(document['manual_guests'], self.revision, self.plan_hash, current, time.time())
                guests = document['manual_guests']['hosts']
            else:
                with ThreadPoolExecutor(max_workers=4) as executor:
                    guests = list(executor.map(lambda host: guest_observation(reader, host), current['instances']))
            require(sorted(map(stable_guest, guests), key=lambda h: h['instance_id']) ==
                    sorted(map(stable_guest, document['hosts']), key=lambda h: h['instance_id']),
                    'Guest process, executable or effective destination changed')
            require(document['coordinated_assumption']['run_id'] == self.run_id,
                    'Coordination acknowledgment belongs to another collection run')
            if renewable:
                after = receiver_inventory(reader, history) if history else receiver_inventory(reader)
                require(current == after, 'Receiver inventory changed during live observation')
                active_mutations(reader, consumer[0])
                require(self.consumer_identity() == consumer, 'Consumer coordination changed during observation')
            fresh = dict(document, hosts=guests)
            validate_receivers(fresh, revision=self.revision, plan_hash=self.plan_hash,
                               database_project=self.database_project, current=current, now=time.time(),
                               provenance_only=renewable)
        else:
            current = inventory(self.deadline)
        if not renewable:
            validate(document, revision=self.revision, plan_hash=self.plan_hash, database_project=self.database_project,
                     current=current, now=time.time())
        state_digest = sha(receiver_state(document)) if document.get('schema') in (2, 3) else sha({key: document[key] for key in (
            "inventory_after", "revisions", "hosts", "alternate_producers", "deployment_and_toggle_hold")})
        require(self.state_digest is None or self.state_digest == state_digest,
                "Observed writer state changed during recovery")
        if renewable:
            require(started <= time.time() < started + MAX_AGE_SECONDS
                    and time.monotonic() < observation_deadline,
                    'Live receiver observation expired; no authorization issued')
            self._consumer_identity = consumer
            self.valid_until = started + MAX_AGE_SECONDS
            if 'manual_guests' in document:
                self.valid_until = min(self.valid_until,
                    timestamp(document['manual_guests']['started_at']) + MANUAL_MAX_AGE_SECONDS)
            require(self.valid_until-time.time() >= 6, 'Manual snapshot or observation expires before mutation')
            self._lease = (started, mono, self.valid_until,
                           mono + self.valid_until-started, time.time())
        else:
            self.valid_until = timestamp(document["started_at"]) + MAX_AGE_SECONDS
        self.state_digest = state_digest
        self.artifact_digest = self._artifact_digest = digest
        self._document_hash = sha(document)
        self._document = document
