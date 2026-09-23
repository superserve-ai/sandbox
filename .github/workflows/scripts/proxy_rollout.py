#!/usr/bin/env python3
"""Host-local generation controller. Static LB configuration is supplied by Terraform.

Only this controller owns NEG endpoint membership and private port forwarding.
It runs in the SSH session under flock; no detached deployment processes exist.
"""
import argparse
import email.parser
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid

ROOT = Path('/var/lib/proxy-rollout')

# Credential renewal can be rebuilt safely until the old generation's
# shutdown starts.  Once stopping is persisted, let that rollout finish with
# its immutable snapshot and renew the now-active generation afterward.
CREDENTIAL_RECOVERABLE_PHASES = frozenset({
    'preparing', 'starting', 'local_ready', 'registering',
    'candidate_verified', 'withdrawing', 'withdrawn', 'switching_private',
    'cutover_verified', 'rollback', 'rollback_restoring',
    'rollback_withdrawing', 'rollback_stopping', 'migration_rollback_waiting',
    'migration_rollback_verifying', 'migration_rollback_withdrawing',
})
TERMINAL_PHASES = frozenset({'complete', 'rolled_back', 'standby_ready'})


class OwnershipLost(RuntimeError):
    pass


class CellLock:
    """Durable, non-expiring ownership; recovery requires the owner's host flock.

    Never steal by age: Compute and systemd do not accept fencing tokens, so a
    suspended writer must remain excluded until its local flock is released.
    A lost host requires operator recovery after fencing that host, not a TTL.
    """
    def __init__(self, config, rollout, identity, state_path, instance_id):
        self.bucket = urllib.parse.quote(config['ownership_bucket'], safe='')
        self.owner = dict(host=config['instance'], zone=config['zone'],
                          instance_id=instance_id, rollout=rollout, identity=identity)
        self.state_path = state_path
        self.generation = None
        self.terminal_saved = False

    def request(self, method, path, data=None):
        token = json.loads(urllib.request.urlopen(urllib.request.Request(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            headers={'Metadata-Flavor': 'Google'}), timeout=5).read())['access_token']
        request = urllib.request.Request('https://storage.googleapis.com/' + path,
                                         method=method,
                                         data=None if data is None else json.dumps(data).encode(),
                                         headers={'Authorization': 'Bearer ' + token,
                                                  'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None

    @property
    def path(self):
        return f'storage/v1/b/{self.bucket}/o/owner'

    def acquire(self):
        try:
            metadata = self.request('GET', self.path)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            generation = '0'
        else:
            generation = metadata['generation']
            previous = self.request('GET', self.path + '?alt=media&ifGenerationMatch=' + generation)
            if previous['owner'] != self.owner:
                raise RuntimeError('cell has unfinished ownership; resume rollout ' +
                                   previous['owner']['rollout'] + ' on ' + previous['owner']['host'])
        # Called only under the host flock. A matching durable owner is recovery
        # from a dead controller, not permission for concurrent CI sessions.
        self.record = dict(owner=self.owner, execution=uuid.uuid4().hex)
        result = self.request('POST', f'upload/storage/v1/b/{self.bucket}/o'
                              '?uploadType=media&name=owner&ifGenerationMatch=' + generation,
                              self.record)
        self.generation = result['generation']

    def assert_owned(self):
        try:
            metadata = self.request('GET', self.path)
        except Exception as error:
            raise OwnershipLost('cannot verify cell ownership') from error
        if metadata['generation'] != self.generation:
            raise OwnershipLost('cell ownership changed; refusing further mutations')

    def update_owner(self, rollout, identity):
        """Update the local release fence after recovering a renewed request."""
        self.owner.update(rollout=rollout, identity=identity)

    def update_identity(self, identity):
        """Preserve the legacy helper for identity-only recovery callers."""
        self.owner['identity'] = identity

    def release(self):
        self.assert_owned()
        self.request('DELETE', self.path + '?ifGenerationMatch=' + self.generation)
        self.generation = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *error):
        # Nonterminal failures retain ownership even when the CI session exits.
        # Terminal state is fsynced before deletion, making lost replies safe.
        if (self.generation is not None and self.state_path.exists()
                and (error[0] is None or self.terminal_saved)):
            state = json.loads(self.state_path.read_text())
            if (state.get('rollout') == self.owner['rollout']
                    and state.get('request_hash') == self.owner['identity']
                    and state['phase'] in TERMINAL_PHASES):
                self.release()


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=120, **kwargs).stdout


def atomic(path, value):
    # Callers commonly pass a path assembled from ``Path`` objects.  Keeping
    # an existing path-like value avoids resolving it through a patched or
    # alternate Path constructor a second time (which can otherwise duplicate
    # an emulated filesystem root in tests).
    if not isinstance(path, os.PathLike):
        path = Path(path)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as out:
        os.chmod(temporary, 0o600)
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ready(body, generation):
    return (isinstance(body, dict) and body.get('resolver_ready') is True
            and body.get('generation', '') == generation)


def manifest_identity(config):
    # Terraform's migration acknowledgement and applied frontend references
    # change while the cell owner is held between bootstrap and resume.
    static = {key: value for key, value in config.items()
              if key not in ('migration_complete', 'frontend_backend_references')}
    # Terraform emits null for an omitted optional address. Keep existing
    # manifests retry-compatible when no frontend pin was configured.
    static['routes'] = [{key: value for key, value in route.items()
                         if key != 'probe_ip' or value is not None}
                        for route in config['routes']]
    return hashlib.sha256(json.dumps(static, sort_keys=True).encode()).hexdigest()


def verify_frontend_references(config):
    """Require Terraform's applied frontend references to cover every route.

    ``migration_complete`` is an operator acknowledgement, not evidence that
    the owning frontend resources were actually switched.  The Terraform
    output carries the applied backend references and bounded frontend
    resource identities grouped by route; keeping this check bounded to the
    manifest's declared routes avoids probing an unbounded LB inventory from
    the rollout hot path.
    """
    routes = config.get('routes')
    references = config.get('frontend_backend_references')
    if not isinstance(routes, list) or not isinstance(references, dict):
        raise RuntimeError('Terraform migration output must include frontend_backend_references')
    if not 1 <= len(routes) <= 8 or len(references) > 8:
        raise RuntimeError('Terraform migration output exceeds the route bound')

    expected = {}
    for route in routes:
        if not isinstance(route, dict):
            raise RuntimeError('Terraform migration output contains an invalid route')
        name = route.get('name') or route.get('backend')
        backend = route.get('backend_self_link') or route.get('backend')
        if not isinstance(name, str) or not name or not isinstance(backend, str) or not backend:
            raise RuntimeError('Terraform migration output route is missing its backend identity')
        if name in expected:
            raise RuntimeError(f'duplicate frontend route {name}')
        expected[name] = backend

    frontend_resources = config.get('frontend_resources')
    if frontend_resources is not None:
        if (not isinstance(frontend_resources, dict)
                or set(frontend_resources) != set(expected)):
            raise RuntimeError('frontend resource inventory must cover every declared route')
        for name, resources in frontend_resources.items():
            if (not isinstance(resources, list) or not 1 <= len(resources) <= 16
                    or any(not isinstance(resource, str) or not resource for resource in resources)):
                raise RuntimeError(f'frontend route {name} is missing its adopted resource inventory')

    if set(references) != set(expected):
        missing = sorted(set(expected) - set(references))
        extra = sorted(set(references) - set(expected))
        raise RuntimeError(f'frontend references do not cover declared routes (missing={missing}, extra={extra})')

    for name, backend in expected.items():
        applied = references[name]
        if isinstance(applied, str):
            applied = [applied]
        if (not isinstance(applied, list) or len(applied) > 16 or not applied
                or any(reference != backend for reference in applied)):
            raise RuntimeError(f'frontend route {name} does not reference replacement backend {backend}')


def validate_probes(config, env):
    domains = {d.strip().lower() for d in
               (env.get('PROXY_DOMAINS') or env.get('PROXY_DOMAIN', '')).split(',') if d.strip()}
    for route in config['routes']:
        url = urllib.parse.urlsplit(route['probe'])
        probe_address(route)
        scheme = 'http' if route['listener'] == 'redirect' else 'https'
        if (url.scheme != scheme or url.hostname not in domains or url.path != '/health'
                or url.query or url.fragment or url.username or url.password
                or url.port not in (None, 80 if scheme == 'http' else 443)):
            raise ValueError('readiness probes must use /health on a bare configured domain and its public listener')


def probe_address(route):
    address = route.get('probe_ip')
    if address is None:
        return None
    # Pin only the destination; curl still verifies the normal hostname's TLS
    # certificate and sends that hostname through the existing URL map.
    if not isinstance(address, str):
        raise ValueError('frontend probe_ip must be an IPv4 address string')
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4:
        raise ValueError('frontend probe_ip must be an IPv4 forwarding address')
    return str(parsed)


def probe_args(route):
    address = probe_address(route)
    if address is None:
        return []
    url = urllib.parse.urlsplit(route['probe'])
    port = 80 if url.scheme == 'http' else 443
    return ['--noproxy', '*', '--resolve', f'{url.hostname}:{port}:{address}']


def request_identity(request, binary, unit=None):
    digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode())
    with Path(binary).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    if unit is not None:
        digest.update(Path(unit).read_bytes())
    return digest.hexdigest()


def check_retry(state, rollout, identity):
    if rollout in state.get('retired_rollouts', []):
        raise RuntimeError('stale rollout identity; use a new identity to redeploy a previous revision')
    if state.get('rollout') == rollout and state.get('request_hash') != identity:
        raise RuntimeError('retry changed immutable rollout inputs; resume with the original request and binary')


def ensure_bootstrap_ready(state, rollout, bootstrap):
    """Reject a fresh generation deploy while the cell still serves legacy listeners."""
    active = state.get('active') or {}
    same_inflight_rollout = (state.get('rollout') == rollout
                             and state.get('phase') not in TERMINAL_PHASES)
    if (not bootstrap and not state.get('bootstrap') and not active.get('id')
            and state.get('phase') != 'rolled_back' and not same_inflight_rollout):
        raise RuntimeError('legacy cell requires completed bootstrap before generation deployment')


def retired_rollouts(state):
    # Keep identity tombstones independently of artifact retention. Otherwise a
    # delayed CI retry can become a new deployment after its artifacts expire.
    retired = list(state.get('retired_rollouts', []))
    if state.get('rollout'):
        retired.append(state['rollout'])
    return retired


def prune_generations(root, keep, host, unit_root=Path('/etc/systemd/system')):
    directory = root / 'generations'
    if not directory.exists():
        return
    for generation in directory.iterdir():
        host.assert_owned()
        # Preparation is never a runnable systemd path. A killed upload can
        # leave this directory before the atomic rename; rebuild it on retry.
        if re.fullmatch('[a-f0-9]{20}\\.preparing', generation.name):
            shutil.rmtree(generation)
            continue
        if generation.name in keep:
            continue
        if not re.fullmatch('[a-f0-9]{20}', generation.name):
            raise RuntimeError('unexpected generation artifact; refusing cleanup')
        unit = f'proxy-{generation.name}.service'
        active = command('systemctl', 'show', unit, '-p', 'ActiveState', '--value').strip()
        if active not in ('inactive', 'failed'):
            raise RuntimeError('unexpected active retained generation; refusing cleanup')
        metadata = json.loads((generation / 'generation.json').read_text())
        if metadata['id'] != generation.name or metadata['unit'] != unit:
            raise RuntimeError('generation artifact identity mismatch; refusing cleanup')
        if any(host.cloud.member(route, metadata['ports'][route['listener']])
               for route in host.config['routes']):
            raise RuntimeError('retained generation is still registered; refusing cleanup')
        command('systemctl', 'disable', unit)
        shutil.rmtree(generation)
        (unit_root / unit).unlink(missing_ok=True)
    command('systemctl', 'daemon-reload')


def wait_for(check, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        if check():
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('readiness deadline exceeded')
        time.sleep(2)


class Cloud:
    def __init__(self, project, zone, instance, ip):
        self.base = f'https://compute.googleapis.com/compute/v1/projects/{project}'
        self.zone, self.instance, self.ip = zone, instance, ip

    def request(self, path, data=None):
        token = json.loads(urllib.request.urlopen(urllib.request.Request(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            headers={'Metadata-Flavor': 'Google'}), timeout=5).read())['access_token']
        url = path if path.startswith('https://compute.googleapis.com/') else self.base + '/' + path
        req = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(),
                                     headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    def operation(self, path, data):
        if getattr(self, 'ownership', None):
            self.ownership.assert_owned()
        result = self.request(path, data)
        deadline = time.monotonic() + 180
        while result.get('status') != 'DONE':
            if time.monotonic() > deadline:
                raise RuntimeError('cloud operation deadline exceeded')
            time.sleep(2)
            # selfLink uses www.googleapis.com rather than compute.googleapis.com.
            result = self.request(result['selfLink'].split('/compute/v1/projects/', 1)[1].split('/', 1)[1])
        if result.get('error'):
            raise RuntimeError(json.dumps(result['error']))

    def endpoints(self, route):
        path = f'zones/{self.zone}/networkEndpointGroups/{route["neg"]}/listNetworkEndpoints'
        result = self.request(path, {})
        if result.get('nextPageToken'):
            raise RuntimeError('unexpected fleet-sized NEG; refusing partial membership reconciliation')
        return result.get('items', [])

    def member(self, route, port):
        return any(item['networkEndpoint'].get('ipAddress') == self.ip
                   and item['networkEndpoint'].get('port') == port for item in self.endpoints(route))

    def membership(self, route, port, present):
        if self.member(route, port) == present:
            return
        action = 'attachNetworkEndpoints' if present else 'detachNetworkEndpoints'
        self.operation(f'zones/{self.zone}/networkEndpointGroups/{route["neg"]}/{action}',
                       {'networkEndpoints': [{'instance': self.instance, 'ipAddress': self.ip, 'port': port}]})

    def healthy(self, route, port):
        group = f'{self.base.replace("compute.googleapis.com", "www.googleapis.com")}/zones/{self.zone}/networkEndpointGroups/{route["neg"]}'
        body = self.request(f'global/backendServices/{route["backend"]}/getHealth', {'group': group})
        return any(item.get('ipAddress') == self.ip and item.get('port') == port
                   and item.get('healthState') == 'HEALTHY' for item in body.get('healthStatus', []))


class Host:
    def __init__(self, config, root=ROOT):
        self.config, self.root = config, root
        self.cloud = Cloud(config['project'], config['zone'], config['instance'], config['ip'])
        self.ownership = None

    def assert_owned(self):
        if self.ownership is not None:
            self.ownership.assert_owned()

    def ports(self, generation):
        return generation['ports']

    def membership(self, generation, present):
        for route in self.config['routes']:
            self.cloud.membership(route, generation['ports'][route['listener']], present)

    def health(self, generation):
        return all(self.cloud.member(r, generation['ports'][r['listener']])
                   and self.cloud.healthy(r, generation['ports'][r['listener']]) for r in self.config['routes'])

    def local(self, generation):
        try:
            body = json.loads(command('curl', '--fail', '--silent', '--show-error', '--max-time', '5',
                                      '-H', 'Host: proxy-readiness.invalid',
                                      f'http://127.0.0.2:{generation["ports"]["public"]}/health'))
            return ready(body, generation['id'])
        except (subprocess.SubprocessError, ValueError):
            return False

    def external(self, generation):
        for route in self.config['routes']:
            # Bare configured domains reach infrastructure /health while retaining
            # the real Host for regional URL-map selection and TLS validation.
            try:
                if route['listener'] == 'redirect':
                    response = command('curl', '--fail', '--silent', '--show-error', '--http1.1',
                                       '--max-time', '5', '-H', 'Connection: close',
                                       '--dump-header', '-', '--output', '/dev/null',
                                       *probe_args(route), route['probe'])
                    blocks = response.replace('\r\n', '\n').strip().split('\n\n')
                    status, _, headers = blocks[-1].partition('\n')
                    headers = email.parser.Parser().parsestr(headers)
                    if (status.split()[1:2] != ['301']
                            or headers.get('Location') != 'https://' + route['probe'].split('://', 1)[1]):
                        return False
                    if generation['id'] and (headers.get('X-Proxy-Generation') != generation['id']
                                             or headers.get('X-Proxy-Resolver-Ready') != 'true'):
                        return False
                    continue
                body = json.loads(command('curl', '--fail', '--silent', '--show-error', '--http1.1',
                                          '--max-time', '5', '-H', 'Connection: close',
                                          *probe_args(route), route['probe']))
                if not ready(body, generation['id']):
                    return False
            except (subprocess.SubprocessError, ValueError):
                return False
        return True

    def registered_ready(self, generation):
        wait_for(lambda: self.local(generation))
        wait_for(lambda: self.health(generation))

    def verify(self, generation):
        self.registered_ready(generation)
        wait_for(lambda: self.external(generation))

    def propagated(self, generation, old):
        deadline = time.monotonic() + 240
        since = None
        while time.monotonic() < deadline:
            absent = all(not self.cloud.member(r, old['ports'][r['listener']]) for r in self.config['routes'])
            if not self.local(generation) or not self.health(generation):
                raise RuntimeError('candidate lost readiness before shutdown')
            if absent and self.external(generation):
                since = since or time.monotonic()
                if time.monotonic() - since >= 60:
                    return
            else:
                since = None
            time.sleep(2)
        raise RuntimeError('candidate did not remain externally ready during propagation')

    def legacy_propagated(self, generation):
        deadline = time.monotonic() + 240
        since = None
        while time.monotonic() < deadline:
            if self.local(generation) and self.external(generation):
                since = since or time.monotonic()
                if time.monotonic() - since >= 60:
                    return
            else:
                since = None
            time.sleep(2)
        raise RuntimeError('legacy frontends did not remain ready during rollback propagation')

    def switch_private(self, generation):
        self.assert_owned()
        # Conntrack retains established TCP/gRPC transports on the old target.
        # Only NEW connections change ownership. VMD remains the sole publisher
        # of the fixed private endpoint; its loopback health URL stays stable.
        ports = generation['ports']
        rules = ['*nat', ':PROXY_GENERATION - [0:0]', '-F PROXY_GENERATION']
        if ports['peer'] != 5009:
            rules.append(f'-A PROXY_GENERATION -d {self.config["ip"]}/32 -p tcp --dport 5009 -j DNAT --to-destination {self.config["ip"]}:{ports["peer"]}')
        if ports['public'] != 5007:
            rules.append(f'-A PROXY_GENERATION -d 127.0.0.1/32 -p tcp --dport 5007 -j DNAT --to-destination 127.0.0.1:{ports["public"]}')
        rules.append('COMMIT')
        command('iptables-restore', '--wait', '10', '--noflush', input='\n'.join(rules)+'\n')
        for chain in ('PREROUTING', 'OUTPUT'):
            check = subprocess.run(['iptables', '-w', '10', '-t', 'nat', '-C', chain, '-j', 'PROXY_GENERATION'], capture_output=True)
            if check.returncode:
                command('iptables', '-w', '10', '-t', 'nat', '-A', chain, '-j', 'PROXY_GENERATION')
        atomic(self.root / 'private.json', generation)
        Path('/run/proxy-private-routing-ready').touch(mode=0o644)

    def stop(self, generation):
        self.assert_owned()
        started = str(int(time.time()))
        units = [generation['unit']]
        if not generation['id']:
            # The pre-generation binary does not track hijacked connections.
            # Keep it entirely alive during the initial migration grace, then
            # force termination without letting Restart=always resurrect it.
            dropin = Path('/etc/systemd/system/proxy.service.d/generation-retirement.conf')
            dropin.parent.mkdir(parents=True,exist_ok=True)
            # Stop the socket and service in the same systemd transaction at
            # the cap. Leaving the socket active can reactivate a retired unit.
            dropin.write_text('[Service]\nRestart=no\nKillSignal=SIGKILL\n')
            command('systemctl','daemon-reload')
            if command('systemctl', 'show', 'proxy.socket', '-p', 'LoadState', '--value').strip() == 'loaded':
                units.append('proxy.socket')
            remaining = generation.get('drain_started',time.time()) + generation.get('drain_seconds',30) - time.time()
            if remaining > 0:
                time.sleep(remaining)
        self.assert_owned()
        subprocess.run(['systemctl', 'disable', '--now', *units], check=True, capture_output=True, timeout=620)
        status = command('systemctl', 'show', generation['unit'], '-p', 'Result', '-p', 'ExecMainStatus')
        journal = command('journalctl','-u',generation['unit'],'--since','@'+started,'--no-pager','-n','80','-o','cat')
        return {'systemd':status.strip(),'drain':journal,'legacy_forced':not bool(generation['id'])}

    def start(self, generation):
        self.assert_owned()
        command('systemctl', 'enable', '--now', generation['unit'])


class Rollout:
    def __init__(self, host, state, save):
        self.host, self.state, self.save = host, state, save

    def phase(self, name, **extra):
        self.state.update(phase=name, **extra)
        timestamps = self.state.setdefault('timestamps', {})
        if name != 'stopping' or name not in timestamps:
            timestamps[name] = time.time()
        self.save(self.state)
        print(json.dumps({k: self.state.get(k) for k in ('rollout', 'revision', 'candidate', 'old', 'endpoint_context', 'phase', 'timestamps', 'failure', 'stop_result')}), flush=True)

    def run(self):
        if self.state.get('target', 'serving') == 'standby':
            return StandbyRollout(self.host, self.state, self.save).run()
        candidate, old = self.state['candidate'], self.state['old']
        irreversible = self.state['phase'] in ('stopping', 'complete')
        if self.state['phase'] == 'complete':
            self.host.verify(candidate)
            return
        if self.state['phase'].startswith('rollback'):
            self.rollback()
            raise RuntimeError('previous rollout failed; rollback completed; use a new rollout identity')
        if self.state['phase'] == 'rolled_back':
            self.host.verify(old)
            # The terminal retry must be durable before raising so CellLock
            # can release ownership; an interrupted verification still keeps
            # the existing recovery fence.
            self.save(self.state)
            raise RuntimeError('rollout was rolled back; use a new rollout identity')
        try:
            if not irreversible:
                self.phase('starting')
            self.host.start(candidate)
            wait_for(lambda: self.host.local(candidate))
            self.phase('local_ready' if not irreversible else 'stopping')
            if not irreversible:
                self.phase('registering')
            self.host.membership(candidate, True)
            self.host.registered_ready(candidate)
            if not irreversible:
                self.phase('candidate_verified')
                self.phase('withdrawing')
            self.host.membership(old, False)
            if not irreversible:
                self.phase('withdrawn')
            if not irreversible:
                self.phase('switching_private')
            self.host.switch_private(candidate)
            self.host.propagated(candidate, old)
            if not irreversible:
                self.phase('cutover_verified')
            # Persist BEFORE sending SIGTERM. A lost response cannot grant a
            # retry permission to "roll back" to listeners already shut down.
            old.setdefault('drain_started',time.time())
            self.phase('stopping')
            irreversible = True
            result = self.host.stop(old)
            self.host.verify(candidate)
            self.phase('complete', active=candidate, stop_result=result)
        except OwnershipLost:
            raise
        except Exception as error:
            self.phase('stopping' if irreversible else 'rollback', failure=str(error))
            if not irreversible:
                self.rollback()
            raise

    def rollback(self):
        candidate, old = self.state['candidate'], self.state['old']
        # Retrying a failed rollback must not restart forward cutover. Restore
        # old membership before probing the route or retiring the candidate.
        self.phase('rollback_restoring')
        self.host.membership(old, True)
        # Remove the candidate before probing the restored route so the public
        # verification cannot still be served by the failed generation.
        self.host.membership(candidate, False)
        self.host.verify(old)
        self.host.switch_private(old)
        self.phase('rollback_withdrawing')
        self.host.propagated(old, candidate)
        self.phase('rollback_stopping')
        self.host.stop(candidate)
        self.phase('rolled_back', active=old)


class StandbyRollout(Rollout):
    """Prepare a generation without making it reachable through serving paths.

    A standby may reuse the serving cell manifest for static route and host
    configuration, but it is not a member of that cell's NEGs. Persist the
    immutable generation without starting it; serving membership and private
    routing remain an explicit promotion operation.
    """
    def run(self):
        if self.state['phase'] == 'standby_ready':
            return
        try:
            if self.state['phase'] != 'standby_starting':
                self.phase('standby_starting')
            self.phase('standby_ready', active=self.state['candidate'])
        except OwnershipLost:
            raise
        except Exception as error:
            self.phase('standby_failed', failure=str(error))
            raise


class Bootstrap(Rollout):
    def legacy(self):
        """Return the process already serving before the frontend migration.

        Bootstrap is an infrastructure adoption step, not a generation
        rollout. Refuse a state that contains a distinct candidate so a
        retry cannot accidentally start, drain, or retire a proxy process.
        """
        legacy = self.state['old']
        if self.state['candidate'] != legacy:
            raise RuntimeError('bootstrap cannot create a replacement generation')
        return legacy

    def run(self, migrated):
        legacy = self.legacy()
        if self.state['phase'] == 'complete':
            if not migrated:
                raise RuntimeError('completed migration cannot return to retired legacy listeners')
            self.host.verify(legacy)
            return
        if self.state['phase'] == 'rolled_back':
            raise RuntimeError('bootstrap was rolled back; use a new rollout identity')
        if (not migrated and self.state.get('migration_started')
                and self.state['phase'] != 'stopping'):
            self.phase('migration_rollback_waiting')
        if self.state['phase'].startswith('migration_rollback'):
            self.restore_legacy(migrated)
            raise RuntimeError('bootstrap rolled back; use a new rollout identity')
        irreversible = self.state['phase'] == 'stopping'
        if irreversible and not migrated:
            raise RuntimeError('frontends reverted after legacy shutdown began')
        try:
            if not irreversible:
                self.phase('bootstrap_starting', migration_started=migrated)
            # Initial migration adopts the proxy that is already serving on the
            # legacy listeners.  Starting a generation-specific unit here would
            # combine frontend migration with a proxy upgrade and make rollback
            # depend on shutting down the only serving process.
            if not irreversible:
                self.phase('bootstrap_registering')
            wait_for(lambda: self.host.local(legacy))
            self.host.membership(legacy, True)
            if not migrated:
                self.phase('bootstrap_ready')
                return
            if not irreversible:
                self.phase('migration_verifying')
            # Terraform switched the normal frontends.  Only now require the
            # new backend's LB health and public readiness; the adopted process
            # remains running throughout the migration and rollback window.
            self.host.verify(legacy)
            self.phase('complete', active=legacy)
        except OwnershipLost:
            raise
        except Exception as error:
            self.phase('stopping' if irreversible else 'migration_rollback_waiting', failure=str(error))
            if not irreversible:
                self.restore_legacy(migrated)
            raise

    def restore_legacy(self, migrated):
        # Only Terraform may restore the instance-group frontends. Keep the
        # adopted proxy running until that apply is acknowledged.
        if migrated:
            raise RuntimeError('restore legacy frontends with Terraform, then resume this rollout to finish rollback')
        old, candidate = self.state['old'], self.state['candidate']
        self.phase('migration_rollback_verifying')
        wait_for(lambda: self.host.local(old))
        self.host.legacy_propagated(old)
        self.phase('migration_rollback_withdrawing')
        self.host.membership(candidate, False)
        self.phase('rolled_back', active=old)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request')
    parser.add_argument('--manifest')
    parser.add_argument('--restore-private', action='store_true')
    parser.add_argument('--bootstrap', action='store_true')
    parser.add_argument('--refresh-credentials', action='store_true')
    args = parser.parse_args()
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    with (ROOT / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest_path = Path('/etc/sandbox/proxy-rollout.json')
        config = json.loads(Path(args.manifest or manifest_path).read_text())
        if not 1 <= len(config['routes']) <= 8 or not any(r['listener'] == 'public' for r in config['routes']):
            raise ValueError('one to eight explicit frontend routes, including public, are required')
        for field,path in [('instance','instance/name'),('zone','instance/zone'),('ip','instance/network-interfaces/0/ip'),('project','project/project-id')]:
            req = urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/'+path,headers={'Metadata-Flavor':'Google'})
            actual = urllib.request.urlopen(req,timeout=5).read().decode().split('/')[-1]
            if config[field] != actual:
                raise RuntimeError('rollout manifest does not describe this host: '+field)
        host = Host(config)
        if args.restore_private:
            host.switch_private(json.loads((ROOT / 'private.json').read_text()))
            return
        # A replacement VM with the same name cannot inherit a dead host's
        # ownership or reconstruct its durable rollout state from legacy defaults.
        instance_id = urllib.request.urlopen(urllib.request.Request(
            'http://metadata.google.internal/computeMetadata/v1/instance/id',
            headers={'Metadata-Flavor': 'Google'}), timeout=5).read().decode()
        legacy = {'id': '', 'unit': 'proxy.service', 'ports': {'public':5007,'redirect':5008,'peer':5009,'local':5010}}
        state_path = ROOT / 'state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {'active':legacy, 'phase':'complete'}
        config_hash = manifest_identity(config)
        if state.get('config_hash',config_hash) != config_hash:
            raise RuntimeError('static rollout manifest changed; reconcile infrastructure before deployment')
        if args.bootstrap and not state.get('bootstrap') and (state['phase'] != 'complete' or state['active']['id']):
            raise RuntimeError('bootstrap is only allowed before the first generation rollout')
        if args.refresh_credentials:
            with tempfile.TemporaryDirectory(prefix='proxy-credentials-') as upload:
                request_path = credential_request(state, ROOT, Path(upload))
                if request_path is None:
                    if legacy_generation(state):
                        reload_legacy_proxy()
                    return
                # Keep the host lock while reusing the normal rollout entry point.
                # The generated request is consumed below, never by a child runner.
                args.request = str(request_path)
                return deploy_locked(args, config, config_hash, host, state, state_path, instance_id)
        return deploy_locked(args, config, config_hash, host, state, state_path, instance_id)


def legacy_generation(state):
    """Return whether the durable rollout still points at the legacy unit."""
    phase = state.get('phase')
    if phase == 'stopping' and not state.get('bootstrap'):
        return False
    generation = (state.get('active') if phase in TERMINAL_PHASES
                  else state.get('old'))
    if not isinstance(generation, dict):
        return False
    return not generation.get('id')


def reload_legacy_proxy(peer=None):
    """Load rotated credentials into the legacy proxy exactly once per snapshot."""
    if peer is None:
        peer = Path('/etc/superserve/peer')
    env = Path('/etc/sandbox/proxy.env')
    identity_file = peer / 'identity.json'
    current = peer / 'current'
    if not env.exists() or not identity_file.exists() or not current.exists():
        return False
    identity = json.loads(identity_file.read_text())['spiffe_uri']
    generation = current.resolve(strict=True).name
    loaded = peer / 'loaded-generation'
    if (f"PEER_PROXY_SPIFFE_URI={identity}" not in env.read_text().splitlines()
            or (loaded.exists() and loaded.read_text() == generation)):
        return False
    command('systemctl', 'try-restart', 'proxy.service')
    loaded.write_text(generation)
    return True


def credential_request(state, root, upload, peer=Path('/etc/superserve/peer')):
    if state['phase'] not in TERMINAL_PHASES:
        generation = state.get('old')
        if not isinstance(generation, dict):
            raise RuntimeError('credential renewal waits for the unfinished deployment')
        # Bootstrap and the first deployment deliberately retain the legacy
        # unit, which has no immutable generation request to renew. Let the
        # caller reload that unit instead of treating its empty ID as an
        # unfinished generation rollout.
        if not generation['id']:
            return None
        if not state.get('rollout', '').startswith('credentials-'):
            raise RuntimeError('credential renewal waits for the unfinished deployment')
        if not (peer / 'current').exists():
            return None
    else:
        generation = state['active']
    if not generation['id'] or not (peer / 'current').exists():
        return None
    directory = root / 'generations' / generation['id']
    request = json.loads((directory / 'request.json').read_text())
    current = (peer / 'current').resolve(strict=True).name
    if state['phase'] in TERMINAL_PHASES:
        if (directory / 'credential-generation').read_text() == current:
            return None
        request['rollout'] = 'credentials-' + hashlib.sha256(
            (generation['id'] + ':' + current + ':' + state.get('rollout', '')).encode()).hexdigest()[:32]
        request['credential_generation'] = current
        atomic(root / 'credential-request.json', request)
    else:
        request = json.loads((root / 'credential-request.json').read_text())
        if request['rollout'] != state['rollout']:
            raise RuntimeError('credential recovery request does not match durable rollout identity')
        baseline = json.loads((directory / 'request.json').read_text())
        immutable = (set(request) | set(baseline)) - {'rollout', 'credential_generation'}
        if any(request.get(key) != baseline.get(key) for key in immutable):
            raise RuntimeError('credential recovery request changed immutable deployment inputs')
        # A candidate snapshot is immutable. If the provider rotated while a
        # recoverable renewal was interrupted, retain the rollout's code and
        # environment but issue a new credential rollout identity so the
        # stale candidate can be reconciled and rebuilt from the new snapshot.
        candidate_id = state.get('candidate', {}).get('id', '')
        candidate = root / 'generations' / candidate_id if candidate_id else None
        if (request.get('credential_generation') != current
                and state['phase'] in CREDENTIAL_RECOVERABLE_PHASES
                and candidate is not None and candidate.exists()):
            previous_rollout = request['rollout']
            request['rollout'] = 'credentials-' + hashlib.sha256(
                (generation['id'] + ':' + current + ':' + previous_rollout).encode()).hexdigest()[:32]
            request['credential_generation'] = current
            atomic(root / 'credential-request.json', request)
            state['_credential_recovery'] = {
                'previous_rollout': previous_rollout,
                'credential_generation': current,
            }
        elif (request.get('credential_generation') != current
              and (candidate is None or not candidate.exists())):
            request['credential_generation'] = current
            atomic(root / 'credential-request.json', request)
    shutil.copyfile(directory / 'proxy', upload / 'proxy')
    shutil.copyfile(directory / 'unit.template', upload / 'proxy.service')
    atomic(upload / 'request.json', request)
    if state['phase'] not in TERMINAL_PHASES:
        # Keep the durable retry fence aligned with a regenerated credential
        # request. The code revision, environment and unit remain unchanged;
        # only the published credential generation is allowed to move. Retain
        # the old hash briefly so CellLock can recover the durable owner that
        # was written before the interruption.
        regenerated_hash = request_identity(request, upload / 'proxy', upload / 'proxy.service')
        if state.get('request_hash') != regenerated_hash:
            state.setdefault('_credential_previous_request_hash', state.get('request_hash'))
            state.setdefault('_credential_previous_rollout', state.get('rollout'))
            state['request_hash'] = regenerated_hash
    return upload / 'request.json'


def deploy_locked(args, config, config_hash, host, state, state_path, instance_id):
    manifest_path = Path('/etc/sandbox/proxy-rollout.json')
    request_path = Path(args.request)
    request = json.loads(request_path.read_text())
    target = request.get('target', 'serving')
    if target not in ('serving', 'standby'):
        raise ValueError('rollout target must be serving or standby')
    if target == 'standby' and args.bootstrap:
        raise ValueError('standby deployments cannot run the serving bootstrap operation')
    validate_probes(config, request['env'])
    rollout = request['rollout']
    if not re.fullmatch('[a-zA-Z0-9_-]{1,80}', rollout):
        raise ValueError('invalid rollout identity')
    identity = request_identity(request, request_path.parent / 'proxy', request_path.parent / 'proxy.service')
    duration = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ms|s|m)',request['env'].get('PROXY_DRAIN_GRACE','30s'))
    if not duration:
        raise ValueError('drain grace must be a duration in ms, s, or m')
    seconds = float(duration[1]) * {'ms':0.001,'s':1,'m':60}[duration[2]]
    if not 0 < seconds <= 600:
        raise ValueError('drain grace must be positive and no more than ten minutes')
    rollback_phase = state['phase'].startswith('migration_rollback') or state['phase'] == 'rolled_back'
    migration_complete = config.get('migration_complete')
    if migration_complete is not None and not isinstance(migration_complete, bool):
        raise RuntimeError('Terraform migration_complete must be a boolean')
    # A legacy-only state has no generation-specific endpoint membership to
    # protect a normal cutover.  Require the explicit operator bootstrap to
    # have completed before accepting a new generation rollout; an interrupted
    # rollout with the same identity remains resumable through its durable
    # phase state, and a rolled-back rollout has already proven legacy
    # membership during its restoration.
    if target == 'serving':
        ensure_bootstrap_ready(state, rollout, args.bootstrap)
    # Normal deployments and the post-Terraform migration phase must prove
    # replacement backend references. A bootstrap retry before migration must
    # be allowed to reconcile the adopted legacy process first. Rollback phases
    # intentionally inspect the restored legacy frontends instead.
    migration_verified = target == 'serving' and (
        not args.bootstrap
        or migration_complete is True
    )
    if state.get('bootstrap') and rollback_phase:
        migration_verified = False
    # Applied frontend references are the migration prerequisite; the
    # acknowledgement is metadata only and must never authorize a rollout.
    if migration_verified:
        verify_frontend_references(config)
    # Keep the old identity durable until the recovered owner has either
    # reached a terminal state or the new rollout has been persisted.  Popping
    # it here made a second interrupted retry unable to match the owner that
    # was written before the certificate rotation.
    owner_identity = state.get('_credential_previous_request_hash') or identity
    check_retry(state, rollout, identity)
    recovery = state.get('_credential_recovery')
    if (state.get('rollout') != rollout
            and state['phase'] not in TERMINAL_PHASES
            and recovery is None):
        raise RuntimeError('resume the unfinished rollout before starting another')

    owner_rollout = (state.get('_credential_previous_rollout')
                     or (recovery['previous_rollout'] if recovery is not None else rollout))
    with CellLock(config, owner_rollout, owner_identity, state_path, instance_id) as ownership:
        # A recovered credential request may have a new rollout identity. The
        # durable owner was acquired with the pre-rotation rollout/hash; move
        # the local release fence only after that owner has been recovered.
        ownership.update_owner(rollout, identity)
        host.ownership = host.cloud.ownership = ownership
        def save(value):
            ownership.assert_owned()
            if value.get('phase') in TERMINAL_PHASES:
                value.pop('_credential_previous_request_hash', None)
                value.pop('_credential_previous_rollout', None)
                value.pop('_credential_recovery', None)
            atomic(state_path, value)
            ownership.terminal_saved = value['phase'] in TERMINAL_PHASES
        # Persist the regenerated request hash and recovery marker while the
        # recovered durable owner is still held.  A process loss before the
        # next phase transition can then reacquire that same owner.
        if recovery is not None:
            save(state)
        if recovery is not None:
            previous_owner_identity = state.get('_credential_previous_request_hash') or owner_identity
            previous_owner_rollout = state.get('_credential_previous_rollout') or recovery['previous_rollout']
            reconcile_credential_renewal(host, state, save, recovery)
            previous = state['old']
            state.update(active=previous, phase='complete', rollout=recovery['previous_rollout'])
            state.pop('candidate', None)
            state.pop('old', None)
            state.pop('_credential_recovery', None)
            state['_credential_previous_request_hash'] = previous_owner_identity
            state['_credential_previous_rollout'] = previous_owner_rollout
        if args.manifest:
            manifest_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            atomic(manifest_path, config)
        if state.get('rollout') != rollout:
            old = state['active']
            if args.bootstrap:
                if not host.local(old) or not host.external(old):
                    raise RuntimeError('legacy proxy must remain ready before bootstrap')
            elif target == 'serving' and not (
                    state.get('target') == 'standby' and state.get('phase') == 'standby_ready'):
                host.verify(old)
            if args.bootstrap:
                # The one-time migration adopts the currently serving proxy;
                # no replacement binary, unit, or listener is created here.
                candidate = dict(old, ports=dict(old['ports']))
            else:
                slot = 1 if old['ports']['public'] == 5100 else 0
                base = 5100 + slot * 10
                generation = hashlib.sha256(rollout.encode()).hexdigest()[:20]
                if not old['id']:
                    old['drain_seconds'] = seconds
                candidate = {'id':generation, 'unit':f'proxy-{generation}.service', 'drain_seconds':seconds,
                             'ports':dict(zip(('public','redirect','peer','local'),range(base,base+4)))}
            state = dict(rollout=rollout, revision=request['revision'], request_hash=identity,
                         config_hash=config_hash, phase='preparing', old=old, candidate=candidate,
                         timestamps={'preparing': time.time()},
                         endpoint_context={key: config[key] for key in
                                           ('project', 'zone', 'instance', 'ip', 'routes')},
                         bootstrap=args.bootstrap, target=target,
                         retired_rollouts=retired_rollouts(state))
            if recovery is not None and previous_owner_identity:
                state['_credential_previous_request_hash'] = previous_owner_identity
                state['_credential_previous_rollout'] = previous_owner_rollout
            save(state)
        candidate = state['candidate']
        # The one-time migration only adopts the already-running legacy
        # process. Keep it outside the generation preparation path so a
        # bootstrap retry cannot install, start, drain, or retire a proxy.
        if state.get('bootstrap'):
            # Bootstrap retains the legacy proxy, but credential publication
            # still needs the host-local controller, helper, and renewal units
            # before the operator can resume the frontend migration.
            install_credential_runtime(request_path, required=True)
            Bootstrap(host, state, save).run(migration_verified)
            return
        # Reclaim retired artifacts before preparation as well as after success:
        # repeated failed candidates must not accumulate binaries and secrets.
        ownership.assert_owned()
        prune_generations(ROOT, {candidate['id'], state['old']['id']}, host)
        if Path(__file__).resolve() != (ROOT/'controller.py').resolve():
            shutil.copyfile(Path(__file__), ROOT/'controller.py')
        refresh_helper = request_path.parent / 'refresh-peer-credentials.py'
        if refresh_helper.exists() and Path('/usr/local/sbin/refresh-peer-credentials').exists():
            shutil.copyfile(refresh_helper, '/usr/local/sbin/refresh-peer-credentials')
            os.chmod('/usr/local/sbin/refresh-peer-credentials', 0o755)
        if target == 'serving':
            Path('/etc/systemd/system/proxy-private-routing.service').write_text('''[Unit]
Description=Restore stable private proxy endpoints
After=network-online.target
Before=superserve-vmd.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /var/lib/proxy-rollout/controller.py --restore-private
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
            if not (ROOT/'private.json').exists():
                host.switch_private(state['old'])
            command('systemctl','daemon-reload')
            command('systemctl','enable','proxy-private-routing.service')
        install_credential_timer()
        credential_lock = Path('/run/lock/vmd-peer-credentials.lock')
        credential_fd = credential_lock.open('a+')
        os.fchmod(credential_fd.fileno(), 0o644)
        try:
            fcntl.flock(credential_fd, fcntl.LOCK_SH)
            if Path('/etc/superserve/peer/identity.json').exists():
                command('/usr/local/sbin/refresh-peer-credentials','--check')
            if not state.get('bootstrap'):
                prepare(host, candidate, request, request_path.parent)
        except OwnershipLost:
            raise
        except Exception as error:
            state['failure'] = str(error)
            state['failure_at'] = time.time()
            save(state)
            # A rejected configuration must not strand a never-started rollout.
            # An interrupted start can leave a running candidate even while the
            # persisted phase is preparing, so inspect it before releasing state.
            # A credential renewal may be interrupted after the phase has
            # advanced past preparation. If no candidate process or endpoint
            # survived, the same guarded recovery is safe for every
            # pre-terminal renewal phase; leaving it in `starting` would keep
            # the durable owner and stale request forever.
            if (state.get('rollout', '').startswith('credentials-')
                    and state['phase'] != 'stopping'
                    and state['phase'] not in TERMINAL_PHASES
                    and not state.get('bootstrap')):
                abandon_preparation(host, state, save)
            raise
        finally:
            credential_fd.close()
        (StandbyRollout if target == 'standby' else Rollout)(host,state,save).run()
        # Keep current and previous immutable artifacts. Membership has already
        # been reconciled and only retired, inactive units may be removed.
        ownership.assert_owned()
        prune_generations(ROOT, {state['candidate']['id'], state['old']['id']}, host)

def install_credential_timer():
    units = Path('/etc/systemd/system')
    (units/'proxy-credential-rollout.service').write_text('''[Unit]
Description=Renew proxy credentials through a health-gated generation rollout
After=network-online.target proxy-private-routing.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /var/lib/proxy-rollout/controller.py --refresh-credentials
TimeoutStartSec=0
''')
    (units/'proxy-credential-rollout.timer').write_text('''[Unit]
Description=Check for published proxy credential generations
[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
[Install]
WantedBy=timers.target
''')
    command('systemctl', 'daemon-reload')
    command('systemctl', 'enable', '--now', 'proxy-credential-rollout.timer')


def install_credential_runtime(request_path, *, required=False):
    """Install the controller and credential refresh path before bootstrap.

    Bootstrap intentionally does not prepare a generation, so it must install
    the shared runtime explicitly before returning with the legacy proxy still
    serving traffic. Credential publication can then safely trigger the
    controller while the migration is paused for Terraform.
    """
    controller = ROOT / 'controller.py'
    if Path(__file__).resolve() != controller.resolve():
        shutil.copyfile(Path(__file__), controller)

    refresh_helper = request_path.parent / 'refresh-peer-credentials.py'
    destination = Path('/usr/local/sbin/refresh-peer-credentials')
    if refresh_helper.exists():
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(refresh_helper, destination)
        os.chmod(destination, 0o755)
    elif required:
        raise RuntimeError('bootstrap upload is missing refresh-peer-credentials.py')

    install_credential_timer()


def reconcile_credential_renewal(host, state, save, recovery):
    """Return a rotated, interrupted renewal to the verified old generation.

    Credential snapshots are immutable once published.  Before the old
    process enters its irreversible drain, a rotated snapshot therefore
    invalidates the candidate rather than allowing it to continue with an
    expiring certificate.  Reconcile membership/private routing first when a
    candidate may have crossed the registration boundary; only then remove
    its artifact so the next generation is prepared from the fresh request.
    """
    if state.get('phase') not in CREDENTIAL_RECOVERABLE_PHASES:
        raise RuntimeError('credential renewal cannot rebuild after shutdown has started')
    candidate, old = state['candidate'], state['old']
    member = any(host.cloud.member(route, candidate['ports'][route['listener']])
                 for route in host.config['routes'])
    active = command('systemctl', 'show', candidate['unit'], '-p', 'ActiveState', '--value').strip()
    full_rollback = member or state['phase'] in {
        'registering', 'candidate_verified', 'withdrawing', 'withdrawn',
        'switching_private', 'cutover_verified', 'rollback',
        'rollback_restoring', 'rollback_withdrawing', 'rollback_stopping',
    }
    if full_rollback:
        Rollout(host, state, save).rollback()
    else:
        # A candidate that has only reached local readiness is not registered
        # and can be stopped directly after the old serving generation proves
        # healthy.  This also covers a start interrupted before its phase was
        # advanced beyond ``starting``.
        host.verify(old)
        if active not in ('inactive', 'failed'):
            host.stop(candidate)
        Rollout(host, state, save).phase('rolled_back', active=old)

    root = getattr(host, 'root', None)
    if not isinstance(root, Path):
        root = ROOT
    candidate_dir = root / 'generations' / candidate['id']
    if candidate_dir.exists():
        shutil.rmtree(candidate_dir)
    unit_root = getattr(host, 'unit_root', None)
    if not isinstance(unit_root, Path):
        unit_root = Path('/etc/systemd/system')
    Path(unit_root, candidate['unit']).unlink(missing_ok=True)
    command('systemctl', 'daemon-reload')


def abandon_preparation(host, state, save):
    if (state.get('_credential_recovery')
            and state.get('phase') in CREDENTIAL_RECOVERABLE_PHASES):
        return reconcile_credential_renewal(host, state, save, state['_credential_recovery'])
    candidate = state['candidate']
    active = command('systemctl', 'show', candidate['unit'], '-p', 'ActiveState', '--value').strip()
    if active not in ('inactive', 'failed'):
        return
    if any(host.cloud.member(route, candidate['ports'][route['listener']]) for route in host.config['routes']):
        return
    host.verify(state['old'])
    Rollout(host, state, save).phase('rolled_back', active=state['old'])


def prepare(host, generation, request, upload):
    host.assert_owned()
    directory = ROOT / 'generations' / generation['id']
    if directory.exists():
        if json.loads((directory/'request.json').read_text()) != request:
            raise RuntimeError('immutable generation request changed')
        shutil.copyfile(directory/'proxy.service',Path('/etc/systemd/system')/generation['unit'])
        command('systemctl','daemon-reload')
        return
    env = dict(request['env'])
    # Preserve legacy TLS identity; never infer or rewrite VMD advertisement.
    legacy_env = {}
    for line in Path('/etc/sandbox/proxy.env').read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key,value = line.split('=',1)
            legacy_env[key] = value.strip('"')
    identity_file = Path('/etc/superserve/peer/identity.json')
    if request.get('require_identity') and not identity_file.exists():
        raise RuntimeError('host requires infrastructure identity bootstrap')
    if legacy_env.get('PEER_PROXY_LISTEN_ADDR') and not env.get('PEER_PROXY_LISTEN_ADDR'):
        raise RuntimeError('proxy rollout cannot remove an advertised peer listener')
    for key,value in legacy_env.items():
        if key.startswith('PEER_PROXY_'):
            env.setdefault(key, value)
    if identity_file.exists():
        env['PEER_PROXY_SPIFFE_URI'] = json.loads(identity_file.read_text())['spiffe_uri']
    vmd_env = Path('/etc/sandbox/vmd.env').read_text()
    for line in vmd_env.splitlines():
        if line.startswith('PROXY_HEALTH_URL=') and line not in ('PROXY_HEALTH_URL=','PROXY_HEALTH_URL=http://127.0.0.1:5007/health'):
            raise RuntimeError('nonstandard VMD health URL requires explicit migration review')
    # Stable advertisement is a prerequisite, not a proxy deployment side effect.
    if env.get('PEER_PROXY_LISTEN_ADDR'):
        expected = f'PEER_PROXY_LISTEN_ADDR={host.config["ip"]}:5009'
        if expected not in vmd_env.splitlines():
            raise RuntimeError('stable peer advertisement prerequisite is not installed')
        env['PEER_PROXY_LISTEN_ADDR'] = f'{host.config["ip"]}:{generation["ports"]["peer"]}'
    identity = Path('/etc/sandbox/host-identity.env')
    if identity.exists():
        for line in identity.read_text().splitlines():
            if line.startswith('HOST_ID='):
                env['HOST_ID'] = line.split('=',1)[1]
    else:
        env['HOST_ID'] = legacy_env.get('HOST_ID',host.config['instance'])
    ports = generation['ports']
    env.update(PROXY_GENERATION=generation['id'],PROXY_ADDR=f':{ports["public"]}',
               PROXY_REDIRECT_ADDR=f':{ports["redirect"]}',PEER_PROXY_TARGET_ADDR=f'127.0.0.1:{ports["local"]}')
    peer_transport = (env.get('PEER_ROUTING_ENABLED') == '1'
                      or bool(env.get('PEER_PROXY_LISTEN_ADDR')))
    if not peer_transport:
        for key in ('PEER_PROXY_CERT_FILE', 'PEER_PROXY_KEY_FILE', 'PEER_PROXY_CA_FILE'):
            env.pop(key, None)
    pending = directory.with_name(directory.name+'.preparing')
    if pending.exists():
        shutil.rmtree(pending)
    pending.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    pending.mkdir(mode=0o755)
    shutil.copyfile(upload/'proxy',pending/'proxy')
    os.chmod(pending/'proxy',0o755)
    credentials = snapshot_credentials(env, pending, directory, request) if peer_transport else []
    for key,value in env.items():
        if not re.fullmatch('[A-Z0-9_]+',key) or any(c in value for c in '\n\r\x00'):
            raise ValueError('invalid environment input')
    (pending/'proxy.env').write_text(''.join(key+'="'+value.replace('\\','\\\\').replace('"','\\"')+'"\n' for key,value in sorted(env.items())))
    os.chmod(pending/'proxy.env',0o600)
    unit = (upload/'proxy.service').read_text().replace('@GENERATION@',generation['id'])
    shutil.copyfile(upload/'proxy.service', pending/'unit.template')
    unit += '\n[Service]\n'+'\n'.join(credentials)+'\n'
    (pending/'proxy.service').write_text(unit)
    atomic(pending/'request.json',request)
    atomic(pending/'generation.json',generation)
    publish_generation(pending, directory)
    shutil.copyfile(directory/'proxy.service',Path('/etc/systemd/system')/generation['unit'])
    command('systemctl','daemon-reload')


def publish_generation(pending, directory):
    # A durable rollout phase must never refer to an executable or credential
    # snapshot that was only in the page cache when the host lost power.
    for artifact in pending.iterdir():
        with artifact.open('rb') as source:
            os.fsync(source.fileno())
    fd = os.open(pending, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(pending, directory)
    fd = os.open(directory.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def snapshot_credentials(env, pending, directory, request, published=Path('/etc/superserve/peer/current')):
    credentials = []
    credential_generation = published.resolve(strict=True).name if published.exists() else ''
    if request.get('credential_generation', credential_generation) != credential_generation:
        raise RuntimeError('credential publication changed before snapshot; retry renewal after recovery')
    for key,label in [('PEER_PROXY_CERT_FILE','peer-cert'),('PEER_PROXY_KEY_FILE','peer-key'),('PEER_PROXY_CA_FILE','peer-ca')]:
        if env.get(key):
            source = env[key]
            if source.startswith('/run/credentials/'):
                source = {'peer-cert':'/etc/superserve/peer/tls.crt','peer-key':'/etc/superserve/peer/tls.key','peer-ca':'/etc/superserve/peer/ca.crt'}[label]
            shutil.copyfile(source, pending / label)
            os.chmod(pending / label, 0o600)
            credentials += [f'LoadCredential={label}:{directory / label}',f'Environment={key}=%d/{label}']
            del env[key]
    (pending/'credential-generation').write_text(credential_generation)
    return credentials


if __name__ == '__main__':
    main()
