"""Cloud Run retirement barrier for the regional YC calendar candidate."""

import copy
import json
import re
import time
import urllib.request

import staging_candidate_validation as common

require = common.require
SERVICE = f'projects/{common.PROJECT}/locations/{common.REGION}/services/{common.SERVICE}'
PARENT = f'projects/{common.PROJECT}/locations/{common.REGION}'
API = 'https://run.googleapis.com/v2/'


def current_generation(resource):
    generation = resource.get('generation')
    return (isinstance(generation, str) and re.fullmatch(r'[1-9][0-9]*', generation) is not None
            and resource.get('observedGeneration') == generation)


def request(path, body=None, mask=None):
    require(path.startswith(PARENT + '/'), 'Cloud Run target outside staging region')
    token = common.command(['gcloud', 'auth', 'print-access-token'])
    url = API + path
    if mask:
        url += '?updateMask=' + mask
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': 'Bearer ' + token,
                                          'Content-Type': 'application/json'},
                                 method='PATCH' if body is not None else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            return json.load(response)
    except Exception:
        raise common.GateError('Cloud Run request failed; provider output withheld') from None


def inventory(get=request):
    service = get(SERVICE)
    revisions = []
    path = SERVICE + '/revisions'
    for _ in range(100):
        page = get(path)
        revisions.extend(page.get('revisions', []))
        token = page.get('nextPageToken')
        if not token:
            break
        from urllib.parse import quote
        path = SERVICE + '/revisions?pageToken=' + quote(token, safe='')
    else:
        raise common.GateError('Revision inventory exceeded bound')
    require(revisions and len({r['name'] for r in revisions}) == len(revisions), 'Incomplete revision inventory')
    require(all(r['name'].startswith(SERVICE + '/revisions/') and r.get('uid') for r in revisions),
            'Revision identity mismatch')
    require(service.get('name') == SERVICE and service.get('uid') and service.get('etag'), 'Service identity unavailable')
    require(not service.get('reconciling') and current_generation(service),
            'Service is reconciling')
    require(service.get('terminalCondition', {}).get('state') == 'CONDITION_SUCCEEDED', 'Service is not ready')
    require(len(service['template']['containers']) == 1, 'Only one-container service is supported')
    return {'service': service, 'revisions': sorted(revisions, key=lambda r: r['name'])}


def configuration(state):
    # Bind scaling, tags, revision minima, command overrides and all other inputs;
    # omit only provider observations that can change without a configuration edit.
    output = {'conditions', 'terminalCondition', 'reconciling', 'observedGeneration',
              'trafficStatuses', 'latestReadyRevision', 'latestCreatedRevision', 'urls',
              'uri', 'logUri', 'scalingStatus', 'etag', 'updateTime'}
    return {key: ([{k: v for k, v in r.items() if k not in output} for r in value]
                  if key == 'revisions' else {k: v for k, v in value.items() if k not in output})
            for key, value in state.items()}


def retired(revision):
    return (not revision.get('reconciling')
            and current_generation(revision)
            and any(c.get('revisionReason') == 'RETIRED' and c.get('state') == 'CONDITION_FAILED'
                    for c in revision.get('conditions', [])))


def exclusive(service, revision):
    expected = [{'type': 'TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION', 'revision': revision, 'percent': 100}]
    observed = [{k: v for k, v in target.items() if k != 'uri'} for target in service.get('trafficStatuses', [])]
    require(service.get('traffic') == expected and observed == expected,
            'Desired/effective traffic must name only the approved revision, without tags')


class Drain:
    def __init__(self, original, image, run_id, *, versions, get=request, sleep=time.sleep, audit=lambda phase, state: None):
        require(re.fullmatch(re.escape(common.IMAGE) + '@sha256:[a-f0-9]{64}', image),
                'Immutable staging image required')
        require(run_id.isdigit(), 'Run identity required')
        self.original, self.image, self.get, self.sleep, self.audit = original, image, get, sleep, audit
        self.parked = common.SERVICE + '-yc-park-' + run_id
        self.application = common.SERVICE + '-yc-app-' + run_id
        self.old = {r['name']: r['uid'] for r in original['revisions']}
        self.parked_state = None
        self.versions = versions

    def template(self, revision):
        template = copy.deepcopy(self.original['service']['template'])
        template['revision'] = revision
        c = template['containers'][0]
        c['image'] = self.image
        for entry in c.get('env', []):
            if entry['name'] in common.SECRETS:
                ref = entry.get('valueSource', {}).get('secretKeyRef', {})
                require(ref.get('secret') == common.SECRETS[entry['name']]
                        and ref.get('version') in ('latest', self.versions[entry['name']]), 'Unexpected secret reference')
                ref['version'] = self.versions[entry['name']]
        return template

    def patch(self, service, **fields):
        require(service['name'] == SERVICE, 'Service target changed')
        operation = self.get(SERVICE, {'name': SERVICE, 'etag': service['etag'], **fields}, ','.join(fields))
        require(operation.get('name', '').startswith(PARENT + '/operations/'), 'Provider operation identity unavailable')
        self.audit('cloud_operation_requested', {'operation': operation['name']})
        for _ in range(120):
            if operation.get('done'):
                require('error' not in operation and operation.get('response', {}).get('name') == SERVICE,
                        'Cloud Run mutation failed; stop and inspect recovery instructions')
                generation = operation['response'].get('generation')
                require(generation and int(generation) > int(service['generation']), 'Mutation generation not established')
                self.expected_generation = generation
                return
            self.sleep(5)
            operation = self.get(operation['name'])
        raise common.GateError('Cloud Run operation incomplete; stop and inspect recovery instructions')

    def ready(self):
        # A failed or unknown update is never taken as evidence of drain.
        for _ in range(60):
            service = self.get(SERVICE)
            if not service.get('reconciling'):
                require(current_generation(service)
                        and service.get('generation') == self.expected_generation
                        and service.get('terminalCondition', {}).get('state') == 'CONDITION_SUCCEEDED',
                        'Cloud Run update did not succeed; stop and inspect recovery instructions')
                return service
            self.sleep(5)
        raise common.GateError('Cloud Run update timed out; stop and inspect recovery instructions')

    def pause(self):
        current = inventory(self.get)
        require(configuration(current) == configuration(self.original), 'Runtime changed since approved preflight')
        service = current['service']
        # Scaling zero does not disable tag-only revisions. Removing tags is part
        # of this same service update; retirement below is the execution barrier.
        traffic = [{'type': 'TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION',
                    'revision': service['latestReadyRevision'].split('/')[-1], 'percent': 100}]
        self.audit('pause_requested', current)
        self.patch(service, scaling={'scalingMode': 'MANUAL', 'manualInstanceCount': 0}, traffic=traffic)
        service = self.ready()
        require(service.get('scaling') == {'scalingMode': 'MANUAL', 'manualInstanceCount': 0}, 'Pause scaling not effective')
        exclusive(service, traffic[0]['revision'])
        template = self.template(self.parked)
        template['healthCheckDisabled'] = True
        container = template['containers'][0]
        container.update(image=self.image, command=['/bin/sleep'], args=['infinity'])
        for key in ('ports', 'startupProbe', 'livenessProbe'):
            container.pop(key, None)
        traffic[0]['revision'] = self.parked
        self.audit('park_requested', {'image': self.image})
        self.patch(service, template=template, traffic=traffic,
                   scaling={'scalingMode': 'MANUAL', 'manualInstanceCount': 0})
        self.ready()
        self.parked_state = inventory(self.get)
        self.verify_parked(self.parked_state)
        self.audit('parked', self.parked_state)

    def verify_parked(self, state):
        service = state['service']
        require(service.get('scaling') == {'scalingMode': 'MANUAL', 'manualInstanceCount': 0}, 'Service no longer paused')
        require(service['template'].get('healthCheckDisabled') is True, 'Parked health-check override missing')
        exclusive(service, self.parked)
        name = SERVICE + '/revisions/' + self.parked
        rev = next((r for r in state['revisions'] if r['name'] == name), None)
        require(rev is not None and len(rev.get('containers', [])) == 1, 'Parked revision missing')
        for containers in (service['template']['containers'], rev['containers']):
            c = containers[0]
            require(c['image'] == self.image and c.get('command') == ['/bin/sleep']
                    and c.get('args') == ['infinity'], 'Parked entrypoint/image mismatch')
        require({r['name']: r['uid'] for r in state['revisions'] if r['name'] != name} == self.old,
                'Old revision inventory changed during drain')
        if self.parked_state:
            require(configuration(state) == configuration(self.parked_state), 'Parked configuration changed')

    def barrier(self):
        require(self.parked_state is not None, 'Pause must precede retirement barrier')
        for _ in range(120):
            state = inventory(self.get)
            self.verify_parked(state)
            if all(retired(r) for r in state['revisions'] if r['name'] in self.old):
                self.audit('old_revisions_retired', state)
                return state
            self.sleep(5)
        raise common.GateError('Old revisions not verifiably retired; no migration permitted')

    def resume(self, migrated):
        require(migrated is True, 'Verified migration required before application startup')
        state = self.barrier()
        template = self.template(self.application)
        # Startup itself may run financial work, even while service scaling is zero.
        self.audit('application_start_requested', {'image': self.image})
        self.patch(state['service'], template=template,
                   traffic=[{'type': 'TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION',
                             'revision': self.application, 'percent': 100}])
        service = self.ready()
        exclusive(service, self.application)
        self.patch(service, scaling=self.original['service'].get('scaling', {}))
        service = self.ready()
        exclusive(service, self.application)
        require(service.get('scaling', {}) == self.original['service'].get('scaling', {}), 'Original scaling was not restored')
        require(service['template']['containers'][0]['image'] == self.image, 'Application image changed')
        self.audit('compatible_runtime_resumed', {'service': service})
