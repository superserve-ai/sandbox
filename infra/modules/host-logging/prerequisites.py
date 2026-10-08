#!/usr/bin/env python3
"""Apply the narrow VM Manager fields absent from the pinned Terraform provider."""
import json
import os
import subprocess
import time
import urllib.error
import urllib.request


class ApiError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(f'Cloud API request failed with HTTP {code}')


def request(method, url, body=None):
    token = subprocess.check_output(
        ['gcloud', 'auth', 'print-access-token'], text=True, timeout=30).strip()
    req = urllib.request.Request(url, method=method,
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Error bodies can echo unrelated VM metadata. Never log them.
        raise ApiError(error.code) from None


def pause(deadline, message):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(message)
    time.sleep(min(5, remaining))


def project_features(project, deadline):
    name = f'projects/{project}/locations/global/projectFeatureSettings'
    url = f'https://osconfig.googleapis.com/v1/{name}'
    while True:
        try:
            current = request('GET', url)
            if current.get('patchAndConfigFeatureSet') == 'OSCONFIG_C':
                return
            request('PATCH', url + '?updateMask=patchAndConfigFeatureSet',
                    {'name': name, 'patchAndConfigFeatureSet': 'OSCONFIG_C'})
        except ApiError as error:
            if error.code not in (403, 429, 500, 502, 503, 504):
                raise
        pause(deadline, 'Full VM Manager configuration did not become available')


def instance_metadata(config, deadline):
    base = f"https://compute.googleapis.com/compute/v1/projects/{config['project_id']}/zones/{config['zone']}"
    # Numeric IDs keep a concurrent same-name VM replacement outside this write.
    url = f"{base}/instances/{config['instance_id']}"
    while True:
        instance = request('GET', url)
        if (str(instance.get('id')) != str(config['instance_id']) or
                instance.get('name') != config['instance_name']):
            raise RuntimeError('Instance ID changed; regenerate the Terraform plan')
        metadata = instance.get('metadata', {})
        items = metadata.get('items', [])
        if any(item['key'] == 'enable-osconfig' and item.get('value', '').upper() == 'TRUE' for item in items):
            return
        # Keep startup scripts, SSH keys, and every unknown/concurrent key.
        desired = [item for item in items if item['key'] != 'enable-osconfig']
        desired.append({'key': 'enable-osconfig', 'value': 'TRUE'})
        if not metadata.get('fingerprint'):
            raise RuntimeError('Instance metadata fingerprint is missing')
        try:
            operation = request('POST', url + '/setMetadata',
                {'fingerprint': metadata['fingerprint'], 'items': desired})
        except ApiError as error:
            if error.code != 412:
                raise
            pause(deadline, 'Instance metadata kept changing during enablement')
            continue
        if str(operation.get('targetId')) != str(config['instance_id']):
            raise RuntimeError('Metadata operation targeted an unexpected instance')
        operation_name = operation.get('name')
        if not operation_name or '/' in operation_name:
            raise RuntimeError('Missing or invalid metadata operation name')
        while operation.get('status') != 'DONE':
            pause(deadline, 'Instance metadata operation did not complete')
            operation = request('GET', f'{base}/operations/{operation_name}')
        if operation.get('error'):
            raise RuntimeError('Instance metadata operation failed')
        # Re-read identity and value; do not treat operation success as proof.
        pause(deadline, 'Instance metadata enablement could not be verified')


def view_permissions(view, deadline):
    url = f'https://logging.googleapis.com/v2/{view}'
    while True:
        try:
            # testIamPermissions may fail open. Exercise the real read/write
            # permissions without changing any binding, condition, or version.
            policy = request('POST', url + ':getIamPolicy',
                             {'options': {'requestedPolicyVersion': 3}})
            if not policy.get('etag'):
                raise RuntimeError('Heartbeat view policy has no concurrency token')
            request('POST', url + ':setIamPolicy', {'policy': policy})
            return
        except ApiError as error:
            if error.code not in (403, 409, 412, 429, 500, 502, 503, 504):
                raise
        # Always fetch a new policy after a denial or conflict; never replay a
        # stale snapshot over a concurrently added reader or condition.
        pause(deadline, 'Heartbeat log-view IAM permission did not propagate')


def configure(config):
    deadline = time.monotonic() + 600
    phase = config['phase']
    if phase == 'project':
        project_features(config['project_id'], deadline)
    elif phase == 'instance':
        instance_metadata(config, deadline)
    elif phase == 'view-iam':
        view_permissions(config['view'], deadline)
    else:
        raise ValueError('Unknown host logging prerequisite phase')
    print(f'Host logging prerequisite ready: {phase}')


if __name__ == '__main__':
    configure(json.loads(os.environ['HOST_LOGGING_PREREQUISITE']))
