"""Wait for CD's policy lifecycle permissions and the zonal OS Config API."""
import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request

PERMISSIONS = [f'osconfig.osPolicyAssignments.{verb}'
               for verb in ('create', 'get', 'list', 'update', 'delete')]


def ready(project, zones):
    token = subprocess.check_output(
        ['gcloud', 'auth', 'print-access-token'], text=True, timeout=30).strip()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    request = urllib.request.Request(
        f'https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions',
        data=json.dumps({'permissions': PERMISSIONS}).encode(), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if not set(PERMISSIONS).issubset(json.load(response).get('permissions', [])):
                return False
        # IAM visibility alone does not prove a newly enabled API is serving.
        for zone in zones:
            request = urllib.request.Request(
                f'https://osconfig.googleapis.com/v1/projects/{project}/locations/{zone}/osPolicyAssignments?pageSize=1',
                headers=headers)
            with urllib.request.urlopen(request, timeout=20) as response:
                json.load(response)
        return True
    except urllib.error.HTTPError as error:
        if error.code in (403, 429, 500, 502, 503, 504):
            return False
        raise RuntimeError(f'Host logging permission check failed with HTTP {error.code}') from None
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


def wait_for_permissions(project, zones, timeout=600):
    deadline = time.monotonic() + timeout
    while True:
        if ready(project, zones):
            print('CD host logging permissions and OS Config API are ready.')
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Host logging permissions/API did not become ready; apply remains blocked.')
        print('Waiting for host logging permissions and API propagation.', flush=True)
        time.sleep(min(10, remaining))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--zone', action='append', required=True)
    args = parser.parse_args()
    wait_for_permissions(args.project, args.zone)
