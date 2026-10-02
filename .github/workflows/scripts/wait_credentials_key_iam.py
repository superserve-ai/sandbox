"""Wait for CD's key IAM permission to propagate without changing key policy."""
import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request

PERMISSION = 'cloudkms.cryptoKeys.setIamPolicy'


def has_permission(project):
    token = subprocess.check_output(
        ['gcloud', 'auth', 'print-access-token'], text=True, timeout=30).strip()
    resource = f'projects/{project}/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek'
    request = urllib.request.Request(
        f'https://cloudkms.googleapis.com/v1/{resource}:testIamPermissions',
        data=json.dumps({'permissions': [PERMISSION]}).encode(),
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        method='POST')
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return PERMISSION in json.load(response).get('permissions', [])
    except urllib.error.HTTPError as error:
        if error.code in (403, 429, 500, 502, 503, 504):
            return False
        raise RuntimeError(f'KMS permission check failed with HTTP {error.code}') from None
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


def wait_for_permission(project, timeout=600):
    deadline = time.monotonic() + timeout
    while True:
        if has_permission(project):
            print('CD can manage credentials-kek IAM.')
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('CD key IAM permission did not propagate; regional apply remains blocked.')
        print('Waiting for credentials-kek IAM permission propagation.', flush=True)
        time.sleep(min(10, remaining))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    wait_for_permission(args.project)
