"""Wait for CD's policy lifecycle permissions and the zonal OS Config API."""
import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request

PERMISSIONS = [f'osconfig.osPolicyAssignments.{verb}'
               for verb in ('create', 'get', 'list', 'update', 'delete')]
# Only roots that carry a legacy policy bind a reader on the cutover heartbeat
# log view, so this is asked for separately rather than added to PERMISSIONS.
LOG_VIEW_PERMISSIONS = ['logging.views.getIamPolicy', 'logging.views.setIamPolicy']


def ready(project, zones, log_views=False, vm_manager=False):
    token = subprocess.check_output(
        ['gcloud', 'auth', 'print-access-token'], text=True, timeout=30).strip()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    required = PERMISSIONS + (LOG_VIEW_PERMISSIONS if log_views else [])
    request = urllib.request.Request(
        f'https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions',
        data=json.dumps({'permissions': required}).encode(), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if not set(required).issubset(json.load(response).get('permissions', [])):
                return False
        # A policy assignment is refused while VM Manager is off, even though
        # every zonal read below succeeds, so check the project metadata too.
        if vm_manager:
            request = urllib.request.Request(
                f'https://compute.googleapis.com/compute/v1/projects/{project}', headers=headers)
            with urllib.request.urlopen(request, timeout=20) as response:
                metadata = json.load(response).get('commonInstanceMetadata', {})
            enabled = {item.get('key'): item.get('value') for item in metadata.get('items') or []}
            if str(enabled.get('enable-osconfig', '')).upper() != 'TRUE':
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


def wait_for_permissions(project, zones, log_views=False, vm_manager=False, timeout=600):
    deadline = time.monotonic() + timeout
    while True:
        if ready(project, zones, log_views=log_views, vm_manager=vm_manager):
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
    parser.add_argument('--require-log-view-admin', action='store_true',
                        help='also require permission to set IAM on a log view')
    parser.add_argument('--require-vm-manager', action='store_true',
                        help='also require full VM Manager to be enabled on the project')
    args = parser.parse_args()
    wait_for_permissions(args.project, args.zone,
                         log_views=args.require_log_view_admin,
                         vm_manager=args.require_vm_manager)
