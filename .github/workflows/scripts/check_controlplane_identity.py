"""Check Terraform's operator identity and configured promotion secret rollout."""
import argparse
import json
import sys


def check(service, project, cell):
    spec = service.get('spec', {}).get('template', {}).get('spec', {})
    expected = f'superserve-controlplane-{cell}@{project}.iam.gserviceaccount.com'
    if spec.get('serviceAccountName') != expected:
        raise ValueError('dedicated control-plane runtime identity is not deployed')
    containers = spec.get('containers', [])
    if not containers:
        raise ValueError('control-plane container is missing')
    tokens = [env for env in containers[0].get('env', [])
              if env.get('name') == 'OPERATOR_API_TOKEN']
    if len(tokens) != 1:
        raise ValueError('operator token mapping is missing or duplicated')
    ref = tokens[0].get('valueFrom', {}).get('secretKeyRef', {})
    if ('value' in tokens[0] or ref.get('name') != f'operator-api-token-{cell}'
            or not ref.get('key')):
        raise ValueError('operator token must reference the dedicated cell secret')
    # Terraform writes its resolved rollout value into the same revision template
    # as the secrets. Missing secrets cannot establish that rollout is disabled.
    rollout = [env for env in containers[0].get('env', [])
               if env.get('name') == 'PROMOTION_EVIDENCE_ENABLED']
    if (len(rollout) != 1 or 'valueFrom' in rollout[0]
            or rollout[0].get('value') not in ('true', 'false')):
        raise ValueError('promotion evidence rollout state is missing or invalid')
    promotion_evidence_enabled = rollout[0]['value'] == 'true'
    for name, secret in (
            ('PROMOTION_AUTH_DATABASE_URL', 'promotion-auth-database-url'),
            ('PROMOTION_CAPTURE_TOKEN', 'promotion-capture-token'),
            ('PROMOTION_ACCOUNT_TOKEN', 'promotion-account-token'),
            ('PROMOTION_ACCOUNT_PUBLIC_KEY', 'promotion-account-public-key')):
        matches = [env for env in containers[0].get('env', []) if env.get('name') == name]
        if not matches and not promotion_evidence_enabled:
            continue
        if len(matches) != 1:
            raise ValueError(f'{name} mapping is missing or duplicated')
        ref = matches[0].get('valueFrom', {}).get('secretKeyRef', {})
        if ('value' in matches[0] or ref.get('name') != f'{secret}-{cell}'
                or not ref.get('key')):
            raise ValueError(f'{name} must reference the dedicated cell secret')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--cell', choices=('use4', 'usw2'), required=True)
    args = parser.parse_args()
    try:
        check(json.load(sys.stdin), args.project, args.cell)
    except (ValueError, AttributeError, TypeError) as exc:
        print(f'::error::Control-plane identity compatibility check failed: {exc}. '
              'Complete the Terraform identity rollout before deploying.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
