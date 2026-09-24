#!/usr/bin/env python3
"""Keep proxy traffic unchanged during ordinary Terraform applies."""

import json
import sys


FRONTENDS = {
    'google_compute_url_map.proxy_frontends["sandbox-proxy-url-map"]',
    'google_compute_url_map.proxy_frontends["sandbox-proxy-url-map-usw2"]',
    'google_compute_url_map.proxy_dataplane',
    'google_compute_target_ssl_proxy.proxy',
    'google_compute_target_tcp_proxy.redirect',
    'google_compute_ssl_policy.https',
    *(f'google_compute_global_forwarding_rule.proxy_frontends["{name}"]'
      for name in ('dataplane', 'ssl', 'redirect', 'east_https', 'west_https')),
    *(f'google_compute_target_https_proxy.adopted["{name}"]'
      for name in ('dp-https', 'sandbox-proxy-https-target', 'sandbox-proxy-https-target-usw2')),
}
STAGING_FRONTENDS = {
    'google_compute_url_map.proxy',
    'google_compute_target_https_proxy.proxy',
    'google_compute_target_ssl_proxy.proxy',
    'google_compute_target_tcp_proxy.redirect',
    *(f'google_compute_global_forwarding_rule.proxy["{route}"]'
      for route in ('https', 'ssl', 'redirect')),
}


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is True


def validate(plan, cell='production'):
    if cell not in ('staging', 'production'):
        raise ValueError('Expected staging or production')
    expected = STAGING_FRONTENDS if cell == 'staging' else FRONTENDS
    frontends = [item for item in plan.get('resource_changes', []) if item['address'] in expected]
    if {item['address'] for item in frontends} != expected or len(frontends) != len(expected):
        raise ValueError('Full plan must include every proxy frontend exactly once')
    def resource_id(value):
        return value[value.index('projects/'):] if isinstance(value, str) and 'projects/' in value else value

    protected_targets = {resource_id(item['change'].get('before', {}).get(field))
                         for item in frontends for field in ('id', 'self_link')
                         if isinstance(item['change'].get('before'), dict)
                         and item['change']['before'].get(field)}
    for item in plan.get('resource_changes', []):
        if item['address'] in expected or item.get('type') != 'google_compute_global_forwarding_rule':
            continue
        change = item['change']
        if any(resource_id((change.get(side) or {}).get('target')) in protected_targets
               for side in ('before', 'after')):
            frontends.append(item)
    for item in frontends:
        change = item['change']
        # A no-op import adopts ownership without changing live traffic.
        if (change['actions'] != ['no-op'] or item.get('previous_address')
                or has_unknown(change.get('after_unknown', {}))
                or not change.get('before') or change['before'] != change.get('after')):
            raise ValueError('Use the explicit proxy migration for frontend changes: ' + item['address'])


if __name__ == '__main__':
    try:
        validate(json.load(sys.stdin), sys.argv[1] if len(sys.argv) > 1 else 'production')
    except (ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
    print('Proxy frontend traffic is unchanged.')
