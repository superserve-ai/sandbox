#!/usr/bin/env python3
"""Validate the one-time staging frontend adoption or its backend rollback."""

import json
import sys


PROJECT = "rayai-dev"
BASE = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/global/backendServices/"
FRONTENDS = {
    "google_compute_url_map.proxy": ("urlMaps", "sandbox-proxy-url-map"),
    "google_compute_target_https_proxy.proxy": ("targetHttpsProxies", "sandbox-proxy-https-target"),
    "google_compute_target_ssl_proxy.proxy": ("targetSslProxies", "sandbox-proxy-ssl"),
    "google_compute_target_tcp_proxy.redirect": ("targetTcpProxies", "sandbox-proxy-tcp"),
    'google_compute_global_forwarding_rule.proxy["https"]': ("forwardingRules", "sandbox-proxy-https-fwd-test"),
    'google_compute_global_forwarding_rule.proxy["ssl"]': ("forwardingRules", "sandbox-proxy-https-fwd"),
    'google_compute_global_forwarding_rule.proxy["redirect"]': ("forwardingRules", "sandbox-proxy-http-fwd"),
}
ROUTES = {
    "google_compute_url_map.proxy": ("default_service", "sandbox-proxy-backend-https", "proxy-staging-public-http-generations"),
    "google_compute_target_ssl_proxy.proxy": ("backend_service", "sandbox-proxy-backend", "proxy-staging-public-tcp-generations"),
    "google_compute_target_tcp_proxy.redirect": ("backend_service", "sandbox-proxy-redirect-backend", "proxy-staging-redirect-generations"),
}
CERTIFICATE_MAP = f"projects/{PROJECT}/locations/global/certificateMaps/sandbox-proxy-cert-map"


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is True


def validate(plan, mode):
    if mode == "steady":
        frontends = [item for item in plan.get("resource_changes", []) if item["address"] in FRONTENDS]
        if {item["address"] for item in frontends} != set(FRONTENDS):
            raise ValueError("Full staging plan must include every proxy frontend")
        if any(item["change"]["actions"] != ["no-op"] or item["change"].get("importing")
               or item.get("previous_address") for item in frontends):
            raise ValueError("Use the explicit proxy migration workflow for frontend changes; full applies cannot undo rollback")
        return
    if mode not in ("cutover", "rollback"):
        raise ValueError("Expected cutover or rollback")
    seen = set()
    for item in plan.get("resource_changes", []):
        address, change = item["address"], item["change"]
        if item.get("previous_address"):
            raise ValueError("State moves are not part of frontend migration")
        if address not in FRONTENDS:
            if change["actions"] != ["no-op"] or change.get("importing"):
                raise ValueError("Non-frontend resource change: " + address)
            continue
        if address in seen:
            raise ValueError("Duplicate frontend: " + address)
        seen.add(address)
        kind, name = FRONTENDS[address]
        # Import plans include the refreshed remote object here. Without that
        # snapshot we cannot prove addresses/TLS unchanged, so fail closed.
        before, after = change.get("before") or {}, change.get("after") or {}
        if change["actions"] not in (["no-op"], ["update"]) or has_unknown(change.get("after_unknown", {})):
            raise ValueError("Frontend must be a fully known in-place update or no-op")
        expected_id = f"projects/{PROJECT}/global/{kind}/{name}"
        if change.get("importing") and change["importing"] != {"id": expected_id}:
            raise ValueError("Unexpected frontend import")
        for value in (before, after):
            if value.get("project") != PROJECT or value.get("name") != name or value.get("id") != expected_id:
                raise ValueError("Unexpected frontend identity")
        allowed = set()
        if address in ROUTES:
            field, legacy, generation = ROUTES[address]
            allowed.add(field)
            if before.get(field) not in (BASE + legacy, BASE + generation):
                raise ValueError("Unexpected current backend")
            if after.get(field) != BASE + (generation if mode == "cutover" else legacy):
                raise ValueError("Unexpected destination backend")
        if kind in ("targetHttpsProxies", "targetSslProxies"):
            allowed.add("certificate_map")
            spellings = (CERTIFICATE_MAP, "https://certificatemanager.googleapis.com/v1/" + CERTIFICATE_MAP,
                         "//certificatemanager.googleapis.com/" + CERTIFICATE_MAP)
            if any(value.get("certificate_map") not in spellings for value in (before, after)):
                raise ValueError("Certificate map identity must stay unchanged")
        changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
        if changed - allowed:
            raise ValueError("Unexpected frontend fields: " + str(sorted(changed - allowed)))
    if seen != set(FRONTENDS):
        raise ValueError("All seven staging frontends must be present in the plan")


if __name__ == "__main__":
    try:
        validate(json.load(sys.stdin), sys.argv[1])
    except (ValueError, KeyError, TypeError, IndexError) as error:
        sys.exit(str(error))
    print("Validated staging frontend references; addresses and TLS unchanged.")
