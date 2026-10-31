#!/usr/bin/env python3
"""Reconcile OS Login policy without owning unrelated instance metadata."""
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request


class ApiError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(f"Compute API request failed with HTTP {code}")


def request(method, url, body=None):
    token = subprocess.check_output(
        ["gcloud", "auth", "print-access-token"], text=True, timeout=30).strip()
    req = urllib.request.Request(
        url, method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # API error bodies may contain unrelated, sensitive instance metadata.
        raise ApiError(error.code) from None


def pause(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("OS Login metadata reconciliation timed out")
    time.sleep(min(2, remaining))


def configure(config):
    for field in ("project_id", "zone", "instance_name"):
        if not re.fullmatch(r"[a-z][a-z0-9-]*", config[field]):
            raise ValueError(f"Invalid {field}")
    instance_id = str(config["instance_id"])
    if not re.fullmatch(r"[0-9]+", instance_id):
        raise ValueError("A numeric instance ID is required")
    desired_value = config["value"]
    if desired_value not in ("TRUE", "FALSE"):
        raise ValueError("OS Login 2FA value must be TRUE or FALSE")

    base = (f"https://compute.googleapis.com/compute/v1/projects/{config['project_id']}"
            f"/zones/{config['zone']}")
    # Pin the plan's incarnation, never a concurrent same-name replacement.
    url = f"{base}/instances/{instance_id}"
    deadline = time.monotonic() + 300
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("OS Login metadata reconciliation timed out")
        instance = request("GET", url)
        if (str(instance.get("id")) != instance_id or
                instance.get("name") != config["instance_name"]):
            raise RuntimeError("Instance identity changed; regenerate the Terraform plan")
        metadata = instance.get("metadata", {})
        items = metadata.get("items", [])
        values = {item["key"]: item.get("value", "") for item in items}
        managed = {"enable-oslogin-2fa": desired_value}
        if desired_value == "TRUE":
            oslogin = values.get("enable-oslogin")
            if oslogin is None:
                project = request("GET", f"https://compute.googleapis.com/compute/v1/projects/{config['project_id']}")
                project_values = {item["key"]: item.get("value", "") for item in
                                  project.get("commonInstanceMetadata", {}).get("items", [])}
                oslogin = project_values.get("enable-oslogin", "")
            if oslogin.upper() != "TRUE":
                raise RuntimeError("OS Login must already be enabled before enabling 2FA")
            # Pin inherited OS Login locally so later project changes cannot disable MFA.
            managed["enable-oslogin"] = "TRUE"
        if all(values.get(key) == value for key, value in managed.items()):
            return
        if not metadata.get("fingerprint"):
            raise RuntimeError("Instance metadata fingerprint is missing")
        desired = [item for item in items if item["key"] not in managed]
        desired.extend({"key": key, "value": value} for key, value in managed.items())
        try:
            operation = request("POST", url + "/setMetadata", {
                "fingerprint": metadata["fingerprint"], "items": desired})
        except ApiError as error:
            if error.code != 412:
                raise
            pause(deadline)
            continue
        operation_name = operation.get("name", "")
        if (str(operation.get("targetId")) != instance_id or
                not re.fullmatch(r"[a-zA-Z0-9_-]+", operation_name)):
            raise RuntimeError("Unexpected metadata operation identity")
        while operation.get("status") != "DONE":
            pause(deadline)
            operation = request("GET", f"{base}/operations/{operation_name}")
        if operation.get("error"):
            raise RuntimeError("Instance metadata operation failed")
        # Completion is not proof: re-read the pinned instance and desired key.
        pause(deadline)


if __name__ == "__main__":
    configure(json.loads(os.environ["OSLOGIN_2FA_CONFIG"]))
    print("OS Login 2FA metadata reconciled; human challenge verification is still required")
