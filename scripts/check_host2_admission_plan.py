"""Accept only one saved-plan admission label transition on staging Host 2."""
import json
import sys

HOST = "module.sandbox_host_b.google_compute_instance.this"
LABEL_FIELDS = {"labels", "terraform_labels", "effective_labels"}
ADMISSION_KEYS = {"component", "sandbox_status"}
TRANSITIONS = {
    (("vmd-staging-standby", "provisioning"), ("vmd", "provisioning")),
    (("vmd", "provisioning"), ("vmd", "ready")),
}


def phase(labels):
    return labels.get("component"), labels.get("sandbox_status")


def validate(plan):
    changes = [r for r in plan.get("resource_changes", [])
               if r["change"]["actions"] != ["no-op"]]
    if len(changes) != 1 or changes[0]["address"] != HOST:
        raise ValueError("Admission requires exactly one change: Host 2 labels; reject all other actions")
    change = changes[0]["change"]
    if change["actions"] != ["update"]:
        raise ValueError("Admission must be in-place; replacement is forbidden")
    before, after = change["before"], change["after"]
    if before.get("name") != "superserve-vmd-staging-2" or not before.get("id"):
        raise ValueError("Expected an existing staging Host 2 instance")
    if (phase(before["labels"]), phase(after["labels"])) not in TRANSITIONS:
        raise ValueError("Expected standby/provisioning -> serving/provisioning -> serving/ready, one step at a time")
    for key in LABEL_FIELDS:
        old, new = before.get(key, {}), after.get(key, {})
        if {k: v for k, v in old.items() if k not in ADMISSION_KEYS} != {
                k: v for k, v in new.items() if k not in ADMISSION_KEYS}:
            raise ValueError(f"Unexpected non-admission label change in {key}")
        if phase(new) != phase(after["labels"]):
            raise ValueError(f"Inconsistent admission labels in {key}")
    # Only the provider-computed label fingerprint may become unknown.
    excluded = LABEL_FIELDS | {"label_fingerprint"}
    if {k: v for k, v in before.items() if k not in excluded} != {
            k: v for k, v in after.items() if k not in excluded}:
        raise ValueError("Non-label VM changes are forbidden, including disks, identity and service account")
    def unknown(value):
        if isinstance(value, dict):
            return any(unknown(v) for v in value.values())
        if isinstance(value, list):
            return any(unknown(v) for v in value)
        return value is True
    if any(unknown(v) for k, v in change.get("after_unknown", {}).items()
           if k != "label_fingerprint"):
        raise ValueError("Unknown non-fingerprint values cannot prove a label-only update")


if __name__ == "__main__":
    try:
        validate(json.load(sys.stdin))
    except (ValueError, KeyError, TypeError) as exc:
        sys.exit(f"REFUSED: {exc}")
    print("PASS: only staging Host 2 admission labels change; no replacement or other resource action")
