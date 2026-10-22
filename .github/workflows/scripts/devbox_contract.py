"""Shared devbox identity, label and manifest contract.

Imported by the create, deploy and destroy workflows so every workflow names,
labels and records a devbox the same way. Pure functions only: callers own
the cloud calls and pass clocks and randomness in where tests need them.
"""

import copy
from datetime import datetime, timedelta, timezone
import re
import secrets


SCHEMA_VERSION = 1
MANAGED_BY = "superserve-devbox"
PROJECT = "rayai-dev"
REGION = "us-central1"
# Zonal resources may live in any of these; create tries them in this order.
DEVBOX_ZONES = ("us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f")
AUTO_ZONE = "auto"
MANIFEST_METADATA_KEY = "devbox-manifest"
# The devbox project also hosts staging, so the workflow identity's IAM is
# conditioned on these name prefixes; labels carry the bare devbox name.
RESOURCE_PREFIX = "devbox-"
DATA_DISK_SUFFIX = "-data"
DATA_DISK_DEVICE_NAME = "devbox-data"
BUCKET_PREFIX = "superserve-devbox-"

DEFAULT_LIFETIME_HOURS = 24
MAX_LIFETIME_HOURS = 168
MAX_NAME_LENGTH = 40
MAX_OWNER_LENGTH = 63

NAME_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,38}[a-z0-9]")
DEVBOX_ID_PATTERN = re.compile(r"[0-9a-f]{12}")
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
BRANCH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")

LABEL_KEYS = ("managed-by", "devbox-name", "devbox-id", "owner", "expires-at")
# Staging and production discover their hosts through these labels (the
# environments.yaml selectors and the component=vmd* deploy targets); a devbox
# carrying any of them could be swept into a real deployment.
FORBIDDEN_LABELS = ("sandbox_role", "sandbox_status", "environment", "region", "component")

STATES = ("creating", "ready", "failed", "deploying", "destroying")
RESOURCE_TYPES = ("instance", "disk", "bucket")
MIGRATION_RESULTS = ("applied", "none", "failed", "unknown")
UNKNOWN_SHA = "unknown"
DEPLOY_RESULTS = ("succeeded", "failed")

REPOSITORIES = ("sandbox", "ui")
COMPONENTS = ("vmd", "proxy", "api", "ui")
COMPONENT_REPOSITORIES = {"vmd": "sandbox", "proxy": "sandbox", "api": "sandbox", "ui": "ui"}
# A fresh host needs the database and API before VMD and secretsproxy start.
CREATE_SCRIPTS = ("host-bootstrap.sh", "services-up.sh", "install-api.sh", "install-vmd.sh",
                  "install-proxy.sh", "seed-base.sh", "install-ui.sh")
# Upgrades follow the production order and never reseed.
COMPONENT_SCRIPTS = {
    "vmd": ("install-vmd.sh",),
    "proxy": ("install-proxy.sh",),
    "api": ("services-up.sh", "install-api.sh"),
    "ui": ("install-ui.sh",),
}

FORWARDED_PORTS = (
    ("Console", 3000),
    ("API", 8080),
    ("Auth/data gateway", 54321),
    ("Mailpit", 8025),
    ("Sandbox proxy", 8090),
)

BOX_SOURCE_DIR = "/opt/superserve-devbox/src"
BOX_CONFIG_DIR = "/etc/superserve-devbox"
BOX_STATE_DIR = "/var/lib/superserve-devbox"
BOX_SCRIPT_DIR = BOX_SOURCE_DIR + "/sandbox/deploy/devbox"


class ContractError(ValueError):
    pass


def normalize_owner(actor):
    owner = re.sub(r"[^a-z0-9_-]", "-", (actor or "").strip().lower())[:MAX_OWNER_LENGTH]
    if not owner:
        raise ContractError("GitHub actor is empty; cannot derive an owner")
    return owner


def validate_name(name):
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ContractError(
            f"Invalid devbox name {name!r}: use 2-{MAX_NAME_LENGTH} lowercase letters, digits "
            "or hyphens, starting with a letter and ending with a letter or digit")
    # Box <name>'s data disk is devbox-<name>-data, which is also the VM and
    # boot disk name of a box called <name>-data.
    if name.endswith(DATA_DISK_SUFFIX):
        raise ContractError(f"Invalid devbox name {name!r}: names may not end in {DATA_DISK_SUFFIX!r}")
    return name


def generate_name(owner, suffix=None):
    suffix = suffix if suffix is not None else secrets.token_hex(3)
    if not re.fullmatch(r"[0-9a-f]{6}", suffix):
        raise ContractError(f"Invalid generated name suffix {suffix!r}")
    tail = f"-dev-{suffix}"
    stem = re.sub(r"[^a-z0-9-]", "-", owner.lower())
    stem = re.sub(r"^[^a-z]+", "", stem)[:MAX_NAME_LENGTH - len(tail)].rstrip("-")
    return validate_name((stem or "box") + tail)


def resolve_name(requested, owner, suffix=None):
    requested = (requested or "").strip()
    return validate_name(requested) if requested else generate_name(owner, suffix)


def new_devbox_id():
    return secrets.token_hex(6)


def validate_devbox_id(devbox_id):
    if not isinstance(devbox_id, str) or not DEVBOX_ID_PATTERN.fullmatch(devbox_id):
        raise ContractError(f"Invalid devbox-id {devbox_id!r}")
    return devbox_id


def parse_lifetime_hours(value):
    text = str(value if value is not None else "").strip() or str(DEFAULT_LIFETIME_HOURS)
    if not re.fullmatch(r"[0-9]+", text):
        raise ContractError(f"Lifetime must be a whole number of hours, got {value!r}")
    hours = int(text)
    if not 1 <= hours <= MAX_LIFETIME_HOURS:
        raise ContractError(f"Lifetime must be between 1 and {MAX_LIFETIME_HOURS} hours, got {hours}")
    return hours


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ContractError(f"Timestamp {text!r} is not UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)") from None


def expiry(created_at, lifetime_hours):
    return created_at + timedelta(hours=parse_lifetime_hours(lifetime_hours))


def concurrency_group(name):
    return "devbox-" + validate_name(name)


def instance_name(name):
    return RESOURCE_PREFIX + validate_name(name)


def data_disk_name(name):
    return instance_name(name) + DATA_DISK_SUFFIX


def bucket_name(devbox_id):
    return BUCKET_PREFIX + validate_devbox_id(devbox_id)


def labels(name, devbox_id, owner, expires_at):
    return {
        "managed-by": MANAGED_BY,
        "devbox-name": validate_name(name),
        "devbox-id": validate_devbox_id(devbox_id),
        "owner": normalize_owner(owner),
        "expires-at": str(int(expires_at.timestamp())),
    }


def format_labels(values):
    return ",".join(f"{key}={values[key]}" for key in LABEL_KEYS)


def check_labels(found, name, devbox_id=None):
    found = found or {}
    if found.get("managed-by") != MANAGED_BY or found.get("devbox-name") != name:
        raise ContractError(f"{name} is not a devbox managed by {MANAGED_BY}")
    leaked = sorted(set(found) & set(FORBIDDEN_LABELS))
    if leaked:
        raise ContractError(f"{name} carries deployment discovery labels {leaked}; refusing to touch it")
    if devbox_id is not None and found.get("devbox-id") != devbox_id:
        raise ContractError(
            f"{name} devbox-id changed from {devbox_id} to {found.get('devbox-id')!r}; "
            "the box was replaced, refusing to continue")
    return validate_devbox_id(found.get("devbox-id"))


def discovery_filter(name=None):
    expression = f"labels.managed-by={MANAGED_BY}"
    if name is not None:
        expression += f" AND labels.devbox-name={validate_name(name)}"
    return expression


def select_instance(instances, name):
    matches = [inst for inst in instances
               if (inst.get("labels") or {}).get("managed-by") == MANAGED_BY
               and (inst.get("labels") or {}).get("devbox-name") == name]
    if not matches:
        raise ContractError(f"No devbox named {name} found")
    if len(matches) > 1:
        raise ContractError(f"{len(matches)} instances claim devbox name {name}; refusing to guess")
    instance = matches[0]
    if instance.get("name") != instance_name(name):
        raise ContractError(f"Instance {instance.get('name')!r} is labelled as devbox {name}")
    check_labels(instance["labels"], name)
    return instance


def validate_zone(zone):
    if zone not in DEVBOX_ZONES:
        raise ContractError(f"Zone {zone!r} is not a devbox zone ({', '.join(DEVBOX_ZONES)})")
    return zone


def zone_candidates(value):
    value = (value or "").strip() or AUTO_ZONE
    return list(DEVBOX_ZONES) if value == AUTO_ZONE else [validate_zone(value)]


def zone_of(resource):
    return validate_zone((resource.get("zone") or "").rsplit("/", 1)[-1])


def resources(name, devbox_id, zone):
    validate_zone(zone)
    return [
        {"type": "instance", "name": instance_name(name), "zone": zone},
        {"type": "disk", "name": instance_name(name), "zone": zone},
        {"type": "disk", "name": data_disk_name(name), "zone": zone},
        {"type": "bucket", "name": bucket_name(devbox_id)},
    ]


def revision(branch, sha):
    if not isinstance(branch, str) or not BRANCH_PATTERN.fullmatch(branch) or ".." in branch:
        raise ContractError(f"Branch {branch!r} is not a plain branch name (letters, digits, '.', '_', '-', '/')")
    if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
        raise ContractError(f"Branch {branch!r} did not resolve to a full commit SHA")
    return {"branch": branch, "sha": sha}


def new_manifest(*, name, devbox_id, owner, actor, created_at, expires_at, revisions, zone,
                 project=PROJECT):
    revisions = {key: revision(revisions[key]["branch"], revisions[key]["sha"]) for key in REPOSITORIES}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "name": validate_name(name),
        "devbox_id": validate_devbox_id(devbox_id),
        "owner": normalize_owner(owner),
        "actor": actor,
        "project": project,
        "zone": zone,
        "created_at": iso(created_at),
        "expires_at": iso(expires_at),
        "state": "creating",
        "resources": resources(name, devbox_id, zone),
        "revisions": revisions,
        "components": {component: dict(revisions[COMPONENT_REPOSITORIES[component]]) for component in COMPONENTS},
        "runtime": {},
        "services": {},
        "deploys": [],
    }
    return validate_manifest(manifest)


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ContractError("Manifest is not a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ContractError(f"Unsupported manifest schema_version {manifest.get('schema_version')!r}")
    for key in ("name", "devbox_id", "owner", "actor", "project", "zone",
                "created_at", "expires_at", "state"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            raise ContractError(f"Manifest field {key!r} is missing")
    validate_name(manifest["name"])
    validate_zone(manifest["zone"])
    validate_devbox_id(manifest["devbox_id"])
    parse_iso(manifest["created_at"])
    parse_iso(manifest["expires_at"])
    if manifest["state"] not in STATES:
        raise ContractError(f"Manifest state {manifest['state']!r} is not one of {STATES}")
    for key, kind in (("resources", list), ("revisions", dict), ("components", dict), ("runtime", dict),
                      ("services", dict), ("deploys", list)):
        if not isinstance(manifest.get(key), kind):
            raise ContractError(f"Manifest field {key!r} must be a {kind.__name__}")
    for resource in manifest["resources"]:
        if not isinstance(resource, dict) or resource.get("type") not in RESOURCE_TYPES or not resource.get("name"):
            raise ContractError(f"Manifest resource {resource!r} is malformed")
    for field, keys in (("revisions", REPOSITORIES), ("components", COMPONENTS)):
        if set(manifest[field]) != set(keys):
            raise ContractError(f"Manifest {field} must have exactly {', '.join(keys)}")
        for value in manifest[field].values():
            if not isinstance(value, dict):
                raise ContractError(f"Manifest {field} entry {value!r} is malformed")
            if field == "components" and value.get("sha") == UNKNOWN_SHA:
                revision(value.get("branch"), "0" * 40)
            else:
                revision(value.get("branch"), value.get("sha"))
            if field == "revisions" and value.get("unconfirmed", True) is not True:
                raise ContractError(f"Manifest revisions entry {value!r} has a malformed unconfirmed flag")
    return manifest


def with_state(manifest, state):
    if state not in STATES:
        raise ContractError(f"Unknown devbox state {state!r}")
    updated = copy.deepcopy(manifest)
    updated["state"] = state
    return validate_manifest(updated)


def parse_components(value):
    selected = {part.strip() for part in (value or "").split(",") if part.strip()}
    if selected == {"all"}:
        return list(COMPONENTS)
    unknown = sorted(selected - set(COMPONENTS))
    if not selected or unknown:
        raise ContractError(
            f"Components must be 'all' or a comma-separated subset of {', '.join(COMPONENTS)}"
            + (f"; unknown: {', '.join(unknown)}" if unknown else ""))
    return [component for component in COMPONENTS if component in selected]


def component_scripts(components):
    return [script for component in components for script in COMPONENT_SCRIPTS[component]]


def record_deploy(manifest, *, at, actor, components, revisions, migrations, result,
                  checked_out=None, deployed=None, unconfirmed=(), in_flight=None):
    """Append a deploy and move only what is confirmed to have changed.

    `revisions` is what the deploy targeted. `checked_out` lists the
    repositories confirmed at the target and `deployed` the components whose
    install finished. A failed deploy must also say which targeted
    repositories it could not confirm either way (`unconfirmed`, kept at their
    previous revision and flagged) and which component's install was running
    when it stopped (`in_flight`, recorded with an unknown SHA).
    """
    if migrations not in MIGRATION_RESULTS:
        raise ContractError(f"Unknown migration result {migrations!r}")
    if result not in DEPLOY_RESULTS:
        raise ContractError(f"Unknown deploy result {result!r}")
    repositories = {COMPONENT_REPOSITORIES[component] for component in components}
    if set(revisions) != repositories:
        raise ContractError(f"Deploy of {', '.join(components)} must resolve exactly {', '.join(sorted(repositories))}")
    if result == "failed" and (checked_out is None or deployed is None):
        raise ContractError("A failed deploy must record which checkouts and components it moved")
    checked_out = set(revisions if checked_out is None else checked_out)
    deployed = set(components if deployed is None else deployed)
    if not checked_out <= repositories or not deployed <= set(components) \
            or any(COMPONENT_REPOSITORIES[component] not in checked_out for component in deployed):
        raise ContractError("Deployed components must be a targeted subset built from checked-out repositories")
    unconfirmed = set(unconfirmed)
    if unconfirmed & checked_out or not unconfirmed <= repositories:
        raise ContractError("Unconfirmed repositories must be targeted and not confirmed checked out")
    if in_flight is not None and (in_flight not in components or in_flight in deployed
                                  or COMPONENT_REPOSITORIES[in_flight] not in checked_out):
        raise ContractError(f"In-flight component {in_flight!r} must be targeted, not deployed, "
                            "and built from a checked-out repository")
    if result == "succeeded" and (checked_out != repositories or deployed != set(components)
                                  or unconfirmed or in_flight is not None):
        raise ContractError("A succeeded deploy must have checked out and deployed everything it targeted")
    updated = copy.deepcopy(manifest)
    target = {key: revision(value["branch"], value["sha"]) for key, value in revisions.items()}
    updated["deploys"].append({
        "at": iso(at),
        "actor": actor,
        "components": list(components),
        "from": {key: value["sha"] for key, value in updated["revisions"].items()},
        "to": {key: value["sha"] for key, value in {**updated["revisions"], **target}.items()},
        "migrations": migrations,
        "result": result,
    })
    updated["revisions"].update({key: target[key] for key in checked_out})
    for key in unconfirmed:
        updated["revisions"][key] = {**updated["revisions"][key], "unconfirmed": True}
    for component in components:
        if component in deployed:
            updated["components"][component] = dict(target[COMPONENT_REPOSITORIES[component]])
    if in_flight is not None:
        updated["components"][in_flight] = {"branch": target[COMPONENT_REPOSITORIES[in_flight]]["branch"],
                                            "sha": UNKNOWN_SHA}
    updated["state"] = "ready" if result == "succeeded" else "failed"
    return validate_manifest(updated)


def forwarding_command(name, zone, project=PROJECT):
    validate_zone(zone)
    forwards = " ".join(f"-L {port}:127.0.0.1:{port}" for _, port in FORWARDED_PORTS)
    return (f"gcloud compute ssh {instance_name(name)} --zone={zone} --project={project} "
            f"--tunnel-through-iap -- -N {forwards}")
