#!/usr/bin/env python3
"""Create devboxes and deploy selected revisions to them from GitHub Actions.

Runs on the credentialed runner from main only. It never executes code from
the selected branches: branches are resolved to SHAs here, then checked out
and built on the box, whose service account has no project permissions. The
runner's cloud credentials are used for provisioning, labels, metadata and
IAP SSH.

Subcommands:
  prepare-create  validate create inputs and resolve SHAs (no cloud access)
  create          provision, install and record a new devbox
  finish-create   mark a cancelled or timed-out create failed
  prepare-deploy  validate deploy inputs and resolve SHAs (no cloud access)
  deploy          deploy selected components to an existing devbox
  finish-deploy   mark a cancelled or timed-out deploy failed
"""

import argparse
import json
import secrets
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).parent))
import devbox_contract as contract


GITHUB_REPOSITORIES = {"sandbox": "superserve-ai/sandbox", "ui": "superserve-ai/superserve"}
SOURCE_DIRS = {"sandbox": "sandbox", "ui": "superserve"}
PROFILE_PATH = Path(__file__).resolve().parents[3] / "deploy" / "devbox" / "profile.json"
SECRET_PREFIX = "DEVBOX_SECRET_"
CONFIG_PREFIX = "DEVBOX_CONFIG_"
DEPLOYABLE_STATES = ("ready", "failed")
LOG_DIR = "/var/log/superserve-devbox"
API_DEPLOY_FILE = contract.BOX_STATE_DIR + "/api-deploy.json"
SSH_ATTEMPTS = 40
SSH_RETRY_SECONDS = 15
# Kept below the job's timeout-minutes so a slow step fails here, with the box
# marked failed, rather than being killed by the runner.
DEADLINE_SECONDS = 160 * 60
# Reporting a failure gets its own budget, so a deadline hit at 160 minutes
# still records it, with room for job setup and the backstop step, before the
# job's 180-minute timeout.
REPORT_SECONDS = 10 * 60
MAX_STATE_BYTES = 32 * 1024


class StepError(Exception):
    pass


def describe(error):
    if isinstance(error, (StepError, contract.ContractError)):
        return str(error)
    return f"{type(error).__name__}: {error}"


class DeadlineExceeded(StepError):
    pass


class Deadline:
    end = None

    reporting = False

    def start(self, seconds):
        self.end = time.monotonic() + seconds

    def report(self):
        if not self.reporting:
            self.reporting = True
            self.start(REPORT_SECONDS)

    def cap(self, timeout):
        if self.end is None:
            return timeout
        remaining = int(self.end - time.monotonic())
        if remaining <= 0:
            raise DeadlineExceeded("Ran out of time before the job timeout")
        return min(timeout, remaining)


DEADLINE = Deadline()


def run(args, *, input=None, capture=True, timeout=600):
    timeout = DEADLINE.cap(timeout)
    try:
        result = subprocess.run(args, input=input, capture_output=capture, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise StepError(f"{' '.join(args[:4])} timed out after {timeout}s") from None
    if result.returncode:
        detail = (result.stderr or "").strip() if capture else ""
        raise StepError(f"{' '.join(args[:4])} failed (exit {result.returncode})"
                        + (f": {detail}" if detail else ""))
    return result


def require_main(env):
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise StepError(f"Devbox workflows only run from main, not {env.get('GITHUB_REF')!r}")


def resolve_branch(key, branch):
    branch = (branch or "").strip() or "main"
    check = subprocess.run(["git", "check-ref-format", "--branch", branch], capture_output=True, text=True)
    if check.returncode or not contract.BRANCH_PATTERN.fullmatch(branch):
        raise StepError(f"{key} branch {branch!r} is not a valid branch name (letters, digits, '.', '_', '-', '/')")
    url = f"https://github.com/{GITHUB_REPOSITORIES[key]}.git"
    ref = f"refs/heads/{branch}"
    result = subprocess.run(["git", "ls-remote", "--exit-code", url, ref], capture_output=True, text=True, timeout=60)
    if result.returncode and result.returncode != 2:
        raise StepError(f"Could not resolve {key} branch {branch!r}: {result.stderr.strip()}")
    # ls-remote matches ref suffixes, so refs/heads/x/refs/heads/main also
    # matches "refs/heads/main"; only an exact ref counts.
    shas = [line.split("\t", 1)[0] for line in result.stdout.splitlines() if line.split("\t", 1)[-1] == ref]
    if not shas:
        raise StepError(f"{key} branch {branch!r} does not exist in {GITHUB_REPOSITORIES[key]}")
    return contract.revision(branch, shas[0])


def require_scripts_at(key, sha, scripts):
    # Lists the commit's tree without checking it out, so no branch code runs
    # on the runner and nothing is provisioned for a revision that can't work.
    url = f"https://github.com/{GITHUB_REPOSITORIES[key]}.git"
    with tempfile.TemporaryDirectory() as directory:
        for args in (["git", "init", "-q", "--bare", directory],
                     ["git", "-C", directory, "fetch", "-q", "--depth=1", "--filter=blob:none", url, sha]):
            result = subprocess.run(args, capture_output=True, text=True, timeout=300)
            if result.returncode:
                raise StepError(f"Could not read {key} {sha}: {result.stderr.strip()}")
        listing = subprocess.run(["git", "-C", directory, "ls-tree", "--name-only", "FETCH_HEAD", "deploy/devbox/"],
                                 capture_output=True, text=True, timeout=60)
    present = {Path(line).name for line in listing.stdout.splitlines()}
    missing = [script for script in scripts if script not in present]
    if listing.returncode or missing:
        raise StepError(f"{key} {sha} does not contain the devbox scripts this workflow runs: "
                        f"{', '.join(missing) or 'deploy/devbox'}")


def write_outputs(env, values):
    with open(env["GITHUB_OUTPUT"], "a") as output:
        for key, value in values.items():
            if "\n" in str(value):
                raise StepError(f"Output {key} contains a newline")
            output.write(f"{key}={value}\n")


def append_summary(env, text):
    path = env.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as summary:
            summary.write(text.rstrip() + "\n")
    print(text)


def prepare_create(env, profile_path=PROFILE_PATH):
    require_main(env)
    load_profile(profile_path)
    owner = contract.normalize_owner(env.get("GITHUB_ACTOR"))
    name = contract.resolve_name(env.get("INPUT_NAME"), owner)
    lifetime = contract.parse_lifetime_hours(env.get("INPUT_LIFETIME_HOURS"))
    sandbox = resolve_branch("sandbox", env.get("INPUT_SANDBOX_BRANCH"))
    ui = resolve_branch("ui", env.get("INPUT_UI_BRANCH"))
    require_scripts_at("sandbox", sandbox["sha"], contract.CREATE_SCRIPTS)
    write_outputs(env, {
        "name": name, "owner": owner, "lifetime_hours": lifetime,
        "sandbox_branch": sandbox["branch"], "sandbox_sha": sandbox["sha"],
        "ui_branch": ui["branch"], "ui_sha": ui["sha"],
    })
    append_summary(env, f"## Devbox `{name}`\n\nsandbox `{sandbox['branch']}` @ `{sandbox['sha']}`, "
                        f"ui `{ui['branch']}` @ `{ui['sha']}`, lifetime {lifetime}h")


def prepare_deploy(env):
    require_main(env)
    name = contract.validate_name((env.get("INPUT_NAME") or "").strip())
    components = contract.parse_components(env.get("INPUT_COMPONENTS"))
    keys = sorted({contract.COMPONENT_REPOSITORIES[component] for component in components})
    outputs = {"name": name, "components": ",".join(components)}
    for key in ("sandbox", "ui"):
        if key in keys:
            resolved = resolve_branch(key, env.get(f"INPUT_{key.upper()}_BRANCH"))
            outputs[f"{key}_branch"], outputs[f"{key}_sha"] = resolved["branch"], resolved["sha"]
        else:
            outputs[f"{key}_branch"] = outputs[f"{key}_sha"] = ""
    if outputs["sandbox_sha"]:
        require_scripts_at("sandbox", outputs["sandbox_sha"], contract.component_scripts(components))
    write_outputs(env, outputs)
    append_summary(env, f"## Deploy to devbox `{name}`\n\ncomponents: {', '.join(components)}")


def load_profile(path=PROFILE_PATH):
    try:
        profile = json.loads(Path(path).read_text())
        instance, boot, data, bucket = (profile[key] for key in ("instance", "boot_disk", "data_disk", "bucket"))
        expected = {
            "schema_version": (profile.get("schema_version"), 1),
            "project": (profile.get("project"), contract.PROJECT),
            "zone": (profile.get("zone"), contract.ZONE),
            "resource_name_prefix": (profile.get("resource_name_prefix"), contract.RESOURCE_PREFIX),
            "data_disk.name_suffix": (data.get("name_suffix"), contract.DATA_DISK_SUFFIX),
            "data_disk.device_name": (data.get("device_name"), contract.DATA_DISK_DEVICE_NAME),
            "bucket.name_prefix": (bucket.get("name_prefix"), contract.BUCKET_PREFIX),
            "labels.managed-by": ((profile.get("labels") or {}).get("managed-by"), contract.MANAGED_BY),
            "instance.external_ip": (instance.get("external_ip"), False),
            "instance.metadata.enable-oslogin": ((instance.get("metadata") or {}).get("enable-oslogin"), "TRUE"),
            "instance.metadata.block-project-ssh-keys":
                ((instance.get("metadata") or {}).get("block-project-ssh-keys"), "TRUE"),
            "boot_disk.auto_delete": (boot.get("auto_delete"), False),
            "data_disk.auto_delete": (data.get("auto_delete"), False),
        }
        for key in ("machine_type", "image_project", "image_family", "subnetwork", "service_account"):
            expected[f"instance.{key}"] = (bool(instance.get(key)), True)
        for section, keys in (("boot_disk", ("type", "size_gb")), ("data_disk", ("type", "size_gb")),
                              ("bucket", ("location", "storage_class"))):
            for key in keys:
                expected[f"{section}.{key}"] = (bool(profile[section].get(key)), True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise StepError(f"Could not read devbox profile {path}: {error!r}") from None
    wrong = [key for key, (actual, wanted) in expected.items() if actual != wanted]
    if wrong:
        raise StepError(f"Devbox profile {path} disagrees with the devbox contract on {', '.join(wrong)}")
    leaked = sorted(set(profile["labels"]) & set(contract.FORBIDDEN_LABELS))
    if leaked:
        raise StepError(f"Devbox profile must not set deployment discovery labels {leaked}")
    return profile


def env_file(values):
    lines = []
    for key, value in sorted(values.items()):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise StepError(f"Invalid environment key {key!r}")
        if "\n" in value or "\r" in value:
            raise StepError(f"Value for {key} contains a newline")
        lines.append(f"{key}={shlex.quote(value)}")
    return "".join(line + "\n" for line in lines)


def prefixed(env, prefix, kind):
    values = {key[len(prefix):]: value for key, value in env.items() if key.startswith(prefix)}
    empty = sorted(key for key, value in values.items() if not value)
    if empty:
        raise StepError(f"devbox environment {kind} not configured: {', '.join(empty)}")
    return values


class Box:
    """One devbox, reached over IAP SSH with the runner's credentials."""

    def __init__(self, name, zone=contract.ZONE, project=contract.PROJECT, devbox_id=None):
        self.name, self.zone, self.project = name, zone, project
        self.instance = contract.instance_name(name)
        self.where = [f"--zone={zone}", f"--project={project}"]
        # Once known, every step that changes the box first re-reads its labels:
        # steps can take many minutes, and a box replaced meanwhile must never be
        # touched under the old identity.
        self.devbox_id = devbox_id

    def guard(self):
        if self.devbox_id is not None:
            self.verify(self.devbox_id)

    def ssh(self, command, *, input=None, capture=True, timeout=600):
        return run(["gcloud", "compute", "ssh", self.instance, *self.where, "--quiet", "--tunnel-through-iap",
                    "--ssh-key-expire-after=4h", "--ssh-flag=-o ServerAliveInterval=30",
                    "--ssh-flag=-o ServerAliveCountMax=6", "--command", command],
                   input=input, capture=capture, timeout=timeout)

    def wait_for_ssh(self, attempts=SSH_ATTEMPTS, delay=SSH_RETRY_SECONDS):
        for attempt in range(1, attempts + 1):
            try:
                self.ssh("true", timeout=120)
                return
            except DeadlineExceeded:
                raise
            except StepError as error:
                print(f"waiting for SSH over IAP ({attempt}/{attempts}): {error}")
                if attempt < attempts:
                    time.sleep(DEADLINE.cap(delay))
        raise StepError(f"{self.name} did not accept SSH over IAP")

    def describe(self):
        result = run(["gcloud", "compute", "instances", "describe", self.instance, *self.where, "--format=json"])
        return json.loads(result.stdout)

    def verify(self, devbox_id):
        instance = self.describe()
        contract.check_labels(instance.get("labels"), self.name, devbox_id)
        return instance

    def write_file(self, path, content, mode):
        self.guard()
        directory = os.path.dirname(path)
        script = (f"set -eu; umask 077; install -d -m 0755 {shlex.quote(directory)}; "
                  f"cat > {shlex.quote(path + '.new')}; chmod {mode} {shlex.quote(path + '.new')}; "
                  f"mv -f {shlex.quote(path + '.new')} {shlex.quote(path)}")
        self.ssh("sudo sh -c " + shlex.quote(script), input=content)

    def read_json(self, path, timeout=600):
        result = self.ssh("sudo cat " + shlex.quote(path), timeout=timeout)
        if len(result.stdout.encode()) > MAX_STATE_BYTES:
            raise StepError(f"{path} on {self.name} is larger than {MAX_STATE_BYTES} bytes")
        try:
            value = json.loads(result.stdout)
        except ValueError:
            raise StepError(f"{path} on {self.name} is not valid JSON") from None
        if not isinstance(value, dict):
            raise StepError(f"{path} on {self.name} is not a JSON object")
        return value

    def remove(self, path):
        self.guard()
        self.ssh("sudo rm -f " + shlex.quote(path))

    def head(self, key):
        source = f"{contract.BOX_SOURCE_DIR}/{SOURCE_DIRS[key]}"
        result = self.ssh(f"sudo git -C {shlex.quote(source)} rev-parse HEAD 2>/dev/null || true", timeout=60)
        return result.stdout.strip()

    def checkout(self, key, sha):
        self.guard()
        source = f"{contract.BOX_SOURCE_DIR}/{SOURCE_DIRS[key]}"
        url = f"https://github.com/{GITHUB_REPOSITORIES[key]}.git"
        script = "; ".join([
            "set -eu",
            "command -v git >/dev/null || { apt-get update -qq && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }",
            f"install -d -m 0755 {shlex.quote(contract.BOX_SOURCE_DIR)}",
            f"[ -d {shlex.quote(source + '/.git')} ] || git init -q {shlex.quote(source)}",
            f"git -C {shlex.quote(source)} fetch -q --depth 1 {shlex.quote(url)} {sha}",
            f"git -C {shlex.quote(source)} checkout -q --force --detach {sha}",
            f"git -C {shlex.quote(source)} clean -qffd",
            f"test \"$(git -C {shlex.quote(source)} rev-parse HEAD)\" = {sha}",
        ])
        print(f"checking out {key} {sha} on {self.name}")
        self.ssh("sudo sh -c " + shlex.quote(script), timeout=1800)

    def require_scripts(self, scripts):
        paths = " ".join(shlex.quote(f"{contract.BOX_SCRIPT_DIR}/{script}") for script in scripts)
        try:
            self.ssh(f"for script in {paths}; do sudo test -f \"$script\" || "
                     "{ echo \"missing $script\" >&2; exit 1; }; done")
        except StepError as error:
            raise StepError("The selected sandbox revision does not contain the devbox scripts "
                            f"this workflow runs: {error}") from None

    def run_script(self, script):
        self.guard()
        path = f"{contract.BOX_SCRIPT_DIR}/{script}"
        log = f"{LOG_DIR}/{script.removesuffix('.sh')}.log"
        command = (f"set -eu -o pipefail; install -d -m 0755 {LOG_DIR}; "
                   f"echo \"=== $(date -u +%FT%TZ) {script}\" >> {shlex.quote(log)}; "
                   f"bash {shlex.quote(path)} 2>&1 | tee -a {shlex.quote(log)}")
        token = secrets.token_hex(16)
        print(f"::group::{script}", flush=True)
        print(f"::stop-commands::{token}", flush=True)
        try:
            self.ssh("sudo bash -c " + shlex.quote(command), input="", capture=False, timeout=3600)
        except StepError as error:
            raise StepError(f"{script} failed on {self.name}; see {log} on the box ({error})") from None
        finally:
            print(f"\n::{token}::", flush=True)
            print("::endgroup::", flush=True)

    def record(self, manifest, devbox_id, *, copy_to_box=True):
        contract.validate_manifest(manifest)
        self.verify(devbox_id)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest, sort_keys=True))
            run(["gcloud", "compute", "instances", "add-metadata", self.instance, *self.where,
                 f"--metadata-from-file={contract.MANIFEST_METADATA_KEY}={path}"])
        if copy_to_box:
            # The metadata is authoritative; a lost on-box copy must not turn
            # a recorded outcome into a failure.
            try:
                self.write_file(f"{contract.BOX_CONFIG_DIR}/manifest.json",
                                json.dumps(manifest, indent=2) + "\n", "0644")
            except StepError as error:
                print(f"::warning::Could not copy the manifest to {self.name}: {error}")


def manifest_from(instance):
    items = (instance.get("metadata") or {}).get("items") or []
    raw = next((item.get("value") for item in items if item.get("key") == contract.MANIFEST_METADATA_KEY), None)
    if raw is None:
        raise StepError(f"{instance.get('name')} has no {contract.MANIFEST_METADATA_KEY} metadata")
    try:
        return contract.validate_manifest(json.loads(raw))
    except ValueError as error:
        raise StepError(f"{instance.get('name')} manifest is invalid: {error}") from None


def box_config(manifest, env):
    values = {
        "DEVBOX_NAME": manifest["name"],
        "DEVBOX_ID": manifest["devbox_id"],
        "DEVBOX_OWNER": manifest["owner"],
        "DEVBOX_PROJECT": manifest["project"],
        "DEVBOX_ZONE": manifest["zone"],
        "DEVBOX_BUCKET": contract.bucket_name(manifest["devbox_id"]),
        "DEVBOX_EXPIRES_AT": str(int(contract.parse_iso(manifest["expires_at"]).timestamp())),
        "DEVBOX_SRC_DIR": contract.BOX_SOURCE_DIR,
        "DEVBOX_SANDBOX_SHA": manifest["revisions"]["sandbox"]["sha"],
        "DEVBOX_UI_SHA": manifest["revisions"]["ui"]["sha"],
    }
    extra = prefixed(env, CONFIG_PREFIX, "variables")
    clash = sorted(set(extra) & set(values))
    if clash:
        raise StepError(f"devbox environment variables may not override {', '.join(clash)}")
    return {**values, **extra}


def configuration(manifest, env):
    return env_file(box_config(manifest, env)), env_file(prefixed(env, SECRET_PREFIX, "secrets"))


def deliver_configuration(box, files):
    devbox_env, secrets_env = files
    box.write_file(f"{contract.BOX_CONFIG_DIR}/devbox.env", devbox_env, "0644")
    box.write_file(f"{contract.BOX_CONFIG_DIR}/secrets.env", secrets_env, "0600")


def collect_state(box, manifest):
    updated = dict(manifest)
    updated["runtime"] = box.read_json(f"{contract.BOX_STATE_DIR}/runtime.json")
    updated["services"] = box.read_json(f"{contract.BOX_STATE_DIR}/services.json")
    return contract.validate_manifest(updated)


def ensure_unused(name, project=contract.PROJECT):
    instance, data = contract.instance_name(name), contract.data_disk_name(name)
    instances = run(["gcloud", "compute", "instances", "list", f"--project={project}",
                     f"--filter=name={instance} OR labels.devbox-name={name}", "--format=value(name,zone.basename())"])
    disks = run(["gcloud", "compute", "disks", "list", f"--project={project}",
                 f"--filter=name={instance} OR name={data} OR labels.devbox-name={name}",
                 "--format=value(name,zone.basename())"])
    taken = [line for line in (instances.stdout + disks.stdout).splitlines() if line.strip()]
    if taken:
        raise StepError(f"Devbox name {name} is already in use ({'; '.join(taken)}); pick another name "
                        "or destroy the existing box first")


def instance_args(name, profile, labels, manifest_path):
    instance, boot, data = profile["instance"], profile["boot_disk"], profile["data_disk"]
    args = ["gcloud", "compute", "instances", "create", contract.instance_name(name), f"--zone={contract.ZONE}",
            f"--project={contract.PROJECT}",
            f"--machine-type={instance['machine_type']}",
            f"--image-project={instance['image_project']}", f"--image-family={instance['image_family']}",
            f"--boot-disk-size={boot['size_gb']}GB", f"--boot-disk-type={boot['type']}",
            "--no-boot-disk-auto-delete",
            f"--disk=name={contract.data_disk_name(name)},device-name={data['device_name']},mode=rw,auto-delete=no",
            f"--service-account={instance['service_account']}",
            f"--scopes={','.join(instance.get('scopes') or ['cloud-platform'])}",
            f"--subnet={instance['subnetwork']}", "--no-address",
            f"--labels={contract.format_labels(labels)}",
            f"--metadata-from-file={contract.MANIFEST_METADATA_KEY}={manifest_path}",
            "--shielded-secure-boot", "--shielded-vtpm", "--shielded-integrity-monitoring"]
    if instance.get("enable_nested_virtualization"):
        args.append("--enable-nested-virtualization")
    if instance.get("min_cpu_platform"):
        args.append(f"--min-cpu-platform={instance['min_cpu_platform']}")
    if instance.get("network_tags"):
        args.append(f"--tags={','.join(instance['network_tags'])}")
    if instance.get("metadata"):
        args.append("--metadata=" + ",".join(f"{key}={value}" for key, value in sorted(instance["metadata"].items())))
    return args


def destroy_command(name):
    return (f"gh workflow run devbox-manage.yml --repo {GITHUB_REPOSITORIES['sandbox']} --ref main "
            f"-f action=destroy-named -f name={name}")


def access_section(name):
    ssh = f"gcloud compute ssh {contract.instance_name(name)} --zone={contract.ZONE} --project={contract.PROJECT} --tunnel-through-iap"
    ports = ", ".join(f"{label} {port}" for label, port in contract.FORWARDED_PORTS)
    return "\n".join([
        "### Access",
        f"Forward {ports} to localhost:",
        "```sh", contract.forwarding_command(name), "```",
        "Shell and logs:",
        "```sh", ssh, f"{ssh} -- 'sudo tail -n 200 -f {LOG_DIR}/*.log'", f"{ssh} -- sudo journalctl -f", "```",
        "Destroy:",
        "```sh", destroy_command(name), "```",
    ])


def manifest_details(manifest):
    return ("<details><summary>Manifest</summary>\n\n```json\n"
            + json.dumps(manifest, indent=2, sort_keys=True) + "\n```\n</details>")


def create(env, profile_path=PROFILE_PATH):
    require_main(env)
    name = contract.validate_name(env["NAME"])
    owner = contract.normalize_owner(env["OWNER"])
    lifetime = contract.parse_lifetime_hours(env["LIFETIME_HOURS"])
    revisions = {key: contract.revision(env[f"{key.upper()}_BRANCH"], env[f"{key.upper()}_SHA"])
                 for key in ("sandbox", "ui")}
    profile = load_profile(profile_path)
    devbox_id = contract.new_devbox_id()
    created_at = contract.utc_now()
    expires_at = contract.expiry(created_at, lifetime)
    labels = contract.labels(name, devbox_id, owner, expires_at)
    manifest = contract.new_manifest(name=name, devbox_id=devbox_id, owner=owner, actor=env["GITHUB_ACTOR"],
                                     created_at=created_at, expires_at=expires_at, revisions=revisions)
    # Built before anything exists, so a bad value (empty, multi-line, or
    # overriding a reserved key) is refused with nothing to clean up.
    files = configuration(manifest, env)
    box = Box(name)
    # A taken name belongs to another box; it must never reach the failure
    # path, whose summary prints a destroy command for the name.
    try:
        ensure_unused(name)
    except StepError as error:
        append_summary(env, f"# Devbox `{name}` was not created\n\n{error}")
        raise
    save_attempt(env, {"name": name, "devbox_id": devbox_id, "reported": False, "instance_started": False})
    try:
        where = [f"--zone={contract.ZONE}", f"--project={contract.PROJECT}"]
        data = profile["data_disk"]
        run(["gcloud", "compute", "disks", "create", contract.data_disk_name(name), *where,
             f"--size={data['size_gb']}GB", f"--type={data['type']}", f"--labels={contract.format_labels(labels)}"])
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True))
            save_attempt(env, {"name": name, "devbox_id": devbox_id, "reported": False, "instance_started": True})
            run(instance_args(name, profile, labels, manifest_path))
        run(["gcloud", "compute", "disks", "add-labels", box.instance, *where,
             f"--labels={contract.format_labels(labels)}"])
        bucket = "gs://" + contract.bucket_name(devbox_id)
        run(["gcloud", "storage", "buckets", "create", bucket, f"--project={contract.PROJECT}",
             f"--location={profile['bucket']['location']}",
             f"--default-storage-class={profile['bucket']['storage_class']}",
             "--uniform-bucket-level-access", "--public-access-prevention", "--soft-delete-duration=0"])
        run(["gcloud", "storage", "buckets", "update", bucket, "--update-labels=" + contract.format_labels(labels)])

        box.wait_for_ssh()
        box.devbox_id = devbox_id
        for key in ("sandbox", "ui"):
            box.checkout(key, revisions[key]["sha"])
        box.require_scripts(contract.CREATE_SCRIPTS)
        deliver_configuration(box, files)
        for script in contract.CREATE_SCRIPTS:
            box.run_script(script)
        manifest = contract.with_state(collect_state(box, manifest), "ready")
        box.record(manifest, devbox_id)
    except (Exception, KeyboardInterrupt) as error:
        report_create_failure(env, name, devbox_id, error, load_attempt(env).get("instance_started", True))
        return 1
    save_attempt(env, {"name": name, "devbox_id": devbox_id, "reported": True})

    append_summary(env, "\n".join([
        f"# Devbox `{name}` is ready",
        "",
        "| | |", "|--|--|",
        f"| Name | `{name}` |", f"| Zone | `{contract.ZONE}` |", f"| Owner | `{owner}` |",
        f"| Expires | {manifest['expires_at']} (lifetime {lifetime}h, auto-deleted) |",
        f"| sandbox | `{revisions['sandbox']['branch']}` @ `{revisions['sandbox']['sha']}` |",
        f"| ui | `{revisions['ui']['branch']}` @ `{revisions['ui']['sha']}` |",
        "",
        access_section(name),
        "",
        manifest_details(manifest),
    ]))
    return 0


def save_attempt(env, attempt):
    if env.get("DEVBOX_ATTEMPT_FILE"):
        path = Path(env["DEVBOX_ATTEMPT_FILE"])
        staged = path.with_name(path.name + ".new")
        staged.write_text(json.dumps(attempt))
        os.replace(staged, path)


def discover(name, devbox_id):
    # Ownership is this run's devbox-id only: labelled resources, disks attached
    # to a labelled instance (the boot disk is labelled just after the VM), and
    # the bucket whose name carries the id. Never match by box name.
    project = f"--project={contract.PROJECT}"
    owned = f"--filter=labels.devbox-id={devbox_id}"
    instances = json.loads(run(["gcloud", "compute", "instances", "list", project, owned, "--format=json"],
                               timeout=120).stdout or "[]")
    disks = json.loads(run(["gcloud", "compute", "disks", "list", project, owned, "--format=json"],
                           timeout=120).stdout or "[]")
    found, seen = [], set()

    def add(kind, resource_name, zone):
        if (kind, resource_name) not in seen:
            seen.add((kind, resource_name))
            found.append({"type": kind, "name": resource_name, "zone": zone})

    for instance in instances:
        zone = (instance.get("zone") or "").rsplit("/", 1)[-1]
        add("instance", instance["name"], zone)
        for disk in instance.get("disks") or []:
            add("disk", (disk.get("source") or "").rsplit("/", 1)[-1], zone)
    for disk in disks:
        add("disk", disk["name"], (disk.get("zone") or "").rsplit("/", 1)[-1])
    bucket = contract.bucket_name(devbox_id)
    exists = subprocess.run(["gcloud", "storage", "buckets", "describe", "gs://" + bucket, "--format=value(name)"],
                            capture_output=True, text=True, timeout=DEADLINE.cap(120))
    if exists.returncode == 0:
        found.append({"type": "bucket", "name": bucket})
    elif "not found" not in exists.stderr.lower():
        raise StepError(f"Could not check bucket {bucket}: {exists.stderr.strip()}")
    return found


def mark_failed(name, devbox_id):
    box = Box(name)
    try:
        manifest = manifest_from(box.verify(devbox_id))
        if manifest["state"] != "creating":
            return None, f"The instance is already {manifest['state']}; left unchanged"
        box.record(contract.with_state(manifest, "failed"), devbox_id, copy_to_box=False)
    except Exception as error:
        return False, f"Could not record state=failed on the instance: {describe(error)}"
    return True, ""


def report_create_failure(env, name, devbox_id, error, instance_started):
    DEADLINE.report()
    try:
        found = discover(name, devbox_id)
        discovery = ""
    except Exception as discover_error:
        found = contract.resources(name, devbox_id)
        discovery = f" (could not list them: {describe(discover_error)}; these may exist)"
    has_instance = any(resource["type"] == "instance" for resource in found)
    marked, note = mark_failed(name, devbox_id) if has_instance else (None, "")
    listing = "\n".join(f"- {resource['type']} `{resource['name']}`"
                        + (f" ({resource['zone']})" if resource.get("zone") else "") for resource in found)
    append_summary(env, "\n".join([
        f"# Devbox `{name}` failed",
        "",
        f"**Error:** {describe(error)}",
        *([f"**Warning:** {note}"] if note else []),
        "",
        f"The devbox is **not** ready. Resources of this attempt{discovery} (a resource still being created "
        "may not be listed yet):",
        listing or "- none",
        "",
        "Clean up with:",
        "```sh", destroy_command(name), "```",
    ]))
    # Settled only when a visible VM was marked failed or had already finished,
    # or no VM was ever requested; a VM that may still appear leaves the attempt
    # open so the backstop step looks again.
    settled = (has_instance and marked is not False) or not instance_started
    save_attempt(env, {"name": name, "devbox_id": devbox_id, "reported": settled,
                       "instance_started": instance_started})
    print(f"::error::Devbox {name} failed: {describe(error)}", file=sys.stderr)


def load_attempt(env):
    path = env.get("DEVBOX_ATTEMPT_FILE")
    if not path or not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text())


def finish_create(env):
    attempt = load_attempt(env)
    if attempt and not attempt["reported"]:
        report_create_failure(env, attempt["name"], attempt["devbox_id"],
                              StepError("The create run was cancelled or timed out"),
                              attempt.get("instance_started", True))


def find_box(name):
    result = run(["gcloud", "compute", "instances", "list", f"--project={contract.PROJECT}",
                  f"--filter={contract.discovery_filter(name)}", "--format=json"])
    instances = json.loads(result.stdout or "[]")
    for instance in instances:
        instance["zone"] = (instance.get("zone") or "").rsplit("/", 1)[-1]
    try:
        return contract.select_instance(instances, name)
    except contract.ContractError as error:
        raise StepError(str(error)) from None


def deploy_request(env):
    components = contract.parse_components(env["COMPONENTS"])
    keys = sorted({contract.COMPONENT_REPOSITORIES[component] for component in components})
    revisions = {key: contract.revision(env[f"{key.upper()}_BRANCH"], env[f"{key.upper()}_SHA"]) for key in keys}
    return contract.validate_name(env["NAME"]), components, revisions


def deploy(env, now=contract.utc_now):
    require_main(env)
    name, components, revisions = deploy_request(env)
    instance = find_box(name)
    box = Box(name, zone=instance["zone"])
    manifest = manifest_from(instance)
    devbox_id = contract.check_labels(instance.get("labels"), name, manifest["devbox_id"])
    box.devbox_id = devbox_id
    if manifest["state"] not in DEPLOYABLE_STATES:
        raise StepError(f"{name} is {manifest['state']}; deploys need one of {', '.join(DEPLOYABLE_STATES)}")
    if not manifest["runtime"]:
        raise StepError(f"{name} never finished its first install; destroy it and create a new box")
    if manifest["state"] == "failed" and components != list(contract.COMPONENTS):
        raise StepError(f"{name} is failed; recover it with components=all (passing the branches it should run) "
                        "so every component is reinstalled before it is marked ready again")
    if contract.parse_iso(manifest["expires_at"]) <= now():
        raise StepError(f"{name} expired at {manifest['expires_at']} and is due for deletion")
    files = configuration({**manifest, "revisions": {**manifest["revisions"], **revisions}}, env)

    box.wait_for_ssh(attempts=5)
    scripts = contract.component_scripts(components)
    if "sandbox" not in revisions:
        # The scripts then come from the box's current sandbox checkout, which
        # prepare could not see; check them before anything on the box changes.
        box.require_scripts(scripts)
    progress = {"checked_out": [], "deployed": [], "api_started": False, "in_flight": None}
    save = lambda: save_attempt(env, {"name": name, "devbox_id": devbox_id, "reported": False, "progress": progress})
    save()
    state, failure = manifest, None
    try:
        box.record(contract.with_state(manifest, "deploying"), devbox_id)
        for key in revisions:
            box.checkout(key, revisions[key]["sha"])
            progress["checked_out"].append(key)
            save()
        box.require_scripts(scripts)
        deliver_configuration(box, files)
        if "api" in components:
            box.remove(API_DEPLOY_FILE)
        for component in components:
            progress["in_flight"] = component
            save()
            for script in contract.COMPONENT_SCRIPTS[component]:
                if script == "install-api.sh":
                    progress["api_started"] = True
                    save()
                box.run_script(script)
            progress["deployed"].append(component)
            progress["in_flight"] = None
            save()
        state = collect_state(box, manifest)
    except (Exception, KeyboardInterrupt) as error:
        failure = error
    return conclude_deploy(env, box, manifest, state, devbox_id, components, revisions, progress, failure, now)


def conclude_deploy(env, box, manifest, state, devbox_id, components, revisions, progress, failure, now):
    DEADLINE.report()
    unconfirmed = []
    if failure is not None:
        # A dropped connection can hide a checkout that finished on the box, so
        # record what one read of the box shows, and never a revision it can't
        # confirm. The installer that was running gets an unknown SHA; the box
        # stays failed until a full deploy settles it.
        for key in revisions:
            if key in progress["checked_out"]:
                continue
            try:
                head = box.head(key)
            except Exception:
                head = ""
            if head == revisions[key]["sha"]:
                progress["checked_out"].append(key)
            elif head != manifest["revisions"][key]["sha"]:
                unconfirmed.append(key)
    migrations = "none"
    if progress["api_started"]:
        # install-api.sh ran, so without a readable report for this revision the
        # outcome is unknown: it may have been killed after migrations committed.
        migrations = read_migrations(box, revisions["sandbox"]["sha"]) or "unknown"
    recorded = contract.record_deploy(state, at=now(), actor=env["GITHUB_ACTOR"], components=components,
                                      revisions=revisions, migrations=migrations,
                                      result="failed" if failure else "succeeded",
                                      checked_out=progress["checked_out"], deployed=progress["deployed"],
                                      unconfirmed=unconfirmed,
                                      in_flight=progress.get("in_flight") if failure is not None else None)
    reported = True
    try:
        box.record(recorded, devbox_id)
    except Exception as error:
        failure, reported = failure or error, False
    save_attempt(env, {"name": box.name, "devbox_id": devbox_id, "reported": reported, "progress": progress})
    append_summary(env, deploy_summary(recorded, manifest, components, progress["deployed"], migrations, failure))
    if failure is not None:
        print(f"::error::Deploy to {box.name} failed: {describe(failure)}", file=sys.stderr)
        return 1
    return 0


def finish_deploy(env, now=contract.utc_now):
    path = env.get("DEVBOX_ATTEMPT_FILE")
    if not path or not Path(path).exists():
        return
    attempt = json.loads(Path(path).read_text())
    if attempt["reported"]:
        return
    name, components, revisions = deploy_request(env)
    instance = find_box(name)
    box = Box(name, zone=instance["zone"], devbox_id=attempt["devbox_id"])
    manifest = manifest_from(instance)
    contract.check_labels(instance.get("labels"), name, attempt["devbox_id"])
    if manifest["state"] == "deploying":
        conclude_deploy(env, box, manifest, manifest, attempt["devbox_id"], components, revisions,
                        attempt["progress"], StepError("The deploy run was cancelled or timed out"), now)


def read_migrations(box, sha):
    try:
        report = box.read_json(API_DEPLOY_FILE, timeout=120)
    except Exception:
        return None
    if report.get("sha") != sha or report.get("migrations") not in contract.MIGRATION_RESULTS:
        return None
    return report["migrations"]


def deploy_summary(manifest, before, components, deployed, migrations, failure):
    rows = []
    for component in contract.COMPONENTS:
        previous, current = before["components"][component], manifest["components"][component]
        if component in deployed:
            new = f"`{current['sha'][:12]}` (`{current['branch']}`)"
        elif current["sha"] == contract.UNKNOWN_SHA:
            new = "unknown (install interrupted; redeploy with components=all)"
        else:
            new = "not deployed" if component in components else "unchanged"
        rows.append(f"| {component} | `{previous['sha'][:12]}` (`{previous['branch']}`) | {new} |")
    services = manifest.get("services") or {}
    status = "failed" if failure else "succeeded"
    return "\n".join([
        f"# Deploy to `{manifest['name']}` {status}",
        "",
        *([f"**Error:** {describe(failure)}", ""] if failure else []),
        "| Component | Previous | New |", "|--|--|--|", *rows,
        "",
        f"**Migrations:** {migrations}",
        f"**State:** {manifest['state']} (expires {manifest['expires_at']}, unchanged)",
        "",
        "**Services (before this deploy):**" if failure else "**Services:**",
        "```json", json.dumps(services, indent=2, sort_keys=True), "```",
        "",
        access_section(manifest["name"]),
        "",
        manifest_details(manifest),
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("prepare-create", "create", "finish-create",
                                            "prepare-deploy", "deploy", "finish-deploy"))
    args = parser.parse_args(argv)
    env = dict(os.environ)
    try:
        if args.command == "prepare-create":
            prepare_create(env)
        elif args.command == "finish-create":
            DEADLINE.report()
            finish_create(env)
        elif args.command == "prepare-deploy":
            prepare_deploy(env)
        elif args.command == "finish-deploy":
            DEADLINE.report()
            finish_deploy(env)
        elif args.command == "create":
            DEADLINE.start(DEADLINE_SECONDS)
            return create(env)
        else:
            DEADLINE.start(DEADLINE_SECONDS)
            return deploy(env)
    except (StepError, contract.ContractError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
