"""Exercise the devbox create and deploy workflows against a mocked gcloud."""

from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import devbox_contract as contract
import devbox_workflow as workflow

ENSURE_UNUSED = workflow.ensure_unused


SANDBOX_SHA = "1" * 40
UI_SHA = "2" * 40
NEW_SHA = "3" * 40
PROFILE = {
    "schema_version": 1, "project": "rayai-dev", "region": "us-central1",
    "resource_name_prefix": "devbox-", "labels": {"managed-by": "superserve-devbox"},
    "instance": {"machine_type": "n2-standard-8", "enable_nested_virtualization": True,
                 "image_project": "ubuntu-os-cloud", "image_family": "ubuntu-2404-lts-amd64",
                 "network": "superserve-devbox", "subnetwork": "superserve-devbox-usc1", "external_ip": False,
                 "network_tags": ["superserve-devbox"],
                 "service_account": "devbox-vm@example-project.iam.gserviceaccount.com",
                 "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                 "metadata": {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE"}},
    "boot_disk": {"type": "pd-balanced", "size_gb": 50, "auto_delete": False},
    "data_disk": {"name_suffix": "-data", "type": "pd-balanced", "size_gb": 150, "device_name": "devbox-data",
                  "filesystem": "xfs", "mount_path": "/mnt/sandbox-data", "auto_delete": False},
    "bucket": {"name_prefix": "superserve-devbox-", "location": "us-central1", "storage_class": "STANDARD",
               "uniform_bucket_level_access": True, "public_access_prevention": "enforced",
               "soft_delete_retention_seconds": 0},
}
SECRETS = {"DEVBOX_SECRET_STRIPE_SECRET_KEY": "sk_test_example", "DEVBOX_SECRET_RECAPTCHA_API_KEY": "recaptcha-secret",
           "DEVBOX_CONFIG_STRIPE_PRO_MONTHLY_PRICE_ID": "price_example", "DEVBOX_CONFIG_BILLING_RESOURCE_CONFIG": "{\"cpu\": 1, \"memory_mib\": 1024}", "DEVBOX_CONFIG_RECAPTCHA_SITE_KEY": "site-key"}


class FakeCloud:
    """Stands in for gcloud, git ls-remote and the box behind IAP SSH."""

    def __init__(self, *, existing=(), branches=None, fail_script=None, migrations="applied", instances=None,
                 relabel_after=None, decoys=(), fail_after_create=False, expire_on_script=None):
        self.commands, self.inputs = [], {}
        self.decoys, self.fail_after_create, self.expire_on_script = decoys, fail_after_create, expire_on_script
        self.deployed_sha = NEW_SHA
        self.disks, self.buckets, self.unlabelled = [], [], set()
        self.disk_zones, self.deleted, self.stockout = {}, [], {}
        self.leak_boot_disk, self.created_at, self.vanished = False, {}, set()
        self.login_denials, self.ssh_ready, self.denied, self.script_denials = 0, False, [], 0
        self.relabel_after_checkouts = None
        self.pending_instance = False
        self.fail_disk_create = False
        self.box_missing = set()
        self.heads, self.drop_after_checkout = {"sandbox": SANDBOX_SHA, "superserve": UI_SHA}, False
        self.heads_unreadable = False
        self.repo_scripts = list(contract.CREATE_SCRIPTS)
        self.existing = list(existing)
        self.branches = branches if branches is not None else {"main": SANDBOX_SHA, "feature": NEW_SHA}
        self.fail_script, self.migrations = fail_script, migrations
        self.instances = instances or {}
        self.metadata_writes, self.box_files, self.scripts, self.checkouts = [], {}, [], []
        self.relabel_after = relabel_after

    def __call__(self, args, input=None, **kwargs):
        self.commands.append(args)
        ok = lambda stdout="": subprocess.CompletedProcess(args, 0, stdout, "")
        fail = lambda code=1, stderr="failed": subprocess.CompletedProcess(args, code, "", stderr)
        if args[:2] == ["git", "check-ref-format"]:
            return ok() if re.fullmatch(r"[A-Za-z0-9/_.-]+", args[-1]) and ".." not in args[-1] else fail()
        if args[:2] == ["git", "init"] or (args[0] == "git" and "fetch" in args):
            return ok()
        if args[0] == "git" and "ls-tree" in args:
            return ok("".join(f"deploy/devbox/{script}\n" for script in self.repo_scripts))
        if args[:2] == ["git", "ls-remote"]:
            refs = {f"refs/heads/{branch}": sha for branch, sha in self.branches.items()}
            refs.update({ref: "f" * 40 for ref in self.decoys})
            lines = [f"{sha}\t{ref}\n" for ref, sha in sorted(refs.items())
                     if ref == args[-1] or ref.endswith("/" + args[-1])]
            return ok("".join(lines)) if lines else fail(2, "")
        assert args[0] == "gcloud", args
        verb = args[1:4]
        zones = arg(args, "--zones").split(",") if any(a.startswith("--zones=") for a in args) else None
        in_zones = lambda zone: zones is None or zone.rsplit("/", 1)[-1] in zones
        if verb == ["compute", "instances", "list"]:
            if "--format=json" in args:
                return ok(json.dumps([i for i in self.instances.values() if in_zones(i["zone"])]))
            return ok("".join(f"{name}\tus-central1-a\n" for name in self.existing))
        if verb == ["compute", "disks", "list"]:
            if re.fullmatch(r"name=\S+", arg(args, "--filter")):
                wanted = arg(args, "--filter")[len("name="):]
                users = {d.get("source", "").rsplit("/", 1)[-1] for i in self.instances.values() for d in i["disks"]}
                return ok(json.dumps([{"name": name, "zone": f"projects/p/zones/{zone}",
                                       "creationTimestamp": self.created_at.get(name, "2026-01-01T00:00:00.000-07:00"),
                                       **({} if name in self.unlabelled else {"labels": {"devbox-id": "x"}}),
                                       **({"users": ["vm"]} if name in users else {})}
                                      for name, zone in self.disk_zones.items() if name == wanted and in_zones(zone)]))
            if "--format=json" in args:
                return ok(json.dumps([{"name": name, "zone": f"projects/p/zones/{zone}"}
                                      for name, zone in self.disk_zones.items()
                                      if name not in self.unlabelled and in_zones(zone)]))
            return ok()
        if verb == ["compute", "instances", "delete"]:
            self.deleted.append(("instance", args[4], arg(args, "--zone")))
            self.instances.pop(args[4], None)
            return ok()
        if verb == ["compute", "disks", "delete"] and args[4] in self.vanished:
            return fail(1, f"ERROR: (gcloud.compute.disks.delete) The resource '{args[4]}' was not found")
        if verb == ["compute", "disks", "delete"]:
            self.deleted.append(("disk", args[4], arg(args, "--zone")))
            self.disk_zones.pop(args[4], None)
            if args[4] in self.disks:
                self.disks.remove(args[4])
            return ok()
        if verb == ["compute", "disks", "add-labels"]:
            self.unlabelled.discard(args[4])
            return ok()
        if verb == ["compute", "disks", "create"]:
            if self.fail_disk_create:
                return fail(1, "quota exceeded")
            if self.stockout.get(arg(args, "--zone")) == "disk":
                return fail(1, "ERROR: (gcloud.compute.disks.create) ZONE_RESOURCE_POOL_EXHAUSTED")
            self.disks.append(args[4])
            self.disk_zones[args[4]] = arg(args, "--zone")
            return ok()
        if verb == ["storage", "buckets", "create"]:
            self.buckets.append(args[4])
            return ok()
        if verb == ["storage", "buckets", "describe"]:
            return ok(args[4]) if args[4] in self.buckets else fail(1, "ERROR: gs://x not found: 404.")
        if verb == ["compute", "instances", "create"]:
            labels = dict(pair.split("=") for pair in arg(args, "--labels").split(","))
            manifest = Path(arg(args, "--metadata-from-file").split("=", 1)[1]).read_text()
            zone = arg(args, "--zone")
            if self.stockout.get(zone) == "partial":
                self.materialize(args[4], labels, manifest, zone)
                return fail(1, "ERROR: (gcloud.compute.instances.create) ZONE_RESOURCE_POOL_EXHAUSTED")
            if self.stockout.get(zone) == "instance":
                if self.leak_boot_disk:
                    self.disk_zones[args[4]] = zone
                    self.unlabelled.add(args[4])
                    self.created_at[args[4]] = datetime.now(timezone.utc).isoformat()
                return fail(1, f"ERROR: (gcloud.compute.instances.create) The zone 'projects/p/zones/{zone}' does "
                               "not have enough resources available to fulfill the request. reason: stockout")
            if self.pending_instance:
                self.pending_instance = lambda: self.materialize(args[4], labels, manifest, zone)
                return fail(1, "operation still pending")
            self.materialize(args[4], labels, manifest, zone)
            return fail(1, "operation timed out") if self.fail_after_create else ok()
        if verb == ["compute", "instances", "describe"]:
            instance = self.instances[args[4]]
            if (self.relabel_after is not None and len(self.metadata_writes) >= self.relabel_after) or \
                    (self.relabel_after_checkouts is not None and len(self.checkouts) >= self.relabel_after_checkouts):
                instance = {**instance, "labels": {**instance["labels"], "devbox-id": "ffffffffffff"}}
            return ok(json.dumps(instance))
        if verb == ["compute", "instances", "add-metadata"]:
            value = Path(arg(args, "--metadata-from-file").split("=", 1)[1]).read_text()
            self.metadata_writes.append(json.loads(value))
            self.instances[args[4]]["metadata"] = {"items": [{"key": "devbox-manifest", "value": value}]}
            return ok()
        if verb == ["compute", "ssh", args[3]]:
            return self.ssh(args, args[args.index("--command") + 1], input, ok, fail)
        return ok()

    def materialize(self, name, labels, manifest, zone="us-central1-a"):
        disks = [{"boot": True, "source": f"projects/p/zones/{zone}/disks/{name}"},
                 {"source": f"projects/p/zones/{zone}/disks/{name}-data"}]
        self.instances[name] = {"name": name, "zone": f"projects/p/zones/{zone}", "labels": labels,
                                "metadata": {"items": [{"key": "devbox-manifest", "value": manifest}]},
                                "disks": disks}
        self.disks.append(name)
        self.disk_zones[name] = zone
        self.unlabelled.add(name)

    def ssh(self, args, command, input, ok, fail):
        if self.login_denials and command != "true" and self.ssh_ready:
            self.login_denials -= 1
            self.denied.append(command)
            return fail(1, "ERROR: (gcloud.compute.ssh) PERMISSION_DENIED: User does not have "
                           "compute.instances.osLogin permission.")
        self.inputs[command] = input
        if command == "true":
            self.ssh_ready = True
            return ok()
        target = re.search(r"mv -f \S+ (/\S+?)'?$", unquote(command))
        if target and input is not None and "cat >" in unquote(command):
            self.box_files[target.group(1)] = input
            return ok()
        if command.startswith("for script in"):
            missing = [script for script in self.box_missing if script in command]
            return fail(1, f"missing {missing[0]}") if missing else ok()
        if "rev-parse HEAD 2>/dev/null" in command:
            if self.heads_unreadable:
                return fail(255, "Connection timed out")
            return ok(self.heads.get(shlex.split(command)[3].rsplit("/", 1)[-1], "") + "\n")
        if "git -C" in unquote(command):
            sha = re.search(r"checkout -q --force --detach ([0-9a-f]{40})", unquote(command)).group(1)
            self.checkouts.append(sha)
            self.heads[re.search(r"src/(\w+)", unquote(command)).group(1)] = sha
            if self.drop_after_checkout:
                return fail(255, "Connection closed by remote host")
            return ok()
        script = re.search(r"deploy/devbox/([a-z-]+\.sh)'? 2>&1", unquote(command))
        if script and self.script_denials:
            self.script_denials -= 1
            self.denied.append(command)
            return fail(1, "ERROR: (gcloud.compute.ssh) PERMISSION_DENIED: User does not have "
                           "compute.instances.osLogin permission.")
        if script:
            self.scripts.append(script.group(1))
            if script.group(1) == self.expire_on_script:
                workflow.DEADLINE.end = 0
            if script.group(1) == "install-api.sh" and self.migrations is not None:
                self.box_files[workflow.API_DEPLOY_FILE] = json.dumps(
                    {"sha": self.deployed_sha, "migrations": self.migrations, "applied": []})
            return fail() if script.group(1) == self.fail_script else ok()
        if command.startswith("sudo rm -f"):
            self.box_files.pop(workflow.API_DEPLOY_FILE, None)
            return ok()
        if command.startswith("sudo cat"):
            path = shlex.split(command)[2]
            if path.endswith("runtime.json"):
                return ok(json.dumps({"firecracker": "1.10.1"}))
            if path.endswith("services.json"):
                return ok(json.dumps({"api": {"ready": True}}))
            return ok(self.box_files.get(path, ""))
        return ok()

    def gcloud(self, *verb):
        return [c for c in self.commands if c[0] == "gcloud" and c[1:1 + len(verb)] == list(verb)]


def arg(args, flag):
    return next(a.split("=", 1)[1] for a in args if a.startswith(flag + "="))


def unquote(command):
    return command.replace("'\"'\"'", "'")


class WorkflowCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.output, self.summary, self.profile = root / "output", root / "summary", root / "profile.json"
        self.output.write_text("")
        self.summary.write_text("")
        self.profile.write_text(json.dumps(PROFILE))
        patcher = patch.object(workflow.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(setattr, workflow.DEADLINE, "end", None)
        self.addCleanup(setattr, workflow.DEADLINE, "reporting", False)

    def env(self, **values):
        return {"GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "AWille-AI", "GITHUB_OUTPUT": str(self.output),
                "GITHUB_STEP_SUMMARY": str(self.summary), **SECRETS, **values}

    def outputs(self):
        return dict(line.split("=", 1) for line in self.output.read_text().splitlines())

    def run_with(self, cloud, function, *args, **kwargs):
        with patch.object(workflow.subprocess, "run", side_effect=cloud), \
             patch("sys.stdout", new=open(os.devnull, "w")), patch("sys.stderr", new=open(os.devnull, "w")):
            return function(*args, **kwargs)


class PrepareTests(WorkflowCase):
    def test_prepare_create_generates_name_and_resolves_shas(self):
        cloud = FakeCloud(branches={"main": SANDBOX_SHA, "feature": NEW_SHA})
        self.run_with(cloud, workflow.prepare_create, self.env(INPUT_NAME="", INPUT_SANDBOX_BRANCH="feature",
                                                            INPUT_UI_BRANCH="", INPUT_LIFETIME_HOURS="48"),
                      profile_path=self.profile)
        outputs = self.outputs()
        self.assertRegex(outputs["name"], r"^awille-ai-dev-[0-9a-f]{6}$")
        self.assertEqual(outputs["owner"], "awille-ai")
        self.assertEqual(outputs["lifetime_hours"], "48")
        self.assertEqual((outputs["sandbox_branch"], outputs["sandbox_sha"]), ("feature", NEW_SHA))
        self.assertEqual((outputs["ui_branch"], outputs["ui_sha"]), ("main", SANDBOX_SHA))
        self.assertEqual([c[:2] for c in cloud.commands if c[0] != "git"], [])
        self.assertIn(NEW_SHA, next(c for c in cloud.commands if "fetch" in c))

    def test_prepare_create_validates_the_zone(self):
        self.run_with(FakeCloud(), workflow.prepare_create, self.env(INPUT_ZONE="us-central1-b"),
                      profile_path=self.profile)
        self.assertEqual(self.outputs()["zone"], "us-central1-b")
        with self.assertRaises(contract.ContractError):
            self.run_with(FakeCloud(), workflow.prepare_create, self.env(INPUT_ZONE="us-east1-b"),
                          profile_path=self.profile)

    def test_create_zone_choices_match_the_contract(self):
        workflow_file = Path(workflow.__file__).resolve().parents[1] / "devbox-create.yml"
        options = re.search(r"      zone:\n(?:        .*\n)*?        options:\n((?:          - .*\n)+)",
                            workflow_file.read_text()).group(1)
        self.assertEqual(re.findall(r"- (\S+)", options), [contract.AUTO_ZONE, *contract.DEVBOX_ZONES])

    def test_prepare_create_refuses_revisions_without_the_box_scripts(self):
        cloud = FakeCloud()
        cloud.repo_scripts.remove("seed-base.sh")
        with self.assertRaisesRegex(workflow.StepError, "seed-base.sh"):
            self.run_with(cloud, workflow.prepare_create, self.env(), profile_path=self.profile)
        self.assertEqual(self.output.read_text(), "")
        with self.assertRaisesRegex(workflow.StepError, "devbox profile"):
            self.run_with(FakeCloud(), workflow.prepare_create, self.env(), profile_path=self.profile.with_name("x"))

    def test_branch_resolution_ignores_suffix_matches(self):
        cloud = FakeCloud(decoys=["refs/heads/evil/refs/heads/main"])
        self.assertEqual(self.run_with(cloud, workflow.resolve_branch, "sandbox", "main")["sha"], SANDBOX_SHA)
        cloud = FakeCloud(branches={}, decoys=["refs/heads/evil/refs/heads/main"])
        with self.assertRaisesRegex(workflow.StepError, "does not exist"):
            self.run_with(cloud, workflow.resolve_branch, "sandbox", "main")

    def test_prepare_create_rejects_bad_inputs(self):
        for values in ({"INPUT_SANDBOX_BRANCH": "missing"}, {"INPUT_UI_BRANCH": "a..b"}, {"INPUT_UI_BRANCH": "x`[y](z)"},
                       {"INPUT_LIFETIME_HOURS": "169"}, {"INPUT_NAME": "Bad_Name"},
                       {"GITHUB_REF": "refs/heads/feature"}):
            with self.subTest(values=values), self.assertRaises((workflow.StepError, contract.ContractError)):
                self.run_with(FakeCloud(), workflow.prepare_create, self.env(**values), profile_path=self.profile)

    def test_prepare_deploy_resolves_only_used_repositories(self):
        cloud = FakeCloud()
        self.run_with(cloud, workflow.prepare_deploy, self.env(INPUT_NAME="my-box", INPUT_COMPONENTS="ui",
                                                            INPUT_SANDBOX_BRANCH="missing", INPUT_UI_BRANCH="feature"))
        outputs = self.outputs()
        self.assertEqual(outputs["components"], "ui")
        self.assertEqual((outputs["ui_branch"], outputs["ui_sha"]), ("feature", NEW_SHA))
        self.assertEqual(outputs["sandbox_sha"], "")
        with self.assertRaises(contract.ContractError):
            self.run_with(FakeCloud(), workflow.prepare_deploy, self.env(INPUT_NAME="my-box", INPUT_COMPONENTS="db"))
        cloud = FakeCloud()
        cloud.repo_scripts.remove("install-ui.sh")
        with self.assertRaisesRegex(workflow.StepError, "install-ui.sh"):
            self.run_with(cloud, workflow.prepare_deploy, self.env(INPUT_NAME="my-box", INPUT_COMPONENTS="all"))


class CreateTests(WorkflowCase):
    def create_env(self, **values):
        return self.env(**{"NAME": "my-box", "OWNER": "awille-ai", "LIFETIME_HOURS": "24", "SANDBOX_BRANCH": "main",
                           "DEVBOX_CI_SERVICE_ACCOUNT": "devbox-ci@example-project.iam.gserviceaccount.com",
                           "DEVBOX_ENGINEER_MEMBERS": "group:engineers@example.com, user:someone@example.com",
                           "SANDBOX_SHA": SANDBOX_SHA, "UI_BRANCH": "main", "UI_SHA": UI_SHA, **values})

    def create(self, cloud, **values):
        return self.run_with(cloud, workflow.create, self.create_env(**values), profile_path=self.profile)

    def test_create_provisions_installs_and_records_ready(self):
        cloud = FakeCloud()
        self.assertEqual(self.create(cloud), 0)

        creates = [c[1:4] for c in cloud.commands if c[0] == "gcloud" and ("create" in c[1:4])]
        self.assertEqual(creates, [["compute", "disks", "create"], ["compute", "instances", "create"],
                                   ["storage", "buckets", "create"]])
        instance = cloud.gcloud("compute", "instances", "create")[0]
        self.assertEqual(instance[4], "devbox-my-box")
        self.assertEqual(cloud.gcloud("compute", "disks", "create")[0][4], "devbox-my-box-data")
        self.assertEqual(cloud.gcloud("compute", "disks", "add-labels")[0][4], "devbox-my-box")
        for flag in ("--no-address", "--no-boot-disk-auto-delete", "--enable-nested-virtualization",
                     "--disk=name=devbox-my-box-data,device-name=devbox-data,mode=rw,auto-delete=no",
                     "--subnet=superserve-devbox-usc1", "--tags=superserve-devbox",
                     "--metadata=block-project-ssh-keys=TRUE,enable-oslogin=TRUE"):
            self.assertIn(flag, instance)
        labelled = [arg(c, "--labels") for c in cloud.commands if any(a.startswith("--labels=") for a in c)]
        labelled += [arg(c, "--update-labels") for c in cloud.gcloud("storage", "buckets", "update")]
        self.assertEqual(len(labelled), 4)
        for labels in labelled:
            values = dict(pair.split("=") for pair in labels.split(","))
            self.assertEqual(set(values), set(contract.LABEL_KEYS))
            self.assertEqual(values["managed-by"], "superserve-devbox")
        devbox_id = dict(pair.split("=") for pair in labelled[0].split(","))["devbox-id"]
        self.assertIn(f"gs://superserve-devbox-{devbox_id}", cloud.gcloud("storage", "buckets", "create")[0])
        self.assertIn("--soft-delete-duration=0", cloud.gcloud("storage", "buckets", "create")[0])

        self.assertEqual(cloud.checkouts, [SANDBOX_SHA, UI_SHA])
        self.assertEqual(cloud.scripts, list(contract.CREATE_SCRIPTS))
        for args in cloud.gcloud("compute", "ssh"):
            self.assertIn("--tunnel-through-iap", args)
        binding = cloud.gcloud("compute", "instances", "add-iam-policy-binding")
        self.assertEqual(len(binding), 3)
        engineer_bindings = [(arg(b, "--member"), arg(b, "--role")) for b in binding[1:]]
        self.assertEqual(engineer_bindings, [("group:engineers@example.com", "roles/compute.osAdminLogin"),
                                             ("user:someone@example.com", "roles/compute.osAdminLogin")])
        self.assertTrue(all("--condition=None" in b for b in binding))
        for flag in ("devbox-my-box", "--member=serviceAccount:devbox-ci@example-project.iam.gserviceaccount.com",
                     "--role=roles/compute.osAdminLogin", "--condition=None"):
            self.assertIn(flag, binding[0])
        self.assertLess(cloud.commands.index(binding[0]), cloud.commands.index(cloud.gcloud("compute", "ssh")[0]))
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["state"], "ready")
        self.assertEqual(final["runtime"], {"firecracker": "1.10.1"})
        self.assertEqual(final["services"], {"api": {"ready": True}})
        self.assertEqual(final["revisions"], {"sandbox": {"branch": "main", "sha": SANDBOX_SHA},
                                              "ui": {"branch": "main", "sha": UI_SHA}})
        self.assertEqual(json.loads(cloud.box_files["/etc/superserve-devbox/manifest.json"]), final)
        summary = self.summary.read_text()
        self.assertIn("is ready", summary)
        self.assertIn(contract.forwarding_command("my-box", "us-central1-a"), summary)
        self.assertIn(workflow.destroy_command("my-box"), summary)

    def test_secrets_travel_over_stdin_only(self):
        cloud = FakeCloud()
        self.assertEqual(self.create(cloud), 0)
        secrets_file = cloud.box_files["/etc/superserve-devbox/secrets.env"]
        self.assertEqual(secrets_file, "RECAPTCHA_API_KEY=recaptcha-secret\nSTRIPE_SECRET_KEY=sk_test_example\n")
        devbox_env = cloud.box_files["/etc/superserve-devbox/devbox.env"]
        self.assertIn("STRIPE_PRO_MONTHLY_PRICE_ID=price_example\n", devbox_env)
        self.assertIn("""BILLING_RESOURCE_CONFIG='{"cpu": 1, "memory_mib": 1024}'\n""", devbox_env)
        self.assertIn(f"DEVBOX_SANDBOX_SHA={SANDBOX_SHA}\n", cloud.box_files["/etc/superserve-devbox/devbox.env"])
        command = next(c for c in cloud.inputs if "secrets.env" in c)
        self.assertIn("chmod 0600", command)
        for args in cloud.commands:
            self.assertFalse(any("sk_test_example" in a or "recaptcha-secret" in a for a in args), args)

    def test_bad_configuration_fails_before_provisioning(self):
        for values in ({"DEVBOX_SECRET_STRIPE_SECRET_KEY": ""}, {"DEVBOX_SECRET_STRIPE_SECRET_KEY": "sk_test\n"},
                       {"DEVBOX_CONFIG_BILLING_RESOURCE_CONFIG": '{\n  "cpu": 1\n}'}, {"DEVBOX_CONFIG_DEVBOX_ID": "x"},
                       {"DEVBOX_CI_SERVICE_ACCOUNT": ""}, {"DEVBOX_CI_SERVICE_ACCOUNT": "user:someone@example.com"},
                       {"DEVBOX_ENGINEER_MEMBERS": "engineers@example.com"},
                       {"DEVBOX_ENGINEER_MEMBERS": "group:a@example.com,allUsers"}):
            cloud = FakeCloud()
            with self.subTest(values=values), self.assertRaises(workflow.StepError):
                self.create(cloud, **values)
            self.assertEqual(cloud.commands, [])

    def test_optional_configuration_is_written_only_when_set(self):
        for value, expected in (("", None), ("0.0", "RECAPTCHA_SCORE_THRESHOLD=0.0\n")):
            cloud = FakeCloud()
            with self.subTest(value=value):
                self.create(cloud, DEVBOX_CONFIG_RECAPTCHA_SCORE_THRESHOLD=value)
                devbox_env = cloud.box_files["/etc/superserve-devbox/devbox.env"]
                if expected:
                    self.assertIn(expected, devbox_env)
                else:
                    self.assertNotIn("RECAPTCHA_SCORE_THRESHOLD", devbox_env)

    def test_no_engineer_members_still_creates_with_a_warning(self):
        cloud = FakeCloud()
        self.assertEqual(self.create(cloud, DEVBOX_ENGINEER_MEMBERS=""), 0)
        self.assertEqual(len(cloud.gcloud("compute", "instances", "add-iam-policy-binding")), 1)

    def test_auto_zone_moves_on_after_a_stockout_and_cleans_up(self):
        cloud = FakeCloud()
        cloud.stockout = {"us-central1-a": "instance", "us-central1-b": "disk"}
        self.assertEqual(self.create(cloud), 0)
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["zone"], "us-central1-c")
        self.assertEqual({r.get("zone") for r in final["resources"]}, {"us-central1-c", None})
        self.assertEqual(cloud.deleted, [("disk", "devbox-my-box-data", "us-central1-a")])
        self.assertEqual(cloud.disk_zones, {"devbox-my-box-data": "us-central1-c", "devbox-my-box": "us-central1-c"})
        self.assertEqual(len(cloud.gcloud("storage", "buckets", "create")), 1)
        for args in cloud.gcloud("compute", "ssh") + cloud.gcloud("compute", "instances", "add-iam-policy-binding"):
            self.assertIn("--zone=us-central1-c", args)
        summary = self.summary.read_text()
        self.assertIn("`us-central1-c` (after us-central1-a out of capacity, us-central1-b out of capacity)", summary)
        self.assertIn(contract.forwarding_command("my-box", "us-central1-c"), summary)
        self.assertIn("DEVBOX_ZONE=us-central1-c\n", cloud.box_files["/etc/superserve-devbox/devbox.env"])

    def test_a_detached_boot_disk_left_in_an_abandoned_zone_is_removed(self):
        cloud = FakeCloud()
        cloud.stockout, cloud.leak_boot_disk = {"us-central1-a": "instance"}, True
        self.assertEqual(self.create(cloud), 0)
        self.assertIn(("disk", "devbox-my-box", "us-central1-a"), cloud.deleted)
        self.assertEqual(cloud.disk_zones, {"devbox-my-box-data": "us-central1-b", "devbox-my-box": "us-central1-b"})

    def test_a_partly_created_vm_and_its_disks_are_removed_before_the_next_zone(self):
        cloud = FakeCloud()
        cloud.stockout = {"us-central1-a": "partial"}
        self.assertEqual(self.create(cloud), 0)
        self.assertEqual(cloud.deleted[:3], [("instance", "devbox-my-box", "us-central1-a"),
                                             ("disk", "devbox-my-box", "us-central1-a"),
                                             ("disk", "devbox-my-box-data", "us-central1-a")])
        self.assertEqual(cloud.metadata_writes[-1]["zone"], "us-central1-b")

    def test_a_disk_gone_during_cleanup_does_not_stop_the_next_zone(self):
        cloud = FakeCloud()
        cloud.stockout, cloud.vanished = {"us-central1-a": "instance"}, {"devbox-my-box-data"}
        self.assertEqual(self.create(cloud), 0)
        self.assertEqual(cloud.metadata_writes[-1]["zone"], "us-central1-b")

    def test_an_old_unlabelled_disk_with_the_box_name_is_left_alone(self):
        cloud = FakeCloud()
        cloud.stockout = {"us-central1-a": "instance"}
        cloud.disk_zones["devbox-my-box"] = "us-central1-a"
        cloud.unlabelled.add("devbox-my-box")
        workflow.ensure_unused = lambda name, project=contract.PROJECT: None
        self.addCleanup(setattr, workflow, "ensure_unused", ENSURE_UNUSED)
        self.assertEqual(self.create(cloud), 0)
        self.assertNotIn(("disk", "devbox-my-box", "us-central1-a"), cloud.deleted)

    def test_capacity_check_ignores_names_and_case(self):
        for text, capacity in (("ZONE_RESOURCE_POOL_EXHAUSTED", True), ("ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS", True),
                               ("reason: stockout", True),
                               ("The zone does not have enough resources available to fulfill the request.", True),
                               ("disk 'devbox-stockout-demo' already exists", False),
                               ("resource_exhausted", False), ("QUOTA_EXCEEDED", False)):
            with self.subTest(text=text):
                self.assertEqual(bool(workflow.CAPACITY_ERRORS.search(text)), capacity)

    def test_os_login_denials_after_the_first_connection_are_waited_out(self):
        cloud = FakeCloud()
        cloud.login_denials = 3
        self.assertEqual(self.create(cloud), 0)
        self.assertEqual(len(cloud.denied), 3)
        self.assertEqual(cloud.metadata_writes[-1]["state"], "ready")
        self.assertEqual(cloud.checkouts, [SANDBOX_SHA, UI_SHA])

    def test_a_denied_script_run_is_retried_not_blamed_on_the_script(self):
        cloud = FakeCloud()
        cloud.script_denials = 2
        self.assertEqual(self.create(cloud), 0)
        self.assertEqual(cloud.scripts, list(contract.CREATE_SCRIPTS))
        self.assertEqual(len(cloud.denied), 2)

    def test_error_annotations_cannot_start_workflow_commands(self):
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            workflow.annotate("error", "failed: x\n::warning::injected\r\n50%")
        self.assertEqual(stderr.getvalue(), "::error::failed: x%0A::warning::injected%0D%0A50%25\n")
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            workflow.echo("waiting: x\n  ::add-mask::secret\n##[warning]injected")
        lines = stdout.getvalue().splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        self.assertTrue(lines[0].startswith("::stop-commands::") and len(token) == 32)
        self.assertEqual(lines[-1], f"::{token}::")
        self.assertNotIn(token, "\n".join(lines[1:-1]))

    def test_script_runs_stream_output_and_keep_only_errors(self):
        seen = []

        def record(args, **kwargs):
            seen.append(kwargs)
            return subprocess.CompletedProcess(args, 0, None, "")

        with patch.object(workflow.subprocess, "run", side_effect=record):
            workflow.Box("my-box", "us-central1-a").run_script("install-vmd.sh")
        self.assertIsNone(seen[-1]["stdout"])
        self.assertEqual(seen[-1]["stderr"], subprocess.PIPE)

    def test_only_os_login_denials_count_as_settling(self):
        for text, settling in (("PERMISSION_DENIED: User does not have compute.instances.osLogin permission", True),
                               ("PERMISSION_DENIED: compute.instances.osLoginExternalUser", False),
                               ("PERMISSION_DENIED: compute.instances.setMetadata", False),
                               ("Permission denied (publickey).", False),
                               ("Error while connecting [4047: 'Failed to lookup instance']", False)):
            with self.subTest(text=text):
                self.assertEqual(bool(workflow.LOGIN_DENIED.search(text)), settling)

    def test_os_login_settling_is_waited_out_in_a_fallback_zone(self):
        cloud = FakeCloud()
        cloud.stockout, cloud.login_denials = {"us-central1-a": "instance"}, 2
        self.assertEqual(self.create(cloud), 0)
        self.assertEqual(len(cloud.denied), 2)
        self.assertEqual(cloud.metadata_writes[-1]["zone"], "us-central1-b")

    def test_os_login_denials_past_the_settling_window_fail(self):
        cloud = FakeCloud()
        cloud.login_denials = 100
        clock = [0.0]
        with patch.object(workflow.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(workflow.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            self.assertEqual(self.create(cloud), 1)
        self.assertGreater(len(cloud.denied), workflow.LOGIN_PROPAGATION_SECONDS // workflow.SSH_RETRY_SECONDS - 2)
        self.assertLessEqual(len(cloud.denied), workflow.LOGIN_PROPAGATION_SECONDS // workflow.SSH_RETRY_SECONDS + 1)
        self.assertIn("compute.instances.osLogin", self.summary.read_text())

    def test_explicit_zone_is_the_only_zone_tried(self):
        cloud = FakeCloud()
        cloud.stockout = {"us-central1-f": "instance"}
        self.assertEqual(self.create(cloud, ZONE="us-central1-f"), 1)
        self.assertEqual({arg(c, "--zone") for c in cloud.gcloud("compute", "disks", "create")}, {"us-central1-f"})
        self.assertEqual(cloud.deleted, [("disk", "devbox-my-box-data", "us-central1-f")])
        self.assertIn("us-central1-f: ", self.summary.read_text())

    def test_every_zone_out_of_capacity_reports_each_zone(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud()
        cloud.stockout = {zone: "instance" for zone in contract.DEVBOX_ZONES}
        self.assertEqual(self.create(cloud, DEVBOX_ATTEMPT_FILE=str(attempt)), 1)
        summary = self.summary.read_text()
        for zone in contract.DEVBOX_ZONES:
            self.assertIn(f"- {zone}: ", summary)
        self.assertEqual(cloud.disk_zones, {})
        self.assertEqual(cloud.instances, {})
        self.assertFalse(cloud.gcloud("storage", "buckets", "create"))
        self.assertTrue(json.loads(attempt.read_text())["reported"])

    def test_other_errors_do_not_try_another_zone(self):
        cloud = FakeCloud()
        cloud.fail_disk_create = True
        self.assertEqual(self.create(cloud), 1)
        self.assertEqual(len(cloud.gcloud("compute", "disks", "create")), 1)
        self.assertEqual(cloud.deleted, [])

    def test_name_collision_is_refused_without_offering_cleanup(self):
        cloud = FakeCloud(existing=["my-box"])
        with self.assertRaisesRegex(workflow.StepError, "already in use"):
            self.create(cloud)
        self.assertFalse([c for c in cloud.commands if "create" in c])
        self.assertIn("already in use", self.summary.read_text())
        self.assertNotIn("devbox-manage.yml", self.summary.read_text())
        self.assertFalse(cloud.gcloud("compute", "instances", "add-metadata"))

    def test_failed_install_marks_failed_and_reports_resources(self):
        cloud = FakeCloud(fail_script="install-api.sh")
        self.assertEqual(self.create(cloud), 1)
        self.assertEqual(cloud.scripts, ["host-bootstrap.sh", "services-up.sh", "install-api.sh"])
        self.assertEqual(cloud.metadata_writes[-1]["state"], "failed")
        summary = self.summary.read_text()
        self.assertNotIn("is ready", summary)
        for resource in ("disk `devbox-my-box-data`", "instance `devbox-my-box`", "disk `devbox-my-box`",
                         "bucket `superserve-devbox-"):
            self.assertIn(resource, summary)
        self.assertIn(workflow.destroy_command("my-box"), summary)

    def test_timed_out_instance_create_is_still_found_and_marked_failed(self):
        cloud = FakeCloud(fail_after_create=True)
        self.assertEqual(self.create(cloud), 1)
        self.assertEqual(cloud.metadata_writes[-1]["state"], "failed")
        summary = self.summary.read_text()
        self.assertIn("instance `devbox-my-box`", summary)
        self.assertIn("disk `devbox-my-box-data`", summary)
        self.assertIn("disk `devbox-my-box` ", summary)
        self.assertIn("devbox-my-box", cloud.unlabelled)
        self.assertNotIn("bucket `", summary)
        self.assertFalse([c for c in cloud.commands if any("name=" in a for a in c) and "list" in c
                          and any("devbox-id" in a for a in c)])

    def test_instance_not_yet_visible_leaves_the_backstop_armed(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud()
        cloud.pending_instance = True
        self.assertEqual(self.create(cloud, DEVBOX_ATTEMPT_FILE=str(attempt)), 1)
        self.assertFalse(json.loads(attempt.read_text())["reported"])
        cloud.pending_instance()
        self.run_with(cloud, workflow.finish_create, self.create_env(DEVBOX_ATTEMPT_FILE=str(attempt)))
        self.assertEqual(cloud.metadata_writes[-1]["state"], "failed")
        self.assertTrue(json.loads(attempt.read_text())["reported"])

    def test_failure_before_any_vm_is_requested_is_settled(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud()
        cloud.fail_disk_create = True
        self.assertEqual(self.create(cloud, DEVBOX_ATTEMPT_FILE=str(attempt)), 1)
        self.assertTrue(json.loads(attempt.read_text())["reported"])
        self.assertFalse(cloud.gcloud("compute", "instances", "create"))

    def test_interrupted_create_is_marked_failed_by_the_backstop(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud(fail_script="install-api.sh")
        self.create(cloud, DEVBOX_ATTEMPT_FILE=str(attempt))
        self.assertTrue(json.loads(attempt.read_text())["reported"])
        writes = len(cloud.metadata_writes)
        self.run_with(cloud, workflow.finish_create, self.create_env(DEVBOX_ATTEMPT_FILE=str(attempt)))
        self.assertEqual(len(cloud.metadata_writes), writes)

        devbox_id = json.loads(attempt.read_text())["devbox_id"]
        instance = cloud.instances["devbox-my-box"]
        manifest = json.loads(instance["metadata"]["items"][0]["value"])
        instance["metadata"]["items"][0]["value"] = json.dumps({**manifest, "state": "creating"})
        attempt.write_text(json.dumps({"name": "my-box", "devbox_id": devbox_id, "reported": False}))
        self.run_with(cloud, workflow.finish_create, self.create_env(DEVBOX_ATTEMPT_FILE=str(attempt)))
        self.assertEqual(cloud.metadata_writes[-1]["state"], "failed")
        self.assertIn("cancelled or timed out", self.summary.read_text())

    def test_deadline_still_leaves_the_box_marked_failed(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud(expire_on_script="install-api.sh")
        workflow.DEADLINE.start(3600)
        self.assertEqual(self.create(cloud, DEVBOX_ATTEMPT_FILE=str(attempt)), 1)
        self.assertEqual(cloud.scripts, ["host-bootstrap.sh", "services-up.sh", "install-api.sh"])
        self.assertEqual(cloud.metadata_writes[-1]["state"], "failed")
        self.assertIn("Ran out of time", self.summary.read_text())
        self.assertTrue(json.loads(attempt.read_text())["reported"])

    def test_box_replaced_during_a_checkout_is_not_touched_again(self):
        cloud = FakeCloud()
        cloud.relabel_after_checkouts = 1
        self.assertEqual(self.create(cloud), 1)
        self.assertEqual(cloud.checkouts, [SANDBOX_SHA])
        self.assertEqual(cloud.scripts, [])
        self.assertFalse([path for path in cloud.box_files if path.endswith(".env")])
        self.assertIn("devbox-id changed", self.summary.read_text())

    def test_replaced_box_is_never_written(self):
        cloud = FakeCloud(relabel_after=0)
        self.assertEqual(self.create(cloud), 1)
        self.assertEqual(cloud.scripts, [])
        self.assertEqual(cloud.metadata_writes, [])
        self.assertIn("devbox-id changed", self.summary.read_text())

    def test_profile_must_agree_with_the_contract(self):
        for profile in ({**PROFILE, "labels": {**PROFILE["labels"], "sandbox_role": "vmd"}},
                        {**PROFILE, "resource_name_prefix": "box-"},
                        {**PROFILE, "project": "other-project"},
                        {**PROFILE, "instance": {**PROFILE["instance"], "external_ip": True}},
                        {**PROFILE, "instance": {**PROFILE["instance"], "metadata": {}}},
                        {**PROFILE, "data_disk": {**PROFILE["data_disk"], "auto_delete": True}},
                        {key: value for key, value in PROFILE.items() if key != "bucket"}):
            self.profile.write_text(json.dumps(profile))
            cloud = FakeCloud()
            with self.subTest(profile=profile), self.assertRaises(workflow.StepError):
                self.create(cloud)
            self.assertEqual(cloud.commands, [])


class DeployTests(WorkflowCase):
    NOW = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)

    def box(self, state="ready", expires_hours=24, runtime=None, zone="us-central1-a", vm_zone=None):
        created = datetime(2026, 10, 20, 15, 0, tzinfo=timezone.utc)
        manifest = contract.new_manifest(
            name="my-box", devbox_id="3f9c0a1b2c4d", owner="awille-ai", actor="awille-ai", created_at=created,
            expires_at=contract.expiry(created, expires_hours), zone=zone,
            revisions={"sandbox": {"branch": "main", "sha": SANDBOX_SHA}, "ui": {"branch": "main", "sha": UI_SHA}})
        manifest = {**contract.with_state(manifest, state),
                    "runtime": {"firecracker": "1.10.1"} if runtime is None else runtime}
        labels = contract.labels("my-box", "3f9c0a1b2c4d", "awille-ai", contract.parse_iso(manifest["expires_at"]))
        return {"devbox-my-box": {"name": "devbox-my-box", "zone": f"projects/p/zones/{vm_zone or zone}", "labels": labels,
                           "metadata": {"items": [{"key": "devbox-manifest", "value": json.dumps(manifest)}]}}}

    def deploy(self, cloud, components="all", **values):
        env = self.env(**{"NAME": "my-box", "COMPONENTS": components, "SANDBOX_BRANCH": "feature",
                          "SANDBOX_SHA": NEW_SHA, "UI_BRANCH": "main", "UI_SHA": UI_SHA,
                          "GITHUB_ACTOR": "someone", **values})
        return self.run_with(cloud, workflow.deploy, env, now=lambda: self.NOW)

    def test_all_components_upgrade_in_contract_order(self):
        cloud = FakeCloud(instances=self.box())
        self.assertEqual(self.deploy(cloud), 0)
        listing = cloud.gcloud("compute", "instances", "list")[0]
        self.assertIn("--filter=labels.managed-by=superserve-devbox AND labels.devbox-name=my-box", listing)
        self.assertEqual(cloud.scripts, ["install-vmd.sh", "install-proxy.sh", "services-up.sh",
                                         "install-api.sh", "install-ui.sh"])
        self.assertEqual(cloud.checkouts, [NEW_SHA, UI_SHA])
        self.assertEqual([m["state"] for m in cloud.metadata_writes], ["deploying", "ready"])
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["expires_at"], "2026-10-21T15:00:00Z")
        self.assertEqual(final["revisions"]["sandbox"], {"branch": "feature", "sha": NEW_SHA})
        self.assertEqual(final["deploys"], [{
            "at": "2026-10-20T18:00:00Z", "actor": "someone", "components": ["vmd", "proxy", "api", "ui"],
            "from": {"sandbox": SANDBOX_SHA, "ui": UI_SHA}, "to": {"sandbox": NEW_SHA, "ui": UI_SHA},
            "migrations": "applied", "result": "succeeded"}])
        self.assertEqual(final["components"]["api"], {"branch": "feature", "sha": NEW_SHA})
        self.assertFalse(cloud.gcloud("compute", "instances", "add-labels"))
        summary = self.summary.read_text()
        self.assertIn(f"| api | `{SANDBOX_SHA[:12]}` (`main`) | `{NEW_SHA[:12]}` (`feature`) |", summary)
        self.assertIn("**Migrations:** applied", summary)

    def test_ui_only_deploy_leaves_sandbox_checkout_alone(self):
        cloud = FakeCloud(instances=self.box())
        self.assertEqual(self.deploy(cloud, "ui", SANDBOX_BRANCH="", SANDBOX_SHA="", UI_BRANCH="feature",
                                     UI_SHA=NEW_SHA), 0)
        self.assertEqual(cloud.scripts, ["install-ui.sh"])
        self.assertEqual(cloud.checkouts, [NEW_SHA])
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["revisions"]["sandbox"], {"branch": "main", "sha": SANDBOX_SHA})
        self.assertEqual(final["components"]["vmd"], {"branch": "main", "sha": SANDBOX_SHA})
        self.assertEqual(final["components"]["ui"], {"branch": "feature", "sha": NEW_SHA})
        self.assertEqual(final["deploys"][0]["migrations"], "none")
        self.assertIn(f"| vmd | `{SANDBOX_SHA[:12]}` (`main`) | unchanged |", self.summary.read_text())

    def test_failed_migration_stops_and_is_recorded(self):
        cloud = FakeCloud(instances=self.box(), fail_script="install-api.sh", migrations="failed")
        self.assertEqual(self.deploy(cloud, "api,ui"), 1)
        self.assertEqual(cloud.scripts, ["services-up.sh", "install-api.sh"])
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["state"], "failed")
        self.assertEqual(final["deploys"][-1]["migrations"], "failed")
        self.assertEqual(final["deploys"][-1]["result"], "failed")
        self.assertIn("**Migrations:** failed", self.summary.read_text())

    def test_partial_failure_moves_only_finished_components(self):
        cloud = FakeCloud(instances=self.box(), fail_script="install-api.sh", migrations="applied")
        self.assertEqual(self.deploy(cloud, "vmd,api,ui", UI_BRANCH="feature", UI_SHA=NEW_SHA), 1)
        self.assertEqual(cloud.scripts, ["install-vmd.sh", "services-up.sh", "install-api.sh"])
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["components"]["vmd"], {"branch": "feature", "sha": NEW_SHA})
        self.assertEqual(final["components"]["api"], {"branch": "feature", "sha": "unknown"})
        self.assertEqual(final["components"]["ui"], {"branch": "main", "sha": UI_SHA})
        self.assertEqual(final["revisions"]["ui"], {"branch": "feature", "sha": NEW_SHA})
        self.assertEqual(final["deploys"][-1]["migrations"], "applied")
        summary = self.summary.read_text()
        self.assertIn("| api | `" + SANDBOX_SHA[:12] + "` (`main`) | unknown (install interrupted; redeploy with components=all) |", summary)
        self.assertIn("| ui | `" + UI_SHA[:12] + "` (`main`) | not deployed |", summary)
        self.assertIn("Services (before this deploy)", summary)

    def test_api_install_without_a_readable_report_is_unknown(self):
        cloud = FakeCloud(instances=self.box(), fail_script="install-api.sh", migrations=None)
        self.assertEqual(self.deploy(cloud, "api"), 1)
        self.assertEqual(cloud.metadata_writes[-1]["deploys"][-1]["migrations"], "unknown")

    def test_migration_report_for_another_revision_is_ignored(self):
        cloud = FakeCloud(instances=self.box())
        cloud.deployed_sha = SANDBOX_SHA
        self.assertEqual(self.deploy(cloud, "api"), 0)
        self.assertEqual(cloud.metadata_writes[-1]["deploys"][-1]["migrations"], "unknown")

    def test_stale_migration_marker_is_not_reported(self):
        cloud = FakeCloud(instances=self.box(), fail_script="services-up.sh")
        cloud.box_files[workflow.API_DEPLOY_FILE] = json.dumps({"sha": NEW_SHA, "migrations": "applied"})
        self.assertEqual(self.deploy(cloud, "api"), 1)
        self.assertEqual(cloud.metadata_writes[-1]["deploys"][-1]["migrations"], "none")

    def test_refuses_busy_expired_or_missing_boxes(self):
        for instances, message in ((self.box(state="creating"), "creating"),
                                   (self.box(state="failed", runtime={}), "never finished"),
                                   (self.box(state="destroying"), "destroying"),
                                   (self.box(expires_hours=1), "expired"),
                                   ({}, "No devbox")):
            with self.subTest(message=message):
                cloud = FakeCloud(instances=instances)
                with self.assertRaisesRegex((workflow.StepError, contract.ContractError), message):
                    self.deploy(cloud)
                self.assertEqual(cloud.metadata_writes, [])
                self.assertEqual(cloud.scripts, [])

    def test_interrupted_deploy_is_concluded_by_the_backstop(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud(instances=self.box())
        self.assertEqual(self.deploy(cloud, "vmd", DEVBOX_ATTEMPT_FILE=str(attempt)), 0)
        writes = len(cloud.metadata_writes)
        self.deploy_backstop(cloud, attempt)
        self.assertEqual(len(cloud.metadata_writes), writes)

        cloud = FakeCloud(instances=self.box(state="deploying"))
        attempt.write_text(json.dumps({"name": "my-box", "devbox_id": "3f9c0a1b2c4d", "reported": False,
                                       "progress": {"checked_out": ["sandbox"], "deployed": [],
                                                    "api_started": False}}))
        self.deploy_backstop(cloud, attempt)
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["state"], "failed")
        self.assertEqual(final["deploys"][-1]["result"], "failed")
        self.assertEqual(final["deploys"][-1]["components"], ["vmd"])
        self.assertEqual(final["components"]["vmd"], {"branch": "main", "sha": SANDBOX_SHA})
        self.assertEqual(final["revisions"]["sandbox"], {"branch": "feature", "sha": NEW_SHA})
        self.assertIn("cancelled or timed out", self.summary.read_text())

    def deploy_backstop(self, cloud, attempt):
        env = self.env(NAME="my-box", COMPONENTS="vmd", SANDBOX_BRANCH="feature", SANDBOX_SHA=NEW_SHA,
                       UI_BRANCH="", UI_SHA="", DEVBOX_ATTEMPT_FILE=str(attempt))
        self.run_with(cloud, workflow.finish_deploy, env, now=lambda: self.NOW)

    def test_box_replaced_between_checkouts_gets_no_second_checkout(self):
        cloud = FakeCloud(instances=self.box())
        cloud.relabel_after_checkouts = 1
        self.assertEqual(self.deploy(cloud, "all"), 1)
        self.assertEqual(cloud.checkouts, [NEW_SHA])
        self.assertEqual(cloud.scripts, [])
        self.assertFalse([path for path in cloud.box_files if path.endswith(".env")])

    def test_ui_only_deploy_checks_the_box_scripts_before_changing_anything(self):
        cloud = FakeCloud(instances=self.box())
        cloud.box_missing = {"install-ui.sh"}
        with self.assertRaisesRegex(workflow.StepError, "install-ui.sh"):
            self.deploy(cloud, "ui", SANDBOX_BRANCH="", SANDBOX_SHA="", UI_BRANCH="feature", UI_SHA=NEW_SHA)
        self.assertEqual(cloud.metadata_writes, [])
        self.assertEqual(cloud.checkouts, [])

    def test_bad_configuration_is_refused_before_the_box_changes(self):
        cloud = FakeCloud(instances=self.box())
        with self.assertRaisesRegex(workflow.StepError, "newline"):
            self.deploy(cloud, "vmd", DEVBOX_SECRET_STRIPE_SECRET_KEY="sk_test\n")
        self.assertEqual(cloud.metadata_writes, [])
        self.assertEqual(cloud.checkouts, [])

    def test_checkout_that_finished_before_a_dropped_connection_is_recorded(self):
        cloud = FakeCloud(instances=self.box())
        cloud.drop_after_checkout = True
        self.assertEqual(self.deploy(cloud, "vmd"), 1)
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["state"], "failed")
        self.assertEqual(final["revisions"]["sandbox"], {"branch": "feature", "sha": NEW_SHA})
        self.assertEqual(final["components"]["vmd"], {"branch": "main", "sha": SANDBOX_SHA})

    def test_unreadable_checkout_after_a_failure_is_flagged_unconfirmed(self):
        cloud = FakeCloud(instances=self.box())
        cloud.drop_after_checkout = True
        cloud.heads_unreadable = True
        self.assertEqual(self.deploy(cloud, "vmd"), 1)
        final = cloud.metadata_writes[-1]
        self.assertEqual(final["revisions"]["sandbox"], {"branch": "main", "sha": SANDBOX_SHA, "unconfirmed": True})
        self.assertEqual(final["components"]["vmd"], {"branch": "main", "sha": SANDBOX_SHA})

    def test_full_deploy_after_an_unknown_install_settles_the_box(self):
        cloud = FakeCloud(instances=self.box(), fail_script="install-vmd.sh")
        self.assertEqual(self.deploy(cloud, "vmd"), 1)
        failed = cloud.metadata_writes[-1]
        self.assertEqual(failed["components"]["vmd"], {"branch": "feature", "sha": "unknown"})
        cloud.fail_script = None
        self.assertEqual(self.deploy(cloud, "all"), 0)
        settled = cloud.metadata_writes[-1]
        self.assertEqual(settled["state"], "ready")
        self.assertEqual(settled["components"]["vmd"], {"branch": "feature", "sha": NEW_SHA})
        self.assertNotIn("unconfirmed", settled["revisions"]["sandbox"])

    def test_install_in_flight_survives_for_the_backstop(self):
        attempt = Path(self.directory.name) / "attempt.json"
        cloud = FakeCloud(instances=self.box(), fail_script="install-vmd.sh")
        original = cloud.ssh

        def killed(args, command, input, ok, fail):
            if re.search(r"install-vmd\.sh'? 2>&1", unquote(command)):
                raise KeyboardInterrupt
            return original(args, command, input, ok, fail)

        cloud.ssh = killed
        with self.assertRaises(KeyboardInterrupt):
            with patch.object(workflow, "conclude_deploy", side_effect=KeyboardInterrupt):
                self.deploy(cloud, "vmd", DEVBOX_ATTEMPT_FILE=str(attempt))
        saved = json.loads(attempt.read_text())
        self.assertEqual(saved["progress"]["in_flight"], "vmd")
        cloud.ssh = original
        self.deploy_backstop(cloud, attempt)
        self.assertEqual(cloud.metadata_writes[-1]["components"]["vmd"], {"branch": "feature", "sha": "unknown"})

    def test_deploy_follows_the_box_to_its_zone(self):
        cloud = FakeCloud(instances=self.box(zone="us-central1-f"))
        self.assertEqual(self.deploy(cloud, "vmd"), 0)
        for args in cloud.gcloud("compute", "ssh") + cloud.gcloud("compute", "instances", "add-metadata"):
            self.assertIn("--zone=us-central1-f", args)
        self.assertIn(contract.forwarding_command("my-box", "us-central1-f"), self.summary.read_text())

    def test_deploy_refuses_a_box_whose_zone_disagrees_with_its_manifest(self):
        cloud = FakeCloud(instances=self.box(zone="us-central1-a", vm_zone="us-central1-b"))
        with self.assertRaisesRegex(workflow.StepError, "manifest says us-central1-a"):
            self.deploy(cloud, "vmd")
        self.assertEqual(cloud.metadata_writes, [])

    def test_deploy_does_not_wait_out_os_login_denials(self):
        cloud = FakeCloud(instances=self.box())
        cloud.login_denials, cloud.ssh_ready = 100, True
        with patch.object(workflow.time, "sleep") as sleep:
            self.assertEqual(self.deploy(cloud, "vmd"), 1)
        self.assertTrue(cloud.denied)
        sleep.assert_not_called()

    def test_failed_box_can_be_redeployed(self):
        cloud = FakeCloud(instances=self.box(state="failed"))
        with self.assertRaisesRegex(workflow.StepError, "components=all"):
            self.deploy(cloud, "ui")
        self.assertEqual(cloud.metadata_writes, [])
        self.assertEqual(self.deploy(cloud, "all"), 0)
        self.assertEqual(cloud.metadata_writes[-1]["state"], "ready")
        self.assertEqual(cloud.metadata_writes[-1]["deploys"][-1]["result"], "succeeded")


if __name__ == "__main__":
    unittest.main()
