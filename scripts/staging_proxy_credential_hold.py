#!/usr/bin/env python3
"""Run on the staging host during the first proxy generation adoption."""

import fcntl
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request


RECEIPT = Path("/run/proxy-generation-migration-receipt.json")
MARKER = Path("/run/proxy-generation-migration-hold")
DROPIN = Path("/run/systemd/system/proxy-credential-rollout.service.d/staging-migration.conf")
STATE = Path("/var/lib/proxy-rollout/state.json")
MANIFEST = Path("/etc/sandbox/proxy-rollout.json")
STATUS_PREFIX = "STAGING_PROXY_MIGRATION_STATUS="
BOOTSTRAP_ABORT_PHASES = {"bootstrap_ready", "migration_rollback_waiting",
                          "migration_rollback_verifying", "migration_rollback_withdrawing"}


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=45).stdout.strip()


def prop(unit, field):
    return run("systemctl", "show", unit, "-p", field, "--value")


def save(receipt):
    pending = RECEIPT.with_suffix(".next")
    pending.write_text(json.dumps(receipt))
    pending.replace(RECEIPT)


def metadata(path):
    request = urllib.request.Request("http://metadata.google.internal/computeMetadata/v1/" + path,
                                     headers={"Metadata-Flavor": "Google"})
    return urllib.request.urlopen(request, timeout=5).read().decode()


def legacy_ready():
    try:
        health = json.loads(run("curl", "--fail", "--silent", "--show-error", "--max-time", "10",
                                "http://127.0.0.1:5007/health"))
        return health.get("resolver_ready") is True
    except (subprocess.SubprocessError, ValueError):
        return False


def failed_first_generation(state):
    old, candidate = state.get("old", {}), state.get("candidate", {})
    return (state.get("bootstrap") is False
            and state.get("phase") in {"rollback", "rollback_restoring", "rollback_withdrawing", "rollback_stopping"}
            and old.get("id") == "" and old.get("unit") == "proxy.service"
            and old.get("ports") == {"public": 5007, "redirect": 5008, "peer": 5009, "local": 5010}
            and re.fullmatch(r"[a-f0-9]{20}", candidate.get("id", "")) is not None
            and candidate.get("unit") == "proxy-" + candidate["id"] + ".service"
            and candidate.get("ports") in [dict(zip(("public", "redirect", "peer", "local"), range(base, base + 4)))
                                           for base in (5100, 5110)]
            and not old.get("drain_started") and "stopping" not in state.get("timestamps", {})
            and not state.get("active", {}).get("id") and not state.get("_credential_recovery"))


def abort_ready(state, receipt, legacy_frontends_verified, allow_bootstrap=False, allow_generation=False):
    if not legacy_frontends_verified:
        raise RuntimeError("Actions must verify all three live legacy frontend references before abort")
    bootstrap = (allow_bootstrap and state.get("bootstrap") is True
                 and state.get("phase") in BOOTSTRAP_ABORT_PHASES
                 and state.get("old", {}).get("id") == "" and state.get("candidate") == state.get("old"))
    generation = allow_generation and failed_first_generation(state)
    terminal = state.get("phase") in ("complete", "rolled_back") and state.get("active", {}).get("id") == ""
    if state and (not (terminal or bootstrap or generation) or state.get("_credential_recovery")):
        raise RuntimeError("Finish controller rollback before aborting the credential hold")
    if prop("proxy.service", "ActiveState") != "active":
        raise RuntimeError("Legacy proxy is not active")
    # Once cleanup was authorized, restored renewal may legitimately reload the
    # legacy proxy. A retry still requires terminal legacy state and readiness.
    if receipt["phase"] not in ("aborting", "aborted") and prop("proxy.service", "InvocationID") != receipt["proxy"]:
        raise RuntimeError("Legacy proxy changed before abort")
    units = run("systemctl", "list-units", "--all", "--plain", "--no-legend", "proxy-*.service")
    for line in units.splitlines():
        unit = line.split()[0]
        if re.fullmatch(r"proxy-[a-f0-9]{20}\.service", unit) and prop(unit, "ActiveState") not in ("inactive", "failed"):
            if not generation or unit != state["candidate"]["unit"]:
                raise RuntimeError("A generation service is still running")
    if not legacy_ready():
        raise RuntimeError("Legacy proxy/VMD readiness is not healthy")


def load_controller():
    spec = importlib.util.spec_from_file_location("staging_proxy_controller", STATE.parent / "controller.py")
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    return controller


def rollback_first_generation(controller, host, state, save):
    old, candidate = state["old"], state["candidate"]
    rollout = controller.Rollout(host, state, save)
    receipt = json.loads(RECEIPT.read_text())

    def check_processes():
        if (prop("superserve-vmd.service", "InvocationID") != receipt["vmd"]
                or prop("proxy.service", "InvocationID") != receipt["proxy"]
                or prop("superserve-vmd.service", "ActiveState") != "active"
                or prop("proxy.service", "ActiveState") != "active"):
            raise RuntimeError("Retained staging processes changed during rollback")

    check_processes()
    host.legacy_propagated(old)
    check_processes()
    host.switch_private(old)
    rollout.phase("rollback_withdrawing")
    operations = state.setdefault("_migration_abort_operations", {})
    intents = state.setdefault("_migration_abort_intents", {})
    fences = state.setdefault("_migration_abort_absent_until", {})
    # Submit every route before polling. Persist intent first because Compute
    # may accept a detach even when its reply or operation-receipt write is lost.
    for route in host.config["routes"]:
        name = route["neg"]
        if name in operations:
            continue
        if host.cloud.member(route, candidate["ports"][route["listener"]]):
            intents[name] = time.time()
            save(state)
            host.assert_owned()
            result = host.cloud.request(
                f'zones/{host.config["zone"]}/networkEndpointGroups/{name}/detachNetworkEndpoints',
                {"networkEndpoints": [{"instance": host.config["instance"], "ipAddress": host.config["ip"],
                                       "port": candidate["ports"][route["listener"]]}]})
            operations[name] = result
            save(state)
        elif name not in fences:
            # An absent endpoint can still have an unrecorded drain in flight,
            # including one submitted by the original controller. Wait the
            # maximum LB drain plus TCP idle timeout and propagation margin.
            fences[name] = time.time() + 4260
            save(state)
    deadline = time.monotonic() + 4500
    while True:
        check_processes()
        pending = False
        for result in operations.values():
            if result.get("status") != "DONE":
                prefix = (f'https://www.googleapis.com/compute/v1/projects/{host.config["project"]}'
                          f'/zones/{host.config["zone"]}/operations/')
                link = result.get("selfLink", "")
                if not link.startswith(prefix) or not re.fullmatch(r"[A-Za-z0-9_-]+", link[len(prefix):]):
                    raise RuntimeError("Unexpected staging endpoint operation identity")
                result.update(host.cloud.request(f'zones/{host.config["zone"]}/operations/' + link[len(prefix):]))
            if result.get("error"):
                raise RuntimeError(json.dumps(result["error"]))
            pending = pending or result.get("status") != "DONE"
        for name, not_before in fences.items():
            if name not in operations:
                pending = pending or time.time() < not_before
        save(state)
        if not pending:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Staging endpoint cleanup exceeded its drain deadline; retry abort")
        time.sleep(10)
    if any(host.cloud.member(route, candidate["ports"][route["listener"]]) for route in host.config["routes"]):
        raise RuntimeError("Failed candidate is still registered")
    host.legacy_propagated(old)
    check_processes()
    rollout.phase("rollback_stopping")
    host.stop(candidate)
    if prop(candidate["unit"], "ActiveState") not in ("inactive", "failed"):
        raise RuntimeError("Failed candidate is still running")
    if not host.local(old):
        raise RuntimeError("Legacy proxy lost readiness during cleanup")
    rollout.phase("rolled_back", active=old)


def rollback_bootstrap(state):
    # Reuse the installed controller's fenced rollback, including propagation,
    # endpoint withdrawal and terminal owner release; never hand-edit its state.
    controller = load_controller()
    config = json.loads(MANIFEST.read_text())
    controller.check_manifest_identity(config, state, MANIFEST)
    for field, path in (("project", "project/project-id"), ("instance", "instance/name"),
                        ("zone", "instance/zone"), ("ip", "instance/network-interfaces/0/ip")):
        if config[field] != metadata(path).rsplit("/", 1)[-1]:
            raise RuntimeError("Installed controller manifest does not describe this host")
    host = controller.Host(config)
    with controller.CellLock(config, state["rollout"], state["request_hash"], STATE, metadata("instance/id")) as ownership:
        host.ownership = host.cloud.ownership = ownership
        if failed_first_generation(state):
            rollback_first_generation(controller, host, state, lambda value: controller.save_owned_state(ownership, STATE, value))
        elif state.get("phase") in BOOTSTRAP_ABORT_PHASES or (state.get("bootstrap") and state["phase"] == "complete"):
            controller.Bootstrap(host, state, lambda value: controller.save_owned_state(ownership, STATE, value)).restore_legacy(False)
        # Terminal state is saved before owner deletion. Re-entering the same
        # recorded owner also finishes a failed/lost deletion on terminal retries.
    return json.loads(STATE.read_text())


def restore(receipt, mode):
    progress, complete = ("releasing", "released") if mode == "release" else ("aborting", "aborted")
    if receipt["phase"] not in (progress, complete):
        receipt["phase"] = progress
        save(receipt)
    # Each operation is repeatable after cancellation or an ambiguous response.
    DROPIN.unlink(missing_ok=True)
    MARKER.unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    run("systemctl", "start" if receipt["timer"] == "active" else "stop", "vmd-peer-credentials.timer")
    if prop("vmd-peer-credentials.timer", "ActiveState") != receipt["timer"]:
        raise RuntimeError("Credential publisher timer has not returned to its recorded state")
    receipt["phase"] = complete
    save(receipt)


def locked(mode, legacy_frontends_verified):
    if (metadata("project/project-id") != "rayai-dev"
            or metadata("instance/name") != "superserve-vmd-staging-2"
            or metadata("instance/zone").rsplit("/", 1)[-1] != "us-central1-a"):
        raise RuntimeError("This procedure is restricted to the staging serving host")
    vmd = prop("superserve-vmd.service", "InvocationID")
    if not vmd or prop("superserve-vmd.service", "ActiveState") != "active":
        raise RuntimeError("VMD must be running")
    previous = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else None
    if mode == "hold" and (previous is None or previous["phase"] == "aborted"):
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        if MARKER.exists() or DROPIN.exists() or (state and previous is None):
            raise RuntimeError("Initial hold requires an unadopted legacy proxy without an existing hold")
        if previous is not None:
            abort_ready(state, previous, legacy_frontends_verified)
        run("openssl", "x509", "-in", "/etc/superserve/peer/current/tls.crt", "-noout", "-checkend", "7200")
        receipt = {"vmd": vmd, "proxy": prop("proxy.service", "InvocationID"), "phase": "holding",
                   "timer": prop("vmd-peer-credentials.timer", "ActiveState"), "created": time.time()}
        if receipt["timer"] not in ("active", "inactive") or not receipt["proxy"]:
            raise RuntimeError("Unexpected legacy service state")
        save(receipt)
    if mode not in ("hold", "check", "release", "abort") or not RECEIPT.exists():
        raise RuntimeError("Expected a recorded migration hold")
    receipt = json.loads(RECEIPT.read_text())
    if receipt["vmd"] != vmd:
        raise RuntimeError("VMD invocation changed during the migration")
    if mode == "hold" and receipt["phase"] == "holding":
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        if state and (state.get("phase") not in ("complete", "rolled_back") or state.get("active", {}).get("id") != ""):
            raise RuntimeError("Legacy state changed during hold setup")
        run("systemctl", "stop", "vmd-peer-credentials.timer")
        for _ in range(30):
            if prop("vmd-peer-credentials.service", "ActiveState") == "inactive":
                break
            time.sleep(1)
        else:
            raise RuntimeError("Credential publication is still active; retry hold or use verified abort")
        # An already-running publisher may reload legacy while it finishes.
        # Seal the serving invocation only after publication has quiesced.
        proxy = prop("proxy.service", "InvocationID")
        if (not proxy or prop("proxy.service", "ActiveState") != "active" or not legacy_ready()
                or prop("superserve-vmd.service", "InvocationID") != receipt["vmd"]):
            raise RuntimeError("Legacy proxy/VMD must be healthy after credential publication")
        receipt["proxy"] = proxy
        DROPIN.parent.mkdir(parents=True, exist_ok=True)
        MARKER.touch(mode=0o600)
        DROPIN.write_text("[Unit]\nConditionPathExists=!/run/proxy-generation-migration-hold\n")
        run("systemctl", "daemon-reload")
        receipt["phase"] = "held"
        save(receipt)
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if mode == "abort":
        if receipt["phase"] not in ("holding", "held", "aborting", "aborted"):
            raise RuntimeError("Cannot abort a forward release")
        abort_ready(state, receipt, legacy_frontends_verified, allow_bootstrap=True, allow_generation=True)
        if state:
            state = rollback_bootstrap(state)
            abort_ready(state, receipt, legacy_frontends_verified)
        restore(receipt, mode)
    elif mode == "release":
        if receipt["phase"] not in ("held", "releasing", "released"):
            raise RuntimeError("Cannot release an aborted or incomplete hold")
        if state.get("phase") != "complete" or not state.get("active", {}).get("id") or state.get("_credential_recovery"):
            raise RuntimeError("Complete the first generation before releasing credential renewal")
        # Completion precedes cloud owner deletion for forward rollouts too.
        state = rollback_bootstrap(state)
        restore(receipt, mode)
    else:
        if (receipt["phase"] != "held" or not MARKER.exists() or not DROPIN.exists()
                or prop("vmd-peer-credentials.timer", "ActiveState") != "inactive"):
            raise RuntimeError("Migration credential hold is incomplete")
        run("openssl", "x509", "-in", "/etc/superserve/peer/current/tls.crt", "-noout", "-checkend", "3600")
    if prop("superserve-vmd.service", "InvocationID") != receipt["vmd"]:
        raise RuntimeError("VMD invocation changed")
    print(STATUS_PREFIX + json.dumps({"mode": mode, "vmd": vmd, "legacy_proxy": receipt["proxy"],
                      "phase": state.get("phase"), "rollout": state.get("rollout"),
                      "legacy_running": prop("proxy.service", "ActiveState") == "active"
                      and prop("proxy.service", "InvocationID") == receipt["proxy"],
                      "legacy_ready": legacy_ready(),
                      "active_generation": state.get("active", {}).get("id")}))


def main(mode, legacy_frontends_verified=False):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with (STATE.parent / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked(mode, legacy_frontends_verified)


if __name__ == "__main__":
    main(sys.argv[1], "--legacy-frontends-verified" in sys.argv[2:])
