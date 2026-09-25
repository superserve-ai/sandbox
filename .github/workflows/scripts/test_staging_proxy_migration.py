"""Exercise the staging frontend plan boundary and credential hold lifecycle."""

import copy
from contextlib import ExitStack
import sys
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[3] / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("check_staging_proxy_frontend_plan")
hold = load("staging_proxy_credential_hold")
REAL_ROLLBACK = hold.rollback_bootstrap


class FrontendPlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"resource_changes": []}
        for address, (kind, name) in guard.FRONTENDS.items():
            before = dict(project=guard.PROJECT, name=name,
                          id=f"projects/{guard.PROJECT}/global/{kind}/{name}")
            if kind in ("targetHttpsProxies", "targetSslProxies"):
                before["certificate_map"] = guard.CERTIFICATE_MAP
            if address in guard.ROUTES:
                field, legacy, generation = guard.ROUTES[address]
                before[field] = guard.BASE + legacy
            after = copy.deepcopy(before)
            if address in guard.ROUTES:
                after[field] = guard.BASE + generation
            self.plan["resource_changes"].append(dict(address=address, change=dict(
                actions=["update"] if before != after else ["no-op"], before=before, after=after,
                importing={"id": before["id"]}, after_unknown={})))

    def test_cutover_and_rollback_keep_topology(self):
        guard.validate(self.plan, "cutover")
        for item in self.plan["resource_changes"]:
            change = item["change"]
            change["before"], change["after"] = change["after"], change["before"]
            change.pop("importing")
        guard.validate(self.plan, "rollback")

    def test_rejects_drift_and_unknown_frontend_fields(self):
        mutations = ("delete", "create", "unknown", "project", "backend", "certificate", "port", "import", "missing", "extra")
        for mutation in mutations:
            plan = copy.deepcopy(self.plan)
            change = plan["resource_changes"][0]["change"]
            if mutation in ("delete", "create"):
                change["actions"] = [mutation]
            elif mutation == "unknown":
                change["after_unknown"] = {"default_service": True}
            elif mutation == "project":
                change["after"]["project"] = "example-production"
            elif mutation == "backend":
                change["after"]["default_service"] = guard.BASE + "example-unrelated"
            elif mutation == "certificate":
                plan["resource_changes"][1]["change"]["after"]["certificate_map"] = "example-certificate"
            elif mutation == "port":
                plan["resource_changes"][-1]["change"]["after"]["port_range"] = "8443"
            elif mutation == "import":
                change["importing"]["id"] = "example-other-resource"
            elif mutation == "missing":
                plan["resource_changes"].pop()
            else:
                plan["resource_changes"].append(dict(address="example.unrelated", change=dict(actions=["update"])))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                guard.validate(plan, "cutover")

    def test_full_apply_cannot_migrate_or_undo_a_rollback(self):
        with self.assertRaises(ValueError):
            guard.validate(self.plan, "steady")
        for item in self.plan["resource_changes"]:
            change = item["change"]
            change.pop("importing")
            change["actions"] = ["no-op"]
            change["before"] = copy.deepcopy(change["after"])
        guard.validate(self.plan, "steady")
        change = self.plan["resource_changes"][0]["change"]
        change["before"]["default_service"] = guard.BASE + "sandbox-proxy-backend-https"
        change["actions"] = ["update"]
        with self.assertRaises(ValueError):
            guard.validate(self.plan, "steady")
        for workflow in ("terraform-cd.yml", "terraform-rollout-staging.yml"):
            source = (Path(__file__).parent.parent / workflow).read_text()
            step = source.split('- name: Terraform apply staging/us-central1', 1)[1].split('terraform apply ', 1)[0]
            self.assertIn('check_proxy_frontend_steady_plan.py" staging', step)

    def test_import_without_refreshed_before_cannot_prove_identity_preservation(self):
        self.plan["resource_changes"][0]["change"]["before"] = None
        with self.assertRaises(ValueError):
            guard.validate(self.plan, "cutover")

    def test_certificate_map_api_reference_preserves_exact_identity(self):
        for item in self.plan["resource_changes"]:
            change = item["change"]
            if "certificate_map" in change["after"]:
                change["before"]["certificate_map"] = "https://certificatemanager.googleapis.com/v1/" + guard.CERTIFICATE_MAP
                change["after"]["certificate_map"] = "//certificatemanager.googleapis.com/" + guard.CERTIFICATE_MAP
                change["actions"] = ["update"]
        guard.validate(self.plan, "cutover")
        self.plan["resource_changes"][1]["change"]["after"]["certificate_map"] += "-other"
        with self.assertRaises(ValueError):
            guard.validate(self.plan, "cutover")


class CredentialHoldTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name in ("RECEIPT", "MARKER", "DROPIN", "STATE", "MANIFEST"):
            patcher = patch.object(hold, name, Path(directory.name) / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(hold, "rollback_bootstrap", side_effect=lambda state: state)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.timer = "active"
        self.vmd = "example-vmd-invocation"
        self.calls = []

        def run(*args):
            self.calls.append(args)
            if args[:3] == ("systemctl", "stop", "vmd-peer-credentials.timer"):
                self.timer = "inactive"
            if args[:3] == ("systemctl", "start", "vmd-peer-credentials.timer"):
                self.timer = "active"
            if args[0] == "curl":
                return '{"resolver_ready":true}'
            return ""

        self.run = run

        def prop(unit, field):
            if field == "InvocationID":
                return self.vmd if unit == "superserve-vmd.service" else "example-proxy-invocation"
            if unit == "vmd-peer-credentials.timer":
                return self.timer
            return "inactive" if unit == "vmd-peer-credentials.service" else "active"

        values = {"project/project-id": "rayai-dev", "instance/name": "superserve-vmd-staging-2",
                  "instance/zone": "projects/example/zones/us-central1-a"}
        for name, implementation in (("run", run), ("prop", prop), ("metadata", values.__getitem__)):
            patcher = patch.object(hold, name, side_effect=implementation)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_hold_is_idempotent_and_release_requires_a_generation(self):
        hold.main("hold")
        hold.main("hold")
        self.assertEqual(self.timer, "inactive")
        with self.assertRaises(RuntimeError):
            hold.main("release")
        self.assertTrue(hold.MARKER.exists())
        hold.STATE.write_text(json.dumps({"phase": "complete", "active": {"id": "example-generation"}}))
        hold.main("release")
        self.assertEqual(self.timer, "active")
        self.assertFalse(hold.MARKER.exists())
        self.assertEqual(json.loads(hold.RECEIPT.read_text())["phase"], "released")
        hold.main("release")
        self.assertFalse(any("restart" in call or "superserve-vmd.service" in call for call in self.calls))

    def test_changed_vmd_or_partial_hold_stops_migration(self):
        hold.main("hold")
        self.vmd = "different-invocation"
        with self.assertRaises(RuntimeError):
            hold.main("check")
        self.vmd = "example-vmd-invocation"
        hold.DROPIN.unlink()
        with self.assertRaises(RuntimeError):
            hold.main("check")

    def test_hold_records_proxy_after_inflight_publication_and_can_abort(self):
        original = hold.prop.side_effect
        publication_finished = False

        def prop(unit, field):
            nonlocal publication_finished
            if unit == "vmd-peer-credentials.service" and field == "ActiveState":
                publication_finished = True
            if unit == "proxy.service" and field == "InvocationID" and publication_finished:
                return "example-reloaded-proxy"
            return original(unit, field)

        with patch.object(hold, "prop", side_effect=prop):
            hold.main("hold")
            self.assertEqual(json.loads(hold.RECEIPT.read_text())["proxy"], "example-reloaded-proxy")
            hold.main("check")
            hold.main("abort", legacy_frontends_verified=True)
        self.assertEqual(self.timer, "active")

    def test_holding_retry_adopts_only_a_healthy_quiescent_legacy_proxy(self):
        hold.main("hold")
        receipt = json.loads(hold.RECEIPT.read_text())
        receipt.update(phase="holding", proxy="example-before-publication")
        hold.save(receipt)
        with patch.object(hold, "legacy_ready", return_value=False):
            with self.assertRaises(RuntimeError):
                hold.main("hold")
        self.assertEqual(json.loads(hold.RECEIPT.read_text())["phase"], "holding")
        hold.main("hold")
        hold.main("check")
        hold.main("abort", legacy_frontends_verified=True)
        self.assertEqual(self.timer, "active")

    def test_release_resumes_after_every_cleanup_side_effect(self):
        for failure in ("releasing", "dropin", "marker", "reload", "timer", "released"):
            with self.subTest(failure=failure):
                for path in (hold.RECEIPT, hold.MARKER, hold.DROPIN, hold.STATE):
                    path.unlink(missing_ok=True)
                self.timer = "active"
                hold.main("hold")
                hold.STATE.write_text(json.dumps({"phase": "complete", "active": {"id": "example-generation"}}))
                original_save, original_unlink = hold.save, Path.unlink

                def fail_save(receipt):
                    original_save(receipt)
                    if receipt["phase"] == failure:
                        raise RuntimeError("injected lost response after receipt write")

                def fail_unlink(path, *args, **kwargs):
                    original_unlink(path, *args, **kwargs)
                    if path == ({"dropin": hold.DROPIN, "marker": hold.MARKER}.get(failure)):
                        raise RuntimeError("injected interruption after unlink")

                def fail_run(*args):
                    result = self.run(*args)
                    if ((failure == "reload" and args == ("systemctl", "daemon-reload"))
                            or (failure == "timer" and args[:2] == ("systemctl", "start"))):
                        raise RuntimeError("injected lost response after systemctl")
                    return result

                with ExitStack() as stack:
                    stack.enter_context(patch.object(hold, "save", side_effect=fail_save))
                    stack.enter_context(patch.object(Path, "unlink", fail_unlink))
                    stack.enter_context(patch.object(hold, "run", side_effect=fail_run))
                    with self.assertRaises(RuntimeError):
                        hold.main("release")
                hold.main("release")
                hold.main("release")
                self.assertEqual(self.timer, "active")
                self.assertFalse(hold.MARKER.exists())
                self.assertEqual(json.loads(hold.RECEIPT.read_text())["phase"], "released")

    def test_verified_abort_before_bootstrap_and_after_controller_rollback(self):
        for state in ({}, {"phase": "rolled_back", "active": {"id": ""}},
                      {"phase": "complete", "active": {"id": ""}}):
            for path in (hold.RECEIPT, hold.MARKER, hold.DROPIN, hold.STATE):
                path.unlink(missing_ok=True)
            self.timer = "active"
            hold.main("hold")
            if state:
                hold.STATE.write_text(json.dumps(state))
            with self.assertRaises(RuntimeError):
                hold.main("abort")
            hold.main("abort", legacy_frontends_verified=True)
            hold.main("abort", legacy_frontends_verified=True)
            self.assertEqual(self.timer, "active")
            self.assertFalse(hold.MARKER.exists())
            hold.main("hold", legacy_frontends_verified=True)
            self.assertEqual(self.timer, "inactive")

    def test_abort_refuses_an_inflight_controller_or_new_generation(self):
        hold.main("hold")
        for state in ({"phase": "bootstrap_ready", "active": {"id": ""}},
                      {"phase": "complete", "active": {"id": "example-generation"}}):
            hold.STATE.write_text(json.dumps(state))
            with self.assertRaises(RuntimeError):
                hold.main("abort", legacy_frontends_verified=True)
            self.assertEqual(self.timer, "inactive")
            self.assertTrue(hold.MARKER.exists())

    def test_abort_finishes_only_the_adopted_legacy_bootstrap(self):
        hold.main("hold")
        legacy = {"id": "", "unit": "proxy.service"}
        state = {"phase": "bootstrap_ready", "bootstrap": True, "old": legacy, "candidate": legacy}
        hold.STATE.write_text(json.dumps(state))
        with patch.object(hold, "rollback_bootstrap", side_effect=RuntimeError("interrupted rollback")) as rollback:
            with self.assertRaises(RuntimeError):
                hold.main("abort", legacy_frontends_verified=True)
            rollback.assert_called_once_with(state)
        self.assertEqual(self.timer, "inactive")
        self.assertTrue(hold.MARKER.exists())

        def finish(value):
            value.update(phase="rolled_back", active=legacy)
            hold.STATE.write_text(json.dumps(value))
            return value

        with patch.object(hold, "rollback_bootstrap", side_effect=finish) as rollback:
            hold.main("abort", legacy_frontends_verified=True)
            rollback.assert_called_once()
        self.assertEqual(self.timer, "active")

    def test_abort_rejects_a_distinct_bootstrap_candidate(self):
        hold.main("hold")
        state = {"phase": "bootstrap_ready", "bootstrap": True,
                 "old": {"id": ""}, "candidate": {"id": "example-new-generation"}}
        hold.STATE.write_text(json.dumps(state))
        with patch.object(hold, "rollback_bootstrap") as rollback, self.assertRaises(RuntimeError):
            hold.main("abort", legacy_frontends_verified=True)
        rollback.assert_not_called()

    def test_real_controller_abort_retries_terminal_owner_release(self):
        from test_proxy_rollout import MODULE as controller, OwnershipStore, Interrupted
        config = dict(project="rayai-dev", zone="us-central1-a", instance="superserve-vmd-staging-2",
                      ip="192.0.2.10", routes=[], ownership_bucket="example-ownership")
        metadata = {"project/project-id": config["project"], "instance/name": config["instance"],
                    "instance/zone": config["zone"], "instance/network-interfaces/0/ip": config["ip"],
                    "instance/id": "example-instance-id"}
        for boundary in ("terminal_save", "delete_failed", "delete_reply_lost", "foreign_owner"):
            with self.subTest(boundary=boundary):
                for path in (hold.RECEIPT, hold.MARKER, hold.DROPIN, hold.STATE):
                    path.unlink(missing_ok=True)
                self.timer = "active"
                hold.main("hold")
                hold.MANIFEST.write_text(json.dumps(config))
                legacy = dict(id="", unit="proxy.service", ports={})
                state = dict(phase="bootstrap_ready", bootstrap=True, old=legacy, candidate=legacy,
                             rollout="example-run", request_hash="example-inputs")
                hold.STATE.write_text(json.dumps(state))
                store = OwnershipStore()
                original_atomic = controller.atomic

                def interrupt_save(path, value):
                    original_atomic(path, value)
                    if value.get("phase") == "rolled_back":
                        raise Interrupted()

                def fail_delete(method, path, data=None):
                    if method == "DELETE":
                        if boundary == "delete_reply_lost":
                            store.request(method, path, data)
                        raise TimeoutError("storage deletion interrupted")
                    return store.request(method, path, data)

                with ExitStack() as stack:
                    stack.enter_context(patch.object(hold, "metadata", side_effect=metadata.__getitem__))
                    stack.enter_context(patch.object(hold, "load_controller", return_value=controller))
                    stack.enter_context(patch.object(hold, "rollback_bootstrap", side_effect=REAL_ROLLBACK))
                    stack.enter_context(patch.object(controller, "Host", return_value=Mock()))
                    stack.enter_context(patch.object(controller.CellLock, "request", side_effect=store.request))
                    with ExitStack() as faults:
                        if boundary in ("terminal_save", "foreign_owner"):
                            faults.enter_context(patch.object(controller, "atomic", side_effect=interrupt_save))
                            expected = Interrupted
                        else:
                            faults.enter_context(patch.object(controller.CellLock, "request", side_effect=fail_delete))
                            expected = TimeoutError
                        with self.assertRaises(expected):
                            hold.main("abort", legacy_frontends_verified=True)
                    self.assertEqual(json.loads(hold.STATE.read_text())["phase"], "rolled_back")
                    self.assertEqual(self.timer, "inactive")
                    if boundary == "foreign_owner":
                        store.record["owner"]["rollout"] = "different-owner"
                        with self.assertRaisesRegex(RuntimeError, "unfinished ownership"):
                            hold.main("abort", legacy_frontends_verified=True)
                        self.assertEqual(store.record["owner"]["rollout"], "different-owner")
                        self.assertEqual(self.timer, "inactive")
                        continue
                    hold.main("abort", legacy_frontends_verified=True)
                    hold.main("abort", legacy_frontends_verified=True)
                    self.assertIsNone(store.record)
                    self.assertEqual(self.timer, "active")
                    next_owner = controller.CellLock(config, "next-run", "next-inputs", hold.STATE, "example-instance-id")
                    next_owner.acquire()
                    next_owner.release()
                    self.assertIsNone(store.record)

    def test_failed_first_generation_abort_resumes_pending_detach_and_releases_owner(self):
        from test_proxy_rollout import MODULE as controller, OwnershipStore
        config = dict(project="rayai-dev", zone="us-central1-a", instance="superserve-vmd-staging-2",
                      ip="192.0.2.10", ownership_bucket="example-ownership",
                      routes=[dict(neg="example-" + name, listener=listener)
                              for name, listener in (("http", "public"), ("tcp", "public"), ("redirect", "redirect"))])
        values = {"project/project-id": config["project"], "instance/name": config["instance"],
                  "instance/zone": config["zone"], "instance/network-interfaces/0/ip": config["ip"],
                  "instance/id": "example-instance-id"}
        old = dict(id="", unit="proxy.service", ports=dict(public=5007, redirect=5008, peer=5009, local=5010))
        candidate = dict(id="a" * 20, unit="proxy-" + "a" * 20 + ".service",
                         ports=dict(public=5100, redirect=5101, peer=5102, local=5103))
        state = dict(phase="rollback_restoring", bootstrap=False, old=old, candidate=candidate,
                     rollout="example-run", request_hash="example-inputs")
        hold.main("hold")
        hold.STATE.write_text(json.dumps(state))
        hold.MANIFEST.write_text(json.dumps(config))
        host = Mock(config=config)
        host.assert_owned = Mock(side_effect=lambda: host.ownership.assert_owned())
        registered = {route["neg"] for route in config["routes"]}
        submitted = []
        operations = {}
        failed_poll = False
        stopped = False
        def request(path, body=None):
            nonlocal failed_poll
            if body is not None:
                name = path.split("/")[-2]
                submitted.append(name)
                self.assertEqual(body["networkEndpoints"][0]["port"], candidate["ports"][
                    next(route["listener"] for route in config["routes"] if route["neg"] == name)])
                link = f'https://www.googleapis.com/compute/v1/projects/{config["project"]}/zones/{config["zone"]}/operations/{name}'
                result = dict(status="RUNNING", selfLink=link)
                operations[name] = result
                return dict(result)
            if not failed_poll:
                failed_poll = True
                raise TimeoutError("injected poll interruption")
            name = path.rsplit("/", 1)[-1]
            registered.remove(name)
            return dict(operations[name], status="DONE")
        def stop(generation):
            nonlocal stopped
            self.assertEqual(generation, candidate)
            self.assertFalse(registered)
            self.assertEqual(self.timer, "inactive")
            stopped = True
        original_prop = hold.prop.side_effect
        def prop(unit, field):
            if unit == candidate["unit"] and field == "ActiveState":
                return "inactive" if stopped else "active"
            return original_prop(unit, field)
        host.cloud.member.side_effect = lambda route, port: route["neg"] in registered
        host.cloud.request.side_effect = request
        host.stop.side_effect = stop
        store = OwnershipStore()
        with ExitStack() as stack:
            stack.enter_context(patch.object(hold, "metadata", side_effect=values.__getitem__))
            stack.enter_context(patch.object(hold, "prop", side_effect=prop))
            stack.enter_context(patch.object(hold, "load_controller", return_value=controller))
            stack.enter_context(patch.object(hold, "rollback_bootstrap", side_effect=REAL_ROLLBACK))
            stack.enter_context(patch.object(controller, "Host", return_value=host))
            stack.enter_context(patch.object(controller.CellLock, "request", side_effect=store.request))
            with self.assertRaises(TimeoutError):
                hold.main("abort", legacy_frontends_verified=True)
            self.assertEqual(len(submitted), 3)
            self.assertEqual(self.timer, "inactive")
            self.assertFalse(stopped)
            self.assertIsNotNone(store.record)
            hold.main("abort", legacy_frontends_verified=True)
            self.assertEqual(len(submitted), 3, "resume must poll recorded operations without resubmitting")
            self.assertIsNone(store.record)
            self.assertTrue(stopped)
            self.assertEqual(self.timer, "active")
            self.assertEqual(json.loads(hold.STATE.read_text())["phase"], "rolled_back")
            self.assertFalse(hold.MARKER.exists())

    def test_unrecorded_detach_requires_a_durable_conservative_drain_fence(self):
        from test_proxy_rollout import MODULE as controller
        hold.main("hold")
        for fault in ("lost_post_reply", "lost_receipt_write", "preexisting_detach"):
            with self.subTest(fault=fault):
                state = dict(phase="rollback_restoring", old={"id": "", "unit": "proxy.service"},
                             candidate={"id": "a" * 20, "unit": "proxy-" + "a" * 20 + ".service", "ports": {"public": 5100}})
                config = dict(project="example-project", zone="example-zone", instance="example-host", ip="192.0.2.10",
                              routes=[{"neg": "example-neg", "listener": "public"}])
                host = Mock(config=config)
                host.assert_owned = Mock()
                host.cloud.member.return_value = fault != "preexisting_detach"
                durable = copy.deepcopy(state)
                def save(value):
                    nonlocal durable
                    if fault == "lost_receipt_write" and value.get("_migration_abort_operations"):
                        raise TimeoutError("receipt write failed")
                    durable = copy.deepcopy(value)
                def detach(path, body):
                    self.assertIn("example-neg", durable["_migration_abort_intents"])
                    host.cloud.member.return_value = False
                    if fault == "lost_post_reply":
                        raise TimeoutError("accepted POST reply lost")
                    return {"status": "RUNNING", "selfLink": "https://www.googleapis.com/compute/v1/projects/example-project/zones/example-zone/operations/example-op"}
                host.cloud.request.side_effect = detach
                with patch.object(hold.time, "time", return_value=100), patch.object(hold.time, "sleep", side_effect=TimeoutError("paused")):
                    with self.assertRaises(TimeoutError):
                        hold.rollback_first_generation(controller, host, state, save)
                    host.stop.assert_not_called()
                    if fault != "preexisting_detach":
                        self.assertFalse(durable["_migration_abort_operations"])
                        with self.assertRaises(TimeoutError):
                            hold.rollback_first_generation(controller, host, copy.deepcopy(durable), save)
                    host.stop.assert_not_called()
                self.assertEqual(durable["_migration_abort_absent_until"]["example-neg"], 4360)
                # Retry before the saved fence cannot complete or reset it.
                with patch.object(hold.time, "time", return_value=4359), patch.object(hold.time, "sleep", side_effect=TimeoutError("paused")):
                    with self.assertRaises(TimeoutError):
                        hold.rollback_first_generation(controller, host, copy.deepcopy(durable), save)
                host.stop.assert_not_called()
                self.assertEqual(durable["_migration_abort_absent_until"]["example-neg"], 4360)
                original = hold.prop.side_effect
                def prop(unit, field):
                    if unit.startswith("proxy-a") and field == "ActiveState":
                        return "inactive"
                    return original(unit, field)
                with patch.object(hold.time, "time", return_value=4361), patch.object(hold, "prop", side_effect=prop):
                    hold.rollback_first_generation(controller, host, copy.deepcopy(durable), save)
                host.stop.assert_called_once()
                self.assertEqual(durable["phase"], "rolled_back")
                self.assertEqual(self.timer, "inactive")

    def test_generation_abort_stops_if_vmd_changes_while_cloud_drain_is_pending(self):
        from test_proxy_rollout import MODULE as controller
        hold.main("hold")
        state = dict(phase="rollback_restoring", old={"id": "", "unit": "proxy.service"},
                     candidate={"id": "a" * 20, "unit": "proxy-" + "a" * 20 + ".service", "ports": {"public": 5100}})
        config = dict(project="example-project", zone="example-zone", instance="example-host", ip="192.0.2.10",
                      routes=[{"neg": "example-neg", "listener": "public"}])
        host = Mock(config=config)
        host.assert_owned = Mock()
        host.cloud.member.return_value = True
        host.cloud.request.return_value = dict(status="RUNNING", selfLink=
            "https://www.googleapis.com/compute/v1/projects/example-project/zones/example-zone/operations/example-op")
        def restart_vmd(_):
            self.vmd = "changed-vmd-invocation"
        with patch.object(hold.time, "sleep", side_effect=restart_vmd):
            with self.assertRaisesRegex(RuntimeError, "processes changed"):
                hold.rollback_first_generation(controller, host, state, lambda value: None)
        host.stop.assert_not_called()
        self.assertEqual(state["phase"], "rollback_withdrawing")
        self.assertEqual(self.timer, "inactive")
        self.assertTrue(hold.MARKER.exists())

    def test_generation_abort_requires_retained_legacy_before_irreversible_drain(self):
        state = dict(phase="rollback_restoring", bootstrap=False,
                     old=dict(id="", unit="proxy.service", ports=dict(public=5007, redirect=5008, peer=5009, local=5010)),
                     candidate=dict(id="a" * 20, unit="proxy-" + "a" * 20 + ".service",
                                    ports=dict(public=5100, redirect=5101, peer=5102, local=5103)))
        self.assertTrue(hold.failed_first_generation(state))
        hold.main("hold")
        receipt = json.loads(hold.RECEIPT.read_text())
        with self.assertRaisesRegex(RuntimeError, "live legacy frontend"):
            hold.abort_ready(state, receipt, False, allow_generation=True)
        for change in (dict(phase="stopping"), dict(timestamps={"stopping": 1}),
                       dict(old=dict(state["old"], drain_started=1)), dict(active={"id": "other"}),
                       dict(candidate=dict(state["candidate"], unit="proxy.service")),
                       dict(candidate=dict(state["candidate"], ports=state["old"]["ports"])),
                       dict(_credential_recovery={"pending": True})):
            with self.subTest(change=change):
                rejected = dict(state, **change)
                self.assertFalse(hold.failed_first_generation(rejected))
                with self.assertRaises(RuntimeError):
                    hold.abort_ready(rejected, receipt, True, allow_generation=True)

    def test_forward_release_reconciles_real_controller_ownership(self):
        from test_proxy_rollout import MODULE as controller, OwnershipStore
        config = dict(project="rayai-dev", zone="us-central1-a", instance="superserve-vmd-staging-2",
                      ip="192.0.2.10", routes=[], ownership_bucket="example-ownership")
        metadata = {"project/project-id": config["project"], "instance/name": config["instance"],
                    "instance/zone": config["zone"], "instance/network-interfaces/0/ip": config["ip"],
                    "instance/id": "example-instance-id"}
        for lost_reply in (False, True):
            for path in (hold.RECEIPT, hold.MARKER, hold.DROPIN, hold.STATE):
                path.unlink(missing_ok=True)
            self.timer = "active"
            hold.main("hold")
            hold.MANIFEST.write_text(json.dumps(config))
            state = dict(phase="complete", active={"id": "example-generation"},
                         rollout="example-forward", request_hash="example-inputs", bootstrap=False)
            store = OwnershipStore()
            with ExitStack() as stack:
                stack.enter_context(patch.object(hold, "metadata", side_effect=metadata.__getitem__))
                stack.enter_context(patch.object(hold, "load_controller", return_value=controller))
                stack.enter_context(patch.object(hold, "rollback_bootstrap", side_effect=REAL_ROLLBACK))
                stack.enter_context(patch.object(controller.CellLock, "request", side_effect=store.request))
                owner = controller.CellLock(config, state["rollout"], state["request_hash"], hold.STATE, "example-instance-id")
                owner.acquire()
                controller.save_owned_state(owner, hold.STATE, state)

                def fail_delete(method, path, data=None):
                    if method == "DELETE":
                        if lost_reply:
                            store.request(method, path, data)
                        raise TimeoutError("owner deletion interrupted")
                    return store.request(method, path, data)

                with patch.object(controller.CellLock, "request", side_effect=fail_delete):
                    with self.assertRaises(TimeoutError):
                        hold.main("release")
                self.assertEqual(self.timer, "inactive")
                self.assertTrue(hold.MARKER.exists())
                hold.main("release")
                hold.main("release")
                self.assertIsNone(store.record)
                self.assertEqual(self.timer, "active")
                next_owner = controller.CellLock(config, "next-run", "next-inputs", hold.STATE, "example-instance-id")
                next_owner.acquire()
                next_owner.release()


class AbortFrontendTests(unittest.TestCase):
    def test_expedited_cleanup_can_only_shorten_three_staging_backend_drains(self):
        with patch.dict(sys.modules, {"check_staging_proxy_frontend_plan": guard}):
            migration = load("staging_proxy_migration")
        items = []
        for route in ("public-http", "public-tcp", "redirect"):
            name = f"proxy-staging-{route}-generations"
            before = dict(project="rayai-dev", name=name,
                          id="projects/rayai-dev/global/backendServices/" + name,
                          connection_draining_timeout_sec=3600, backend=[{"group": "example-neg"}])
            items.append(dict(address=f'module.proxy_generations["staging"].google_compute_backend_service.generation["{route}"]',
                              change=dict(actions=["update"], before=before,
                                          after=dict(before, connection_draining_timeout_sec=1))))
        migration.validate_drain_plan(dict(resource_changes=items))
        for mutation in ("project", "backend", "drain", "delete", "unknown", "missing", "extra", "import", "move"):
            changed = copy.deepcopy(items)
            change = changed[0]["change"]
            if mutation == "project":
                change["before"]["project"] = change["after"]["project"] = "example-production"
            elif mutation == "backend":
                change["after"]["backend"] = []
            elif mutation == "drain":
                change["after"]["connection_draining_timeout_sec"] = 30
            elif mutation == "delete":
                change["actions"] = ["delete", "create"]
            elif mutation == "unknown":
                change["after_unknown"] = {"backend": True}
            elif mutation == "missing":
                changed.pop()
            elif mutation == "extra":
                changed.append(dict(address="example.unrelated", change=dict(actions=["update"])))
            elif mutation == "import":
                change["importing"] = {"id": change["before"]["id"]}
            else:
                changed[0]["previous_address"] = "example.previous"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                migration.validate_drain_plan(dict(resource_changes=changed))
        for item in items:
            item["change"]["before"] = copy.deepcopy(item["change"]["after"])
            item["change"]["actions"] = ["no-op"]
        migration.validate_drain_plan(dict(resource_changes=items))

    def test_shortened_drains_require_live_readback_on_every_backend(self):
        with patch.dict(sys.modules, {"check_staging_proxy_frontend_plan": guard}):
            migration = load("staging_proxy_migration")
        ready = json.dumps({"connectionDraining": {"drainingTimeoutSec": 1}})
        with patch.object(migration, "command", return_value=ready) as command:
            migration.verify_shortened_drains()
            self.assertEqual(command.call_count, 3)
        for index in range(3):
            for value in (0, 3600, None):
                records = [ready] * 3
                records[index] = json.dumps({"connectionDraining": {"drainingTimeoutSec": value}})
                with self.subTest(index=index, value=value), patch.object(migration, "command", side_effect=records):
                    with self.assertRaisesRegex(RuntimeError, "did not change"):
                        migration.verify_shortened_drains()

    def test_host_status_is_framed_separately_from_ssh_key_generation(self):
        with patch.dict(sys.modules, {"check_staging_proxy_frontend_plan": guard}):
            migration = load("staging_proxy_migration")
        status = {"mode": "hold", "vmd": "example-invocation"}
        record = hold.STATUS_PREFIX + json.dumps(status) + "\n"
        with patch.object(migration, "command", return_value="Generating public/private rsa key pair.\n+---[RSA 3072]----+\n" + record):
            self.assertEqual(migration.host("hold"), status)
        for output in ("", json.dumps(status), record + record,
                       hold.STATUS_PREFIX + "{}", hold.STATUS_PREFIX + "[]",
                       hold.STATUS_PREFIX + '{"mode":"release"}'):
            with self.subTest(output=output), patch.object(migration, "command", return_value=output):
                with self.assertRaises(RuntimeError):
                    migration.host("hold")

    def test_initial_switch_requires_exact_legacy_membership_without_lb_health(self):
        with patch.dict(sys.modules, {"check_staging_proxy_frontend_plan": guard}):
            migration = load("staging_proxy_migration")
        groups = [[{"networkEndpoint": {"instance": "superserve-vmd-staging-2", "ipAddress": "10.0.0.3", "port": port}}]
                  for port in (5007, 5007, 5008)]
        with patch.object(migration, "command", side_effect=[json.dumps(x) for x in groups]) as command:
            migration.registered_legacy_endpoints()
            self.assertTrue(all("list-network-endpoints" in call.args for call in command.call_args_list))
        for mutation in ("empty", "duplicate", "port", "ipAddress", "instance"):
            changed = copy.deepcopy(groups)
            if mutation == "empty":
                changed[1] = []
            elif mutation == "duplicate":
                changed[1] *= 2
            else:
                changed[1][0]["networkEndpoint"][mutation] = 5100 if mutation == "port" else "example-other"
            with self.subTest(mutation=mutation), patch.object(migration, "command", side_effect=[json.dumps(x) for x in changed]):
                with self.assertRaises(RuntimeError):
                    migration.registered_legacy_endpoints()

    def test_abort_requires_all_live_legacy_references(self):
        with patch.dict(sys.modules, {"check_staging_proxy_frontend_plan": guard}):
            migration = load("staging_proxy_migration")
        resources = [{"defaultService": guard.BASE + "sandbox-proxy-backend-https"},
                     {"service": guard.BASE + "sandbox-proxy-backend"},
                     {"service": guard.BASE + "sandbox-proxy-redirect-backend"}]
        with patch.object(migration, "command", side_effect=[json.dumps(x) for x in resources]), patch.object(migration, "host") as host:
            migration.main("abort")
            host.assert_called_once_with("abort", legacy_frontends_verified=True)
        for index in range(3):
            changed = copy.deepcopy(resources)
            changed[index] = {key: guard.BASE + "example-generation" for key in changed[index]}
            with patch.object(migration, "command", side_effect=[json.dumps(x) for x in changed]), patch.object(migration, "host") as host:
                with self.assertRaises(RuntimeError):
                    migration.main("abort")
                host.assert_not_called()


if __name__ == "__main__":
    unittest.main()
