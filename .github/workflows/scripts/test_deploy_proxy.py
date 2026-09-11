import importlib.util
import json
import os
import subprocess
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "deploy_proxy", Path(__file__).with_name("deploy-proxy.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


SOURCE = Path(__file__).with_name("deploy-proxy.py").read_text()


class DeployProxyOrderingTest(unittest.TestCase):
    def test_ssh_key_created_before_parallel_fanout(self):
        # Per-host deploys run in parallel, and gcloud generates the runner's
        # SSH key on first use. Two hosts starting together race ssh-keygen and
        # one fails before uploading anything, so the key must exist before
        # the pool starts.
        keygen = SOURCE.find('"ssh-keygen", "-q"')
        pool = SOURCE.find("ThreadPoolExecutor(max_workers=len(instances))")
        self.assertNotEqual(keygen, -1)
        self.assertNotEqual(pool, -1)
        self.assertLess(keygen, pool)


class DeployProxyTests(unittest.TestCase):
    def generate_script(self, peer_addr, identity="spiffe://example.test/peer", required_identity=True):
        scripts = []

        def run(args, **kwargs):
            output = ""
            if args[:4] == ["gcloud", "compute", "instances", "list"]:
                output = "example-host,us-central1-a\n"
            elif args[:3] == ["gcloud", "compute", "ssh"]:
                scripts.append(args[args.index("--command") + 1])
            elif args[:2] == ["ssh-keygen", "-q"]:
                pass
            elif args[:3] != ["gcloud", "compute", "scp"]:
                raise AssertionError(f"unexpected command: {args}")
            return subprocess.CompletedProcess(args, 0, output, "")

        env = {
            "GCP_PROJECT": "example-project",
            "SHA": "12345678",
            "PROXY_DOMAIN": "sandbox.example.test",
            "PEER_PROXY_LISTEN_ADDR": peer_addr,
            "PEER_IDENTITY_HOSTS": "example-host" if required_identity else "",
            "PEER_PROXY_SPIFFE_URI": identity,
            "PEER_PROXY_CERT_FILE": "/etc/peer/cert.pem",
            "PEER_PROXY_KEY_FILE": "/etc/peer/key.pem",
            "PEER_PROXY_CA_FILE": "/etc/peer/ca.pem",
        }
        with tempfile.TemporaryDirectory() as runner_dir, patch.dict(os.environ, env, clear=True), patch.object(
            MODULE.subprocess, "run", side_effect=run
        ), patch.object(MODULE.os.path, "expanduser", return_value=str(Path(runner_dir) / "google_compute_engine")):
            self.assertEqual(MODULE.main(), 0)
        self.assertEqual(len(scripts), 1)
        self.assertIn("PEER_PROXY_TARGET_ADDR=127.0.0.1:5010\n", scripts[0])
        return scripts[0]

    def test_generated_shell_parses(self):
        for peer_addr in ("", "auto"):
            with self.subTest(peer_addr=peer_addr):
                result = subprocess.run(
                    ["bash", "-n"], input=self.generate_script(peer_addr), capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflow_identity_is_not_authoritative(self):
        script = self.generate_script("auto", "spiffe://stale.example.test/peer")
        self.assertNotIn("spiffe://stale.example.test/peer", script)
        self.assertIn("/etc/superserve/peer/identity.json", script)
        self.assertLess(script.index("refresh-peer-credentials --check"), script.index("sudo mv /tmp/proxy"))

    def test_vmd_readiness_requires_current_invocation(self):
        script = self.generate_script("")
        readiness = script[script.index("wait_for_vmd_ready() {"):script.index("rollback_peer_advertisement() {")]
        for mode in ("ready", "not-ready", "restarted", "heartbeat-pending"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                functions = f'''
                sleep() {{ :; }}
                sudo() {{ "$@"; }}
                systemctl() {{
                    if [ "$1" = show ]; then
                        if [ "{mode}" = restarted ]; then
                            echo x >> "{tmp}/invocations"
                            wc -l < "{tmp}/invocations"
                        else
                            echo current-invocation
                        fi
                    fi
                    return 0
                }}
                journalctl() {{
                    [ "{mode}" != not-ready ] || return 1
                    if [ "{mode}" = heartbeat-pending ] && [[ "$*" == *"host endpoint heartbeat accepted"* ]]; then
                        return 1
                    fi
                    return 0
                }}
                '''
                result = subprocess.run(["bash"], input=functions + readiness + "wait_for_vmd_ready", text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, mode == "ready", result.stderr)

    def test_rollback_restores_listener_before_advertisement(self):
        cases = [(addr, failure, "spiffe://example.test/peer") for addr, failure in (("192.0.2.2:5010", "proxy"),
                                          ("192.0.2.2:5010", "superserve-vmd"),
                                          ("", "proxy"),
                                          ("192.0.2.2:5010", "tee"),
                                          ("192.0.2.2:5010", "sed"),
                                          ("192.0.2.2:5010", "chmod"),
                                          ("192.0.2.2:5010", "tee-dropin"),
                                          ("192.0.2.2:5010", "proxy-always"),
                                          ("192.0.2.2:5010", "none"))]
        cases += [("", "none", "spiffe://example.test/peer"), ("", "none", ""), ("auto", "none", ""),
                  ("auto", "missing-identity", ""),
                  ("", "missing-cert", "spiffe://example.test/peer")]
        for peer_addr, failed_service, identity in cases:
            with self.subTest(peer_addr=peer_addr, failed_service=failed_service), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                old_env = "PEER_PROXY_LISTEN_ADDR=192.0.2.2:5009\n"
                old_credentials = "[Service]\nLoadCredential=old-cert:/etc/peer/old.pem\n"
                files = {
                    "etc/sandbox/proxy.env": old_env,
                    "etc/sandbox/vmd.env": old_env,
                    "etc/systemd/system/proxy.service.d/peer-credentials.conf": old_credentials,
                    "etc/superserve/peer/tls.crt": "test cert",
                    "etc/superserve/peer/tls.key": "test key",
                    "etc/superserve/peer/ca.crt": "test ca",
                    "tmp/proxy-12345678": "binary",
                    "tmp/proxy.service": "unit",
                }
                for name, contents in files.items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(contents)
                (root / "bin").mkdir()
                (root / "run/lock").mkdir(parents=True)
                (root / "run/lock/vmd-peer-credentials.lock").touch()
                check = root / "bin/refresh-peer-credentials"
                check.write_text("#!/bin/sh\nexit 0\n")
                check.chmod(0o755)
                if identity:
                    (root / "etc/superserve/peer/identity.json").write_text(json.dumps({"spiffe_uri": identity}))
                if not identity or failed_service == "missing-cert":
                    (root / "etc/superserve/peer/tls.crt").unlink()
                script = self.generate_script(peer_addr, identity, bool(identity) or failed_service == "missing-identity")
                script = script.replace("/etc/", f"{root}/etc/")
                script = script.replace("/tmp/proxy", f"{root}/tmp/proxy")
                script = script.replace("/usr/local/bin", f"{root}/bin")
                script = script.replace("/usr/local/sbin", f"{root}/bin")
                script = script.replace("/run/lock", f"{root}/run/lock")
                # A backup suffix makes GNU in-place sed syntax portable to BSD sed.
                script = script.replace("sed -i ", "sed -i.bak ")
                functions = f'''
                sudo() {{
                    if [ ! -f "{root}/failed" ]; then
                        case "{failed_service}:$1:$2" in
                            tee:tee:*/proxy.env|sed:sed:-i.bak|chmod:chmod:0600|tee-dropin:tee:*/peer-credentials.conf)
                                "$@"
                                touch "{root}/failed"
                                return 1
                                ;;
                        esac
                    fi
                    "$@"
                }}
                sleep() {{ :; }}
                flock() {{ :; }}
                systemctl() {{
                    if [ "$1" = show ]; then echo current-invocation; return 0; fi
                    if [ "$1" = restart ]; then
                        echo "$2" >> "{root}/restarts"
                        if [ "{failed_service}" = proxy-always ] && [ "$2" = proxy ]; then
                            touch "{root}/failed"
                            return 1
                        fi
                        if [ "$2" = "{failed_service}" ] && [ ! -f "{root}/failed" ]; then
                            touch "{root}/failed"
                            return 1
                        fi
                    fi
                    return 0
                }}
                journalctl() {{ :; }}
                '''
                result = subprocess.run(["bash"], input=functions + script, text=True, capture_output=True)
                if failed_service == "none":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    proxy_env = (root / "etc/sandbox/proxy.env").read_text()
                    if not identity:
                        self.assertEqual("".join(line + "\n" for line in proxy_env.splitlines() if line.startswith("PEER_PROXY_")), old_env)
                        self.assertEqual((root / "etc/sandbox/vmd.env").read_text(), old_env)
                        self.assertEqual((root / "etc/systemd/system/proxy.service.d/peer-credentials.conf").read_text(), old_credentials)
                        self.assertEqual((root / "restarts").read_text().splitlines(), ["proxy"])
                        self.assertIn("PROXY_DOMAIN=sandbox.example.test", proxy_env)
                        continue
                    self.assertIn(f"PEER_PROXY_LISTEN_ADDR={peer_addr}\n", proxy_env)
                    if peer_addr:
                        self.assertIn(peer_addr, (root / "etc/sandbox/vmd.env").read_text())
                    else:
                        self.assertNotIn("PEER_PROXY_LISTEN_ADDR", (root / "etc/sandbox/vmd.env").read_text())
                    dropin = root / "etc/systemd/system/proxy.service.d/peer-credentials.conf"
                    self.assertEqual(dropin.exists(), bool(identity))
                    if identity:
                        for name in ("cert", "key", "ca"):
                            self.assertIn(f"LoadCredential=peer-{name}:", dropin.read_text())
                            self.assertIn(f"PEER_PROXY_{name.upper()}_FILE=/run/credentials/proxy.service/peer-{name}\n", proxy_env)
                    self.assertEqual(list((root / "etc/sandbox").glob("proxy-rollback.*")), [])
                    continue
                self.assertNotEqual(result.returncode, 0)
                if failed_service == "missing-identity":
                    self.assertIn("host requires infrastructure identity bootstrap", result.stderr)
                    self.assertEqual((root / "etc/sandbox/proxy.env").read_text(), old_env)
                    self.assertFalse((root / "restarts").exists())
                    continue
                if failed_service == "missing-cert":
                    self.assertIn("peer credential missing", result.stderr)
                    self.assertEqual((root / "etc/sandbox/proxy.env").read_text(), old_env)
                    self.assertEqual((root / "etc/systemd/system/proxy.service.d/peer-credentials.conf").read_text(), old_credentials)
                    self.assertFalse((root / "restarts").exists())
                    continue
                self.assertTrue((root / "failed").exists(), result.stderr)
                self.assertEqual((root / "etc/sandbox/proxy.env").read_text(), old_env)
                self.assertEqual((root / "etc/sandbox/vmd.env").read_text(), old_env)
                self.assertEqual((root / "etc/systemd/system/proxy.service.d/peer-credentials.conf").read_text(), old_credentials)
                restarts = (root / "restarts").read_text().splitlines()
                if failed_service == "tee-dropin":
                    self.assertEqual(restarts, ["proxy"])
                elif failed_service == "proxy-always":
                    self.assertEqual(restarts, ["proxy", "proxy"])
                    self.assertIn("snapshots retained", result.stderr)
                    self.assertEqual(len(list((root / "etc/sandbox").glob("proxy-rollback.*"))), 1)
                    continue
                else:
                    self.assertEqual(restarts[-2:], ["proxy", "superserve-vmd"])
                self.assertEqual(list((root / "etc/sandbox").glob("proxy-rollback.*")), [])


if __name__ == "__main__":
    unittest.main()
