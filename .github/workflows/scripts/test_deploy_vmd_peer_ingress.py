"""Run the peer-listener upsert against a fake host env."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

from shell_test_support import linux_shell_prelude

spec = importlib.util.spec_from_file_location('deploy_vmd_peer', Path(__file__).with_name('deploy-vmd.py'))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class PeerIngressDeploymentTest(unittest.TestCase):
    def exercise(self, existing, env, metadata_ip='192.0.2.10'):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'vmd.env'
            path.write_text(existing)
            script = deploy.peer_ingress_update(env).replace('/etc/sandbox/vmd.env', str(path))
            stubs = f'sudo() {{ "$@"; }}\ncurl() {{ echo {metadata_ip}; }}\n'
            result = subprocess.run(['bash', '-ec', linux_shell_prelude() + '\n' + stubs + script], text=True, capture_output=True)
            return result, path.read_text()

    def test_enabled_advertises_host_peer_listener_once(self):
        result, contents = self.exercise('UNRELATED=keep\nPEER_PROXY_LISTEN_ADDR=192.0.2.9:5009\n', {'PEER_INGRESS_ENABLED': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(contents, 'UNRELATED=keep\nPEER_PROXY_LISTEN_ADDR=192.0.2.10:5009\n')
        result, again = self.exercise(contents, {'PEER_INGRESS_ENABLED': '1'})
        self.assertEqual((result.returncode, again), (0, contents))

    def test_disabled_leaves_existing_setting(self):
        self.assertEqual(deploy.peer_ingress_update({'PEER_INGRESS_ENABLED': ''}), '')
        self.assertEqual(deploy.peer_ingress_update({}), '')

    def test_unexpected_metadata_fails_before_writing(self):
        result, contents = self.exercise('UNRELATED=keep\n', {'PEER_INGRESS_ENABLED': '1'}, metadata_ip='not-an-ip')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(contents, 'UNRELATED=keep\n')


if __name__ == '__main__':
    unittest.main()
