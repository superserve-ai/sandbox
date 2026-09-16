import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_peer_bootstrap import load, ROOT, REFRESH

URI = 'spiffe://example.test/ns/vmd/sa/vmd-peer-proxy'


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.peer = self.root / 'peer'
        self.peer.mkdir()
        (self.peer / 'identity.json').write_text(json.dumps({'spiffe_uri': URI}))
        self.source = self.root / 'source'
        self.source.mkdir()
        self.command('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '60',
                     '-subj', '/CN=example-ca', '-keyout', 'ca.key', '-out', 'ca.crt',
                     '-addext', 'basicConstraints=critical,CA:TRUE')
        (self.root / 'index').touch()
        (self.root / 'serial').write_text('01\n')
        (self.root / 'ca.conf').write_text('''[ca]
default_ca=issuer
[issuer]
database=index
serial=serial
new_certs_dir=.
certificate=ca.crt
private_key=ca.key
default_md=sha256
default_days=30
policy=subject
x509_extensions=leaf
[subject]
commonName=supplied
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=URI:'''+URI+'\n')
        self.mint()
        shutil.copy(self.root / 'ca.crt', self.source / 'ca.crt')
        real_open = Path.open
        def opened(path, *args, **kwargs):
            if str(path) == '/run/lock/vmd-peer-credentials.lock':
                path = self.root / 'lock'
            return real_open(path, *args, **kwargs)
        self.patch = patch.object(Path, 'open', opened)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.umask = os.umask(0o077)
        self.addCleanup(os.umask, self.umask)

    def command(self, *args):
        subprocess.run(['openssl', *map(str, args)], cwd=self.root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def mint(self, *dates):
        self.command('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=example-leaf',
                     '-keyout', 'source/tls.key', '-out', 'request.csr')
        self.command('ca', '-batch', '-config', 'ca.conf', '-in', 'request.csr',
                     '-out', 'source/tls.crt', '-notext', *dates)

    def publish(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            REFRESH.refresh(self.peer, self.root / 'absent-mwi', mode='superserve',
                            cert=self.source / 'tls.crt', key=self.source / 'tls.key',
                            ca=self.source / 'ca.crt', **kwargs)

    def test_publish_is_atomic_root_private_idempotent_and_reports_policy(self):
        with patch.object(REFRESH.subprocess, 'run', wraps=subprocess.run) as run:
            self.publish()
            generation = (self.peer / 'current').resolve()
            self.publish()
            self.assertFalse(any(call.args[0][0] == 'systemctl' for call in run.call_args_list))
        self.assertEqual((self.peer / 'current').resolve(), generation)
        self.assertEqual((generation / 'tls.key').stat().st_mode & 0o777, 0o600)
        self.assertEqual((generation / 'tls.key').stat().st_uid, os.geteuid())
        status = json.loads((self.peer / 'status.json').read_text())
        self.assertEqual(status['provider'], 'superserve')
        self.assertGreater(status['seconds_remaining'], 29 * 86400)
        self.assertGreater(status['last_successful_installation'], 0)
        self.assertTrue(status['proxy_reload_required'])

    def test_missing_files_and_bad_bundle_keep_current(self):
        self.publish()
        before = (self.peer / 'current').resolve()
        for file in ('tls.crt', 'tls.key', 'ca.crt'):
            original = (self.source / file).read_bytes()
            (self.source / file).unlink()
            with self.assertRaises(FileNotFoundError):
                self.publish()
            (self.source / file).write_bytes(original)
            self.assertEqual((self.peer / 'current').resolve(), before)
        (self.source / 'tls.key').write_bytes((self.root / 'ca.key').read_bytes())
        with self.assertRaisesRegex(ValueError, 'key changed'):
            self.publish()
        self.assertEqual((self.peer / 'current').resolve(), before)

    def test_provider_is_explicit_and_mwi_never_downgrades(self):
        self.assertEqual(REFRESH.configured_provider(self.peer), 'mwi')
        self.publish()
        self.assertEqual(REFRESH.configured_provider(self.peer), 'superserve')
        with self.assertRaises(FileNotFoundError):
            REFRESH.refresh(self.peer, self.root / 'absent-mwi')
        with self.assertRaisesRegex(ValueError, 'requires explicit'):
            REFRESH.refresh(self.peer, mode='superserve')
        with self.assertRaisesRegex(ValueError, 'does not accept'):
            REFRESH.refresh(self.peer, cert=self.source / 'tls.crt')
        self.assertEqual(REFRESH.configured_provider(self.peer), 'superserve')

    def test_dates_wrong_identity_and_ca(self):
        for start, end in [('20200101000000Z', '20200102000000Z'),
                           ('20900101000000Z', '20900102000000Z')]:
            # Separate CA database records permit equal subjects for distinct fixtures.
            (self.root / 'index').write_text('')
            self.mint('-startdate', start, '-enddate', end)
            with self.assertRaisesRegex(ValueError, 'expired or not yet valid'):
                self.publish()
        (self.root / 'index').write_text('')
        self.mint()
        with self.assertRaisesRegex(ValueError, 'URI SAN'):
            REFRESH.validate(self.source, URI + '-wrong')
        self.command('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                     '-subj', '/CN=other-ca', '-keyout', 'other.key', '-out', 'source/ca.crt')
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()

    def test_configurable_lifetime_and_failure_visibility(self):
        self.publish()
        (self.peer / 'identity.json').write_text(json.dumps({'spiffe_uri': URI,
            'credential_policy': {'leaf_lifetime_seconds': 86400}}))
        with self.assertRaisesRegex(ValueError, 'configured leaf lifetime'):
            self.publish()
        with contextlib.redirect_stdout(io.StringIO()):
            REFRESH.report(self.peer, 'superserve', {'seconds_remaining': 2 * 86400}, error='renewal unavailable')
        status = json.loads((self.peer / 'status.json').read_text())
        self.assertEqual(status['failures'], 1)
        self.assertEqual(status['severity'], 'critical')
        self.assertTrue(status['renewal_due'])
        self.assertGreater(status['last_successful_installation'], 0)


if __name__ == '__main__':
    unittest.main()
