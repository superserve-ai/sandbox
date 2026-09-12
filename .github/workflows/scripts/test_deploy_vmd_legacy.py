"""Execute the enrollment guard against legacy, unmanaged and guest processes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_deploy_vmd_fresh import deploy_vmd, SOURCE


class LegacyRetirementTest(unittest.TestCase):
    def exercise(self, guests='', listener='', legacy='loaded', fresh=True, probe_error=False, stop_fails=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = root / 'agentbox-vmd.service'
            if legacy == 'loaded':
                unit.write_text('[Service]\nExecStart=/usr/local/bin/vmd\n')
            script = deploy_vmd.legacy_vmd_enrollment().replace('/etc/systemd/system', tmp)
            prelude = '''set -eu
sudo() { "$@"; }
pgrep() { if [ "$PROBE_ERROR" = 1 ]; then return 2; fi; [ "$GUESTS" = process ]; }
ss() { echo "$LISTENER"; }
systemctl() {
    case "$1" in
    list-units) if [ "$GUESTS" = unit ]; then echo 'firecracker@guest.service loaded active running guest'; fi ;;
    show)
        case "$*" in
        *LoadState*) echo "$LEGACY" ;;
        *ActiveState*) if [ "$STOP_FAILS" = 1 ]; then echo active; else echo inactive; fi ;;
        esac ;;
    disable|stop|mask|daemon-reload)
        echo "$1" >> "$CALLS"
        if [ "$1" = mask ]; then ln -sf /dev/null "$UNIT"; LEGACY=masked; fi ;;
    is-enabled) if [ -L "$UNIT" ]; then echo masked; return 1; else echo enabled; fi ;;
    esac
}
'''
            script += '\nif [ "$SECRETSPROXY_FRESH" = 1 ]; then retire_legacy_vmd; fi\necho socket-may-start\n'
            env = dict(os.environ, GUESTS=guests, LISTENER=listener, LEGACY=legacy,
                       PROBE_ERROR=str(int(probe_error)), STOP_FAILS=str(int(stop_fails)),
                       SECRETSPROXY_FRESH=str(int(fresh)), UNIT=str(unit), CALLS=str(root/'calls'))
            result = subprocess.run(['bash', '-c', prelude + script], env=env, text=True, capture_output=True)
            calls = (root/'calls').read_text() if (root/'calls').exists() else ''
            backup = root/'agentbox-vmd.service.retired'
            if result.returncode == 0 and fresh and legacy == 'loaded':
                self.assertEqual(os.readlink(unit), '/dev/null')
                self.assertIn('ExecStart=', backup.read_text())
                # A retry does not stop anything again and keeps the persistent mask.
                env['LEGACY'] = 'masked'
                retry = subprocess.run(['bash', '-c', prelude + script], env=env, text=True, capture_output=True)
                self.assertEqual(retry.returncode, 0, retry.stderr)
                self.assertEqual((root/'calls').read_text().count('stop\n'), 1)
            return result, calls

    def test_retirement_disables_stops_and_persistently_masks_local_unit(self):
        result, calls = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.splitlines(), ['disable', 'stop', 'mask', 'daemon-reload'])

    def test_guests_or_failed_inspection_abort_before_retirement(self):
        for options in ({'guests': 'process'}, {'guests': 'unit'}, {'probe_error': True}):
            with self.subTest(options=options):
                result, calls = self.exercise(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, '')
                self.assertNotIn('socket-may-start', result.stdout)

    def test_unmanaged_listeners_on_either_port_block_activation(self):
        for port in (50051, 9090):
            result, calls = self.exercise(legacy='not-found', listener=f'LISTEN 0 10 *:{port} *:* users:(("vmd",pid=123))')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('still have a listener', result.stderr)
            self.assertEqual(calls, '')

    def test_legacy_that_does_not_stop_blocks_activation(self):
        result, _ = self.exercise(stop_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('legacy VMD did not stop', result.stderr)

    def test_normal_serving_deploy_does_not_run_retirement(self):
        result, calls = self.exercise(fresh=False, guests='process')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, '')

    def test_checks_are_wired_before_mutation_and_socket_activation(self):
        self.assertLess(SOURCE.index('legacy_vmd_enrollment() +'), SOURCE.index('# Fresh-host env bootstrap:'))
        self.assertLess(SOURCE.index('                retire_legacy_vmd'), SOURCE.index('# Extract the deploy bundle'))
        gate = SOURCE.index('                require_vmd_ports_free', SOURCE.index('                restart_secretsproxy'))
        self.assertLess(gate, SOURCE.index('sudo rm -f /etc/systemd/system/superserve-vmd.socket.d/05-fresh-runtime.conf'))
