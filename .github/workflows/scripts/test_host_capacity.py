import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_deploy_vmd_fresh import deploy_vmd


class HostCapacityTest(unittest.TestCase):
    def exercise(self, host='named-host', memory='', cpu='', supplied=('110000', '32')):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / 'vmd.env'
            original = f'HOST_ID={host}\nVMD_SCHEDULABLE_MEMORY_MIB={memory}\nVMD_SCHEDULABLE_VCPUS={cpu}\n'
            env.write_text(original)
            script = deploy_vmd.capacity_script(*supplied).replace('/etc/sandbox/vmd.env', str(env))
            result = subprocess.run(['bash', '-ec', 'sudo() { "$@"; };\n' + script + '\necho activation-allowed'], capture_output=True, text=True)
            if result.returncode:
                self.assertEqual(env.read_text(), original)
                self.assertNotIn('activation-allowed', result.stdout)
            return result, env.read_text()

    def test_staging_and_production_selection(self):
        self.assertEqual(deploy_vmd.capacity_inputs('superserve-vmd-staging-2', {}), ('110000', '32'))
        for cell, memory, cpu in [('USE4', '900000', '100'), ('USW2', '800000', '90')]:
            # Synthetic policy values; these are not production admission defaults.
            values = deploy_vmd.capacity_inputs('production-host', {'VMD_SCHEDULABLE_MEMORY_MIB': memory, 'VMD_SCHEDULABLE_VCPUS': cpu})
            result, content = self.exercise(supplied=values)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('VMD_SCHEDULABLE_MEMORY_MIB=' + memory, content)
            self.assertIn('VMD_SCHEDULABLE_VCPUS=' + cpu, content)
            workflow = (Path(__file__).parents[1] / 'deploy-vmd.yml').read_text()
            self.assertIn('${{ vars.VMD_SCHEDULABLE_MEMORY_MIB_' + cell + ' }}', workflow)
            self.assertIn('${{ vars.VMD_SCHEDULABLE_VCPUS_' + cell + ' }}', workflow)
        self.assertEqual(deploy_vmd.capacity_inputs('production-host', {}), ('', ''))
        self.assertEqual(deploy_vmd.capacity_inputs('production-host', {}, {'capacity_memory_mib': 12345, 'capacity_vcpus': 12}), ('12345', '12'))

    def test_missing_zero_or_invalid_capacity_blocks_activation(self):
        for supplied in [('', '32'), ('110000', ''), ('0', '32'), ('110000', '0'), ('-1', '32'), ('1.5', '32'), ('2147483648', '32')]:
            result, _ = self.exercise(supplied=supplied)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('positive explicit', result.stderr)
        result, _ = self.exercise(memory='0', cpu='32')
        self.assertNotEqual(result.returncode, 0)

    def test_existing_explicit_values_and_legacy_default_are_preserved(self):
        result, content = self.exercise(memory='90000', cpu='24')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('VMD_SCHEDULABLE_MEMORY_MIB=90000', content)
        self.assertIn('VMD_SCHEDULABLE_VCPUS=24', content)
        result, content = self.exercise(host='default', supplied=('', ''))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(content, 'HOST_ID=default\nVMD_SCHEDULABLE_MEMORY_MIB=\nVMD_SCHEDULABLE_VCPUS=\n')
