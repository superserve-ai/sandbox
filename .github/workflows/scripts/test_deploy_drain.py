import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('deploy_vmd_drain', pathlib.Path(__file__).with_name('deploy-vmd.py'))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

class DrainEnrollmentTest(unittest.TestCase):
    def test_default_preserves_existing_configuration(self):
        self.assertEqual(deploy.drain_configuration({}), '')

    def test_explicit_enrollment_requires_control_plane_principal(self):
        with self.assertRaises(SystemExit):
            deploy.drain_configuration({'VMD_DRAIN_ENABLED': 'true'})
        script = deploy.drain_configuration({'VMD_DRAIN_ENABLED': 'true', 'VMD_ADMISSION_CALLER_EMAIL': 'control@example.iam.gserviceaccount.com'})
        self.assertIn('VMD_DRAIN_ENABLED=true', script)
        self.assertIn('VMD_ADMISSION_CALLER_EMAIL=control@example.iam.gserviceaccount.com', script)

    def test_cannot_disable_persisted_fence_by_deployment(self):
        with self.assertRaises(SystemExit):
            deploy.drain_configuration({'VMD_DRAIN_ENABLED': 'false'})
