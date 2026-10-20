import hashlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hostprep_reader import stream

ORIGINAL = os.urandom(3 << 20)


class StreamTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "base.ext4"
        self.path.write_bytes(ORIGINAL)
        # Filesystem timestamps move in coarse ticks; backdate the file and wait
        # for a later tick so any change made during the read is visible.
        os.utime(self.path, ns=(0, 0))
        scratch = Path(self.dir.name) / "tick"
        while True:
            scratch.write_bytes(b"")
            if scratch.stat().st_ctime_ns > self.path.stat().st_ctime_ns:
                break

    def tearDown(self):
        self.dir.cleanup()

    def read(self, after_first_block):
        out, calls = io.BytesIO(), []

        def hook():
            calls.append(1)
            if len(calls) == 1:
                after_first_block()

        sha256, size, stable = stream(self.path, out, hook)
        self.assertEqual(sha256, hashlib.sha256(out.getvalue()).hexdigest())
        self.assertEqual(size, len(out.getvalue()))
        return out.getvalue(), stable

    def test_unchanged_file_is_stable(self):
        data, stable = self.read(lambda: None)
        self.assertEqual(data, ORIGINAL)
        self.assertTrue(stable)

    def test_atomic_replacement_mid_read_keeps_the_original_and_is_stable(self):
        def replace():
            staged = self.path.with_suffix(".new")
            staged.write_bytes(os.urandom(len(ORIGINAL)))
            os.replace(staged, self.path)

        data, stable = self.read(replace)
        self.assertEqual(data, ORIGINAL)
        self.assertTrue(stable)

    def test_in_place_write_mid_read_is_unstable(self):
        def write():
            with open(self.path, "r+b") as target:
                target.seek(len(ORIGINAL) - 1)
                target.write(b"\0" if ORIGINAL[-1:] != b"\0" else b"\1")

        self.assertFalse(self.read(write)[1])

    def test_in_place_write_that_restores_mtime_is_unstable(self):
        def write():
            with open(self.path, "r+b") as target:
                target.seek(len(ORIGINAL) - 1)
                target.write(b"\0" if ORIGINAL[-1:] != b"\0" else b"\1")
            os.utime(self.path, ns=(0, 0))

        self.assertFalse(self.read(write)[1])


if __name__ == "__main__":
    unittest.main()
