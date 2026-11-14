"""Infrastructure-only public CI smoke checks, not a GhostMyFresh test suite."""

import pathlib
import sys
import unittest


class PublicRunnerSmokeTest(unittest.TestCase):
    def test_python_version(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 12))

    def test_public_inputs_directory_exists(self):
        self.assertTrue(pathlib.Path("jobs/README.md").is_file())


if __name__ == "__main__":
    unittest.main()
