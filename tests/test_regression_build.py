"""Ensure the committed regression suites include every helper they require."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RegressionBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # These checks cover Go test fixtures, independently of native Cronet.
        cls.tags = subprocess.check_output(
            ["make", "-s", "NAIVE=0", "print-TAGS"], cwd=ROOT, text=True
        ).strip()

    def assert_suite_builds(self, package):
        result = subprocess.run(
            ["go", "test", "-tags", self.tags, "-ldflags=-checklinkname=0",
             "-run", "^$", package],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_config_regressions_compile(self):
        self.assert_suite_builds("./v2/config")

    def test_core_regressions_compile(self):
        self.assert_suite_builds("./v2/hcore")


if __name__ == "__main__":
    unittest.main()
