"""Check unreachable production code independently of missing test fixtures."""

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProductionVetTest(unittest.TestCase):
    def test_config_has_no_unreachable_code(self):
        tags = subprocess.check_output(
            ["make", "-s", "NAIVE=0", "print-TAGS"], cwd=ROOT, text=True
        ).strip()
        package = json.loads(subprocess.check_output(
            ["go", "list", "-tags", tags, "-json", "./v2/config"], cwd=ROOT, text=True
        ))
        # GoFiles respects platform selection and excludes test files. Existing
        # test-fixture compilation is covered separately by issue #28.
        sources = [str(Path(package["Dir"]) / name) for name in package["GoFiles"]]
        result = subprocess.run(
            ["go", "vet", "-unreachable", "-tags", tags, *sources], cwd=ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
