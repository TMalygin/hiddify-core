"""Build the real Linux Makefile target with a minimal, non-networking Go core."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LinuxLoaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="hiddify-loader-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.bundle = cls.root / "bin"
        shutil.copyfile(ROOT / "Makefile", cls.root / "Makefile")
        (cls.root / "go.mod").write_text("module example.invalid/loader\n\ngo 1.27.3\n")
        (cls.root / "platform/desktop").mkdir(parents=True)
        (cls.root / "platform/desktop/main.go").write_text('''package main
/*
#include <stdlib.h>
*/
import "C"
//export parseCli
func parseCli(argc C.int, argv **C.char) *C.char { return C.CString("fixture-ok") }
func main() {}
''')
        (cls.root / "cmd/bydll").mkdir(parents=True)
        shutil.copyfile(ROOT / "cmd/bydll/clibydll.go", cls.root / "cmd/bydll/clibydll.go")
        (cls.root / "cronet").mkdir()
        (cls.root / "cronet/cronet.env").write_text("CC=cc\nCGO_LDFLAGS=\n")
        (cls.root / "hiddify-sing-box/.github").mkdir(parents=True)
        (cls.root / "hiddify-sing-box/.github/CRONET_GO_VERSION").write_text("fixture\n")
        # This disposable fixture is deliberately outside the source Git tree.
        result = subprocess.run(["make", "ARCH=amd64", "build-linux"], cwd=cls.root,
                                env={**os.environ, "GOFLAGS": "-buildvcs=false"},
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
        if result.returncode:
            raise AssertionError("fixture could not build with the production Makefile:\n" + result.stdout)
        cls.environment = dict(os.environ)
        cls.environment.pop("LD_LIBRARY_PATH", None)
        cls.environment.pop("LD_PRELOAD", None)

    def run_cli(self, directory):
        return subprocess.run([str(self.bundle / "HiddifyCli")], cwd=directory, env=self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)

    def test_cli_loads_beside_its_executable_from_an_unrelated_directory(self):
        control = self.run_cli(self.bundle)
        self.assertEqual(control.returncode, 0, control.stdout)
        self.assertEqual(control.stdout.strip(), "fixture-ok")
        outside = self.root / "unrelated"
        outside.mkdir()
        result = self.run_cli(outside)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.strip(), "fixture-ok")

    def test_library_identity_and_dependency_are_not_relative_paths(self):
        library = subprocess.check_output(["readelf", "-d", str(self.bundle / "lib/hiddify-core.so")], text=True)
        cli = subprocess.check_output(["readelf", "-d", str(self.bundle / "HiddifyCli")], text=True)
        self.assertRegex(library, r"\(SONAME\).*\[hiddify-core\.so\]")
        self.assertRegex(cli, r"\(NEEDED\).*\[hiddify-core\.so\]")
        self.assertNotIn("[./lib/hiddify-core.so]", cli)


if __name__ == "__main__":
    unittest.main()
