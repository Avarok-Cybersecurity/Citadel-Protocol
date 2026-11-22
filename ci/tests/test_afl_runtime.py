"""Tests of ci/afl-runtime.sh and of the fuzz workflow's use of it.

Run: python3 -m unittest discover -s ci/tests

The script is run against stand-ins for `cargo` and `rustc` on PATH: they answer as cargo-afl
does (the runtime check `cargo afl build --help` makes, its version) from a state directory, so
each case sets up exactly the installed version and runtime it judges. The real tools are not
needed to judge the script's decisions, and installing them takes minutes.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cargo_locked_gate  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "ci" / "afl-runtime.sh"
LOCK = 'version = 4\n\n[[package]]\nname = "afl"\nversion = "0.18.2"\nsource = "registry+x"\n'

CARGO = """#!/usr/bin/env bash
state="$STUB_STATE"
echo "cargo $*" >> "$state/calls"
case "$*" in
  "afl --version") [ -f "$state/version" ] && echo "cargo-afl $(cat "$state/version")" || exit 101 ;;
  "afl build --locked --help")
    [ -f "$state/runtime" ] || { echo "AFL LLVM runtime was not built for Rust rustc-1.100.0-0ef1bc3" >&2; exit 1; } ;;
  "install cargo-afl --version "*" --locked") echo "$4" > "$state/version" ;;
  "afl config --build") touch "$state/runtime" ;;
  *) echo "unexpected: cargo $*" >&2; exit 99 ;;
esac
"""
RUSTC = """#!/usr/bin/env bash
printf 'rustc 1.100.0\\nrelease: 1.100.0\\ncommit-hash: 0ef1bc386059596dada8fb65b50425aab2ea637a\\n'
"""


class AflRuntimeScript(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "ci").mkdir()
        (self.tmp / "fuzz").mkdir()
        shutil.copy(SCRIPT, self.tmp / "ci" / "afl-runtime.sh")
        (self.tmp / "fuzz" / "Cargo.lock").write_text(LOCK)
        self.bin = self.tmp / "bin"
        self.state = self.tmp / "state"
        self.bin.mkdir()
        self.state.mkdir()
        for name, text in (("cargo", CARGO), ("rustc", RUSTC)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)

    def given(self, version=None, runtime=False):
        if version:
            (self.state / "version").write_text(version)
        if runtime:
            (self.state / "runtime").touch()

    def run_script(self, mode):
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "STUB_STATE": str(self.state)}
        return subprocess.run(["bash", str(self.tmp / "ci" / "afl-runtime.sh"), mode], env=env, capture_output=True, text=True)

    def calls(self):
        path = self.state / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def test_check_names_the_install_when_cargo_afl_is_missing(self):
        done = self.run_script("check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("cargo-afl is not installed", done.stderr)
        self.assertIn("run: cargo install cargo-afl --version 0.18.2 --locked", done.stderr)

    def test_check_names_the_install_when_cargo_afl_is_another_version(self):
        self.given(version="0.17.0", runtime=True)
        done = self.run_script("check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("cargo-afl 0.17.0 is installed, fuzz/Cargo.lock pins afl 0.18.2", done.stderr)

    def test_check_names_the_config_build_when_the_toolchain_has_no_runtime(self):
        self.given(version="0.18.2")
        done = self.run_script("check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("no AFL++ runtime for rustc-1.100.0-0ef1bc3", done.stderr)
        self.assertIn("run: cargo afl config --build", done.stderr)

    def test_check_passes_when_both_are_in_place(self):
        self.given(version="0.18.2", runtime=True)
        self.assertEqual(self.run_script("check").returncode, 0)

    def test_install_installs_both_from_nothing(self):
        done = self.run_script("install")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("cargo install cargo-afl --version 0.18.2 --locked", self.calls())
        self.assertIn("cargo afl config --build", self.calls())

    def test_install_rebuilds_nothing_that_is_in_place(self):
        self.given(version="0.18.2", runtime=True)
        self.assertEqual(self.run_script("install").returncode, 0)
        self.assertFalse([c for c in self.calls() if c.startswith(("cargo install", "cargo afl config"))])

    def test_an_unknown_mode_is_refused(self):
        self.assertEqual(self.run_script("build").returncode, 2)


class FuzzWiring(unittest.TestCase):
    def test_the_workflow_installs_through_the_script_before_fuzzing(self):
        text = cargo_locked_gate.workflow_commands((REPO / ".github" / "workflows" / "fuzz.yml").read_text())
        self.assertNotIn("binstall", text)
        self.assertLess(text.index("ci/afl-runtime.sh install"), text.index("cargo make fuzz"))

    def test_the_fuzz_task_checks_before_it_builds(self):
        script = tomllib.loads((REPO / "Makefile.toml").read_text())["tasks"]["fuzz"]["script"]
        self.assertLess(script.index("ci/afl-runtime.sh check"), script.index("cargo afl build"))


if __name__ == "__main__":
    unittest.main()
