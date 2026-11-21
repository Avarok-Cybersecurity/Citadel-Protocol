"""Unit tests of ci/types_version_gate.py. Run: python3 -m unittest discover -s ci/tests"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import types_version_gate as gate  # noqa: E402

BINDING = "citadel-protocol-types-ts/src/KemAlgorithm.ts"
RUST = "citadel_types/src/crypto/mod.rs"


def write_package(root: Path, version: str, lock_version: str | None = None) -> None:
    pkg = root / gate.PACKAGE_DIR
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "package.json").write_text(json.dumps({"name": "t", "version": version}))
    (pkg / "package-lock.json").write_text(json.dumps({"name": "t", "version": lock_version or version}))


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def repo_findings(edit: str | None, head_version: str, lock_version: str | None = None) -> list[str]:
    """A two-commit repository: master at 0.14.1, then a branch commit; the gate judges the branch."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        git(root, "init", "-q", "-b", "master")
        git(root, "config", "user.email", "gate@test")
        git(root, "config", "user.name", "gate")
        git(root, "config", "commit.gpgsign", "false")
        write_package(root, "0.14.1")
        (root / "README").write_text("x")
        git(root, "add", ".")
        git(root, "commit", "-q", "-m", "base")
        git(root, "checkout", "-q", "-b", "branch")
        if edit is not None:
            (root / edit).parent.mkdir(parents=True, exist_ok=True)
            (root / edit).write_text("changed")
        write_package(root, head_version, lock_version)
        git(root, "add", ".")
        git(root, "commit", "-q", "--allow-empty", "-m", "branch")
        return gate.findings(root, "master")


class TypesVersionGate(unittest.TestCase):
    def test_a_binding_change_with_a_bump_passes(self):
        self.assertEqual(repo_findings(BINDING, "0.15.0"), [])

    def test_a_binding_change_without_a_bump_fails(self):
        self.assertTrue(repo_findings(BINDING, "0.14.1"))

    def test_a_rust_types_change_without_a_bump_fails(self):
        self.assertTrue(repo_findings(RUST, "0.14.1"))

    def test_a_lower_version_fails(self):
        self.assertTrue(repo_findings(BINDING, "0.14.0"))

    def test_an_unrelated_change_needs_no_bump(self):
        self.assertEqual(repo_findings("citadel_proto/src/lib.rs", "0.14.1"), [])

    def test_a_lockfile_behind_package_json_fails(self):
        self.assertTrue(repo_findings(None, "0.15.0", lock_version="0.14.1"))

    def test_a_non_semver_version_is_refused(self):
        with self.assertRaises(ValueError):
            gate.parse_version("0.15")


if __name__ == "__main__":
    unittest.main()
