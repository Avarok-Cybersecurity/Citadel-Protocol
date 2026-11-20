import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_deps_gate import findings  # noqa: E402

ROOT = """
[workspace]
members = ["a", "b"]
[workspace.dependencies]
used_plain = "1"
used_dev = "1"
used_target = "1"
unused = "1"
"""
A = """
[package]
name = "a"
[dependencies]
used_plain = { workspace = true }
local = { path = "../local" }
[dev-dependencies]
used_dev = { workspace = true, features = ["x"] }
"""
B = """
[package]
name = "b"
[target.'cfg(unix)'.dependencies]
used_target = { workspace = true }
"""


def tree(root: str, a: str = A, b: str = B) -> Path:
    base = Path(tempfile.mkdtemp())
    (base / "Cargo.toml").write_text(root)
    for name, text in (("a", a), ("b", b)):
        (base / name).mkdir()
        (base / name / "Cargo.toml").write_text(text)
    return base


class WorkspaceDepsGate(unittest.TestCase):
    def test_an_unused_entry_is_named(self):
        self.assertEqual(
            findings(tree(ROOT)),
            ["Cargo.toml: workspace dependency `unused` is used by no member; remove it"],
        )

    def test_entries_inherited_in_every_section_count_as_used(self):
        self.assertEqual(findings(tree(ROOT.replace('unused = "1"\n', ""))), [])

    def test_a_member_naming_the_crate_without_inheriting_does_not_count(self):
        a = A.replace("used_plain = { workspace = true }", 'used_plain = "1"')
        root = ROOT.replace('unused = "1"\n', "")
        self.assertEqual(
            findings(tree(root, a=a)),
            ["Cargo.toml: workspace dependency `used_plain` is used by no member; remove it"],
        )

    def test_this_repository_passes(self):
        self.assertEqual(findings(Path(__file__).resolve().parents[2]), [])


if __name__ == "__main__":
    unittest.main()
