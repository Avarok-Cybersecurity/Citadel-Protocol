"""Unit tests of ci/toolchain_pin_gate.py. Run: python3 -m unittest discover -s ci/tests"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import toolchain_pin_gate as gate  # noqa: E402

PINNED = '[toolchain]\nchannel = "1.100.0"\n'
SETUP = "steps:\n  - run: rustup toolchain install\n"
IMAGE = "FROM rust:latest\nCOPY . .\nRUN rustup toolchain install\nRUN cargo build --locked\n"


def tree(toolchain=PINNED, action=SETUP, image=IMAGE) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "rust-toolchain.toml").write_text(toolchain)
        (root / ".github" / "actions").mkdir(parents=True)
        (root / ".github" / "actions" / "action.yml").write_text(action)
        (root / "docker" / "server").mkdir(parents=True)
        (root / "docker" / "server" / "Dockerfile").write_text(image)
        return gate.findings(root)


class ToolchainPinGate(unittest.TestCase):
    def test_a_pinned_tree_passes(self):
        self.assertEqual(tree(), [])

    def test_the_repository_passes(self):
        self.assertEqual(gate.findings(Path(__file__).resolve().parents[2]), [])

    def test_a_floating_action_ref_fails(self):
        self.assertTrue(tree(action="steps:\n  - uses: dtolnay/rust-toolchain@stable\n"))

    def test_a_floating_toolchain_input_fails(self):
        self.assertTrue(tree(action="with:\n  toolchain: stable\n"))

    def test_a_floating_cargo_override_fails(self):
        self.assertTrue(tree(action="run: cargo +nightly build --locked\n"))

    def test_a_floating_cargo_make_argument_fails(self):
        self.assertTrue(tree(action='args = ["component", "add", "x", "--toolchain", "nightly"]\n'))

    def test_a_channel_that_is_not_a_version_fails(self):
        self.assertTrue(tree(toolchain='[toolchain]\nchannel = "stable"\n'))

    def test_an_image_on_its_base_toolchain_fails(self):
        self.assertTrue(tree(image="FROM rust:latest\nCOPY . .\nRUN cargo build --locked\n"))

    def test_an_image_installing_before_the_tree_is_copied_fails(self):
        self.assertTrue(tree(image="FROM rust:latest\nRUN rustup toolchain install\nCOPY . .\nRUN cargo build --locked\n"))
