"""Unit tests of the pure decisions in ci/lockfile_age_gate.py and ci/cargo_locked_gate.py.

Run: python3 -m unittest discover -s ci/tests
"""
import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cargo_locked_gate as locked  # noqa: E402
import lockfile_age_gate as age  # noqa: E402

NOW = dt.datetime(2026, 11, 18, tzinfo=dt.timezone.utc)
FLOOR = dt.timedelta(days=14)


def lock(*entries: str) -> str:
    return "version = 4\n" + "".join(entries)


def pkg(name: str, version: str, checksum: str | None = "ab", source: str | None = age.CRATES_IO) -> str:
    out = f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if source:
        out += f'source = "{source}"\n'
    if checksum:
        out += f'checksum = "{checksum}"\n'
    return out


def at(when: dt.datetime, cksum: str = "ab") -> age.Published:
    return age.Published(when, cksum)


class AgeGate(unittest.TestCase):
    def judge(self, base: str, head: str, published: dict, allow: str = "") -> list[str]:
        entries = age.new_entries(age.parse_lock(base), age.parse_lock(head))
        return age.violations(entries, published, age.parse_allowlist(allow), NOW, FLOOR)

    def test_fresh_bump_fails(self):
        found = self.judge(lock(pkg("a", "1.0.0")), lock(pkg("a", "1.0.1")), {("a", "1.0.1"): at(NOW - dt.timedelta(days=2))})
        self.assertEqual(len(found), 1)
        self.assertIn("a 1.0.1", found[0])

    def test_old_bump_passes(self):
        self.assertEqual(self.judge(lock(pkg("a", "1.0.0")), lock(pkg("a", "1.0.1")), {("a", "1.0.1"): at(NOW - dt.timedelta(days=30))}), [])

    def test_unchanged_young_entry_is_not_rejudged(self):
        self.assertEqual(self.judge(lock(pkg("a", "1.0.0")), lock(pkg("a", "1.0.0")), {}), [])

    def test_missing_base_judges_everything(self):
        found = self.judge("", lock(pkg("a", "1.0.0")), {("a", "1.0.0"): at(NOW)})
        self.assertEqual(len(found), 1)

    def test_missing_checksum_fails(self):
        found = self.judge("", lock(pkg("a", "1.0.0", checksum=None)), {})
        self.assertEqual(found, ["a 1.0.0: no checksum in Cargo.lock"])

    def test_checksum_must_match_the_index(self):
        found = self.judge("", lock(pkg("a", "1.0.0")), {("a", "1.0.0"): at(NOW - dt.timedelta(days=90), "cd")})
        self.assertEqual(found, ["a 1.0.0: Cargo.lock checksum differs from crates.io's"])

    def test_unknown_version_or_missing_pubtime_fails(self):
        self.assertEqual(self.judge("", lock(pkg("a", "1.0.0")), {}), ["a 1.0.0: not in the crates.io index"])
        found = self.judge("", lock(pkg("a", "1.0.0")), {("a", "1.0.0"): age.Published(None, "ab")})
        self.assertEqual(found, ["a 1.0.0: the index gives no publish time"])

    def test_index_layout(self):
        self.assertEqual([age.index_path(n) for n in ("a", "cc", "lru", "Bytes")], ["1/a", "2/cc", "3/l/lru", "by/te/bytes"])
        recs = age.parse_index('{"vers":"1.0.0","cksum":"ab","pubtime":"2026-11-01T00:00:00Z"}\n{"vers":"0.1.0","cksum":"cd"}\n')
        self.assertEqual(recs["1.0.0"], age.Published(dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc), "ab"))
        self.assertIsNone(recs["0.1.0"].pubtime)

    def test_git_and_path_entries_are_not_judged_here(self):
        head = lock(pkg("q", "0.11.0", checksum=None, source="git+https://github.com/x/q?rev=1#1"), pkg("local", "0.1.0", checksum=None, source=None))
        self.assertEqual(self.judge("", head, {}), [])

    def test_allowlisted_fresh_entry_passes(self):
        allow = '[[exception]]\nname = "a"\nversion = "1.0.1"\nadded = 2026-11-18\nreason = "security fix"\n'
        self.assertEqual(self.judge("", lock(pkg("a", "1.0.1")), {("a", "1.0.1"): at(NOW)}, allow), [])

    def test_allowlist_names_the_exact_version(self):
        allow = '[[exception]]\nname = "a"\nversion = "1.0.0"\nadded = 2026-11-18\nreason = "security fix"\n'
        self.assertEqual(len(self.judge("", lock(pkg("a", "1.0.1")), {("a", "1.0.1"): at(NOW)}, allow)), 1)

    def test_allowlist_entry_needs_date_and_reason(self):
        with self.assertRaises(ValueError):
            age.parse_allowlist('[[exception]]\nname = "a"\nversion = "1.0.1"\nadded = 2026-11-18\n')
        with self.assertRaises(ValueError):
            age.parse_allowlist('[[exception]]\nname = "a"\nversion = "1.0.1"\nadded = "soon"\nreason = "r"\n')


class LockedGate(unittest.TestCase):
    def problems(self, line: str) -> list[str]:
        return [f.problem for f in locked.judge_line("x", line)]

    def test_resolving_without_locked_fails(self):
        self.assertEqual(self.problems("cargo build -p a"), ["resolves without --locked"])
        self.assertEqual(self.problems("cargo nextest run -p a && cargo test --locked"), ["resolves without --locked"])

    def test_resolving_with_locked_passes(self):
        self.assertEqual(self.problems("cargo nextest run --locked -p a"), [])
        self.assertEqual(self.problems("cargo install cargo-make --locked; cargo install x --locked"), [])

    def test_wasm_pack_forwards_locked(self):
        self.assertEqual(self.problems("wasm-pack test --node -- --test t"), ["wasm-pack forwards no --locked to cargo"])
        self.assertEqual(self.problems("wasm-pack test --node -- --locked --test t"), [])

    def test_non_resolving_and_unknown(self):
        self.assertEqual(self.problems("cargo fmt --check"), [])
        self.assertEqual(self.problems("cargo frobnicate"), ["unclassified cargo subcommand `frobnicate`"])

    def test_only_run_values_are_commands(self):
        text = "- name: cargo build all\n  run: cargo build --locked\n- run: |\n    cargo check\n  env:\n    A: cargo test\n"
        lines = [l for _, l in locked.logical_lines(locked.workflow_commands(text))]
        self.assertEqual(lines, ["cargo build --locked", "cargo check"])


if __name__ == "__main__":
    unittest.main()


class OutOfWorkspaceLockfiles(unittest.TestCase):
    def tree(self) -> Path:
        import tempfile
        root = Path(tempfile.mkdtemp())
        for d in ("", "fuzz", "target/debug", "web/node_modules/x"):
            (root / d).mkdir(parents=True, exist_ok=True)
            (root / d / "Cargo.lock").write_text("version = 4\n")
        (root / "fuzz" / "Cargo.toml").write_text("[package]\n")
        return root

    def test_only_lockfiles_outside_the_workspace_and_build_dirs_are_found(self):
        root = self.tree()
        self.assertEqual(locked.lockfiles_outside_the_workspace(root), [root / "fuzz" / "Cargo.lock"])

    def test_a_lockfile_cargo_would_rewrite_fails(self):
        root = self.tree()
        stale = lambda _m: (101, "error: cannot update the lock file because --locked was passed\n")
        found = locked.stale_lockfiles(root, locked.lockfiles_outside_the_workspace(root), stale)
        self.assertEqual(len(found), 1)
        self.assertIn("not current", found[0].problem)

    def test_a_current_lockfile_passes(self):
        root = self.tree()
        self.assertEqual(locked.stale_lockfiles(root, locked.lockfiles_outside_the_workspace(root), lambda _m: (0, "")), [])

    def test_a_lockfile_without_a_manifest_fails(self):
        root = self.tree()
        (root / "fuzz" / "Cargo.toml").unlink()
        found = locked.stale_lockfiles(root, locked.lockfiles_outside_the_workspace(root), lambda _m: (0, ""))
        self.assertEqual([f.problem for f in found], ["has no Cargo.toml beside it"])
