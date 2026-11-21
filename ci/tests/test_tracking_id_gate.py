"""Unit tests of ci/tracking_id_gate.py. Run: python3 -m unittest discover -s ci/tests

The identifiers are assembled at run time so this file never contains one itself.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tracking_id_gate as gate  # noqa: E402

PREFIX = "S" + "A-"
GH_PREFIX = "GH" + "SA-"


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class Scan(unittest.TestCase):
    def test_public_algorithm_names_pass(self) -> None:
        self.assertEqual(gate.scan("sign with ML-D" + PREFIX + "65 (MlDsa65); D" + PREFIX + "65 too"), [])

    def test_identifier_fails(self) -> None:
        self.assertEqual(gate.scan("fix\n\nlane " + PREFIX + "10 done"), [(3, "lane " + PREFIX + "10 done")])

    def test_identifier_fails_in_lower_case(self) -> None:
        self.assertEqual(len(gate.scan(PREFIX.lower() + "3: tidy")), 1)

    def test_gh_identifier_fails(self) -> None:
        self.assertEqual(len(gate.scan("see " + GH_PREFIX + "abcd-")), 1)

    def test_plain_text_passes(self) -> None:
        self.assertEqual(gate.scan("fix(proto): close the stream on drop\n\nNo identifiers here."), [])

    def test_finding_names_source_and_line(self) -> None:
        self.assertEqual(gate.findings([("commit abc", "ok\n" + PREFIX + "10")]), ["commit abc line 2: " + PREFIX + "10"])


class CommitRange(unittest.TestCase):
    def test_only_commits_the_branch_adds_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q", "-b", "master")
            for args in (("user.name", "t"), ("user.email", "t@example.invalid"), ("commit.gpgsign", "false")):
                git(root, "config", *args)
            git(root, "commit", "-q", "--allow-empty", "-m", "base " + PREFIX + "1")
            git(root, "checkout", "-q", "-b", "topic")
            git(root, "commit", "-q", "--allow-empty", "-m", "topic work")
            messages = gate.commit_messages(root, "master")
            self.assertEqual([body.strip() for _, body in messages], ["topic work"])
            self.assertEqual(gate.findings(messages), [])


if __name__ == "__main__":
    unittest.main()
