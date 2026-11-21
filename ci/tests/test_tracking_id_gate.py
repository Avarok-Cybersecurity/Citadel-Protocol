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
        self.assertEqual(gate.findings([(None, "commit abc", "ok\n" + PREFIX + "10")], set()), ["commit abc line 2: " + PREFIX + "10"])


LISTED = "a" * 40
UNLISTED = "b" * 40


class Exemptions(unittest.TestCase):
    def test_a_listed_commit_is_not_judged(self) -> None:
        source = [(LISTED, "commit aaa", "lane " + PREFIX + "10")]
        self.assertEqual(gate.findings(source, gate.parse_exemptions(LISTED + "\n")), [])

    def test_an_unlisted_commit_with_the_same_message_fails(self) -> None:
        source = [(UNLISTED, "commit bbb", "lane " + PREFIX + "10")]
        self.assertEqual(len(gate.findings(source, gate.parse_exemptions(LISTED + "\n"))), 1)

    def test_pull_request_text_is_never_exempt(self) -> None:
        source = [(None, "pull request body", PREFIX + "10")]
        self.assertEqual(len(gate.findings(source, gate.parse_exemptions(LISTED + "\n"))), 1)

    def test_a_malformed_line_is_refused_by_number_not_text(self) -> None:
        for bad in (LISTED[:12] + "\n", LISTED + " lane " + PREFIX + "10\n", LISTED.upper() + "\n", "\n", LISTED + "\n\n"):
            with self.assertRaises(ValueError) as caught:
                gate.parse_exemptions(bad)
            self.assertIn("not a full 40-hex commit SHA", str(caught.exception))
            self.assertNotIn(PREFIX, str(caught.exception))

    def test_an_empty_list_exempts_nothing(self) -> None:
        self.assertEqual(gate.parse_exemptions(""), set())


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
            self.assertEqual([body.strip() for _, _, body in messages], ["topic work"])
            self.assertEqual(gate.findings(messages, set()), [])


if __name__ == "__main__":
    unittest.main()
