"""Unit tests of ci/required_checks_gate.py. Run: python3 -m unittest discover -s ci/tests"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import required_checks_gate as gate  # noqa: E402

CALLER = """\
name: Execute Pipeline
on:
  pull_request:
    types:
      - opened
jobs:
  workflow:
    name: Validate PR
    uses: ./.github/workflows/validate.yml
    secrets: inherit
"""
CALLEE = """\
name: Validate PR
on:
  workflow_call:
jobs:
  fmt:
    name: fmt and CI gates
    runs-on: ubuntu-latest
  sdk:
    strategy:
      matrix:
        os: [ ubuntu-latest, macos-latest ]
    name: citadel_sdk (${{ matrix.os }})
    needs: [fmt]
  all_checks:
    name: All checks
    if: always()
    needs:
      - fmt
      - sdk
    runs-on: ubuntu-latest
"""


def judge(caller: str = CALLER, callee: str = CALLEE, required: str = "Validate PR / All checks") -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "exec.yml").write_text(caller)
        (root / ".github" / "workflows" / "validate.yml").write_text(callee)
        return gate.findings(root, [required])


class RequiredChecksGate(unittest.TestCase):
    def test_the_reported_aggregate_passes(self):
        self.assertEqual(judge(), [])

    def test_a_renamed_aggregate_job_fails(self):
        found = judge(callee=CALLEE.replace("name: All checks", "name: All jobs"))
        self.assertEqual(len(found), 1)
        self.assertIn("requires `Validate PR / All checks`, which no pull_request workflow reports", found[0])
        self.assertIn("`Validate PR / All jobs`", found[0])

    def test_a_renamed_caller_job_fails(self):
        self.assertEqual(len(judge(caller=CALLER.replace("name: Validate PR", "name: Validate"))), 1)

    def test_a_caller_that_pull_requests_do_not_start_fails(self):
        self.assertEqual(len(judge(caller=CALLER.replace("pull_request:", "push:"))), 1)

    def test_an_aggregate_that_misses_a_job_fails(self):
        found = judge(callee=CALLEE.replace("      - sdk\n", ""))
        self.assertEqual(len(found), 1)
        self.assertIn("required check `Validate PR / All checks`: job `all_checks` does not need sdk", found[0])

    def test_an_aggregate_that_runs_only_on_success_fails(self):
        found = judge(callee=CALLEE.replace("    if: always()\n", ""))
        self.assertEqual(len(found), 1)
        self.assertIn("give it `if: always()`", found[0])

    def test_a_matrix_job_never_reports_its_bare_name(self):
        self.assertEqual(len(judge(required="Validate PR / citadel_sdk (${{ matrix.os }})")), 1)

    def test_the_repository_passes(self):
        self.assertEqual(gate.findings(Path(__file__).resolve().parents[2]), [])


if __name__ == "__main__":
    unittest.main()
