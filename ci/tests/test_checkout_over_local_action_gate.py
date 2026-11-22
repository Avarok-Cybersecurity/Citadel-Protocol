"""Unit tests of ci/checkout_over_local_action_gate.py. Run: python3 -m unittest discover -s ci/tests"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import checkout_over_local_action_gate as gate  # noqa: E402

# The docs deploy as it failed on master (run 45004463334).
CHECKOUT_OVER_THE_TREE = """\
name: Build docs
on:
  push:
    branches:
      - master
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: ./.github/actions/setup-rust
        with:
          cache-key: none
      - name: Compile documentation
        run: cargo make docs
      - uses: actions/checkout@v5
        if: success()
        with:
          ref: gh-pages
      - name: Ensure valid redirection
        run: git push
"""


class CheckoutOverLocalActionGate(unittest.TestCase):
    def judge(self, text: str) -> list[str]:
        return gate.findings_in(text, "w.yml")

    def test_a_second_checkout_over_the_tree_fails(self):
        found = self.judge(CHECKOUT_OVER_THE_TREE)
        self.assertEqual(len(found), 1)
        self.assertIn("w.yml:16: job `docs`", found[0])
        self.assertIn("./.github/actions/setup-rust (line 11)", found[0])

    def test_a_second_checkout_under_its_own_path_passes(self):
        self.assertEqual(self.judge(CHECKOUT_OVER_THE_TREE.replace("ref: gh-pages", "ref: gh-pages\n          path: pages")), [])

    def test_a_path_outside_the_with_block_does_not_count(self):
        shifted = CHECKOUT_OVER_THE_TREE.replace("        if: success()", "        if: success()\n        path: pages")
        self.assertEqual(len(self.judge(shifted)), 1)

    def test_a_checkout_before_the_local_action_passes(self):
        self.assertEqual(self.judge(CHECKOUT_OVER_THE_TREE.split("      - name: Compile")[0]), [])

    def test_each_job_is_judged_on_its_own(self):
        two_jobs = """\
jobs:
  build:
    steps:
      - uses: actions/checkout@v5
      - uses: ./.github/actions/setup-rust
  pages:
    steps:
      - uses: actions/checkout@v5
        with:
          ref: gh-pages
"""
        self.assertEqual(self.judge(two_jobs), [])

    def test_the_repository_passes(self):
        self.assertEqual(gate.findings(Path(__file__).resolve().parents[2]), [])


if __name__ == "__main__":
    unittest.main()
