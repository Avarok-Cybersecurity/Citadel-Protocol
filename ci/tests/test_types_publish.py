"""Tests of the TypeScript types publish: ci/npm-published.sh, ci/types_node_gate.py, and the
consumer notification in typescript-publish.yml.

Run: python3 -m unittest discover -s ci/tests

npm-published.sh is run against a stand-in `npm` on PATH that answers as npm does for each case
(the outputs were taken from npm 10 and npm 11 against the live registry), because a registry
outage cannot be produced on demand.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import types_node_gate as gate  # noqa: E402
import workflow_yaml  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "ci" / "npm-published.sh"

NPM = {
    "published": 'echo \'"0.15.1"\'',
    "missing-npm11": 'echo "npm error code E404" >&2; echo "npm error 404 No match found for version 9.9.9" >&2; exit 1',
    "missing-json-on-stdout": 'echo \'{"error": {"code": "E404"}}\'; exit 1',
    "missing-npm10": "exit 0",
    "network": 'echo "npm error code ENOTFOUND" >&2; echo "npm error network request failed" >&2; exit 1',
    "auth": 'echo "npm error code E401" >&2; exit 1',
    "odd": "echo '\"0.15.0\"'",
}


class NpmPublished(unittest.TestCase):
    def run_script(self, case: str, version: str = "0.15.1"):
        with tempfile.TemporaryDirectory() as tmp:
            npm = Path(tmp) / "npm"
            npm.write_text(f"#!/usr/bin/env bash\n{NPM[case]}\n")
            npm.chmod(0o755)
            env = {**os.environ, "PATH": f"{tmp}{os.pathsep}{os.environ['PATH']}"}
            return subprocess.run(["bash", str(SCRIPT), "@avarok/citadel-protocol-types", version],
                                  env=env, capture_output=True, text=True)

    def judge(self, case: str) -> tuple[int, str]:
        done = self.run_script(case)
        return done.returncode, done.stdout.strip()

    def test_a_published_version_is_true(self):
        self.assertEqual(self.judge("published"), (0, "true"))

    def test_a_registry_404_is_false(self):
        self.assertEqual(self.judge("missing-npm11"), (0, "false"))
        self.assertEqual(self.judge("missing-json-on-stdout"), (0, "false"))

    def test_an_empty_answer_from_older_npm_is_false(self):
        self.assertEqual(self.judge("missing-npm10"), (0, "false"))

    def test_a_network_failure_fails(self):
        code, out = self.judge("network")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("ENOTFOUND", self.run_script("network").stderr)

    def test_an_auth_failure_fails(self):
        self.assertEqual(self.judge("auth"), (1, ""))

    def test_an_answer_naming_another_version_fails(self):
        self.assertEqual(self.judge("odd")[0], 1)


def workflows(publish_node: str = "'24'", check_node: str = "'24'", check_runs: str = "npm test") -> list[str]:
    publish = f"""\
jobs:
  publish:
    steps:
      - uses: actions/setup-node@v5
        with:
          node-version: {publish_node}
      - name: Run tests
        working-directory: citadel-protocol-types-ts
        run: npm test
"""
    check = f"""\
jobs:
  typescript_types:
    steps:
      - uses: actions/setup-node@v5
        with:
          # the same Node the publish job runs
          node-version: {check_node}
      - name: Run tests
        working-directory: citadel-protocol-types-ts
        run: {check_runs}
"""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / gate.PUBLISH).write_text(publish)
        (root / gate.PULL_REQUEST).write_text(check)
        return gate.findings(root)


class TypesNodeGate(unittest.TestCase):
    def test_the_same_major_passes(self):
        self.assertEqual(workflows(), [])
        self.assertEqual(workflows(check_node="24.x"), [])

    def test_a_publish_job_moved_to_another_node_fails(self):
        found = workflows(publish_node="'26'")
        self.assertEqual(len(found), 1)
        self.assertIn("on Node 24, the publish job (`publish`", found[0])
        self.assertIn("on Node 26", found[0])

    def test_a_pull_request_job_that_does_not_test_the_package_fails(self):
        self.assertIn("no job runs `npm test`", workflows(check_runs="npm run build")[0])

    def test_the_repository_passes(self):
        self.assertEqual(gate.findings(REPO), [])


class ConsumersAreTold(unittest.TestCase):
    def test_a_published_version_is_dispatched_to_both_consumers(self):
        jobs = workflow_yaml.jobs((REPO / gate.PUBLISH).read_text())
        notify = jobs["notify"]
        self.assertEqual(notify.needs, ["publish"])
        self.assertIn("needs.publish.outputs.published == 'true'", notify.keys["if"])
        text = "\n".join(line for step in notify.steps for line in step.lines)
        self.assertIn("CONSUMERS: citadel-internal-service,citadel-workspace", (REPO / gate.PUBLISH).read_text())
        for field in ("event_type=types-released", "client_payload[producer]=sdk",
                      "client_payload[version]=$VERSION", "client_payload[rev]=$GITHUB_SHA"):
            self.assertIn(field, text)


if __name__ == "__main__":
    unittest.main()
