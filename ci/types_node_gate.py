#!/usr/bin/env python3
"""Fails unless a pull-request job runs the TypeScript types' tests on the Node the publish job uses.

typescript-publish.yml runs `npm test` and then publishes, on master pushes only, so a Node it is
moved to is first exercised by the publish itself. The first publish on Node 24 failed that way
(run 44905845663): Node 24 refused the test script's `node --test tests/`. The PR job that builds
and tests the package (validate.yml's `typescript_types`) must therefore run the same Node major,
so a change of either is tested before it can stop a release.

Usage: types_node_gate.py <repo root>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import workflow_yaml

PACKAGE_DIR = "citadel-protocol-types-ts"
PUBLISH = ".github/workflows/typescript-publish.yml"
PULL_REQUEST = ".github/workflows/validate.yml"


def node_major(job: workflow_yaml.Job) -> str | None:
    for step in job.steps:
        if (step.value("uses") or "").startswith("actions/setup-node@"):
            m = re.match(r"\d+", step.input("node-version") or "")
            return m.group(0) if m else None
    return None


def tests_the_package(job: workflow_yaml.Job) -> bool:
    return any(
        (step.value("run") or "").strip() == "npm test" and step.value("working-directory") == PACKAGE_DIR
        for step in job.steps
    )


def findings(root: Path) -> list[str]:
    publishers = [j for j in workflow_yaml.jobs((root / PUBLISH).read_text()).values() if tests_the_package(j)]
    if not publishers:
        return [f"{PUBLISH}: no job runs `npm test` in {PACKAGE_DIR}"]
    publish_node = node_major(publishers[0])
    if publish_node is None:
        return [f"{PUBLISH}: job `{publishers[0].id}` names no Node major in actions/setup-node"]
    checks = [j for j in workflow_yaml.jobs((root / PULL_REQUEST).read_text()).values() if tests_the_package(j)]
    if not checks:
        return [f"{PULL_REQUEST}: no job runs `npm test` in {PACKAGE_DIR}, so the publish job is the first to"]
    return [
        f"{PULL_REQUEST}: job `{j.id}` tests {PACKAGE_DIR} on Node {node_major(j)}, the publish job"
        f" (`{publishers[0].id}` in {PUBLISH}) on Node {publish_node}"
        for j in checks
        if node_major(j) != publish_node
    ]


def main() -> int:
    found = findings(Path(sys.argv[1]))
    for line in found:
        print(f"types_node_gate: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
