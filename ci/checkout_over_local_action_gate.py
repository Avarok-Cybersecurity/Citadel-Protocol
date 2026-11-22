#!/usr/bin/env python3
"""Fails when a job checks the repository out again after running a local action.

A local action (`uses: ./.github/actions/...`) is read from the checked-out tree, and the runner
reads its action.yml once more for the action's post step at the end of the job. A later
`actions/checkout` without `path:` replaces that tree (with another ref, it may hold no
.github/ at all), so the post step fails: "Can't find 'action.yml' ... Did you forget to run
actions/checkout". The docs deploy failed so on every master push (run 45004463334) after checking
gh-pages out over the workspace. A second checkout belongs under its own `path:`.

Usage: checkout_over_local_action_gate.py <repo root>
"""
from __future__ import annotations

import sys
from pathlib import Path

import workflow_yaml

CHECKOUT = "actions/checkout@"


def findings_in(text: str, where: str) -> list[str]:
    out = []
    for job in workflow_yaml.jobs(text).values():
        local: tuple[int, str] | None = None
        for step in job.steps:
            uses = step.value("uses") or ""
            if uses.startswith("./"):
                local = local or (step.line, uses)
            elif uses.startswith(CHECKOUT) and local and not step.input("path"):
                out.append(
                    f"{where}:{step.line}: job `{job.id}` checks out over the workspace after the local action"
                    f" {local[1]} (line {local[0]}), whose post step then finds no action.yml; check it out under `path:`"
                )
    return out


def findings(root: Path) -> list[str]:
    out = []
    for path in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        out += findings_in(path.read_text(), str(path.relative_to(root)))
    return out


def main() -> int:
    found = findings(Path(sys.argv[1]))
    for line in found:
        print(f"checkout_over_local_action_gate: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
