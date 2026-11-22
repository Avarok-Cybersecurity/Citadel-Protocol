#!/usr/bin/env python3
"""Fails unless every status check branch protection requires is one a pull request produces.

Branch protection names checks by context: a job's name, or for a job in a called workflow,
"<caller job's name> / <job's name>". Rename either and the required context is never reported,
so every pull request waits on it forever, and nothing in the repository says so. REQUIRED is the
in-repository record of what protection on master requires; keep it equal to the setting (a
repository admin reads it with `gh api repos/<owner>/<repo>/branches/master/protection`).

Each required check must also be an aggregate: a job that runs whatever happened before it
(`if: always()`) and needs every other job of its workflow, since a job it does not need could
fail without failing the one check protection reads.

Usage: required_checks_gate.py <repo root>
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import workflow_yaml

REQUIRED = ["Validate PR / All checks"]
PR_EVENTS = {"pull_request", "pull_request_target"}
WORKFLOWS = Path(".github/workflows")


@dataclass(frozen=True)
class Context:
    name: str
    workflow: Path  # the file that defines the job reporting it
    job: workflow_yaml.Job


def contexts(root: Path, workflow: Path, prefix: str = "", seen: frozenset[Path] = frozenset()) -> list[Context]:
    if workflow in seen:
        return []
    out = []
    for job in workflow_yaml.jobs((root / workflow).read_text()).values():
        name = f"{prefix}{job.display}"
        callee = job.keys.get("uses", "")
        if callee.startswith("./"):
            out += contexts(root, Path(callee[2:]), f"{name} / ", seen | {workflow})
        elif not job.has_matrix:  # a matrix job reports one context per leg, never its bare name
            out.append(Context(name, workflow, job))
    return out


def produced(root: Path) -> list[Context]:
    out = []
    for path in sorted((root / WORKFLOWS).glob("*.y*ml")):
        if workflow_yaml.triggers(path.read_text()) & PR_EVENTS:
            out += contexts(root, path.relative_to(root))
    return out


def aggregate_problems(root: Path, found: Context) -> list[str]:
    problems = []
    if found.job.keys.get("if", "").replace("${{", "").replace("}}", "").strip() != "always()":
        problems.append(f"job `{found.job.id}` runs only when its needs pass; give it `if: always()`")
    others = set(workflow_yaml.jobs((root / found.workflow).read_text())) - {found.job.id}
    if missing := sorted(others - set(found.job.needs)):
        problems.append(f"job `{found.job.id}` does not need {', '.join(missing)}")
    return [f"{found.workflow}: required check `{found.name}`: {p}" for p in problems]


def findings(root: Path, required: list[str] = REQUIRED) -> list[str]:
    by_name = {c.name: c for c in produced(root)}
    out = []
    for name in required:
        if name not in by_name:
            names = ", ".join(f"`{n}`" for n in sorted(by_name) if "${{" not in n)
            out.append(f"branch protection requires `{name}`, which no pull_request workflow reports (reported: {names})")
        else:
            out += aggregate_problems(root, by_name[name])
    return out


def main() -> int:
    found = findings(Path(sys.argv[1]))
    for line in found:
        print(f"required_checks_gate: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
