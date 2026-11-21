#!/usr/bin/env python3
"""Fails when a CI cargo invocation could resolve dependencies without the committed lockfile.

Without `--locked`, cargo may rewrite Cargo.lock to the newest matching releases, and the build
then runs code that neither review nor ci/lockfile_age_gate.py ever saw. This reads every command
CI runs: the `run:` text of each workflow and local action, the Dockerfiles those workflows build,
the ci/ shell scripts they run, and the cargo-make tasks they call (with the tasks those depend on).

`--locked` refuses a lockfile that no longer matches its manifests, so it only helps if the
lockfile is kept current. The workspace's Cargo.lock is held to that by every pull-request build.
A lockfile outside the workspace (the fuzz crate's) is built only on a schedule, so a stale one
would surface there, days later. Each is checked here with `cargo metadata --locked`.

A command is judged when it invokes a cargo subcommand that resolves the graph (RESOLVING), or
wasm-pack, which forwards the arguments after `--` to cargo. Commands that never resolve
(fmt, audit, which only reads the lockfile, and the like) are listed in NON_RESOLVING with the
reason; a subcommand in neither set fails the gate, so a new one is classified, not skipped.

Usage: cargo_locked_gate.py <repo root>
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
import tomllib
from dataclasses import dataclass
from pathlib import Path

RESOLVING = {
    "build", "check", "test", "clippy", "nextest", "llvm-cov", "doc", "run", "bench", "install",
    "tree", "metadata", "pkgid", "rustc", "rustdoc", "fix", "publish", "package", "fetch",
    "vendor", "deny", "afl", "pgo",
}
NON_RESOLVING = {
    "fmt": "formats sources; reads no dependency",
    "audit": "reads Cargo.lock as committed; never resolves",
    "binstall": "downloads a released binary; compiles nothing",
    "generate-lockfile": "writes the lockfile by definition",
    "update": "updates the lockfile by definition",
    "make": "judged through the cargo-make task it names",
    "workspaces": "cargo-workspaces version/publish: the release workflow, run by hand; it bumps versions and so must rewrite the lockfile",
    "--version": "prints the version",
}
# Forms of resolving subcommands that resolve nothing: `cargo afl system-config` configures the
# kernel, `cargo pgo info` reports the toolchain.
NON_RESOLVING_FORMS = [
    re.compile(r"\bcargo afl system-config\b"),
    re.compile(r"\bcargo pgo info\b"),
    # runs the fuzzer on the binary `cargo afl build --locked` built
    re.compile(r"\bcargo afl fuzz\b"),
]

CARGO = re.compile(r"(?<![\w-])cargo\s+(\+\S+\s+)?(?P<sub>--version|[a-z][\w-]*)")
WASM_PACK = re.compile(r"(?<![\w-])wasm-pack\s+(test|build)\b")
ECHO = re.compile(r"^(echo|printf)\b")
SEPARATOR = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
MAKE = re.compile(r"(?<![\w-])cargo\s+make\s+(?P<task>[\w-]+)")


@dataclass(frozen=True)
class Finding:
    where: str
    command: str
    problem: str


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines with shell continuations joined, comments dropped, keeping the first line number."""
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        if not buf:
            start = n
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        if buf.strip():
            out.append((start, buf.strip()))
        buf = ""
    return out


RUN_KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<rest>.*)$")


def workflow_commands(text: str) -> str:
    """The text of every `run:` value in a workflow or action file, blank lines elsewhere.

    Line numbers are kept, so a finding names the line in the file."""
    lines = text.splitlines()
    out = [""] * len(lines)
    i = 0
    while i < len(lines):
        m = RUN_KEY.match(lines[i])
        if not m:
            i += 1
            continue
        rest = m.group("rest").strip()
        if rest and rest[0] not in "|>":
            out[i] = rest.strip("'\"")
            i += 1
            continue
        key_column = lines[i].index("run:")
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > key_column):
            out[i] = lines[i]
            i += 1
    return "\n".join(out)


def judge_line(where: str, line: str) -> list[Finding]:
    found: list[Finding] = []
    if any(f.search(line) for f in NON_RESOLVING_FORMS) or ECHO.match(line):
        return found
    for m in CARGO.finditer(line):
        sub = m.group("sub")
        segment = SEPARATOR.split(line[m.start():], maxsplit=1)[0]
        if sub in NON_RESOLVING:
            continue
        if sub not in RESOLVING:
            found.append(Finding(where, segment, f"unclassified cargo subcommand `{sub}`"))
        elif "--locked" not in segment.split():
            found.append(Finding(where, segment, "resolves without --locked"))
    for m in WASM_PACK.finditer(line):
        segment = SEPARATOR.split(line[m.start():], maxsplit=1)[0]
        after = segment.split(" -- ", 1)
        if len(after) < 2 or "--locked" not in after[1].split():
            found.append(Finding(where, segment, "wasm-pack forwards no --locked to cargo"))
    return found


def make_tasks(makefile: dict, roots: set[str]) -> dict[str, dict]:
    tasks = makefile.get("tasks", {})
    seen: dict[str, dict] = {}
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        if name not in tasks:
            raise KeyError(name)
        seen[name] = tasks[name]
        todo.extend(tasks[name].get("dependencies", []))
    return seen


def task_lines(task: dict) -> list[str]:
    lines: list[str] = []
    if task.get("command"):
        lines.append(" ".join([task["command"], *task.get("args", [])]))
    script = task.get("script")
    if isinstance(script, list):
        script = "\n".join(script)
    if isinstance(script, str):
        lines.extend(l for _, l in logical_lines(script))
    return lines


SKIPPED_DIRS = {"target", "node_modules", ".git"}

# Runs `cargo metadata --locked` for one manifest: (exit status, stderr).
Resolve = Callable[[Path], tuple[int, str]]


def cargo_metadata_locked(manifest: Path) -> tuple[int, str]:
    done = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(manifest)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    return done.returncode, done.stderr


def lockfiles_outside_the_workspace(root: Path) -> list[Path]:
    """Every Cargo.lock below the root, other than the workspace's own, beside its manifest."""
    found = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)
        if "Cargo.lock" in files and Path(here) != root:
            found.append(Path(here) / "Cargo.lock")
    return sorted(found)


def stale_lockfiles(root: Path, locks: list[Path], resolve: Resolve) -> list[Finding]:
    findings = []
    for lock in locks:
        rel = lock.relative_to(root)
        manifest = lock.with_name("Cargo.toml")
        if not manifest.is_file():
            findings.append(Finding(str(rel), "-", "has no Cargo.toml beside it"))
            continue
        status, stderr = resolve(manifest)
        if status != 0:
            reason = next((l for l in stderr.splitlines() if l.startswith("error")), "cargo metadata failed")
            findings.append(Finding(str(rel), "cargo metadata --locked", f"is not current with its manifest ({reason})"))
    return findings


def main(root: Path, resolve: Resolve = cargo_metadata_locked) -> int:
    findings: list[Finding] = []
    called_tasks: set[str] = set()
    sources = sorted(root.glob(".github/workflows/*.y*ml")) + sorted(root.glob(".github/actions/**/action.y*ml"))
    sources += sorted(root.glob("docker/**/Dockerfile*")) + sorted(root.glob("docker/**/*.sh"))
    sources += sorted(root.glob("ci/*.sh"))
    for path in sources:
        rel = path.relative_to(root)
        text = path.read_text()
        if path.suffix in (".yml", ".yaml"):
            text = workflow_commands(text)
        for n, line in logical_lines(text):
            findings += judge_line(f"{rel}:{n}", line)
            called_tasks.update(m.group("task") for m in MAKE.finditer(line))
    makefile = tomllib.loads((root / "Makefile.toml").read_text())
    try:
        tasks = make_tasks(makefile, called_tasks)
    except KeyError as missing:
        print(f"a workflow calls cargo-make task {missing}, which Makefile.toml does not define", file=sys.stderr)
        return 1
    for name, task in sorted(tasks.items()):
        for line in task_lines(task):
            findings += judge_line(f"Makefile.toml [tasks.{name}]", line)
    locks = lockfiles_outside_the_workspace(root)
    findings += stale_lockfiles(root, locks, resolve)
    print(
        f"judged {len(sources)} workflow, action, Dockerfile and script sources, {len(tasks)} cargo-make tasks"
        f" and {len(locks)} lockfile(s) outside the workspace"
    )
    for f in findings:
        print(f"{f.where}: {f.problem}: {f.command}", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
