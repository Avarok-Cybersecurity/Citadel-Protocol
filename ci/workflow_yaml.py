"""Reads the jobs and steps of a GitHub workflow, for the gates in this directory.

The gates run on a bare python3, which has no YAML parser, so this reads the subset of YAML the
workflows here use: block mappings by indentation, `key: value` scalars, `[a, b]` and `- a`
lists. It locates a job's keys and its steps; it does not evaluate expressions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

KEY = re.compile(r"^(?P<indent> *)(?P<key>[\w.-]+|'on'|\"on\"):(?:\s+(?P<value>.*?))?\s*$")
ITEM = re.compile(r"^(?P<indent> *)-(?:\s+(?P<rest>.*?))?\s*$")


@dataclass
class Step:
    line: int  # 1-based, the `- ` that opens it
    lines: list[str]

    def value(self, key: str) -> str | None:
        """The scalar `key:` of this step itself (not of its `with:` or `env:`)."""
        column = indent(self.lines[0]) + 2
        for n, text in enumerate(self.lines):
            body = text if n else " " * column + text.lstrip()[1:].lstrip()
            m = KEY.match(body)
            if m and len(m.group("indent")) == column and m.group("key") == key:
                return scalar(m.group("value") or "")
        return None

    def input(self, key: str) -> str | None:
        """The `with:` input `key` of this step."""
        column = indent(self.lines[0]) + 2
        inside = False
        for n, text in enumerate(self.lines):
            body = text if n else " " * column + text.lstrip()[1:].lstrip()
            m = KEY.match(body)
            if not m:
                continue
            depth = len(m.group("indent"))
            if depth == column:
                inside = m.group("key") == "with"
            elif inside and depth > column and m.group("key") == key:
                return scalar(m.group("value") or "")
        return None


@dataclass
class Job:
    id: str
    line: int
    keys: dict[str, str] = field(default_factory=dict)  # the job's own scalar keys
    needs: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    has_matrix: bool = False

    @property
    def display(self) -> str:
        """The name GitHub shows, and builds status-check contexts from."""
        return self.keys.get("name") or self.id


def indent(text: str) -> int:
    return len(text) - len(text.lstrip(" "))


def significant(text: str) -> bool:
    return bool(text.strip()) and not text.lstrip().startswith("#")


def scalar(value: str) -> str:
    value = re.sub(r"\s+#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def children(lines: list[str], start: int, end: int) -> list[tuple[int, str]]:
    """The `(index, key)` of each key one level below lines[start], up to `end`."""
    column = None
    out = []
    for i in range(start + 1, end):
        if not significant(lines[i]):
            continue
        if column is None:
            column = indent(lines[i])
        m = KEY.match(lines[i])
        if m and len(m.group("indent")) == column:
            out.append((i, scalar(m.group("key"))))
    return out


def block_end(lines: list[str], start: int) -> int:
    """The index after the last line nested below lines[start]."""
    column = indent(lines[start])
    i = start + 1
    while i < len(lines) and (not significant(lines[i]) or indent(lines[i]) > column):
        i += 1
    return i


def top_level(lines: list[str]) -> dict[str, int]:
    return {scalar(m.group("key")): i for i, text in enumerate(lines) if (m := KEY.match(text)) and not m.group("indent")}


def triggers(text: str) -> set[str]:
    """The events in the workflow's `on:`."""
    lines = text.splitlines()
    at = top_level(lines).get("on")
    if at is None:
        return set()
    inline = scalar(KEY.match(lines[at]).group("value") or "")
    if inline:
        return {e.strip() for e in inline.strip("[]").split(",") if e.strip()}
    end = block_end(lines, at)
    found = {key for _, key in children(lines, at, end)}
    found |= {scalar(m.group("rest") or "") for i in range(at + 1, end) if (m := ITEM.match(lines[i]))}
    return found


def parse_list(lines: list[str], at: int) -> list[str]:
    inline = scalar(KEY.match(lines[at]).group("value") or "")
    if inline:
        return [v.strip().strip("'\"") for v in inline.strip("[]").split(",") if v.strip()]
    return [scalar(m.group("rest") or "") for i in range(at + 1, block_end(lines, at)) if (m := ITEM.match(lines[i]))]


def parse_steps(lines: list[str], at: int) -> list[Step]:
    end = block_end(lines, at)
    items = [i for i in range(at + 1, end) if ITEM.match(lines[i])]
    if not items:
        return []
    column = indent(lines[items[0]])
    starts = [i for i in items if indent(lines[i]) == column]
    steps = []
    for n, start in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else end
        steps.append(Step(start + 1, lines[start:stop]))
    return steps


def jobs(text: str) -> dict[str, Job]:
    lines = text.splitlines()
    at = top_level(lines).get("jobs")
    if at is None:
        return {}
    out: dict[str, Job] = {}
    for job_at, job_id in children(lines, at, block_end(lines, at)):
        job = Job(job_id, job_at + 1)
        for key_at, key in children(lines, job_at, block_end(lines, job_at)):
            if key == "needs":
                job.needs = parse_list(lines, key_at)
            elif key == "steps":
                job.steps = parse_steps(lines, key_at)
            elif key == "strategy":
                job.has_matrix = any(k == "matrix" for _, k in children(lines, key_at, block_end(lines, key_at)))
            else:
                value = scalar(KEY.match(lines[key_at]).group("value") or "")
                if value and value not in "|>":
                    job.keys[key] = value
        out[job_id] = job
    return out
