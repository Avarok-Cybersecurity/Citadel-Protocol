#!/usr/bin/env python3
"""Fails when Cargo.lock gains a crates.io entry younger than the age floor, or one whose checksum
is missing or differs from crates.io's.

A crate published minutes ago has had no time for a yank or an advisory; the floor gives the
ecosystem that time before a release can reach this workspace. Only entries that are new or changed
relative to the base lockfile are judged, so an old pin never has to be re-justified.

Usage: lockfile_age_gate.py --base-ref <git ref> --allowlist <toml> --min-age-days <n> --cache <json>
                            --lockfile <path> [--lockfile <path> ...]

Each lockfile's base is read with `git show <ref>:<path>`; a base without it makes every entry new.
Publish times and checksums come from crates.io's sparse index (index.crates.io), one request per
changed crate with a user agent set: its record of every version carries `pubtime` and `cksum`.
The JSON API was the first choice and throttled a full-lockfile check (HTTP 429 after a few hundred
requests at one a second); the index is crates.io's CDN-served read path and never did. Records of
published versions never change, so the cache file is kept between runs.
The reference time is the moment of the check: an entry passes once it is old enough, never before.

An exception is an allowlist entry naming the exact version, the date it was added, and why
(an urgent security patch). An entry without all three fails the gate.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
INDEX = "https://index.crates.io"
USER_AGENT = "citadel-protocol-ci lockfile age gate (https://github.com/Avarok-Cybersecurity/Citadel-Protocol)"


@dataclass(frozen=True)
class Entry:
    name: str
    version: str
    source: str | None
    checksum: str | None


@dataclass(frozen=True)
class Published:
    pubtime: dt.datetime | None
    cksum: str


@dataclass(frozen=True)
class Exception_:
    name: str
    version: str
    added: dt.date
    reason: str


# ---- pure decisions -------------------------------------------------------------------------


def parse_lock(text: str) -> dict[tuple[str, str], Entry]:
    packages = tomllib.loads(text).get("package", []) if text else []
    return {
        (p["name"], p["version"]): Entry(p["name"], p["version"], p.get("source"), p.get("checksum"))
        for p in packages
    }


def new_entries(base: dict[tuple[str, str], Entry], head: dict[tuple[str, str], Entry]) -> list[Entry]:
    """Entries of head that base lacks, or that base holds with another source or checksum."""
    return sorted(
        (e for key, e in head.items() if base.get(key) != e),
        key=lambda e: (e.name, e.version),
    )


def parse_allowlist(text: str) -> dict[tuple[str, str], Exception_]:
    out: dict[tuple[str, str], Exception_] = {}
    for raw in tomllib.loads(text).get("exception", []):
        missing = [k for k in ("name", "version", "added", "reason") if not raw.get(k)]
        if missing:
            raise ValueError(f"allowlist entry {raw!r} lacks {', '.join(missing)}")
        if not isinstance(raw["added"], dt.date):
            raise ValueError(f"allowlist entry {raw['name']}: `added` must be a TOML date")
        out[(raw["name"], raw["version"])] = Exception_(raw["name"], raw["version"], raw["added"], raw["reason"])
    return out


def index_path(name: str) -> str:
    """The sparse-index path of a crate (cargo's layout: 1/, 2/, 3/<c>/, then <ab>/<cd>/)."""
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def parse_index(text: str) -> dict[str, Published]:
    out: dict[str, Published] = {}
    for line in text.splitlines():
        if line.strip():
            rec = json.loads(line)
            stamp = rec.get("pubtime")
            when = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None
            out[rec["vers"]] = Published(when, rec["cksum"])
    return out


def violations(
    entries: list[Entry],
    published: dict[tuple[str, str], Published | None],
    allow: dict[tuple[str, str], Exception_],
    now: dt.datetime,
    min_age: dt.timedelta,
) -> list[str]:
    found: list[str] = []
    for e in entries:
        if e.source != CRATES_IO:
            continue
        key = (e.name, e.version)
        if not e.checksum:
            found.append(f"{e.name} {e.version}: no checksum in Cargo.lock")
            continue
        record = published.get(key)
        if record is None:
            found.append(f"{e.name} {e.version}: not in the crates.io index")
            continue
        if record.cksum != e.checksum:
            found.append(f"{e.name} {e.version}: Cargo.lock checksum differs from crates.io's")
            continue
        if record.pubtime is None:
            found.append(f"{e.name} {e.version}: the index gives no publish time")
            continue
        age = now - record.pubtime
        if age < min_age and key not in allow:
            found.append(
                f"{e.name} {e.version}: published {record.pubtime:%Y-%m-%d %H:%M}Z, "
                f"{age.days} days ago (floor {min_age.days})"
            )
    return found


# ---- I/O ------------------------------------------------------------------------------------


def base_lock(ref: str, path: Path) -> str:
    shown = subprocess.run(["git", "show", f"{ref}:{path.as_posix()}"], capture_output=True, text=True)
    if shown.returncode == 0:
        return shown.stdout
    if "does not exist" in shown.stderr or "exists on disk, but not in" in shown.stderr:
        return ""
    raise SystemExit(f"git show {ref}:{path} failed: {shown.stderr.strip()}")


def fetch_published(entries: list[Entry], cache_path: Path) -> dict[tuple[str, str], Published | None]:
    cache: dict[str, dict] = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    out: dict[tuple[str, str], Published | None] = {}
    fetched: dict[str, dict[str, Published]] = {}
    for e in entries:
        if e.source != CRATES_IO or not e.checksum:
            continue
        ck = f"{e.name}@{e.version}"
        if ck not in cache:
            if e.name not in fetched:
                req = urllib.request.Request(f"{INDEX}/{index_path(e.name)}", headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    fetched[e.name] = parse_index(resp.read().decode())
            rec = fetched[e.name].get(e.version)
            if rec is None:
                out[(e.name, e.version)] = None
                continue
            cache[ck] = {"pubtime": rec.pubtime.isoformat() if rec.pubtime else None, "cksum": rec.cksum}
        c = cache[ck]
        out[(e.name, e.version)] = Published(dt.datetime.fromisoformat(c["pubtime"]) if c["pubtime"] else None, c["cksum"])
    cache_path.write_text(json.dumps(cache, indent=0, sort_keys=True))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-ref", required=True)
    ap.add_argument("--allowlist", required=True, type=Path)
    ap.add_argument("--min-age-days", required=True, type=int)
    ap.add_argument("--cache", required=True, type=Path)
    ap.add_argument("--lockfile", required=True, type=Path, action="append")
    args = ap.parse_args()

    changed = {
        (e.name, e.version, e.source): e
        for lock in args.lockfile
        for e in new_entries(parse_lock(base_lock(args.base_ref, lock)), parse_lock(lock.read_text()))
    }
    entries = sorted(changed.values(), key=lambda e: (e.name, e.version))
    allow = parse_allowlist(args.allowlist.read_text())
    published = fetch_published(entries, args.cache)
    now = dt.datetime.now(dt.timezone.utc)
    found = violations(entries, published, allow, now, dt.timedelta(days=args.min_age_days))

    judged = sum(1 for e in entries if e.source == CRATES_IO)
    print(f"{judged} new or changed crates.io entries against {args.base_ref}")
    for key, ex in sorted(allow.items()):
        print(f"allowlisted {key[0]} {key[1]} (added {ex.added}): {ex.reason}")
    if found:
        print("Cargo.lock entries the age gate refuses:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
