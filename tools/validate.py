#!/usr/bin/env python3
"""trinity-templates validator — the registry's deterministic quality gate.

README.md is the human-readable contract; this file is the executable one.
A FAIL is a blocker, never an advisory.

Why this exists: `registry.yaml` is live production config. Every Trinity
install fetches it (1 h TTL) and the bundled floor is EMPTY, so a document-level
refusal — a bad `version:`, a non-list `templates:`, a YAML alias, a duplicate
key, 256 KiB+ — removes the agent-template catalog from every install on the
next fetch. CI is the only gate between a commit here and that.

Usage:
    python3 tools/validate.py                     document gates (offline, hermetic)
    python3 tools/validate.py --resolve           + per-repo gates (GitHub API)
    python3 tools/validate.py --platform-parser /tmp/platform
        CI mode: additionally parse the document with the Trinity platform's OWN
        parser (template_registry_service.py + utils/safe_yaml.py vendored into
        the given directory) so this repo and the platform cannot drift.
    python3 tools/validate.py --json              machine-readable findings

Stdlib-only, except PyYAML — used when available, and required for the
alias/duplicate-key guards to be checked locally (CI always has it).

Exit code: 0 when no FAIL, 1 otherwise. WARN never fails the build.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "registry.yaml"

# --- The platform contract, mirrored ---------------------------------------
# Source: Abilityai/trinity src/backend/services/template_registry_service.py
# and src/backend/utils/safe_yaml.py. Every constant here is a platform bound,
# not a house preference — do not tighten one without checking the source.
SUPPORTED_SCHEMA_VERSION = 1
MAX_REGISTRY_TEMPLATES = 25
REGISTRY_MAX_BYTES = 256 * 1024
MAX_DISPLAY_NAME_LEN = 200
MAX_DESCRIPTION_LEN = 1000
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
TRAVERSAL_SEGMENTS = frozenset({".", ".."})

# The allowlist. A registry entry CANNOT assert anything else — the platform
# ignores unknown keys silently, which is exactly why an author who writes one
# needs to be told it does nothing.
ENTRY_KEYS = {"repo", "display_name", "description", "priority"}

# Keys that only the listed repo's own template.yaml may declare. Naming them
# separately turns the generic "unknown key" WARN into a FAIL, because writing
# one of these here means the author believes a claim is being made that is not.
TRUST_BOUNDARY_KEYS = {
    "fork_to_own", "credentials", "schedules", "hidden", "id", "skills",
    "resources", "data_paths", "persistent_state", "mcp_servers", "git",
}

# Staleness bound for a listed repo's last push. Not a platform rule — a
# curation one: a template nobody has touched in this long is drifting away
# from the platform it teaches.
STALE_PUSH_DAYS = 120
PLACEHOLDER_RE = re.compile(
    r"\b(your name|your-name|yourname|changeme|change-me|tbd|fixme|xxx+)\b", re.I
)

findings: list[tuple[str, str, str]] = []   # (level, gate, message)


def fail(gate: str, msg: str) -> None:
    findings.append(("FAIL", gate, msg))


def warn(gate: str, msg: str) -> None:
    findings.append(("WARN", gate, msg))


# ---------------------------------------------------------------------------
# Gate: document
# ---------------------------------------------------------------------------

def load_yaml(text: str, *, path: str):
    """Parse with the platform's guards where PyYAML allows it.

    Aliases and duplicate keys are DOCUMENT-LEVEL refusals in the platform's
    hardened loader, so they are FAILs here, not warnings.
    """
    try:
        import yaml
    except ImportError:
        warn("deps", "PyYAML not installed — alias/duplicate-key guards skipped "
                     "(pip install pyyaml for the full local check)")
        return None, False

    class _Guarded(yaml.SafeLoader):
        pass

    def _no_alias(loader, node):
        raise yaml.YAMLError("YAML aliases are refused by the platform loader")

    def _mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key {key!r}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    _Guarded.add_constructor("tag:yaml.org,2002:map", _mapping)
    _Guarded.yaml_constructors = dict(_Guarded.yaml_constructors)

    class _NoAlias(_Guarded):
        def compose_node(self, parent, index):
            if self.check_event(yaml.events.AliasEvent):
                _no_alias(self, None)
            return yaml.composer.Composer.compose_node(self, parent, index)

    try:
        return yaml.load(text, Loader=_NoAlias), True
    except yaml.YAMLError as e:
        fail("document", f"{path}: refused by the hardened loader — {e}")
        return None, False


def check_document(text: str) -> list[dict]:
    """Mirror `parse_registry_document`. Returns the accepted entries."""
    size = len(text.encode("utf-8"))
    if size > REGISTRY_MAX_BYTES:
        fail("document", f"registry.yaml is {size} bytes, over the "
                         f"{REGISTRY_MAX_BYTES}-byte platform cap — whole document refused")
        return []

    data, parsed = load_yaml(text, path="registry.yaml")
    if not parsed:
        return []

    if not isinstance(data, dict):
        fail("document", f"top level is a {type(data).__name__}, not a mapping — "
                         "whole document refused, every install drops to the empty floor")
        return []

    version = data.get("version", SUPPORTED_SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int):
        fail("document", f"`version` must be an integer, got "
                         f"{type(version).__name__} — whole document refused")
        return []
    if version != SUPPORTED_SCHEMA_VERSION:
        fail("document", f"`version: {version}` is not supported "
                         f"(expected {SUPPORTED_SCHEMA_VERSION}) — whole document refused")
        return []

    raw = data.get("templates")
    if not isinstance(raw, list):
        fail("document", f"`templates` must be a list, got {type(raw).__name__} — "
                         "whole document refused")
        return []

    for key in data:
        if key not in {"version", "templates"}:
            warn("document", f"top-level key `{key}` is not read by the platform")

    if len(raw) > MAX_REGISTRY_TEMPLATES:
        fail("document", f"{len(raw)} templates declared; the platform uses only the "
                         f"first {MAX_REGISTRY_TEMPLATES} — the rest are silently invisible")
        raw = raw[:MAX_REGISTRY_TEMPLATES]

    entries: list[dict] = []
    seen: dict[str, int] = {}
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            fail("entry", f"entry {i}: expected a mapping, got {type(entry).__name__} — dropped")
            continue

        repo = entry.get("repo")
        if not isinstance(repo, str):
            fail("entry", f"entry {i}: `repo` must be a string, got "
                          f"{type(repo).__name__} — entry dropped")
            continue
        repo = repo.strip()
        owner, _, name = repo.partition("/")
        if (not REPO_RE.match(repo) or owner in TRAVERSAL_SEGMENTS
                or name in TRAVERSAL_SEGMENTS):
            fail("entry", f"entry {i}: `repo` {repo!r} is not a valid owner/repo — entry dropped")
            continue

        key = repo.lower()
        if key in seen:
            fail("entry", f"entry {i}: duplicate repo {repo!r} (case-insensitive, "
                          f"first seen at entry {seen[key]}) — entry dropped")
            continue
        seen[key] = i

        for field, cap in (("display_name", MAX_DISPLAY_NAME_LEN),
                           ("description", MAX_DESCRIPTION_LEN)):
            value = entry.get(field)
            if value is None:
                warn("entry", f"{repo}: no `{field}` — the card falls back to the repo's "
                              f"own template.yaml, which is unreadable when GitHub rate-limits")
            elif not isinstance(value, str):
                fail("entry", f"{repo}: `{field}` must be a string, got {type(value).__name__}")
            elif len(value.strip()) > cap:
                fail("entry", f"{repo}: `{field}` is {len(value.strip())} chars, "
                              f"truncated by the platform at {cap}")

        priority = entry.get("priority")
        if priority is not None and (isinstance(priority, bool) or not isinstance(priority, int)):
            fail("entry", f"{repo}: `priority` must be an integer, got "
                          f"{type(priority).__name__} — field ignored, catalog order undefined")

        for key_name in set(entry) - ENTRY_KEYS:
            if key_name in TRUST_BOUNDARY_KEYS:
                fail("allowlist", f"{repo}: `{key_name}` is read ONLY from the listed repo's own "
                                  f"template.yaml — declaring it here asserts nothing and is "
                                  f"silently ignored by the platform")
            else:
                warn("allowlist", f"{repo}: unknown key `{key_name}` — ignored by the platform")

        entries.append({
            "repo": repo,
            "display_name": entry.get("display_name") or "",
            "description": entry.get("description") or "",
            "priority": priority if isinstance(priority, int) and not isinstance(priority, bool) else None,
        })

    return entries


# ---------------------------------------------------------------------------
# Gate: resolution (network)
# ---------------------------------------------------------------------------

def gh(path: str):
    """GitHub API GET. Returns (status, parsed-json-or-None)."""
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "trinity-templates-validator",
            **({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
               if os.environ.get("GITHUB_TOKEN") else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # noqa: BLE001 — a network fault is a WARN, not a verdict
        warn("resolve", f"GET {path} failed: {type(e).__name__}")
        return None, None


def check_resolution(entries: list[dict]) -> None:
    from datetime import datetime, timezone

    try:
        import yaml
    except ImportError:
        yaml = None

    for entry in entries:
        repo = entry["repo"]

        status, meta = gh(f"/repos/{repo}")
        if status == 404:
            fail("clone-tokenless", f"{repo}: does not exist or is not public — a fresh "
                                    f"install cannot clone it (the tokenless create path)")
            continue
        if status != 200 or meta is None:
            warn("resolve", f"{repo}: GitHub returned {status}; gates skipped this run")
            continue
        if meta.get("private"):
            fail("clone-tokenless", f"{repo}: repository is private — the tokenless clone "
                                    f"path cannot reach it")
        if meta.get("archived"):
            warn("freshness", f"{repo}: repository is archived")

        pushed = meta.get("pushed_at")
        if pushed:
            age = (datetime.now(timezone.utc)
                   - datetime.fromisoformat(pushed.replace("Z", "+00:00"))).days
            if age > STALE_PUSH_DAYS:
                warn("freshness", f"{repo}: last pushed {age} days ago")

        status, blob = gh(f"/repos/{repo}/contents/template.yaml")
        if status == 404:
            fail("template-yaml", f"{repo}: no template.yaml at the repo root — the "
                                  f"platform has nothing to read; the card renders bare")
            continue
        if status != 200 or blob is None:
            warn("resolve", f"{repo}: template.yaml fetch returned {status}; gates skipped")
            continue

        try:
            raw = base64.b64decode(blob.get("content", "")).decode("utf-8")
        except Exception:  # noqa: BLE001
            fail("template-yaml", f"{repo}: template.yaml is not valid UTF-8")
            continue

        if yaml is None:
            warn("deps", f"{repo}: PyYAML missing — template.yaml gates skipped")
            continue
        try:
            tpl = yaml.safe_load(raw)
        except Exception as e:  # noqa: BLE001
            fail("template-yaml", f"{repo}: template.yaml does not parse — {e}")
            continue
        if not isinstance(tpl, dict):
            fail("template-yaml", f"{repo}: template.yaml is not a mapping")
            continue

        for field in ("name", "description"):
            if not tpl.get(field):
                fail("template-yaml", f"{repo}: template.yaml declares no `{field}`")

        # The security gate. A template whose agent writes to its own repo MUST
        # declare fork_to_own: required, or every created agent binds to THIS
        # shared upstream instead of a user-owned copy (the ent#162 class).
        git_block = tpl.get("git") or {}
        pushes = isinstance(git_block, dict) and git_block.get("push_enabled") is True
        fork = tpl.get("fork_to_own")
        if pushes and fork != "required":
            paths = ", ".join(git_block.get("commit_paths") or []) or "(unrestricted)"
            fail("fork-to-own", f"{repo}: template.yaml sets `git.push_enabled: true` "
                                f"(commit_paths: {paths}) but does not declare "
                                f"`fork_to_own: required` — every agent created from this "
                                f"template binds to the shared upstream, not a user-owned copy")
        if tpl.get("hidden") is True:
            warn("template-yaml", f"{repo}: declares `hidden: true`, which is INERT for a "
                                  f"registry-listed repo — de-list it here to hide it")

        for field in ("author", "name", "description", "tagline"):
            value = tpl.get(field)
            if isinstance(value, str) and PLACEHOLDER_RE.search(value):
                warn("freshness", f"{repo}: template.yaml `{field}` still carries a "
                                  f"placeholder: {value.strip()[:60]!r}")

        # Declared business metrics (trinity-enterprise#483). Warn-tier: a malformed
        # block is how an agent silently loses every metric once the platform
        # validates recorded points against the declaration (ent#477 registry,
        # compat check D-009). Same shape rules as the platform reader.
        if "metrics" in tpl:
            for msg in metrics_block_findings(tpl.get("metrics")):
                warn("metrics", f"{repo}: {msg}")



# ---------------------------------------------------------------------------
# Gate: declared business metrics — shape parity with the platform reader
# (trinity-enterprise#477 `services/template_metrics.py`, compat D-009).
# Pure: takes the parsed `metrics:` value, returns human-readable findings.
# ---------------------------------------------------------------------------

METRIC_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
METRIC_TYPES = {"counter", "gauge", "percentage", "status", "duration", "bytes"}
METRIC_DIRECTIONS = {"up_good", "down_good", "neutral"}
METRIC_AGGREGATIONS = {"last", "sum", "avg"}
METRIC_KNOWN_KEYS = {"name", "type", "label", "description", "unit", "warning_threshold",
                     "critical_threshold", "values", "cadence", "direction", "aggregation",
                     "dimensions"}
CADENCE_SHORT_RE = re.compile(r"^(\d+)([smhdw])$")
CADENCE_ISO_RE = re.compile(r"^P(?:(\d+)W|(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?)$")
CADENCE_MIN_S, CADENCE_MAX_S = 60, 366 * 86400
MAX_METRICS, MAX_STATUS_VALUES, MAX_DIMENSIONS = 50, 50, 10


def cadence_seconds(value) -> int | None:
    """Parse the platform's cadence grammar: <n>(s|m|h|d|w) or an ISO 8601 duration
    without years/months. Returns None when unparseable or out of bounds."""
    if not isinstance(value, str):
        return None
    m = CADENCE_SHORT_RE.match(value.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        secs = n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    else:
        m = CADENCE_ISO_RE.match(value.strip())
        if not m or value.strip() in ("P", "PT"):
            return None
        w, d, h, mi, sec = (int(x) if x else 0 for x in m.groups())
        secs = w * 604800 + d * 86400 + h * 3600 + mi * 60 + sec
    return secs if CADENCE_MIN_S <= secs <= CADENCE_MAX_S else None


def metrics_block_findings(block) -> list[str]:
    out: list[str] = []
    if block is None:
        return out
    if not isinstance(block, list):
        return ["`metrics:` must be a list of metric entries"]
    if len(block) > MAX_METRICS:
        out.append(f"`metrics:` declares {len(block)} entries — the platform caps at {MAX_METRICS}")
    seen: set[str] = set()
    for i, entry in enumerate(block):
        at = f"metrics[{i}]"
        if not isinstance(entry, dict):
            out.append(f"{at}: entry is not a mapping")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not METRIC_NAME_RE.match(name):
            out.append(f"{at}: `name` must be snake_case (^[a-z][a-z0-9_]{{0,63}}$), got {name!r}")
        elif name in seen:
            out.append(f"{at}: duplicate metric name `{name}`")
        else:
            seen.add(name)
        mtype = entry.get("type")
        if mtype not in METRIC_TYPES:
            out.append(f"{at}: `type` must be one of {sorted(METRIC_TYPES)}, got {mtype!r}")
        if not isinstance(entry.get("label"), str) or not entry.get("label"):
            out.append(f"{at}: `label` is required (shown in the UI)")
        if "cadence" in entry and cadence_seconds(entry.get("cadence")) is None:
            out.append(f"{at}: `cadence` {entry.get('cadence')!r} is not a duration between 60s and "
                       f"366d (<n>s|m|h|d|w or ISO 8601 without years/months)")
        if "direction" in entry and entry.get("direction") not in METRIC_DIRECTIONS:
            out.append(f"{at}: `direction` must be one of {sorted(METRIC_DIRECTIONS)}")
        if "aggregation" in entry and entry.get("aggregation") not in METRIC_AGGREGATIONS:
            out.append(f"{at}: `aggregation` must be one of {sorted(METRIC_AGGREGATIONS)}")
        dims = entry.get("dimensions")
        if dims is not None:
            if not isinstance(dims, list) or not all(isinstance(d, str) and METRIC_NAME_RE.match(d) for d in dims):
                out.append(f"{at}: `dimensions` must be a list of snake_case keys")
            elif len(dims) > MAX_DIMENSIONS:
                out.append(f"{at}: `dimensions` lists {len(dims)} keys — the platform caps at {MAX_DIMENSIONS}")
        values = entry.get("values")
        if mtype == "status":
            if not isinstance(values, list) or not values:
                out.append(f"{at}: a `status` metric must declare non-empty `values`")
            else:
                if len(values) > MAX_STATUS_VALUES:
                    out.append(f"{at}: `values` lists {len(values)} — the platform caps at {MAX_STATUS_VALUES}")
                for j, v in enumerate(values):
                    if not isinstance(v, dict) or not isinstance(v.get("value"), str) or not v.get("value"):
                        out.append(f"{at}.values[{j}]: each status value needs a string `value`")
        elif values is not None:
            out.append(f"{at}: `values` is only meaningful on a `status` metric")
        for key in entry:
            if isinstance(key, str) and key not in METRIC_KNOWN_KEYS and not key.startswith("x-"):
                out.append(f"{at}: unknown key `{key}` (x- keys pass through)")
    return out


def selftest_metrics() -> int:
    """Fixture parity with the platform's named findings (ent#477 D-009). Exit 1 on drift."""
    cases = [
        ("valid", [{"name": "items", "type": "counter", "label": "Items", "cadence": "6h",
                    "direction": "up_good", "aggregation": "sum", "dimensions": ["region"]},
                   {"name": "state", "type": "status", "label": "State", "cadence": "P1D",
                    "values": [{"value": "ok", "color": "green", "label": "OK"}]}], 0),
        ("absent", None, 0),
        ("not-a-list", {"name": "x"}, 1),
        ("bad-name", [{"name": "Bad-Name", "type": "gauge", "label": "x"}], 1),
        ("dup-name", [{"name": "a", "type": "gauge", "label": "x"}, {"name": "a", "type": "gauge", "label": "y"}], 1),
        ("bad-type", [{"name": "a", "type": "histogram", "label": "x"}], 1),
        ("bad-cadence-year", [{"name": "a", "type": "gauge", "label": "x", "cadence": "1y"}], 1),
        ("bad-cadence-short", [{"name": "a", "type": "gauge", "label": "x", "cadence": "30s"}], 1),
        ("status-no-values", [{"name": "a", "type": "status", "label": "x"}], 1),
        ("values-on-gauge", [{"name": "a", "type": "gauge", "label": "x", "values": [{"value": "v"}]}], 1),
        ("x-key-passes", [{"name": "a", "type": "gauge", "label": "x", "x-owner": "me"}], 0),
        ("unknown-key", [{"name": "a", "type": "gauge", "label": "x", "bogus": 1}], 1),
    ]
    bad = 0
    for label, block, expected in cases:
        got = len(metrics_block_findings(block))
        ok = (got == 0) if expected == 0 else (got >= expected)
        print(f"{'ok  ' if ok else 'FAIL'} metrics-selftest {label}: {got} finding(s)")
        bad += 0 if ok else 1
    return 1 if bad else 0

# ---------------------------------------------------------------------------
# Gate: platform-parser parity (CI)
# ---------------------------------------------------------------------------

def check_platform_parser(directory: str, text: str, expected: int) -> None:
    """Parse with Trinity's own parser so this repo and the platform cannot drift."""
    sys.path.insert(0, directory)
    try:
        from services.template_registry_service import parse_registry_document
    except Exception as e:  # noqa: BLE001
        fail("parity", f"could not import the vendored platform parser from "
                       f"{directory}: {type(e).__name__}: {e}")
        return

    result = parse_registry_document(text)
    if not result.ok:
        fail("parity", f"the platform's own parser REFUSES this document "
                       f"({result.error_code}) — every install drops to the empty floor")
        for err in result.errors:
            fail("parity", f"platform parser: {err}")
        return
    for err in result.errors:
        fail("parity", f"platform parser: {err}")
    if len(result.entries) != expected:
        fail("parity", f"platform parser accepted {len(result.entries)} entries, this "
                       f"validator accepted {expected} — the two have drifted")


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--resolve", action="store_true",
                    help="also check that every listed repo resolves and passes the repo gates")
    ap.add_argument("--platform-parser", metavar="DIR",
                    help="directory holding the vendored Trinity parser (CI parity mode)")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--selftest-metrics", action="store_true",
                    help="run the declared-metrics gate against its parity fixtures and exit")
    args = ap.parse_args()
    if args.selftest_metrics:
        return selftest_metrics()

    if not REGISTRY.exists():
        print("FAIL document: registry.yaml not found", file=sys.stderr)
        return 1

    text = REGISTRY.read_text(encoding="utf-8")
    entries = check_document(text)

    if args.platform_parser:
        check_platform_parser(args.platform_parser, text, len(entries))
    if args.resolve and entries:
        check_resolution(entries)

    fails = [f for f in findings if f[0] == "FAIL"]
    warns = [f for f in findings if f[0] == "WARN"]

    if args.json:
        print(json.dumps({
            "entries": entries,
            "findings": [{"level": lv, "gate": g, "message": m} for lv, g, m in findings],
            "fail": len(fails), "warn": len(warns),
        }, indent=2))
    else:
        for level, gate, msg in findings:
            print(f"{level} {gate}: {msg}")
        print(f"\n{len(entries)} entries · {len(fails)} FAIL · {len(warns)} WARN")
        if not fails:
            print("registry.yaml is valid.")

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
