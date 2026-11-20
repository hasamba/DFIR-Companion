#!/usr/bin/env python3
"""Compile-check the vendored AI-agent YARA rules (#2720).

The companion never compiles these rules itself: aiAgentRuleParse.ts reads only rule names and
meta. The first real compile happens on the endpoint, inside Velociraptor (libyara 4.x via
go-yara), so a broken upstream re-sync would fail every scan instead of the PR that brought it.

Two passes, both with yara-python (libyara 4.x, the same dialect; NOT yara-x, which is stricter):

  1. Every .yar/.yara file on its own, so a failure names the file.
  2. Every scan scope's joined rule set, built the way aiAgentArtifact.ts builds it: the files whose
     scope-map.yaml entry lists that scope, in aiAgentRuleSet.ts's walk order (sorted names, depth
     first), CRLF -> LF, joined with "\\n". This catches what pass 1 cannot: two files that define
     the same rule name, which only fails once they share one scope.

Mirror of aiAgentRuleSet.ts loadYara/listFiles and aiAgentArtifact.ts buildConfig; keep in step.

Usage: python3 companion/scripts/checkAiAgentYara.py [rules-dir]
Needs: pip install yara-python pyyaml
"""

import os
import re
import sys

import yaml
import yara

DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ai-agent-rules")
YARA_EXT = re.compile(r"\.yara?$", re.IGNORECASE)
MAX_RULE_FILE_BYTES = 256 * 1024  # aiAgentRuleSet.ts MAX_RULE_FILE_BYTES: larger files are skipped


def list_yara_files(root):
    """Paths under root (forward slashes), in aiAgentRuleSet.ts listFiles order."""
    out = []

    def walk(d):
        for name in sorted(os.listdir(d)):
            full = os.path.join(d, name)
            if os.path.isdir(full):
                walk(full)
            elif YARA_EXT.search(name) and os.path.getsize(full) <= MAX_RULE_FILE_BYTES:
                out.append(os.path.relpath(full, root).replace(os.sep, "/"))

    if os.path.isdir(root):
        walk(root)
    return out


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read().replace("\r\n", "\n")


def compile_or_error(source):
    try:
        yara.compile(source=source)
        return None
    except yara.Error as e:
        return str(e)


def scoped_files(scope_map, files):
    """{file: [scope ids]} for files with an entry naming at least one declared scope."""
    scope_ids = set((scope_map.get("scopes") or {}).keys())
    assigned = scope_map.get("yara") or {}
    out = {}
    for path in files:
        entry = assigned.get(path) or {}
        scopes = [s for s in (entry.get("scopes") or []) if isinstance(s, str) and s in scope_ids]
        if scopes:
            out[path] = scopes
    return out


def main(argv):
    rules_dir = os.path.abspath(argv[1] if len(argv) > 1 else DEFAULT_DIR)
    yara_dir = os.path.join(rules_dir, "yara")
    with open(os.path.join(rules_dir, "scope-map.yaml"), encoding="utf-8") as f:
        scope_map = yaml.safe_load(f) or {}

    files = list_yara_files(yara_dir)
    if not files:
        print(f"FAIL: no .yar/.yara files under {yara_dir}")
        return 1
    texts = {p: read_text(os.path.join(yara_dir, p)) for p in files}
    failures = 0

    for path in files:
        err = compile_or_error(texts[path])
        print(f"{'FAIL' if err else 'ok  '} file  yara/{path}" + (f": {err}" if err else ""))
        failures += bool(err)

    assigned = scoped_files(scope_map, files)
    for scope_id in (scope_map.get("scopes") or {}).keys():
        members = [p for p in files if scope_id in assigned.get(p, [])]
        if not members:
            print(f"skip scope {scope_id}: no rule files assigned")
            continue
        err = compile_or_error("\n".join(texts[p] for p in members))
        print(f"{'FAIL' if err else 'ok  '} scope {scope_id} ({len(members)} files)" + (f": {err}" if err else ""))
        failures += bool(err)

    print(f"{len(files)} files checked, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
