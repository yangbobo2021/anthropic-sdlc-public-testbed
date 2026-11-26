# SPDX-FileCopyrightText: 2026 boob.yang
"""Select relevant named test groups, time their runs, and publish listener history."""

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic

from decision import distinct_index, identifier, require, timestamp


def changed_paths(base, head):
    for sha in (base, head):
        identifier(sha, r"[0-9a-f]{40}", "diff endpoint")
    output = subprocess.check_output(["git", "diff", "--no-renames", "--name-only", "-z", base, head, "--"])
    return [item.decode("utf-8", errors="surrogateescape") for item in output.split(b"\x00") if item]


def select(policy, history, paths, full):
    groups = distinct_index(policy["groups"], "name")
    require(groups, "no groups configured")
    for name in groups:
        identifier(name, r"[a-z][a-z0-9-]{0,60}", "test group")
    latest = {}
    if history:
        age = (datetime.now(timezone.utc) - timestamp(history["recorded_at"])).total_seconds()
        if 0 <= age <= policy["history_max_age_seconds"]:
            latest = distinct_index(history["results"], "name")
    complete = set(groups) == set(latest)
    relevant, unmatched = set(), []
    for path in paths:
        matching = {name for name, group in groups.items() if any(fnmatchcase(path, pat) for pat in group["packages"])}
        if not matching or any(fnmatchcase(path, pat) for pat in policy["always_full"]):
            unmatched.append(path)
        relevant.update(matching)
    full = full or not paths or not complete or bool(unmatched)
    selected = set(groups) if full else relevant | {name for name, result in latest.items() if not result["passed"]}
    order = sorted(selected, key=lambda name: (latest.get(name, {}).get("passed", True),
                                               latest.get(name, {}).get("duration_ms", 0), name))
    return {"full": full, "selected": order, "unmapped": unmatched, "known_history": complete}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--history-sha")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--base")
    parser.add_argument("--head", required=True)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    history = json.loads(args.history.read_text()) if args.history and args.history.exists() else None
    identifier(args.head, r"[0-9a-f]{40}", "test source commit")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == args.head,
            "working checkout does not match the assessed commit")
    if history:
        require(args.history_sha and history["source_sha"] == args.history_sha and history["full"],
                "history does not come from the expected full CI run")
        identifier(args.history_sha, r"[0-9a-f]{40}", "historical CI commit")
        if not args.base or subprocess.run(["git", "merge-base", "--is-ancestor", args.history_sha, args.base],
                                           check=False).returncode != 0:
            history = None
    paths = [] if args.full else changed_paths(args.base, args.head)
    plan = select(policy, history, paths, args.full)
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts / "impact-selection.json").write_text(json.dumps(plan) + "\n")
    results = []
    for name in plan["selected"]:
        begin = monotonic()
        try:
            passed = subprocess.run(["make", f"test-{name}"], check=False,
                                    timeout=policy["group_timeout_seconds"]).returncode == 0
        except subprocess.TimeoutExpired:
            passed = False
        results.append({"name": name, "passed": passed, "duration_ms": round((monotonic() - begin) * 1000)})
    before = distinct_index(history["results"], "name") if history and not plan["full"] else {}
    before.update(distinct_index(results, "name"))
    receipt = {"recorded_at": datetime.now(timezone.utc).isoformat(), "source_sha": args.head,
               "results": list(before.values()), "executed": results, "full": plan["full"]}
    (args.artifacts / "impact-history.json").write_text(json.dumps(receipt) + "\n")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
