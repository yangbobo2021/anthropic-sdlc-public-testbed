# SPDX-FileCopyrightText: 2026 boob.yang
"""Report a scheduled full run, required suites, and the optional PR selection gap."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("policy", type=Path)
parser.add_argument("report", type=Path)
parser.add_argument("--sha", required=True)
parser.add_argument("--pr-selection", type=Path)
args = parser.parse_args()
policy = json.loads(args.policy.read_text())
names = policy["required_suites"]
if not names or len(set(names)) != len(names) or not all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) for name in names):
    parser.error("missing or invalid suite policy")
observed = {}
for name in names:
    run = subprocess.run(["make", f"test-full-{name}"], check=False)
    coverage = Path("artifacts") / f"coverage-{name}.json"
    observed[name] = {"state": "missing-evidence" if not coverage.is_file() else
                              "success" if run.returncode == 0 else "failure",
                      "coverage": str(coverage) if coverage.is_file() else None}
selected = json.loads(args.pr_selection.read_text())["selected"] if args.pr_selection else None
report = {"sha": args.sha, "suites": observed, "notify_owner": policy["notify_owner"],
          "omitted_by_pr_selection": sorted(set(names) - set(selected)) if selected is not None else None}
args.report.parent.mkdir(parents=True, exist_ok=True)
args.report.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
sys.exit(0 if all(row["state"] == "success" for row in observed.values()) else 1)
