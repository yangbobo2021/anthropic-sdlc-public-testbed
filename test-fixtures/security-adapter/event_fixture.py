# SPDX-FileCopyrightText: 2026 boob.yang
"""Run synthetic security checks on a live PR event in the public testbed."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from github_evidence import api

SCANNER = "trusted-security-findings"
VERDICT = "trusted-pr-security-review"
FIXTURE_APP_ID = 15368


def read_checks(repo, sha, name):
    endpoint = (
        f"repos/{repo}/commits/{sha}/check-runs?"
        f"check_name={name}&app_id={FIXTURE_APP_ID}&filter=latest&per_page=100"
    )
    response = api(endpoint)
    return sorted(
        (run for run in response["check_runs"]
         if run["head_sha"] == sha and run["name"] == name and run["app"]["id"] == FIXTURE_APP_ID),
        key=lambda run: run["id"],
    )


def receipt(run):
    return {
        "id": run["id"],
        "name": run["name"],
        "head_sha": run["head_sha"],
        "status": run["status"],
        "conclusion": run["conclusion"],
        "text": run["output"]["text"],
        "app_id": run["app"]["id"],
        "url": run["html_url"],
    }


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    assert repo == "yangbobo2021/anthropic-sdlc-public-testbed"
    assert os.environ["GITHUB_EVENT_NAME"] == "pull_request_target"
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pull = event["pull_request"]
    action = event["action"]
    head = pull["head"]["sha"]
    base = os.environ["GITHUB_SHA"]
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert re.fullmatch(r"[0-9a-f]{40}", head)
    assert checkout == base == pull["base"]["sha"] and head != checkout
    assert pull["base"]["ref"] == "main"
    assert pull["head"]["repo"]["full_name"] == repo
    branch = pull["head"]["ref"]
    current = api(f"repos/{repo}/pulls/{pull['number']}")
    assert current["state"] == "open" and current["head"]["sha"] == head

    previous = None
    previous_scanner = []
    if branch == "codex/sdlc-0050-native-refresh" and action == "synchronize":
        case = "only-stale-report"
        previous = event["before"]
        assert re.fullmatch(r"[0-9a-f]{40}", previous) and previous != head
        assert event["after"] == head and not read_checks(repo, head, SCANNER)
        previous_scanner = read_checks(repo, previous, SCANNER)
        assert previous_scanner and previous_scanner[-1]["conclusion"] == "success"
        assert json.loads(previous_scanner[-1]["output"]["text"])["source_sha"] == previous
        expected = "failure"
    else:
        assert action == "opened"
        if branch == "codex/sdlc-0050-native-refresh":
            case, findings, expected = "complete-empty-report", [], "success"
        else:
            assert branch == "codex/sdlc-0050-native-blocking"
            case, expected = "unresolved-high-finding", "failure"
            findings = [{"id": "synthetic-risk", "severity": "high", "status": "open"}]
        report = {"source_sha": head, "status": "complete", "findings": findings}
        scanner = api(f"repos/{repo}/check-runs", {
            "name": SCANNER,
            "head_sha": head,
            "status": "completed",
            "conclusion": "success",
            "output": {"title": "Synthetic scanner", "summary": case, "text": json.dumps(report)},
        })
        assert scanner["app"]["id"] == FIXTURE_APP_ID and scanner["head_sha"] == head

    policy = Path(os.environ["RUNNER_TEMP"]) / "security-event-policy.json"
    policy.write_text(json.dumps({"security_review": {
        "name": SCANNER,
        "app_id": FIXTURE_APP_ID,
        "blocking_severities": ["critical", "high"],
    }}))
    adapter = Path(__file__).with_name("github_evidence.py")
    decision = subprocess.run([sys.executable, str(adapter), "security", str(policy)], check=False)
    assert decision.returncode == (0 if expected == "success" else 1)
    current = api(f"repos/{repo}/pulls/{pull['number']}")
    assert current["state"] == "open" and current["head"]["sha"] == head
    verdicts = read_checks(repo, head, VERDICT)
    assert verdicts and verdicts[-1]["conclusion"] == expected
    assert verdicts[-1]["status"] == "completed"
    scanners = read_checks(repo, head, SCANNER)
    if previous:
        assert not scanners
    else:
        assert scanners and json.loads(scanners[-1]["output"]["text"]) == report

    result = {
        "case": case,
        "action": action,
        "pr": pull["number"],
        "pr_head": head,
        "base_sha": base,
        "checkout_sha": checkout,
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        "adapter_exit": decision.returncode,
        "scanner": [receipt(run) for run in scanners],
        "prior_head": previous,
        "prior_scanner": [receipt(run) for run in previous_scanner],
        "verdict": receipt(verdicts[-1]),
    }
    output = Path("artifacts/security-event-result.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{case}: PR {pull['number']}, {head}, {expected}")


if __name__ == "__main__":
    main()
