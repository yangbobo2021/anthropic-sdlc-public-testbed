# SPDX-FileCopyrightText: 2026 boob.yang
"""Collect GitHub App evidence for one SHA and publish a blocking check."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from decision import distinct_index, identifier, require, review, severity

SEVERITY_LINE = re.compile(r"<!-- bughunter-severity: (\{[^\n]+\}) -->")
HOSTED_NAME = "Claude Code Review"


def api(endpoint, payload=None):
    command = ["gh", "api", endpoint]
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    return json.loads(subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                                     capture_output=True, text=True, check=True).stdout)


def last_check(repo, head, name, app_id):
    require(type(app_id) is int and app_id > 0, f"set the GitHub App ID for {name}")
    out = api(f"repos/{repo}/commits/{head}/check-runs?check_name={name.replace(' ', '%20')}&app_id={app_id}&filter=latest&per_page=100")
    candidates = [run for run in out["check_runs"]
                  if run["app"]["id"] == app_id and run["head_sha"] == head and run["name"] == name]
    require(candidates, f"missing authenticated check: {name}")
    return max(candidates, key=lambda run: run["id"])


def hosted_findings(run):
    require(run["status"] == "completed" and run["conclusion"] in {"neutral", "skipped"},
            "Claude review unavailable or incomplete")
    title = run["output"].get("title") or ""
    if title.startswith("Code review not repeated"):
        return [{"id": "claude-kept-important", "severity": "important", "status": "open"}]
    if title.endswith("no new changes") and run["conclusion"] == "skipped":
        return []
    lines = (run["output"].get("text") or "").strip().splitlines()
    match = SEVERITY_LINE.fullmatch(lines[-1]) if lines else None
    require(match, "Claude review has no authenticated verdict")
    counts = json.loads(match.group(1))
    require(set(counts) == {"normal", "nit", "pre_existing"} and
            all(type(value) is int and value >= 0 for value in counts.values()), "invalid Claude severity summary")
    return [{"id": "claude-important", "severity": "important", "status": "open"}] if counts["normal"] else []


def security_verdict(repo, head, policy):
    expected = policy["security_review"]
    run = last_check(repo, head, expected["name"], expected["app_id"])
    require(run["status"] == "completed" and run["conclusion"] in {"success", "failure", "neutral"},
            "security review has no terminal verdict")
    packet = json.loads(run["output"]["text"])
    require(packet["source_sha"] == head and packet["status"] == "complete" and isinstance(packet["findings"], list),
            "security evidence is incomplete or stale")
    blocking = {severity(level) for level in expected["blocking_severities"]}
    require(blocking, "security threshold policy is missing")
    for finding in distinct_index(packet["findings"], "id").values():
        state = finding["status"]
        require(state == "open" or (state == "fixed" and finding.get("verified_fix_sha") == head),
                "security finding disposition is invalid")
        require(severity(finding["severity"]) not in blocking or state == "fixed",
                "security review reported unresolved findings")
    require(run["conclusion"] != "failure", "security reviewer reported failure")


def github_approvals(repo, number, head):
    current = {}
    for page in range(1, 11):
        reviews = api(f"repos/{repo}/pulls/{number}/reviews?per_page=100&page={page}")
        for row in reviews:
            user = row.get("user") or {}
            if user.get("type") == "User" and row["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                current[user["login"].lower()] = row
        if len(reviews) < 100:
            break
    else:
        raise ValueError("review pagination limit exceeded")
    return [{"actor": actor, "actor_type": "human", "sha": head} for actor, row in current.items()
            if row["state"] == "APPROVED" and row.get("commit_id") == head]


def evaluated_event(repo, event, kind):
    if kind == "merge_group":
        return event["merge_group"]["head_sha"], None
    if kind == "check_run":
        run = event["check_run"]
        pulls = run["pull_requests"]
        require(len(pulls) == 1, "check event does not identify a single PR")
        head, number = run["head_sha"], pulls[0]["number"]
    else:
        pull = event["pull_request"]
        head, number = pull["head"]["sha"], pull["number"]
    pull = api(f"repos/{repo}/pulls/{int(number)}")
    require(pull["state"] == "open" and pull["head"]["sha"] == head, "PR event is stale")
    return head, pull


def collect(repo, head, pull, policy):
    checks = []
    if pull is None:
        run = last_check(repo, head, policy["queue_receipt_check"], policy["queue_receipt_app_id"])
        require(run["conclusion"] == "success", "queue receipt check did not pass")
        packet = json.loads(run["output"]["text"])
        require(packet["sha"] == head and packet["event"] == "merge_group", "queue receipt scope mismatch")
    else:
        findings = hosted_findings(last_check(repo, head, HOSTED_NAME, policy["claude_app_id"]))
        packet = {"sha": head, "event": "pull_request", "author": pull["user"]["login"].lower(),
                  "findings_sha": head, "findings": findings,
                  "approvals": github_approvals(repo, pull["number"], head)}
    for expected in policy["checks"]:
        run = last_check(repo, head, expected["name"], expected["app_id"])
        check = {"name": expected["name"], "sha": head, "producer": expected["producer"],
                 "state": run["conclusion"] if run["status"] == "completed" else "pending",
                 "run_id": str(run["id"])}
        if check["state"] == "skipped":
            require(expected.get("may_be_not_applicable") is True, "check is not eligible for an applicability waiver")
            waiver = json.loads(run["output"].get("text") or "")
            require(isinstance(waiver, dict) and type(waiver.get("schema_version")) is int
                    and waiver["schema_version"] == 1 and waiver.get("source_sha") == head
                    and waiver.get("check_name") == expected["name"] and waiver.get("state") == "not_applicable",
                    "applicability waiver scope mismatch")
            reason = waiver.get("reason")
            require(isinstance(reason, str) and reason.strip(), "applicability waiver needs a reason")
            check.update(state="not_applicable", reason=reason.strip())
        checks.append(check)
    return {**packet, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("security", "required"))
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    repo = os.environ["GITHUB_REPOSITORY"]
    kind = os.environ["GITHUB_EVENT_NAME"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    policy = json.loads(args.policy.read_text())
    if kind == "check_run":
        trigger = event["check_run"]
        if args.mode == "security":
            expected = policy["security_review"]
            accepted = {(expected["name"], expected["app_id"])}
        else:
            accepted = {(HOSTED_NAME, policy["claude_app_id"]),
                        (policy["queue_receipt_check"], policy["queue_receipt_app_id"])}
        if args.mode == "required":
            accepted.update((check["name"], check["app_id"]) for check in policy["checks"])
        if (trigger["name"], trigger["app"]["id"]) not in accepted:
            return 0
        if not trigger["pull_requests"]:
            if args.mode == "required" and trigger["name"] == policy["queue_receipt_check"]:
                kind = "merge_group"
                event = {"merge_group": {"head_sha": trigger["head_sha"]}}
            else:
                head = trigger["head_sha"]
                identifier(head, r"[0-9a-f]{40}", "check trigger SHA")
                pulls = api(f"repos/{repo}/commits/{head}/pulls")
                current = [pull for pull in pulls if pull["state"] == "open" and pull["head"]["sha"] == head]
                if len(current) != 1:
                    return 0
                event = {"pull_request": current[0]}
                kind = "pull_request_target"
    if kind == "workflow_run":
        upstream = event["workflow_run"]
        require(upstream["repository"]["full_name"].lower() == repo.lower(), "foreign workflow signal")
        if upstream["event"] == "merge_group":
            kind = "merge_group"
            event = {"merge_group": {"head_sha": upstream["head_sha"]}}
        elif upstream["event"] in {"pull_request_review", "pull_request"}:
            current = upstream["pull_requests"]
            if not current:
                head = upstream["head_sha"]
                identifier(head, r"[0-9a-f]{40}", "upstream SHA")
                current = [pull for pull in api(f"repos/{repo}/commits/{head}/pulls")
                           if pull["state"] == "open" and pull["head"]["sha"] == head]
            if len(current) != 1:
                return 0
            # The signal supplies a PR identifier. Read current checks and approvals independently.
            number = current[0]["number"]
            event = {"pull_request": api(f"repos/{repo}/pulls/{number}")}
        else:
            return 0
    if kind == "workflow_dispatch":
        number = int(event["inputs"].get("pr_number") or 0)
        if number:
            pull = api(f"repos/{repo}/pulls/{number}")
            event = {"pull_request": pull}
        elif args.mode == "required":
            kind = "merge_group"
            event = {"merge_group": {"head_sha": event["inputs"]["queue_sha"]}}
    head, pull = evaluated_event(repo, event, kind)
    identifier(head, r"[0-9a-f]{40}", "evaluated SHA")
    try:
        if args.mode == "security":
            security_verdict(repo, head, policy)
        else:
            review(policy, collect(repo, head, pull, policy), datetime.now(timezone.utc))
        passed = True
    except (KeyError, TypeError, ValueError, subprocess.CalledProcessError):
        passed = False
    name = "trusted-pr-security-review" if args.mode == "security" else "trusted-sdlc-policy"
    summary = "Verified required inputs." if passed else "Required evidence is missing, blocked, or not authenticated."
    api(f"repos/{repo}/check-runs", {"name": name, "head_sha": head, "status": "completed",
                                    "conclusion": "success" if passed else "failure",
                                    "output": {"title": name, "summary": summary}})
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
