# SPDX-FileCopyrightText: 2026 boob.yang
"""Reference policy checks. Evidence files are inputs from a trusted adapter."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def identifier(value, pattern, label):
    require(isinstance(value, str) and re.fullmatch(pattern, value), f"invalid {label}")


def identity(value, label):
    identifier(value, r"[a-z0-9][a-z0-9._:@/-]{0,127}", label)
    return value


SEVERITIES = {"critical", "high", "medium", "low", "info", "important", "nit", "pre_existing"}


def severity(value):
    require(isinstance(value, str), "invalid severity")
    canonical = value.strip().lower().replace("-", "_")
    if canonical == "normal":
        canonical = "important"
    require(canonical in SEVERITIES, "unknown finding severity")
    return canonical


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(stamp.utcoffset() is not None, "evidence timestamp requires a timezone")
    return stamp


def current_time(value):
    return timestamp(value) if value else datetime.now(timezone.utc)


def distinct_index(items, key):
    result = {}
    for item in items:
        value = item[key]
        require(value not in result, f"duplicate {key}: {value}")
        result[value] = item
    return result


def review(policy, proof, now):
    head = proof["sha"]
    identifier(head, r"[0-9a-f]{40}", "checked commit")
    author = identity(proof["author"], "PR author")
    require(proof["event"] in policy["events"], "unsupported check event")
    expected_items = distinct_index(policy["checks"], "name")
    require(expected_items, "required checks cannot be empty")
    minimum = policy["minimum_humans"]
    require(type(minimum) is int and minimum >= 0, "invalid independent approval requirement")
    actual = distinct_index(proof["checks"], "name")
    for expected in expected_items.values():
        check = actual.get(expected["name"])
        require(check is not None, f"missing required check: {expected['name']}")
        require(check["sha"] == head and check["producer"] == expected["producer"],
                f"stale or untrusted check: {expected['name']}")
        require(isinstance(check["run_id"], str) and check["run_id"].strip(), "missing run ID")
        if check["state"] == "not_applicable":
            require(expected.get("may_be_not_applicable", False) and check.get("reason"),
                    f"missing applicability decision: {expected['name']}")
        else:
            require(check["state"] == "success", f"required check did not succeed: {expected['name']}")
    require(proof["findings_sha"] == head, "review findings are for a different commit")
    configured_severities = policy["blocking_severities"]
    require(isinstance(configured_severities, list) and configured_severities,
            "blocking severity policy is missing")
    blocking_severities = {severity(value) for value in configured_severities}
    require(isinstance(proof["findings"], list), "findings must be a list")
    for finding in distinct_index(proof["findings"], "id").values():
        level = severity(finding["severity"])
        require(finding["status"] in {"open", "fixed", "dismissed"}, "unknown finding status")
        if level not in blocking_severities:
            continue
        if finding["status"] == "fixed":
            require(finding.get("verified_fix_sha") == head, "fix was not verified at this commit")
            continue
        if finding["status"] == "dismissed":
            require(finding.get("approver") in policy["exception_approvers"] and
                    identity(finding["approver"], "exception approver") != author and
                    finding.get("reason") and
                    timestamp(finding["expires_at"]) > now,
                    "finding disposition lacks a valid exception")
            continue
        raise ValueError(f"unresolved finding: {finding['id']}")
    approvals = set()
    for approval in proof.get("approvals", []):
        if (approval["sha"] == head and approval["actor_type"] == "human"
                and approval["actor"] in policy["human_approvers"]
                and identity(approval["actor"], "approval actor") != author):
            approvals.add(approval["actor"])
    require(len(approvals) >= minimum, "required independent approvals missing")
    return {"decision": "allow", "sha": head, "event": proof["event"]}


def promote(policy, proof, now):
    digest, commit = proof["digest"], proof["source_sha"]
    identifier(digest, r"sha256:[0-9a-f]{64}", "artifact digest")
    identifier(commit, r"[0-9a-f]{40}", "source commit")
    require(proof["target"] == policy["target"], "target is not approved")
    expected_signer_sha = commit if policy.get("signer_revision") == "source-sha" else policy["signer_sha"]
    identifier(expected_signer_sha, r"[0-9a-f]{40}", "signer revision")
    provenance = proof["provenance"]
    require(provenance["status"] == "verified" and provenance["signer"] == policy["signer"]
            and provenance["repository"] == policy["repository"]
            and provenance["source_ref"] == policy["source_ref"]
            and provenance["signer_sha"] == expected_signer_sha
            and provenance["digest"] == digest and provenance["source_sha"] == commit,
            "artifact provenance mismatch")
    staging = proof["staging"]
    require(staging["status"] == "passed" and staging["digest"] == digest and staging["source_sha"] == commit
            and staging["environment"] == policy["staging"] and staging["run_id"],
            "missing or mismatched staging receipt")
    require(staging["runner_identity"] == policy["staging_runner"], "untrusted smoke runner")
    seen = timestamp(staging["completed_at"])
    require(0 <= (now - seen).total_seconds() <= 3600 * policy["staging_max_hours"],
            "staging receipt is outside the allowed window")
    approval = proof["approval"]
    require(approval["status"] == "approved" and approval["digest"] == digest
            and approval.get("source_sha") == commit and approval["environment"] == policy["target"]
            and approval["approval_id"] and timestamp(approval["expires_at"]) > now,
            "production approval does not cover this artifact")
    return {"decision": "allow", "source_sha": commit, "digest": digest, "target": proof["target"]}


def delegate(policy, request, now):
    grants = distinct_index(policy["grants"], "grant_id")
    grant = grants.get(request["grant_id"])
    require(grant is not None, "unknown authorization grant")
    claims = ("initiator", "executor", "action", "target", "artifact")
    for claim in claims:
        require(bool(request[claim]) and request[claim] == grant[claim], f"grant has a different {claim}")
    initiator = identity(request["initiator"], "grant initiator")
    executor = identity(request["executor"], "grant executor")
    approver = identity(grant["approver"], "grant approver")
    approvers = policy["authorized_approvers"]
    require(isinstance(approvers, list), "authorized approvers must be a list")
    require(grant["status"] == "approved" and approver in approvers
            and approver not in {initiator, executor}
            and timestamp(grant["starts_at"]) <= now < timestamp(grant["expires_at"]),
            "authorization is inactive or not independent")
    return {"decision": "allow", "grant_id": grant["grant_id"], "action": request["action"]}


def load(filename):
    return json.loads(Path(filename).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("review", "promote", "delegate"))
    parser.add_argument("policy")
    parser.add_argument("evidence")
    parser.add_argument("--now", help="Deterministic test clock, ISO-8601 with timezone")
    args = parser.parse_args()
    try:
        policy, evidence = load(args.policy), load(args.evidence)
        decision = {"review": review, "promote": promote, "delegate": delegate}[args.mode]
        now = current_time(args.now)
        print(json.dumps(decision(policy, evidence, now), sort_keys=True))
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        print(json.dumps({"decision": "deny", "reason": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
