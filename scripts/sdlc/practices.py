# SPDX-FileCopyrightText: 2026 boob.yang
"""Portable checks for defensive SDLC fixtures and project adapters."""

import argparse
from collections import defaultdict
from fnmatch import fnmatchcase
import hashlib
import json
from math import ceil
from pathlib import Path
import sys

from decision import current_time, distinct_index, identifier, require, severity, timestamp


def differential(document, policy, _now):
    old, new = (distinct_index(document[k], "id") for k in ("old", "new"))
    require(isinstance(policy, list), "approved deltas policy must be a list")
    approved = policy
    differences = []
    for identity in sorted(old.keys() | new.keys()):
        if identity not in old or identity not in new:
            differences.append({"id": identity, "field": "$record", "before": old.get(identity), "after": new.get(identity)})
            continue
        for field in sorted(old[identity].keys() | new[identity].keys()):
            before, after = old[identity].get(field), new[identity].get(field)
            if (field in old[identity]) != (field in new[identity]) or before != after:
                differences.append({"id": identity, "field": field, "before": before, "after": after,
                                    "missing_before": field not in old[identity], "missing_after": field not in new[identity]})
    unexplained = [item for item in differences if item not in approved]
    return {"passed": not unexplained, "differences": differences, "unapproved": unexplained}


def impact(document):
    groups = set(document["all_groups"])
    require(groups, "no test groups are configured")
    paths = document["changed_paths"]
    selected, unmatched = set(), []
    mapping = document["rules"]
    for path in paths:
        results = set()
        for rule in mapping:
            if fnmatchcase(path, rule["pattern"]):
                results.update(rule["groups"])
        if not results or path in document.get("force_full_on", []):
            unmatched.append(path)
        selected.update(results)
    require(selected <= groups, "rule selects an unknown test group")
    all_run = not paths or bool(unmatched)
    return {"passed": True, "selected": sorted(groups if all_run else selected), "full": all_run, "unmapped": unmatched}


def canary(document, policy, now):
    identifier(document["digest"], r"sha256:[0-9a-f]{64}", "canary digest")
    require(document["digest"] == policy["digest"], "target digest does not match release")
    require(document["producer"] == policy["producer"], "untrusted telemetry producer")
    start, end = (timestamp(document[key]) for key in ("started_at", "completed_at"))
    duration = (end - start).total_seconds()
    age = (now - end).total_seconds()
    require(duration >= policy["min_seconds"] > 0 and 0 <= age <= policy["max_age_seconds"],
            "canary measurement window is invalid")
    rates = {}
    for name in ("observations", "control"):
        cohort = document[name]
        count, errors, latency = (cohort[key] for key in ("requests", "errors", "p95_ms"))
        require(type(count) is int and type(errors) is int and count >= policy["min_requests"] > 0 and
                0 <= errors <= count and 0 <= latency, "invalid or insufficient cohort evidence")
        rates[name] = errors / count
    observed = rates["observations"]
    candidate, baseline = (document[name]["p95_ms"] for name in ("observations", "control"))
    require(0 <= policy["max_error_rate"] < 1 and 0 <= policy["max_error_increase"] < 1,
            "invalid error budget")
    passed = (observed <= policy["max_error_rate"] and
              observed - rates["control"] <= policy["max_error_increase"] and
              candidate <= min(policy["max_p95_ms"], baseline + policy["max_p95_increase_ms"]))
    return {"passed": passed, "action": "advance" if passed else "hold", "error_rate": observed,
            "digest": document["digest"], "completed_at": document["completed_at"]}


def staging(document, policy, now):
    identifier(document["digest"], r"sha256:[0-9a-f]{64}", "staging digest")
    identifier(document["source_sha"], r"[0-9a-f]{40}", "source commit")
    require(document["environment"] == policy["environment"] == "staging" and document["run_id"],
            "staging identity unavailable")
    require(document["runner_identity"] == policy["runner_identity"], "untrusted smoke runner")
    require(timestamp(document["completed_at"]) <= now, "smoke completion is in the future")
    actual = distinct_index(document["results"], "name")
    expected = policy["required_smokes"]
    require(isinstance(expected, list) and expected, "trusted smoke test list is empty")
    passed = all(actual.get(name, {}).get("status") == "passed" for name in expected)
    return {"passed": passed, "status": "passed" if passed else "failed", **{
        key: document[key] for key in ("digest", "source_sha", "environment", "run_id",
                                      "runner_identity", "completed_at")}}


def staging_security(document, policy, now):
    for key in ("environment", "approval_id", "scope_id", "runner_identity", "digest", "source_sha"):
        require(document[key] and document[key] == policy[key], f"security scope mismatch: {key}")
    require(document["environment"] == "staging", "security scope must be staging")
    identifier(document["digest"], r"sha256:[0-9a-f]{64}", "scanned digest")
    identifier(document["source_sha"], r"[0-9a-f]{40}", "scanned commit")
    completed = timestamp(document["completed_at"])
    require(timestamp(policy["starts_at"]) <= completed <= now < timestamp(policy["expires_at"]),
            "scan is outside the approved window")
    require(document["report_ref"] and document["report_status"] == "complete", "scan result is incomplete")
    blocking = policy["blocking_severities"]
    require(isinstance(blocking, list) and blocking, "blocking severities are required")
    blocking = {severity(value) for value in blocking}
    require(isinstance(document["findings"], list), "findings must be a list")
    unresolved = []
    for finding in distinct_index(document["findings"], "id").values():
        level = severity(finding["severity"])
        require(finding["status"] in {"open", "fixed"}, "unsupported scan finding status")
        if level in blocking and (finding["status"] != "fixed" or
                                  finding.get("verified_fix_digest") != document["digest"]):
            unresolved.append(finding["id"])
    return {"passed": not unresolved, "unresolved": unresolved, "scope_id": document["scope_id"],
            "source_sha": document["source_sha"], "digest": document["digest"]}


def sample(document):
    groups = defaultdict(list)
    for receipt in distinct_index(document["approved"], "decision_id").values():
        identifier(receipt["checked_sha"], r"[0-9a-f]{40}", "approved SHA")
        require(receipt["decision"] == "auto-approved" and receipt["producer"] == document["producer"],
                "receipt is not an automatic decision from the expected provider")
        groups[receipt["risk"]].append(receipt)
    picked = []
    for level, records in sorted(groups.items()):
        share = document["fractions"][level]
        require(0 <= share <= 1, "sampling fraction outside [0,1]")
        ordered = sorted(records, key=lambda row: hashlib.sha256(
            f"{document['seed']}::{row['decision_id']}".encode()).hexdigest())
        picked.extend(row["decision_id"] for row in ordered[:ceil(len(records) * share)])
    by_id = distinct_index(document["approved"], "decision_id")
    return {"passed": True, "sampled": picked, "review_queue": [
        {"decision_id": key, "checked_sha": by_id[key]["checked_sha"], "producer": by_id[key]["producer"]}
        for key in picked]}


def main():
    modes = {"differential": differential, "impact": impact, "canary": canary, "staging": staging,
             "staging-security": staging_security, "sample": sample}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=modes)
    parser.add_argument("input", type=Path)
    parser.add_argument("--policy", type=Path, help="Independent policy from protected configuration")
    parser.add_argument("--now", help="Deterministic test clock")
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text())
        if args.mode in {"differential", "staging", "staging-security", "canary"}:
            require(args.policy and args.policy.resolve() != args.input.resolve(), "independent policy is required")
            result = modes[args.mode](document, json.loads(args.policy.read_text()), current_time(args.now))
        else:
            result = modes[args.mode](document)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["passed"] else 1
    except (KeyError, TypeError, AttributeError, ValueError, OSError) as error:
        print(f"{args.mode}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
