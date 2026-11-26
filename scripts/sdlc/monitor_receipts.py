# SPDX-FileCopyrightText: 2026 boob.yang
"""Normalize defensive monitoring signals into coverage and owner evidence."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def unique(rows, columns):
    index = {}
    for row in rows:
        key = tuple(row[column] for column in columns)
        require(all(isinstance(item, str) and item for item in key) and key not in index, "invalid evidence key")
        index[key] = row
    return index


def outcomes(mode, inventory, evidence, policy, now):
    found = []
    if mode in {"dependency", "container"}:
        columns = ("package", "version") if mode == "dependency" else ("running_digest",)
        matches = unique(evidence["alerts"], (*columns, "alert_id"))
        deployed = unique(inventory, ("service", *columns))
        for (_, *components), asset in deployed.items():
            for key, alert in matches.items():
                if tuple(components) == key[:-1]:
                    finding = {"service": asset["service"], "owner": asset["owner"], "alert_id": key[-1],
                               "severity": alert["severity"], "status": "tracked-remediation"}
                    if mode == "container":
                        digest = asset["running_digest"]
                        require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "invalid running digest")
                        finding["running_digest"] = digest
                    found.append(finding)
    elif mode == "secret":
        owners = unique(inventory, ("service",))
        alerts = unique(evidence["alerts"], ("alert_id",))
        for alert in alerts.values():
            owner = owners[(alert["service"],)]["owner"]
            found.append({"alert_id": alert["alert_id"], "credential_class": alert["credential_class"],
                          "owner": owner, "action": "verify-and-rotate", "status": "open"})
    else:
        baseline = unique(policy["baselines"], ("asset",))
        exceptions = unique(policy.get("exceptions", []), ("asset", "field"))
        observed = unique(evidence["assets"], ("asset",))
        for (asset,), expected in baseline.items():
            for field, value in expected["settings"].items():
                actual = observed.get((asset,), {}).get("settings", {})
                if field in actual and actual[field] == value:
                    continue
                exception = exceptions.get((asset, field))
                if exception and stamp(exception["expires_at"]) > now and exception["approved_by"]:
                    continue
                found.append({"asset": asset, "owner": expected["owner"], "field": field, "status": "drift"})
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dependency", "container", "secret", "cloud"))
    parser.add_argument("policy", type=Path)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--now", help="Deterministic fixture clock")
    args = parser.parse_args()
    try:
        now = stamp(args.now) if args.now else datetime.now(timezone.utc)
        policy = json.loads(args.policy.read_text())
        evidence = json.loads(args.packet.read_text())
        age = (now - stamp(evidence["collected_at"])).total_seconds()
        require(evidence["producer"] == policy["producer"] and 0 <= age <= policy["max_age_seconds"],
                "monitor feed is not current or authorized")
        inventory = evidence.get("inventory", [])
        require(args.mode == "cloud" or inventory, "inventory is missing")
        if args.mode in {"dependency", "container"}:
            require(evidence["feed_version"], "feed version is missing")
        result = outcomes(args.mode, inventory, evidence, policy, now)
        print(json.dumps({"kind": args.mode, "observed_at": evidence["collected_at"], "findings": result}))
    except (KeyError, TypeError, ValueError, OSError):
        print("Monitoring input is incomplete, stale, or out of scope.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
