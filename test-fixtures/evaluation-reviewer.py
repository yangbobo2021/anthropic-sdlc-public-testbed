# SPDX-FileCopyrightText: 2026 boob.yang
"""Deterministic reviewer used only by the evaluation fixture."""
import json
import sys

packet = json.load(sys.stdin)["input"]
findings = []
if packet["required"] and packet["current_sha"] != packet["verified_sha"]:
    findings.append("stale-verification")
if not packet["approver"]:
    findings.append("missing-approver")
print(json.dumps({"findings": findings}))
