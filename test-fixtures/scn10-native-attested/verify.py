# SPDX-FileCopyrightText: 2026 boob.yang
"""Verify a native attestation without running the candidate's evaluator."""

import json
import os
from pathlib import Path
import re
import subprocess

SIGNER = "yangbobo2021/anthropic-sdlc-oidc-peer"
WORKFLOW = ".github/workflows/scn10-trusted-verdict.yml"
REF = "refs/heads/codex/scn10-attest-verdict"

def require(condition, reason):
    if not condition:
        raise SystemExit(reason)

event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
pr = event["pull_request"]
payload = Path("proofs/test-fixtures/scn10-native-proof/verdict.json")
mode = os.environ.get("SCN10_MODE", "")
require(mode in {"trusted", "alternate"}, "No evaluator attestation configured")
bundle = payload.with_name(f"{mode}-bundle.json")
require(bundle.is_file() and payload.is_file(), "Required attestation bundle or verdict missing")
signer_commit = os.environ.get("SCN10_SIGNER_COMMIT", "")
require(re.fullmatch(r"[0-9a-f]{40}", signer_commit), "Signer commit must be pinned")
proof_commit = os.environ.get("SCN10_PROOF_COMMIT", "")
require(re.fullmatch(r"[0-9a-f]{40}", proof_commit), "Proof publication must be pinned")
for path, expected in (("proofs", proof_commit), ("policy", pr["base"]["sha"])):
    checked = subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()
    require(checked == expected, f"Unexpected pinned checkout in {path}")
decision = {
    "repository": pr["base"]["repo"]["full_name"], "pr": pr["number"],
    "head": pr["head"]["sha"], "base": pr["base"]["sha"], "test_merge": os.environ["GITHUB_SHA"],
    "signer_commit": signer_commit, "publication_commit": proof_commit, "case": mode,
}
print("SCN10_NATIVE_INPUTS=" + json.dumps(decision, sort_keys=True), flush=True)
verdict = json.loads(payload.read_text())
require(verdict.get("schema") == "scn10-synthetic-holdout-verdict/v1", "Unexpected verdict schema")
require(verdict.get("passed") is True, "Evaluator rejected candidate")
for field, expected in (
    ("target_repository", decision["repository"]),
    ("base_sha", decision["base"]),
    ("candidate_sha", decision["head"]),
):
    require(verdict.get(field) == expected, f"Verdict does not bind PR field {field}")
require(re.fullmatch(r"[0-9a-f]{64}", verdict.get("score_sha256", "")), "Private score digest missing")
require(type(verdict.get("evaluation_run_id")) is int and verdict["evaluation_run_id"] > 0, "Private run ID missing")
subprocess.run([
    "gh", "attestation", "verify", str(payload),
    "--repo", SIGNER, "--bundle", str(bundle),
    "--cert-identity", f"https://github.com/{SIGNER}/{WORKFLOW}@{REF}",
    "--source-ref", REF, "--source-digest", signer_commit, "--signer-digest", signer_commit,
    "--deny-self-hosted-runners",
], check=True)
print("SCN10_NATIVE_VERDICT=verified", flush=True)
