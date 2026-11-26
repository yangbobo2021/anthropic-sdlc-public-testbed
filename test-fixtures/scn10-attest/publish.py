# SPDX-FileCopyrightText: 2026 boob.yang
"""Execute the native-verdict acceptance fixture for one frozen synthetic PR."""

import json
import os
from pathlib import Path
import subprocess

REPOSITORY = "yangbobo2021/anthropic-sdlc-public-testbed"
PR = 54
BASE_BRANCH = "scn10-attested-verdict-sandbox"
BASE_SHA = "42811f7dcc48a12239bb474c075be754a9509d09"
CANDIDATE_SHA = "2e4a42bee76c4fa9d6201dd3df92ce6e178674b1"
SIGNER_REPOSITORY = "yangbobo2021/anthropic-sdlc-oidc-peer"
SIGNER_WORKFLOW = f"{SIGNER_REPOSITORY}/.github/workflows/scn10-trusted-verdict.yml"
SIGNER_REF = "refs/heads/codex/scn10-attest-verdict"
SIGNER_SHA = "d837d74ca2e213a5eec2243224c508e45f0ecd17"
FILES = Path(__file__).resolve().parent

def api(route, method="GET", payload=None):
    command = ["gh", "api", "--method", method, f"repos/{REPOSITORY}/{route}"]
    if payload is None:
        return json.loads(subprocess.check_output(command, text=True))
    return json.loads(subprocess.check_output(command + ["--input", "-"], input=json.dumps(payload), text=True))

def current_pr():
    pull = api(f"pulls/{PR}")
    pair = (pull["base"]["sha"], pull["head"]["sha"])
    assert (pull["base"]["ref"], pull["base"]["repo"]["full_name"]) == (BASE_BRANCH, REPOSITORY)
    assert pull["state"] == "open" and pair == (BASE_SHA, CANDIDATE_SHA)
    merge_sha = api(f"git/ref/pull/{PR}/merge")["object"]["sha"]
    merge = api(f"git/commits/{merge_sha}")
    assert tuple(parent["sha"] for parent in merge["parents"]) == pair
    return merge_sha

def main():
    merge_sha = current_pr()
    mode = (FILES / "case.txt").read_text().strip()
    assert mode in {"missing", "alternate", "trusted"}
    verdict = FILES / "verdict.json"
    bundle = FILES / f"{mode}-bundle.json"
    metadata = json.loads(verdict.read_text())
    expected = {
        "schema": "scn10-synthetic-holdout-verdict/v1",
        "target_repository": REPOSITORY,
        "evaluation_run_id": 45758708203,
        "score_sha256": "d52cb74894b2cb668128c50c798ba1cc90dc71b0f883a11e8f664d17eeb911d0",
        "base_sha": BASE_SHA,
        "candidate_sha": CANDIDATE_SHA,
        "passed": True,
    }
    if not bundle.is_file():
        conclusion, reason = "failure", "required bundle is missing"
    elif metadata != expected:
        conclusion, reason = "failure", "signed verdict does not match the exact evaluated PR"
    else:
        verification = subprocess.run(
            [
                "gh", "attestation", "verify", str(verdict),
                "--repo", SIGNER_REPOSITORY, "--bundle", str(bundle),
                "--signer-workflow", SIGNER_WORKFLOW, "--source-ref", SIGNER_REF,
                "--source-digest", SIGNER_SHA, "--deny-self-hosted-runners",
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        print(verification.stdout, flush=True)
        conclusion, reason = (
            ("success", "trusted workflow attested this verdict") if verification.returncode == 0
            else ("failure", "attestation verification rejected the supplied bundle")
        )
    if current_pr() != merge_sha:
        raise RuntimeError("PR test merge changed during verification")
    decision = {
        "case": mode, "reason": reason, "conclusion": conclusion, "pr": PR,
        "head_sha": CANDIDATE_SHA, "base_sha": BASE_SHA, "test_merge_sha": merge_sha,
        "publisher_workflow_sha": os.environ["WORKFLOW_SHA"], "allowed_signer_workflow": SIGNER_WORKFLOW,
    }
    print("SCN10_DECISION=" + json.dumps(decision, sort_keys=True), flush=True)
    run_url = f"https://github.com/{REPOSITORY}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    created = api("check-runs", "POST", {
        "name": "SCN-10 attested holdout verdict", "head_sha": merge_sha,
        "status": "completed", "conclusion": conclusion, "details_url": run_url,
        "output": {"title": reason, "summary": json.dumps(decision, indent=2)},
    })
    print("SCN10_NATIVE_CHECK=" + json.dumps({
        "id": created["id"], "head_sha": created["head_sha"],
        "app_id": created["app"]["id"], "conclusion": created["conclusion"],
    }), flush=True)
    if conclusion != "success":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
