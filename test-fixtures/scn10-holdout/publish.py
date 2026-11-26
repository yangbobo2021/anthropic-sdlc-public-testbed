# SPDX-FileCopyrightText: 2026 boob.yang
"""Publish a test-only verdict from a fixed fixture signature."""

from base64 import b64decode
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


def api(endpoint, payload=None):
    args = ["gh", "api", endpoint]
    if payload is not None:
        args.extend(["--method", "POST", "--input", "-"])
    return json.loads(subprocess.check_output(args, input=json.dumps(payload) if payload is not None else None, text=True))


def main():
    repo, number = os.environ["GITHUB_REPOSITORY"], int(os.environ["PR_NUMBER"])
    assert repo == "yangbobo2021/anthropic-sdlc-public-testbed" and number > 0
    pr = api(f"repos/{repo}/pulls/{number}")
    assert pr["state"] == "open" and pr["base"]["ref"] == "scn10-holdout-sandbox"
    assert pr["head"]["repo"]["full_name"] == repo and pr["head"]["ref"] in {
        "codex/scn10-gate-maintained", "codex/scn10-gate-regressed", "codex/scn10-gate-refresh",
    }
    head = pr["head"]["sha"]
    assert re.fullmatch("[0-9a-f]{40}", head)
    root = Path(__file__).resolve().parent
    manifest = root / "signed-verdict.json"
    with TemporaryDirectory(prefix="scn10-verify-") as folder:
        signature = Path(folder) / "signature"
        signature.write_bytes(b64decode((root / "signed-verdict.sig.b64").read_bytes().strip(), validate=True))
        subprocess.run(["openssl","pkeyutl","-verify","-rawin","-pubin","-inkey",str(root/"fixture-ed25519.pub"),
                        "-in",str(manifest),"-sigfile",str(signature)], check=True)
    body = manifest.read_bytes()
    report = json.loads(body)
    assert report["schema"] == 1 and re.fullmatch("[0-9a-f]{64}", report["score_report_sha256"])
    verdict = report["verdicts"].get(head)
    if verdict not in {"success", "failure"}:
        raise SystemExit("Signed report does not cover the current PR SHA.")
    current = api(f"repos/{repo}/pulls/{number}")
    assert current["state"] == "open" and current["head"]["sha"] == head
    summary = {"fixture_manifest_sha256": sha256(body).hexdigest(),
               "score_report_sha256": report["score_report_sha256"], "candidate_sha": head}
    name = "trusted-private-holdout"
    check = api(f"repos/{repo}/check-runs", {
        "name": name, "head_sha": head, "status": "completed", "conclusion": verdict,
        "output": {"title": name, "summary": "Signed synthetic private holdout verdict",
                   "text": json.dumps(summary, sort_keys=True)},
    })
    assert check["app"]["id"] == 15368 and check["head_sha"] == head
    assert check["name"] == name and check["conclusion"] == verdict
    result = {**summary, "check_id": check["id"], "app_id": check["app"]["id"], "verdict": verdict,
              "pr_number": number, "workflow_commit": os.environ["GITHUB_SHA"]}
    output = Path("artifacts/scn10-holdout-result.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True)+"\n")
    print("SCN10_PUBLISHED_CHECK=" + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
