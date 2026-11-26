# SPDX-FileCopyrightText: 2026 boob.yang
"""Verify a synthetic holdout decision and return it as the native job result."""

from base64 import b64decode
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

REPO = "yangbobo2021/anthropic-sdlc-public-testbed"
BRANCH = "scn10-native-job-sandbox"


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    pr = event["pull_request"]
    head = pr["head"]["sha"]
    assert os.environ["GITHUB_REPOSITORY"] == pr["head"]["repo"]["full_name"] == REPO
    assert pr["base"]["ref"] == BRANCH and head == os.environ["PUBLISHED_HEAD"]
    assert os.environ["GITHUB_ACTOR"] == "yangbobo2021"
    base = subprocess.check_output(
        ["git", "-C", "sandbox", "rev-parse", "HEAD"], text=True
    ).strip()
    assert base == pr["base"]["sha"]
    main_head = subprocess.check_output(
        ["git", "-C", "published", "rev-parse", "HEAD"], text=True
    ).strip()
    root = Path("published/test-fixtures/scn10-native-job-verdict")
    manifest = root / "signed-verdict.json"
    if not manifest.is_file():
        raise SystemExit("No signed score report is published for this sandbox.")
    with TemporaryDirectory(prefix="scn10-verify-") as folder:
        signature = Path(folder) / "signature"
        signature.write_bytes(b64decode((root / "signed-verdict.sig.b64").read_bytes().strip(), validate=True))
        subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
             str(root / "fixture-ed25519.pub"), "-in", str(manifest), "-sigfile", str(signature)],
            check=True,
        )
    body = manifest.read_bytes()
    signed = json.loads(body)
    verdict = signed["verdicts"].get(head, "uncovered")
    assert signed["schema"] == 1 and signed["sandbox_base"] == base
    print("SCN10_NATIVE_DECISION=" + json.dumps({
        "pr": pr["number"], "scope": BRANCH, "candidate_sha": head, "base_sha": base,
        "checks_sha": os.environ["GITHUB_SHA"], "publisher_sha": main_head,
        "manifest_sha256": sha256(body).hexdigest(), "score_sha256": signed["score_report_sha256"],
        "decision": verdict,
    }, sort_keys=True), flush=True)
    if verdict != "success":
        raise SystemExit(f"Signed score verdict: {verdict}")


if __name__ == "__main__":
    main()
