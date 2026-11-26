# SPDX-FileCopyrightText: 2026 boob.yang
"""Deploy an approved digest and attest project smoke outcomes in a staging runner."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

from decision import identifier, require
from practices import staging


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("digest")
    parser.add_argument("sha")
    parser.add_argument("run_id")
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    identifier(args.digest, r"sha256:[0-9a-f]{64}", "artifact digest")
    identifier(args.sha, r"[0-9a-f]{40}", "source commit")
    require(policy["environment"] == "staging" and policy["required_smokes"] and args.run_id,
            "missing staging policy")
    names = policy["required_smokes"]
    for name in names:
        identifier(name, r"[a-z][a-z0-9-]{0,60}", "smoke name")
    bindings = [f"RELEASE_DIGEST={args.digest}", f"RELEASE_SOURCE_SHA={args.sha}"]
    subprocess.run(["make", "staging-deploy", *bindings], stdout=sys.stderr, check=True)
    outcomes = []
    for name in names:
        status = subprocess.run(["make", f"smoke-{name}", *bindings], stdout=sys.stderr, check=False).returncode
        outcomes.append({"name": name, "status": "passed" if status == 0 else "failed"})
    completed = datetime.now(timezone.utc)
    packet = {"digest": args.digest, "source_sha": args.sha, "run_id": args.run_id,
              "environment": policy["environment"], "runner_identity": policy["runner_identity"],
              "completed_at": completed.isoformat(), "results": outcomes}
    receipt = staging(packet, policy, completed)
    print(json.dumps(receipt))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
