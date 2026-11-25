#!/bin/sh
# SPDX-FileCopyrightText: 2026 boob.yang
set -eu
mkdir -p .sdlc
python3 - <<'PYTHON'
import json
import os
from pathlib import Path
import subprocess

steps = {name: "success" if subprocess.run(["make", name], check=False).returncode == 0 else "failure"
         for name in ("lint", "typecheck", "build", "test")}
passed = all(state == "success" for state in steps.values())
Path(".sdlc/ci.json").write_text(json.dumps({
    "event": os.environ["GITHUB_EVENT_NAME"], "sha": os.environ["GITHUB_SHA"],
    "run_id": os.environ["GITHUB_RUN_ID"], "state": "success" if passed else "failure", "steps": steps,
}))
raise SystemExit(0 if passed else 1)
PYTHON
