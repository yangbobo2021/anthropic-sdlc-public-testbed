# SPDX-FileCopyrightText: 2026 boob.yang
from pathlib import Path
import hashlib
import json
import os
import sys

path = Path(sys.argv[1])
with path.open("rb") as artifact:
    digest = hashlib.file_digest(artifact, "sha256").hexdigest()
document = {"file": path.name, "source_sha": os.environ["GITHUB_SHA"],
            "digest": "sha256:" + digest, "build_run": os.environ["GITHUB_RUN_ID"],
            "build_workflow": os.environ["GITHUB_WORKFLOW_REF"]}
path.with_name("receipt.json").write_text(json.dumps(document, indent=2) + "\n")
