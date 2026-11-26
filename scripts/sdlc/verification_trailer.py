# SPDX-FileCopyrightText: 2026 boob.yang
"""Record a local verification stamp in a real Git commit message."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from verify_work import git, valid_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("message", type=Path)
parser.add_argument("receipt", type=Path)
args = parser.parse_args()
try:
    root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
    if args.receipt.resolve() != (root / ".sdlc/verify.json").resolve() or not valid_receipt(root, index=True):
        raise ValueError("receipt is not current for the commit")
    receipt = json.loads(args.receipt.read_text())
    status = receipt["status"]
    digest = receipt["diff_sha256"]
    if status not in {"passed", "failed"} or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid verification stamp")
except (OSError, TypeError, ValueError, KeyError, subprocess.SubprocessError):
    status, digest = "none", None
trailers = [f"Verification-Status: {status}"]
trailers.append(f"Verification-Diff-SHA256: {digest or 'none'}")
command = ["git", "interpret-trailers", "--in-place", "--if-exists=replace"]
for trailer in trailers:
    command.extend(("--trailer", trailer))
subprocess.run([*command, "--", str(args.message)], check=True)
