# SPDX-FileCopyrightText: 2026 boob.yang
"""Run a project-owned validation command and bind its result to the current diff."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def git(root, *args, env=None):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL, env=env)


def fingerprint(root):
    head = git(root, "rev-parse", "HEAD").strip()
    with tempfile.TemporaryDirectory(prefix="sdlc-index-") as scratch:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(scratch) / "index")}
        git(root, "read-tree", head.decode(), env=env)
        git(root, "add", "-A", env=env)
        tree = git(root, "write-tree", env=env).strip()
    return head.decode(), hashlib.sha256(head + b"\x00" + tree).hexdigest()


def configured_command(root):
    command = json.loads(git(root, "config", "--local", "--get", "sdlc.verifyCommand"))
    if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("sdlc.verifyCommand must be a JSON argument array")
    return command


def index_matches(root, head, state):
    tree = git(root, "write-tree").strip()
    staged = hashlib.sha256(head.encode() + b"\x00" + tree).hexdigest()
    return staged == state and not git(root, "ls-files", "--", ".sdlc")


def write_receipt(path, document):
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("verification artifacts cannot use symlinked paths")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".verify-", delete=False, mode="w", encoding="utf-8") as out:
        tmp = Path(out.name)
        json.dump(document, out, indent=2)
        out.write("\n")
    try:
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def receipt_path(root, task=None):
    if task is not None and not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", task):
        raise ValueError("invalid task ID")
    path = root / ".sdlc" / (f"task-{task}.json" if task else "verify.json")
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("verification artifacts cannot use symlinked paths")
    return path


def valid_receipt(root, *, task=None, index=False):
    command = configured_command(root)
    report = json.loads(receipt_path(root, task).read_text())
    head, state = fingerprint(root)
    return (report["status"] == "passed" and report["head"] == head and
            report["diff_sha256"] == state and report["command_sha256"] == command_digest(command) and
            report.get("task_id") == task and (not index or index_matches(root, head, state)))


def command_digest(command):
    return hashlib.sha256(json.dumps(command).encode()).hexdigest()


def ignore_receipts(root):
    receipt_path(root)
    excludes = git(root, "rev-parse", "--git-path", "info/exclude").decode().strip()
    path = root / excludes
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as stream:
        stream.seek(0)
        if "/.sdlc/" not in stream.read().splitlines():
            stream.write("\n/.sdlc/\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "check"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--task", help="Write or verify the receipt for this Claude task")
    parser.add_argument("--index", action="store_true", help="Require Git index and verified worktree to agree")
    args = parser.parse_args()
    try:
        cwd = Path(args.root).resolve()
        root = Path(git(cwd, "rev-parse", "--show-toplevel").decode().strip())
        target = receipt_path(root, args.task)
        if args.mode == "check":
            return 0 if valid_receipt(root, task=args.task, index=args.index) else 1
        target.unlink(missing_ok=True)
        ignore_receipts(root)
        command = configured_command(root)
        head, before = fingerprint(root)
        result = subprocess.run(command, cwd=root, check=False, timeout=args.timeout)
        stable = fingerprint(root) == (head, before) and configured_command(root) == command
        passed = result.returncode == 0 and stable and (not args.index or index_matches(root, head, before))
        write_receipt(target, {
            "head": head, "diff_sha256": before, "command_sha256": command_digest(command),
            "task_id": args.task, "status": "passed" if passed else "failed",
            "return_code": result.returncode, "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"verification evidence unavailable: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
