# SPDX-FileCopyrightText: 2026 boob.yang
"""Allow project writes under the organization's approved source roots."""
import json
import subprocess
from pathlib import Path
import sys

try:
    event = json.load(sys.stdin)
    root = Path(subprocess.check_output(["git", "-C", event["cwd"], "rev-parse", "--show-toplevel"],
                                        text=True, stderr=subprocess.DEVNULL).strip()).resolve(strict=True)
    key = "notebook_path" if event.get("tool_name") == "NotebookEdit" else "file_path"
    cwd = Path(event["cwd"]).resolve(strict=True)
    target = (cwd / event["tool_input"][key]).resolve()
    relative = target.relative_to(root)
    if not relative.parts or relative.parts[0] not in {"src", "tests"}:
        raise ValueError("outside managed write scope")
except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
    print("Managed write scope denied the path.", file=sys.stderr)
    sys.exit(2)
