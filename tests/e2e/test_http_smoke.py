# SPDX-FileCopyrightText: 2026 boob.yang
"""Start the project's E2E service and verify the live health endpoint."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, default=Path("artifacts/e2e.json"))
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply the project's service command after --")
    checks = json.loads(args.scenario.read_text())["checks"]
    if not checks or not all(item["path"].startswith("/") and item["path"] != "/health" for item in checks):
        parser.error("scenario requires a critical path distinct from readiness")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = str(sock.getsockname()[1])
    trace = {"source_sha": os.environ.get("GITHUB_SHA"), "readiness_endpoint": "/health", "steps": [], "passed": False}
    args.trace.parent.mkdir(parents=True, exist_ok=True)
    opener = build_opener(ProxyHandler({}))
    with args.trace.with_suffix(".log").open("w") as service_log:
        process = subprocess.Popen(command, env={**os.environ, "HOST": "127.0.0.1", "PORT": port},
                                   stdout=service_log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                        trace["status"] = response.status
                        trace["ready"] = response.status == 200
                        break
                except OSError:
                    time.sleep(0.15)
            if trace.get("ready"):
                for item in checks:
                    status = None
                    try:
                        with opener.open(f"http://127.0.0.1:{port}{item['path']}", timeout=3) as response:
                            status = response.status
                    except HTTPError as error:
                        status = error.code
                    except OSError:
                        pass
                    trace["steps"].append({"path": item["path"], "status": status, "passed": status == item["status"]})
                trace["passed"] = all(step["passed"] for step in trace["steps"])
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            args.trace.write_text(json.dumps(trace) + "\n")
    return 0 if trace["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
