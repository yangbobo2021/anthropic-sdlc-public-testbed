# SPDX-FileCopyrightText: 2026 boob.yang
"""Run a reviewer against a frozen, versioned corpus and measure regressions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def score(cases, command, cwd, image=None):
    if image:
        command = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "512m",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--mount",
                   f"type=bind,source={cwd.resolve()},destination=/work,readonly", "--workdir", "/work",
                   "--user", "65534:65534", image, *command]
    misses = wrong = 0
    for case in cases:
        query = {"input": case["input"], "evidence_type": case["evidence_type"]}
        process = subprocess.run(command, cwd=cwd, input=json.dumps(query), capture_output=True, text=True,
                                 check=True, timeout=120)
        reported = json.loads(process.stdout)["findings"]
        if not isinstance(reported, list) or not all(isinstance(value, str) for value in reported):
            raise ValueError("reviewer must return a string list of findings")
        actual, expected = set(reported), set(case["findings"])
        misses += len(expected - actual)
        wrong += len(actual - expected)
    return {"misses": misses, "false_positives": wrong}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--candidate", type=Path, default=Path("."))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--isolate-image", help="Pinned reviewer image for untrusted candidates")
    parser.add_argument("command", nargs="+")
    args = parser.parse_intermixed_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        raw = args.corpus.read_bytes()
        cases = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if (len({case["case_id"] for case in cases}) != len(cases) or
                sum(bool(case["findings"]) for case in cases) < 2 or all(case["findings"] for case in cases)):
            raise ValueError("incomplete frozen corpus")
        if args.isolate_image and "@sha256:" not in args.isolate_image:
            raise ValueError("reviewer image must be pinned to a digest")
        baseline = score(cases, command, args.baseline, args.isolate_image) if args.baseline else None
        candidate = score(cases, command, args.candidate, args.isolate_image)
        passed = not any(candidate.values()) if baseline is None else all(
            candidate[key] <= baseline[key] for key in candidate)
        print(json.dumps({"passed": passed, "cases": len(cases), "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                          "candidate": candidate, "baseline": baseline}))
        return 0 if passed else 1
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        print("Evaluation case or reviewer output is invalid.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
