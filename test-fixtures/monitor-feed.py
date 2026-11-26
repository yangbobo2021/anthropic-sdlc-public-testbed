from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys

kind = sys.argv[1]
root = Path(__file__).resolve().parents[1]
feed = json.loads((root / f"examples/monitor-{kind}.json").read_text())
event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
mode = event.get("client_payload", {}).get("case", "current")
assert mode in {"current", "unmatched", "stale"}
now = datetime.now(timezone.utc)
feed["collected_at"] = (now - timedelta(hours=2) if mode == "stale" else now).isoformat()
if kind == "dependency":
    feed["inventory"].append({"package":"fixture-library","version":"2.0","service":"modern","owner":"modern-owner"})
    if mode == "unmatched":
        feed["alerts"][0]["version"] = "not-deployed"
elif kind == "container":
    feed["inventory"].append({"running_digest":"sha256:" + "3"*64,"service":"current","owner":"current-owner"})
    feed["alerts"][0]["severity"] = "critical"
    if mode == "unmatched":
        feed["alerts"][0]["running_digest"] = "sha256:" + "4"*64
elif kind == "secret" and mode == "unmatched":
    feed["alerts"] = []
elif kind == "cloud" and mode == "unmatched":
    feed["assets"][0]["settings"]["public_access"] = False
print(json.dumps(feed))
