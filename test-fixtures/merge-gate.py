from pathlib import Path
import json
import os
import subprocess
import sys

event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
target=event["pull_request"]
head=target["head"]["sha"]
kind=target["head"]["ref"].removeprefix("codex/policy-gate-fixture-")
assert target["base"]["ref"]=="policy-sandbox"
assert kind in {"passed","timed-out","missing","neutral","old","unauthorized"}
policy=Path(".github/sdlc/merge-gate-fixture.json")
checks=[{"name":"build","sha":head,"producer":"trusted-build-app","state":"success","run_id":"synthetic-build"},
        {"name":"review-evidence","sha":head,"producer":"trusted-review-app","state":"success","run_id":"synthetic-review"}]
request={"sha":head,"author":"fixture-author","event":"pull_request","checks":checks,"findings_sha":head,
         "findings":[],"approvals":[{"sha":head,"actor_type":"human","actor":"maintainer"}]}
if kind in {"timed-out","neutral"}:
    checks[-1]["state"]=kind.replace("-","_")
elif kind=="missing":
    checks.pop()
elif kind=="old":
    checks[-1]["sha"]=target["base"]["sha"]
elif kind=="unauthorized":
    request["approvals"][0]["actor"]="outside-maintainer"
out=Path("artifacts")
out.mkdir(exist_ok=True)
evidence=out/"test-evidence.json"
evidence.write_text(json.dumps(request)+"\n")
process=subprocess.run([sys.executable,"scripts/sdlc/decision.py","review",str(policy),str(evidence)],capture_output=True,text=True)
decision=json.loads(process.stdout or process.stderr)
assert process.returncode==(0 if kind=="passed" else 1)
assert decision["decision"]==("allow" if kind=="passed" else "deny")
run_url=f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
payload={"name":"trusted-sdlc-policy","head_sha":head,"status":"completed",
         "conclusion":"success" if decision["decision"]=="allow" else "failure",
         "details_url":run_url,"external_id":f"policy-fixture:{head}",
         "output":{"title":f"Sandbox merge decision: {decision['decision']}","summary":json.dumps(decision)}}
native=json.loads(subprocess.check_output(["gh","api","-X","POST",f"repos/{os.environ['GITHUB_REPOSITORY']}/check-runs",
                 "--input","-"],input=json.dumps(payload),text=True))
report={"fixture_case":kind,"head":head,"base":target["base"]["sha"],"run_url":run_url,"proof":request,"result":decision,
        "check_run":{"id":native["id"],"head_sha":native["head_sha"],"conclusion":native["conclusion"],
                     "integration_id":native["app"]["id"],"app_slug":native["app"]["slug"]}}
(out/"merge-gate.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"case":kind,**report["check_run"]}))
