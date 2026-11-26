from datetime import datetime, timezone
from hashlib import sha256
import json
from math import ceil
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

root=Path(os.environ["RUNNER_TEMP"])/"sdlc-canary-fixture"
root.mkdir(exist_ok=True)
state_file=root/"state.json"
state=json.loads(state_file.read_text()) if state_file.exists() else {}
digest=os.environ["RELEASE_DIGEST"]
service=Path(__file__).with_name("canary-service.py")
stable="sha256:"+sha256(b"stable synthetic fixture release previously deployed").hexdigest()
case=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["inputs"]["case"]
policy=json.loads(Path(".github/sdlc/canary-policy.json").read_text())

def http(port,path):
    start=time.monotonic()
    try:
        response=urlopen(f"http://127.0.0.1:{port}{path}",timeout=2)
    except HTTPError as error:
        response=error
    with response:
        return response.status,response.headers["X-Artifact-Digest"],(time.monotonic()-start)*1000

def start(name,selected_digest,fail_every):
    port_file=root/f"{name}-port.txt"
    env={**os.environ,"FIXTURE_PORT_FILE":str(port_file),"FIXTURE_DIGEST":selected_digest,
         "FIXTURE_FAIL_EVERY":str(fail_every)}
    process=subprocess.Popen([sys.executable,str(service)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,start_new_session=True,env=env)
    for _ in range(45):
        try:
            port=int(port_file.read_text())
            if http(port,"/health")[:2]==(200,selected_digest):
                return {"port":port,"pid":process.pid,"digest":selected_digest}
        except (OSError,URLError,ValueError):
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError("isolated server did not start")

def measure(cohort,samples):
    responses=[http(cohort["port"],"/") for _ in range(samples)]
    assert all(d==cohort["digest"] for _,d,_ in responses)
    latency=sorted(t for _,_,t in responses)
    return {"requests":samples,"errors":sum(s>=500 for s,_,_ in responses),"p95_ms":round(latency[ceil(samples*.95)-1],3)}

mode=sys.argv[1]
if mode=="verify-promotion":
    assert digest=="sha256:"+sha256(service.read_bytes()).hexdigest()
    state={"bound_digest":digest,"rollout":0}
elif mode=="deploy":
    assert state["bound_digest"]==digest
    state["stable"]=start("stable",stable,0)
    state["candidate"]=start("candidate",digest,10 if case=="high-error" else 0)
    state["rollout"]=10
    print("isolated sandbox candidate traffic 10%")
elif mode=="observe":
    assert state["rollout"]==10
    before=datetime.now(timezone.utc)
    then=time.monotonic()
    control=measure(state["stable"],120)
    observations=measure(state["candidate"],20 if case=="short-sample" else 120)
    time.sleep(max(0,policy["min_seconds"]+0.1-(time.monotonic()-then)))
    after=datetime.now(timezone.utc)
    print(json.dumps({"digest":digest,"producer":"fixture-metrics","started_at":before.isoformat(),
        "completed_at":after.isoformat(),"observations":observations,"control":control}))
elif mode=="advance":
    assert state["rollout"]==10 and http(state["candidate"]["port"],"/health")[:2]==(200,digest)
    state["rollout"]=100
    print("isolated sandbox advanced to 100% and candidate health returned HTTP 200")
elif mode=="rollback":
    if state.get("candidate"):
        os.kill(state["candidate"]["pid"],signal.SIGTERM)
    if state.get("stable"):
        assert http(state["stable"]["port"],"/health")[:2]==(200,stable)
    state["rollout"]=0
    print("isolated sandbox rolled back to 0% and stable health returned HTTP 200")
else:
    raise ValueError(mode)
state_file.write_text(json.dumps(state)+"\n")
