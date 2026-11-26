from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

payload=Path("test-fixtures/staging-payload.json").read_bytes()
digest="sha256:"+sha256(payload).hexdigest()
runtime=Path(os.environ["RUNNER_TEMP"])/"sdlc-staging-probe"
runtime.mkdir(exist_ok=True)
mode=sys.argv[1]

def probe(port,path):
    with urlopen(f"http://127.0.0.1:{port}{path}",timeout=2) as response:
        return response.status

def serve(port,broken):
    class Endpoint(BaseHTTPRequestHandler):
        def do_GET(self):
            valid=self.path in {"/health","/feature"} and not (broken and self.path=="/feature")
            self.send_response(200 if valid else 503)
            self.end_headers()
            self.wfile.write(payload)
    ThreadingHTTPServer(("127.0.0.1",port),Endpoint).serve_forever()

def launch(broken,target):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0))
        port=listener.getsockname()[1]
    with (runtime/f"{target}-http.log").open("w") as log:
        process=subprocess.Popen([sys.executable,__file__,"serve",str(port),str(broken)],
            stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    for _ in range(30):
        try:
            if probe(port,"/health")==200:
                return port,process
        except URLError:
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError("The isolated application never became ready")

def main():
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["inputs"]
    if mode=="deploy":
        assert os.environ["RELEASE_DIGEST"]==digest and os.environ["RELEASE_SOURCE_SHA"]==os.environ["GITHUB_SHA"]
        port,_=launch(event["smoke_case"]=="broken","smoke")
        (runtime/"smoke-port").write_text(str(port))
    elif mode=="smoke":
        path="/health" if sys.argv[2]=="health" else "/feature"
        port=int((runtime/"smoke-port").read_text())
        try:
            assert probe(port,path)==200
        except URLError as problem:
            print(f"Isolated staging path {path} failed: {problem}",file=sys.stderr)
            sys.exit(1)
    elif mode=="report":
        policy=json.loads(Path(os.environ["SDLC_SCAN_APPROVAL"]).read_text())
        target=event["scan_target"]
        now=datetime.now(timezone.utc)
        if not (target=="staging" and policy["environment"]==target and policy["digest"]==digest and
                datetime.fromisoformat(policy["starts_at"]) <= now < datetime.fromisoformat(policy["expires_at"])):
            print("Staging security adapter denied target before starting a probe or contacting a service",file=sys.stderr)
            sys.exit(1)
        port, process=launch(False,"security")
        try:
            assert probe(port,"/health")==200 and probe(port,"/feature")==200
            print("Ran approved probes against an isolated loopback staging application",file=sys.stderr)
            result={key:policy[key] for key in ("environment","approval_id","scope_id","runner_identity","source_sha","digest")}
            result.update(completed_at=datetime.now(timezone.utc).isoformat(),report_ref="urn:sdlc:staging-health",
                          report_status="complete",findings=[])
            print(json.dumps(result))
        finally:
            process.terminate()
            process.wait(timeout=3)
    else:
        raise ValueError(mode)

if mode=="serve":
    serve(int(sys.argv[2]),sys.argv[3]=="True")
else:
    main()
