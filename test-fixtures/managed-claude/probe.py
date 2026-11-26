from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread

out=Path("artifacts/managed-claude").resolve()
out.mkdir(parents=True,exist_ok=True)
fixture_sha=os.environ["GITHUB_SHA"]
cli=subprocess.check_output(["claude","--version"],text=True).strip()

def emit(path,data):
    path.write_text(json.dumps(data,indent=2)+"\n")

def hash(path):
    return sha256(path.read_bytes()).hexdigest()

def run_write(workspace,target,baseline_only=False):
    marker=workspace/"project-hook-executed"
    calls=[]
    class AnthropicFixture(BaseHTTPRequestHandler):
        def log_message(self,*_):
            pass
        def do_POST(self):
            req=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            results=[part for msg in req.get("messages",[]) for part in msg["content"]
                     if isinstance(part,dict) and part.get("type")=="tool_result"]
            finish=bool(results)
            calls.append({"path":self.path,"tool_result_received":finish})
            if self.path.endswith("/count_tokens"):
                payload=b'{"input_tokens":100}'
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.end_headers()
                self.wfile.write(payload)
                return
            tool={"type":"tool_use","id":"toolu_managed_write","name":"Write","input":{"file_path":str(target),"content":"synthetic fixture write\n"}}
            content={"type":"text","text":"Synthetic native Write returned."} if finish else tool
            common={"id":"msg_fixture_final" if finish else "msg_fixture_call","type":"message","role":"assistant",
              "model":req.get("model","claude-sonnet-4-6"),"content":[],"stop_reason":None,"stop_sequence":None,
              "usage":{"input_tokens":100,"output_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}
            stop="end_turn" if finish else "tool_use"
            if not req.get("stream"):
                payload=json.dumps({**common,"content":[content],"stop_reason":stop}).encode()
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.end_headers()
                self.wfile.write(payload)
                return
            events=[{"type":"message_start","message":common}]
            if finish:
                events += [{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}},
                           {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":content["text"]}}]
            else:
                events += [{"type":"content_block_start","index":0,"content_block":{**tool,"input":{}}},
                           {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":json.dumps(tool["input"])}}]
            events.extend([{"type":"content_block_stop","index":0},{"type":"message_delta","delta":{"stop_reason":stop,"stop_sequence":None},
                          "usage":{"output_tokens":8}},{"type":"message_stop"}])
            self.send_response(200)
            self.send_header("Content-Type","text/event-stream")
            self.end_headers()
            for event in events:
                self.wfile.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())
    server=ThreadingHTTPServer(("127.0.0.1",0),AnthropicFixture)
    thread=Thread(target=server.serve_forever,daemon=True)
    thread.start()
    env={**os.environ,"ANTHROPIC_BASE_URL":f"http://127.0.0.1:{server.server_port}",
         "ANTHROPIC_AUTH_TOKEN":"synthetic-test-only","CLAUDE_CONFIG_DIR":str(workspace/"config"),
         "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1","CLAUDE_CODE_DISABLE_AUTO_MEMORY":"1","DISABLE_TELEMETRY":"1"}
    args=["claude","-p","--model","claude-sonnet-4-6","--setting-sources","user,project",
          "--permission-mode","dontAsk","--no-session-persistence","--tools","Write","--allowedTools","Write",
          "--max-turns","3","--output-format","stream-json","--verbose","--","Fixture: target write."]
    try:
        raw=subprocess.run(args,cwd=workspace,env=env,capture_output=True,text=True,timeout=85)
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
    events=[json.loads(line) for line in raw.stdout.splitlines() if line.startswith("{")]
    seen=[item for event in events for item in (event.get("message") or {}).get("content",[])
          if isinstance(item,dict) and item.get("type") in {"tool_use","tool_result"}]
    report={"client":cli,"fixture_sha":fixture_sha,"workspace":workspace.name,"target":str(target.relative_to(workspace)),
            "exit":raw.returncode,"stderr":raw.stderr,"observed_tool_events":seen,
            "calls":calls,"managed_file_sha256":hash(Path("/etc/claude-code/managed-settings.json")),
            "target_written":target.exists(),"project_hook_ran":marker.exists()}
    emit(out/(workspace.name+"-"+target.name+".json"),report)
    assert any(event.get("name")=="Write" for event in seen) and any(event.get("type")=="tool_result" for event in seen),report
    return report

def setup(parent,name,competing):
    work=parent/name
    for area in ("src","docs",".claude","config"):
        (work/area).mkdir(parents=True)
    subprocess.run(["git","init","-q",str(work)],check=True)
    if competing:
        command=f"printf unused > {work/'project-hook-executed'}"
        emit(work/".claude/settings.json",{"disableAllHooks":True,"allowManagedHooksOnly":False,
            "hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":command}]}]}})
    return work

with TemporaryDirectory(prefix="sdlc-managed-") as name:
    parent=Path(name)
    ordinary=setup(parent,"trusted-fixture",False)
    competing=setup(parent,"candidate-settings-fixture",True)
    for workspace in (ordinary,competing):
        allow=run_write(workspace,workspace/"src"/"allowed.txt")
        deny=run_write(workspace,workspace/"docs"/"denied.txt")
        assert allow["target_written"] and not deny["target_written"]
        assert not allow["project_hook_ran"] and not deny["project_hook_ran"]
        assert any("Managed write scope denied" in str(event) for event in deny["observed_tool_events"]),deny

    hook="/opt/company/sdlc/managed_write_scope.py"
    subprocess.run(["sudo","mv",hook,hook+".missing"],check=True)
    try:
        missing=run_write(ordinary,ordinary/"src"/"missing.txt")
        assert not missing["target_written"],missing
    finally:
        subprocess.run(["sudo","mv",hook+".missing",hook],check=True)

    conf=competing/"config"
    emit(competing/".mcp.json",{"mcpServers":{"unapproved-fixture":{"command":"/usr/bin/python3","args":["-c",
          f"from pathlib import Path; Path({str(competing/'unapproved-launched')!r}).touch()"]}}})
    raw=subprocess.run(["claude","mcp","list"],cwd=competing,env={**os.environ,"CLAUDE_CONFIG_DIR":str(conf),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1"},capture_output=True,text=True,timeout=45)
    emit(out/"mcp-list.json",{"client":cli,"fixture_sha":fixture_sha,"stdout":raw.stdout,"stderr":raw.stderr,"exit":raw.returncode,
         "unapproved_launched":(competing/"unapproved-launched").exists(),"managed_mcp_sha256":hash(Path("/etc/claude-code/managed-mcp.json"))})
    assert raw.returncode==0 and "approved-knowledge" in raw.stdout and "unapproved-fixture" not in raw.stdout
    assert not (competing/"unapproved-launched").exists()

service=Path("/opt/company/sdlc/knowledge_mcp.py")
knowledge=json.loads(service.with_name("approved-knowledge.json").read_text())
operations=[
 {"method":"initialize","params":{}},
 {"method":"tools/call","params":{"name":"read_article","arguments":{"id":next(iter(knowledge))}}},
 {"method":"tools/call","params":{"name":"read_article","arguments":{"id":"outside-allowlist"}}},
 {"method":"tools/call","params":{"name":"write_article","arguments":{"id":"outside-allowlist"}}},
]
requests=[{"jsonrpc":"2.0","id":idx,**item} for idx,item in enumerate(operations,start=1)]
raw=subprocess.run(["/usr/bin/python3",str(service)],input="".join(json.dumps(x)+"\n" for x in requests),
                   capture_output=True,text=True,check=True,timeout=15)
responses=[json.loads(line) for line in raw.stdout.splitlines()]
assert "result" in responses[1] and [x["error"]["code"] for x in responses[2:]]==[-32602,-32602]
emit(out/"mcp-server.json",{"service_sha":hash(service),"operations":operations,"responses":responses,
                            "recorded_at":datetime.now(timezone.utc).isoformat(),"fixture_sha":fixture_sha})
