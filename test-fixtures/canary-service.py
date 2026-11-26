from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path

digest=os.environ["FIXTURE_DIGEST"]
fail_every=int(os.environ["FIXTURE_FAIL_EVERY"])
class Handler(BaseHTTPRequestHandler):
    requests=0
    def do_GET(self):
        if self.path!="/health":
            Handler.requests+=1
        error=self.path!="/health" and fail_every and Handler.requests%fail_every==0
        self.send_response(503 if error else 200)
        self.send_header("X-Artifact-Digest",digest)
        self.end_headers()
        self.wfile.write(b"unavailable" if error else b"healthy")
    def log_message(self,*_):
        pass
server=HTTPServer(("127.0.0.1",0),Handler)
Path(os.environ["FIXTURE_PORT_FILE"]).write_text(str(server.server_port))
server.serve_forever()
