"""Small service for isolated acceptance exercises."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


def response(path: str) -> tuple[int, str]:
    if path == "/health":
        return 503, "unhealthy synthetic change"
    if path == "/":
        return 200, "acceptance service"
    return 404, "not found"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status, body = response(self.path)
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == "__main__":
    HTTPServer((os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
