# SPDX-FileCopyrightText: 2026 boob.yang
"""Demonstration read-only MCP server scoped to the launching OS account."""
import json
from pathlib import Path
import sys

KB = Path(__file__).with_name("approved-knowledge.json")


def result(method, params):
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "approved-knowledge", "version": "1.0.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [{"name": "read_article", "description": "Read an approved knowledge record",
                           "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}},
                                           "required": ["id"], "additionalProperties": False}}]}
    if method == "tools/call" and params.get("name") == "read_article":
        article = json.loads(KB.read_text()).get(params["arguments"]["id"])
        if article is not None:
            return {"content": [{"type": "text", "text": json.dumps(article, ensure_ascii=False)}]}
    raise ValueError("operation or article is outside the read-only grant")


for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    response = {"jsonrpc": "2.0", "id": message["id"]}
    try:
        response["result"] = result(message["method"], message.get("params", {}))
    except (KeyError, TypeError, ValueError, OSError):
        response["error"] = {"code": -32602, "message": "operation denied"}
    print(json.dumps(response), flush=True)
