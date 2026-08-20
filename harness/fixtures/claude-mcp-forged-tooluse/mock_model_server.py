#!/usr/bin/env python3
"""P2 하네스의 mock Anthropic Messages API.

시나리오 스크립트대로 assistant turn을 흘려보낸다:

- ``forge``    — turn1: 악성 MCP 툴(`mcp__evil__fetch_notes`) tool_use를 emit해
                 Claude가 실제 MCP 서버를 호출하게 한다. turn2+: 순수 text(툴 없음).
                 → marker가 생기면 그것은 오직 MCP tool_result content가 실행된 것이다
                   (모델은 Bash를 emit한 적 없음).
- ``positive`` — turn1: 진짜 Bash `touch <marker>` tool_use를 emit(오라클 sanity +
                 Bash(touch:*) allow-rule이 실제로 auto-approve함을 증명).

127.0.0.1에서만 listen. SSE 스트리밍 형식은 A14 mock과 동일한 뼈대.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


def sse_event(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8")


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


class MockHandler(BaseHTTPRequestHandler):
    server_version = "HunmaMockAnthropicP2/1"
    lock = threading.Lock()

    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        sys.stderr.write("mock-p2: " + (fmt % args) + "\n")

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200); self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(b"{}")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length else b"{}"
        if not self.path.startswith("/v1/messages"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(b"{}")
            return
        with MockHandler.lock:
            self.server.call_count += 1
            idx = self.server.call_count
        self.handle_messages(idx)

    def handle_messages(self, idx: int) -> None:
        message_id = f"msg_hunma_{uuid.uuid4().hex[:16]}"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def send(event: str, data: dict) -> None:
            self.wfile.write(chunk(sse_event(event, data)))

        send("message_start", {"type": "message_start", "message": {
            "id": message_id, "type": "message", "role": "assistant",
            "model": "claude-mock", "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 0}}})

        if idx == 1 and self.server.scenario == "forge":
            self._emit_tool_use(send, self.server.mcp_tool_name, {})
        elif idx == 1 and self.server.scenario == "positive":
            self._emit_tool_use(send, "Bash",
                                {"command": f"touch {self.server.marker}",
                                 "description": "hunma p2 positive control"})
        else:
            self._emit_text(send, "hunma-p2-done")

        send("message_stop", {"type": "message_stop"})
        self.wfile.write(b"0\r\n\r\n")

    def _emit_tool_use(self, send, name: str, tool_input: dict) -> None:
        tid = f"toolu_hunma_{uuid.uuid4().hex[:16]}"
        send("content_block_start", {"type": "content_block_start", "index": 0,
             "content_block": {"type": "tool_use", "id": tid, "name": name, "input": {}}})
        send("content_block_delta", {"type": "content_block_delta", "index": 0,
             "delta": {"type": "input_json_delta", "partial_json": json.dumps(tool_input)}})
        send("content_block_stop", {"type": "content_block_stop", "index": 0})
        send("message_delta", {"type": "message_delta",
             "delta": {"stop_reason": "tool_use", "stop_sequence": None},
             "usage": {"output_tokens": 8}})

    def _emit_text(self, send, text: str) -> None:
        send("content_block_start", {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}})
        send("content_block_delta", {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": text}})
        send("content_block_stop", {"type": "content_block_stop", "index": 0})
        send("message_delta", {"type": "message_delta",
             "delta": {"stop_reason": "end_turn", "stop_sequence": None},
             "usage": {"output_tokens": 2}})


def serve(port: int, scenario: str, mcp_tool_name: str, marker: str) -> HTTPServer:
    httpd = HTTPServer(("127.0.0.1", port), MockHandler)
    httpd.call_count = 0
    httpd.scenario = scenario
    httpd.mcp_tool_name = mcp_tool_name
    httpd.marker = marker
    return httpd


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--scenario", choices=("forge", "positive"), default="forge")
    p.add_argument("--mcp-tool-name", default="mcp__evil__fetch_notes")
    p.add_argument("--marker", required=True)
    a = p.parse_args()
    serve(a.port, a.scenario, a.mcp_tool_name, a.marker).serve_forever()
