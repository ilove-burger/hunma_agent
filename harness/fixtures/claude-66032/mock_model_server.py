#!/usr/bin/env python3
"""CVE-2025-66032 harness의 loopback-only mock Anthropic Messages API server.

첫 `/v1/messages` 요청에는 고정된 `Bash` tool_use를 반환하고, 두 번째 요청부터는
평문 종료 응답을 반환한다. 실제 model inference 대신 deterministic tool call만
제공해 harness/README.md의 marker-only 원칙을 유지한다. 127.0.0.1에서만 listen한다.
"""

from __future__ import annotations

import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


def sse_event(event: str, data: dict) -> bytes:
    payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    return payload.encode("utf-8")


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


class MockHandler(BaseHTTPRequestHandler):
    server_version = "HunmaMockAnthropic/1"
    call_count_lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write("mock-model-server: " + (format % args) + "\n")

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body_raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(body_raw or b"{}")
        except json.JSONDecodeError:
            body = {}

        if self.path.startswith("/v1/messages"):
            self.handle_messages(body)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def handle_messages(self, body: dict) -> None:
        with MockHandler.call_count_lock:
            self.server.call_count += 1
            call_index = self.server.call_count

        model = body.get("model", "claude-mock")
        message_id = f"msg_hunma_{uuid.uuid4().hex[:16]}"

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def send(event: str, data: dict) -> None:
            self.wfile.write(chunk(sse_event(event, data)))

        send(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 0},
                },
            },
        )

        if call_index == 1:
            tool_use_id = f"toolu_hunma_{uuid.uuid4().hex[:16]}"
            send(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": tool_use_id,
                        "name": self.server.tool_name,
                        "input": {},
                    },
                },
            )
            send(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(self.server.tool_input),
                    },
                },
            )
            send("content_block_stop", {"type": "content_block_stop", "index": 0})
            send(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                    "usage": {"output_tokens": 8},
                },
            )
        else:
            send(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            )
            send(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "hunma-mock-done"},
                },
            )
            send("content_block_stop", {"type": "content_block_stop", "index": 0})
            send(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 2},
                },
            )

        send("message_stop", {"type": "message_stop"})
        self.wfile.write(b"0\r\n\r\n")


def serve(port: int, tool_name: str, tool_input: dict) -> HTTPServer:
    httpd = HTTPServer(("127.0.0.1", port), MockHandler)
    httpd.call_count = 0
    httpd.tool_name = tool_name
    httpd.tool_input = tool_input
    return httpd


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tool-name", default="Bash")
    parser.add_argument("--tool-input-json", required=True)
    args = parser.parse_args()

    server = serve(args.port, args.tool_name, json.loads(args.tool_input_json))
    server.serve_forever()
