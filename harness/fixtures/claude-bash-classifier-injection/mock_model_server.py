#!/usr/bin/env python3
"""A14 (Bash LLM prefix-classifier prompt injection) harness의 verdict-aware mock.

CVE-2025-66032 mock과 달리 이 서버는 두 종류의 `/v1/messages` 요청을 구분한다:

1. **main-agent turn** — Claude Code가 한 번의 non-interactive turn을 돌릴 때 보내는
   요청. 고정된 `Bash` tool_use(케이스가 지정한 command 문자열)를 반환한다.
2. **bash-prefix classifier call** — Claude Code가 command를 auto-approve할지
   결정할 때, 코드 분류기(`A78`/`Rx`)가 too-complex로 넘긴 command를 haiku급 LLM에
   보내 "안전 prefix"를 추출하는 요청(`sr2`/`tengu_bash_prefix`). system prompt
   `Your task is to process Bash commands ...` 와 user prompt의
   `# Claude Code Code Bash command prefix detection` / `Command: <cmd>` 로 식별한다.

classifier 요청에 대한 응답이 이 하네스의 조작 변수다:

- ``--classifier-mode honest``  → 항상 ``command_injection_detected`` 반환
  (정직한 분류기 = 음성 대조군: injection을 올바로 잡음).
- ``--classifier-mode fooled``  → ``--fooled-prefix`` 로 준 benign prefix 중,
  현재 분류 대상 command의 실제 문자열 prefix인 가장 긴 것을 반환
  (프롬프트 인젝션에 속아 악성 tail을 무시하고 앞부분 benign 명령만 보고하는 분류기).
  어느 것도 prefix가 아니면 ``none`` 을 반환한다.

이 mock은 "분류기가 속았다고 **가정**했을 때" downstream 코드(`re2`의 `Rx`·`te2`
방어)가 전체 command를 실제로 auto-execute하는지를 결정론적으로 드러낸다. 분류기가
실제로 속는지(haiku 취약성)는 이 mock의 범위가 아니며 별도 empirical probe가 다룬다.
127.0.0.1에서만 listen한다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


CLASSIFIER_SYSTEM_MARK = "Your task is to process Bash commands"
CLASSIFIER_USER_MARK = "Bash command prefix detection"
COMMAND_LINE_RE = re.compile(r"(?:^|\n)Command:\s*(.*)\s*$", re.DOTALL)


def sse_event(event: str, data: dict) -> bytes:
    payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    return payload.encode("utf-8")


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def _collect_text(content) -> str:
    """Anthropic Messages 요청 body의 system/user content를 평문으로 이어붙인다."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return ""


def request_text(body: dict) -> str:
    system_text = _collect_text(body.get("system"))
    user_text_parts = []
    for message in body.get("messages", []) or []:
        if isinstance(message, dict):
            user_text_parts.append(_collect_text(message.get("content")))
    return system_text + "\n" + "\n".join(user_text_parts)


def is_classifier_request(body: dict) -> bool:
    text = request_text(body)
    return CLASSIFIER_SYSTEM_MARK in text or CLASSIFIER_USER_MARK in text


def extract_command(body: dict) -> str | None:
    text = request_text(body)
    match = COMMAND_LINE_RE.search(text)
    if not match:
        return None
    return match.group(1).strip()


def classifier_verdict(command: str | None, mode: str, fooled_prefixes: list[str]) -> str:
    if mode == "honest":
        return "command_injection_detected"
    # fooled: 악성 tail을 무시하고 실제 문자열 prefix인 가장 긴 benign prefix를 보고.
    if command is None:
        return "none"
    candidates = [p for p in fooled_prefixes if command.startswith(p)]
    if not candidates:
        return "none"
    return max(candidates, key=len)


class MockHandler(BaseHTTPRequestHandler):
    server_version = "HunmaMockAnthropicA14/1"
    lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write("mock-a14: " + (format % args) + "\n")

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
        classifier = is_classifier_request(body)
        with MockHandler.lock:
            self.server.call_count += 1
            if classifier:
                self.server.classifier_call_count += 1
            else:
                self.server.agent_call_count += 1
            agent_index = self.server.agent_call_count

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

        if classifier:
            command = extract_command(body)
            verdict = classifier_verdict(
                command, self.server.classifier_mode, self.server.fooled_prefixes
            )
            with MockHandler.lock:
                self.server.classifier_log.append({"command": command, "verdict": verdict})
            self._emit_text(send, verdict)
        elif agent_index == 1:
            self._emit_tool_use(send)
        else:
            self._emit_text(send, "hunma-a14-done")

        send("message_stop", {"type": "message_stop"})
        self.wfile.write(b"0\r\n\r\n")

    def _emit_tool_use(self, send) -> None:
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

    def _emit_text(self, send, text: str) -> None:
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
                "delta": {"type": "text_delta", "text": text},
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


def serve(
    port: int,
    tool_name: str,
    tool_input: dict,
    classifier_mode: str,
    fooled_prefixes: list[str],
) -> HTTPServer:
    httpd = HTTPServer(("127.0.0.1", port), MockHandler)
    httpd.call_count = 0
    httpd.agent_call_count = 0
    httpd.classifier_call_count = 0
    httpd.tool_name = tool_name
    httpd.tool_input = tool_input
    httpd.classifier_mode = classifier_mode
    httpd.fooled_prefixes = fooled_prefixes
    httpd.classifier_log = []
    return httpd


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tool-name", default="Bash")
    parser.add_argument("--tool-input-json", required=True)
    parser.add_argument("--classifier-mode", choices=("honest", "fooled"), default="honest")
    parser.add_argument("--fooled-prefix", action="append", default=[])
    args = parser.parse_args()

    server = serve(
        args.port,
        args.tool_name,
        json.loads(args.tool_input_json),
        args.classifier_mode,
        args.fooled_prefix,
    )
    server.serve_forever()
