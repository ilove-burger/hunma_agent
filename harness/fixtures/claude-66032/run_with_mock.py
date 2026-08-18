#!/usr/bin/env python3
"""CVE-2025-66032 harness wrapper.

Loopback-only mock Anthropic Messages API를 백그라운드 thread로 띄우고, 실제
Claude Code CLI artifact(`cli.js`)를 그 mock을 향해 한 번의 non-interactive turn으로
실행한다. mock은 고정된 `Bash` tool_use만 반환하므로 취약점 재현의 유일한 model
입력은 case가 지정한 command 문자열이다. 실제 side effect(marker 생성)는
run-case의 filesystem snapshot이 관찰하고, 이 스크립트는 Claude CLI의 raw
stream-json 출력을 `${OUTSIDE}/claude-result.json`에 보존한다.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mock_model_server  # noqa: E402


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-js")
    parser.add_argument("--binary")
    parser.add_argument("--node", default="node")
    parser.add_argument("--command", required=True)
    parser.add_argument("--tool-name", default="Bash")
    parser.add_argument("--result-out", required=True)
    parser.add_argument("--prompt", default="주어진 작업을 진행하세요.")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()

    port = free_loopback_port()
    tool_input = {"command": args.command, "description": "hunma harness probe"}
    httpd = mock_model_server.serve(port, args.tool_name, tool_input)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    env = dict(os.environ)
    env.update(
        {
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
            "ANTHROPIC_API_KEY": "sk-ant-hunma-mock-not-a-real-key",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_BUG_COMMAND": "1",
            "DISABLE_COST_WARNINGS": "1",
        }
    )
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)

    if bool(args.cli_js) == bool(args.binary):
        parser.error("--cli-js와 --binary 중 정확히 하나를 지정해야 합니다")
    if args.binary:
        argv = [args.binary, "-p", args.prompt, "--output-format", "json"]
    else:
        argv = [args.node, args.cli_js, "-p", args.prompt, "--output-format", "json"]

    result_path = Path(args.result_out)
    result_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        completed = subprocess.run(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=args.timeout_seconds,
        )
        stdout_text = completed.stdout
        stderr_text = completed.stderr
        exit_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout_text = exc.stdout or ""
        stderr_text = exc.stderr or ""
        exit_code = None
        timed_out = True
    finally:
        httpd.shutdown()
        server_thread.join(timeout=5)

    parsed: dict | None = None
    try:
        parsed = json.loads(stdout_text)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    record = {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "mock_call_count": httpd.call_count,
        "stdout_raw": stdout_text,
        "stderr_raw": stderr_text,
        "parsed_result": parsed,
        "permission_denials": (parsed or {}).get("permission_denials"),
    }
    result_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
