#!/usr/bin/env python3
"""A14 harness wrapper — verdict-aware mock 위에서 실제 Claude Code CLI를 구동한다.

CVE-2025-66032 wrapper와 같은 뼈대다: loopback-only mock Anthropic Messages API를
백그라운드 thread로 띄우고, 실제 Claude Code artifact를 한 번의 non-interactive
turn으로 실행한다. 차이는 두 가지다:

1. mock이 verdict-aware(`mock_model_server`)라 Bash prefix classifier 요청에
   대해 honest/fooled verdict를 돌려준다.
2. `--allowed-tool` 로 넘긴 allow-rule을 `claude -p ... --allowedTools ...` 로
   전달한다. 이 allow-rule이 있어야 분류기가 보고한 benign prefix가 실제 auto-approve로
   이어지므로, "분류기가 속으면 전체 command가 실행되는가"라는 downstream 불변식을
   격리해서 관측할 수 있다.

실제 side effect(marker)는 run-case의 filesystem snapshot이 관찰하고, 이 스크립트는
Claude CLI raw 출력과 mock의 classifier_log를 `${OUTSIDE}/claude-result.json`에
보존한다.
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
    parser.add_argument("--classifier-mode", choices=("honest", "fooled"), default="honest")
    parser.add_argument("--fooled-prefix", action="append", default=[])
    parser.add_argument("--allowed-tool", action="append", default=[])
    parser.add_argument("--result-out", required=True)
    parser.add_argument("--prompt", default="주어진 작업을 진행하세요.")
    parser.add_argument("--timeout-seconds", type=int, default=35)
    args = parser.parse_args()

    if bool(args.cli_js) == bool(args.binary):
        parser.error("--cli-js와 --binary 중 정확히 하나를 지정해야 합니다")

    port = free_loopback_port()
    tool_input = {"command": args.command, "description": "hunma a14 probe"}
    httpd = mock_model_server.serve(
        port, args.tool_name, tool_input, args.classifier_mode, args.fooled_prefix
    )
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

    launcher = [args.binary] if args.binary else [args.node, args.cli_js]
    argv = [*launcher, "-p", args.prompt, "--output-format", "json"]
    for rule in args.allowed_tool:
        argv += ["--allowedTools", rule]

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

    try:
        parsed = json.loads(stdout_text)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    record = {
        "argv": argv,
        "classifier_mode": args.classifier_mode,
        "fooled_prefixes": args.fooled_prefix,
        "allowed_tools": args.allowed_tool,
        "command": args.command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "call_count": httpd.call_count,
        "agent_call_count": httpd.agent_call_count,
        "classifier_call_count": httpd.classifier_call_count,
        "classifier_log": httpd.classifier_log,
        "stdout_raw": stdout_text,
        "stderr_raw": stderr_text,
        "parsed_result": parsed,
        "permission_denials": (parsed or {}).get("permission_denials"),
    }
    result_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
