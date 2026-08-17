#!/usr/bin/env python3
"""Deterministic, marker-only runner for local agent security research cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_ROOT = REPO_ROOT / "harness"
CASES_ROOT = HARNESS_ROOT / "cases"
FIXTURES_ROOT = HARNESS_ROOT / "fixtures"
RUNS_ROOT = HARNESS_ROOT / "runs"

SAFE_INHERITED_ENV = ("PATH", "LANG", "LC_ALL", "TERM", "TZ")
BLOCKED_ENV = {
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
}
PROTECTED_ENV = {"HOME", "TMPDIR", "HUNMA_RUN_DIR"}
MAX_SNAPSHOT_ENTRIES = 10_000
MAX_HASH_BYTES = 8 * 1024 * 1024
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class CaseError(RuntimeError):
    pass


def json_dump(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_within(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise CaseError(f"{label} must stay below {root_resolved}: {path}") from exc
    return resolved


def safe_relative(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise CaseError(f"{label} must be a relative path without '..': {value}")
    return path


def load_case(case_argument: str) -> tuple[Path, dict[str, Any]]:
    candidate = Path(case_argument)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    case_path = require_within(candidate, CASES_ROOT, "case file")
    try:
        value = json.loads(case_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseError(f"cannot load case {case_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CaseError("case root must be a JSON object")
    return case_path, value


def validate_case(case: dict[str, Any]) -> None:
    required = ("schema_version", "id", "description", "safety", "execution", "expectations")
    missing = [key for key in required if key not in case]
    if missing:
        raise CaseError(f"missing required case fields: {', '.join(missing)}")
    if case["schema_version"] != 1:
        raise CaseError("only case schema_version 1 is supported")
    if not isinstance(case["id"], str) or not CASE_ID_RE.fullmatch(case["id"]):
        raise CaseError("case id must match [a-z0-9][a-z0-9._-]{0,127}")

    safety = case["safety"]
    execution = case["execution"]
    expectations = case["expectations"]
    if not isinstance(safety, dict) or not isinstance(execution, dict) or not isinstance(expectations, dict):
        raise CaseError("safety, execution, and expectations must be JSON objects")
    if safety.get("network") not in ("inherit", "outer-isolation-required"):
        raise CaseError("safety.network must be 'inherit' or 'outer-isolation-required'")
    if not isinstance(safety.get("host_safe"), bool):
        raise CaseError("safety.host_safe must be boolean")

    argv = execution.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise CaseError("execution.argv must be a non-empty array of strings")
    if execution.get("cwd", "workspace") not in ("workspace", "fake_home", "outside"):
        raise CaseError("execution.cwd must be workspace, fake_home, or outside")
    timeout = execution.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or not 1 <= timeout <= 600:
        raise CaseError("execution.timeout_seconds must be an integer from 1 to 600")
    observation_seconds = execution.get("observation_seconds")
    if observation_seconds is not None:
        if "timeout_seconds" in execution:
            raise CaseError("execution may use timeout_seconds or observation_seconds, not both")
        if not isinstance(observation_seconds, int) or not 1 <= observation_seconds <= 600:
            raise CaseError("execution.observation_seconds must be an integer from 1 to 600")
    environment = execution.get("environment", {})
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
    ):
        raise CaseError("execution.environment must map strings to strings")
    blocked = sorted(BLOCKED_ENV.intersection(environment))
    if blocked:
        raise CaseError(f"case may not inject credential environment variables: {', '.join(blocked)}")
    unset_environment = execution.get("unset_environment", [])
    if not isinstance(unset_environment, list) or not all(
        isinstance(key, str) and key for key in unset_environment
    ):
        raise CaseError("execution.unset_environment must be an array of non-empty strings")
    protected = sorted(PROTECTED_ENV.intersection(unset_environment))
    if protected:
        raise CaseError(f"case may not unset safety environment variables: {', '.join(protected)}")

    fixture_dir = case.get("fixture_dir")
    if fixture_dir is not None:
        if not isinstance(fixture_dir, str):
            raise CaseError("fixture_dir must be a string")
        fixture_path = require_within(REPO_ROOT / fixture_dir, FIXTURES_ROOT, "fixture directory")
        if not fixture_path.is_dir():
            raise CaseError(f"fixture directory does not exist: {fixture_path}")
    for template in case.get("template_files", []):
        safe_relative(template, "template file")

    target = case.get("target", {})
    if not isinstance(target, dict):
        raise CaseError("target must be a JSON object")
    allowed_hashes = target.get("allowed_sha256", [])
    if not isinstance(allowed_hashes, list) or not all(
        isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in allowed_hashes
    ):
        raise CaseError("target.allowed_sha256 must be an array of lowercase SHA-256 strings")

    for key in ("created", "absent", "unchanged"):
        values = expectations.get(key, [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise CaseError(f"expectations.{key} must be an array of strings")
        for value in values:
            safe_relative(value, f"expectations.{key}")
    contents = expectations.get("contents", {})
    if not isinstance(contents, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in contents.items()
    ):
        raise CaseError("expectations.contents must map paths to exact strings")
    for value in contents:
        safe_relative(value, "expectations.contents")
    exit_codes = expectations.get("exit_codes", [0])
    if not isinstance(exit_codes, list) or not exit_codes or not all(isinstance(item, int) for item in exit_codes):
        raise CaseError("expectations.exit_codes must be a non-empty array of integers")


def substitute(value: str, variables: dict[str, str]) -> str:
    result = value
    for name, replacement in variables.items():
        result = result.replace("${" + name + "}", replacement)
    unresolved = re.findall(r"\$\{[A-Z0-9_]+\}", result)
    if unresolved:
        raise CaseError(f"unresolved placeholders in {value!r}: {', '.join(unresolved)}")
    return result


def snapshot(root: Path) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for index, path in enumerate(sorted(root.rglob("*"), key=lambda item: str(item))):
        if index >= MAX_SNAPSHOT_ENTRIES:
            entries["__snapshot_error__"] = {"reason": "entry limit exceeded"}
            break
        relative = path.relative_to(root).as_posix()
        try:
            stat_result = path.lstat()
            if path.is_symlink():
                entries[relative] = {
                    "type": "symlink",
                    "target": os.readlink(path),
                    "mode": oct(stat_result.st_mode & 0o7777),
                }
            elif path.is_dir():
                entries[relative] = {
                    "type": "directory",
                    "mode": oct(stat_result.st_mode & 0o7777),
                }
            elif path.is_file():
                item: dict[str, Any] = {
                    "type": "file",
                    "size": stat_result.st_size,
                    "mode": oct(stat_result.st_mode & 0o7777),
                    "inode": stat_result.st_ino,
                    "device": stat_result.st_dev,
                }
                if stat_result.st_size <= MAX_HASH_BYTES:
                    item["sha256"] = sha256_file(path)
                else:
                    item["sha256"] = None
                    item["hash_skipped"] = "file exceeds 8 MiB"
                entries[relative] = item
            else:
                entries[relative] = {"type": "other", "mode": oct(stat_result.st_mode & 0o7777)}
        except OSError as exc:
            entries[relative] = {"type": "error", "error": str(exc)}
    return entries


def evaluate(
    expectations: dict[str, Any],
    lab_root: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    exit_code: int | None,
    timed_out: bool,
    observation_mode: bool,
    observation_window_elapsed: bool,
) -> tuple[str, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    if timed_out:
        add("timeout", False, "target exceeded the configured timeout")
    elif observation_mode:
        detail = (
            "configured observation window elapsed; target process group was terminated"
            if observation_window_elapsed
            else f"target exited before the observation window ended; exit_code={exit_code}"
        )
        add("observation_window", True, detail)
    else:
        allowed = expectations.get("exit_codes", [0])
        add("exit_code", exit_code in allowed, f"observed={exit_code}, allowed={allowed}")

    for relative in expectations.get("created", []):
        add(
            f"created:{relative}",
            relative not in before and relative in after,
            f"before={relative in before}, after={relative in after}",
        )
    for relative in expectations.get("absent", []):
        add(f"absent:{relative}", relative not in after, f"after={relative in after}")
    for relative in expectations.get("unchanged", []):
        add(
            f"unchanged:{relative}",
            before.get(relative) == after.get(relative),
            "filesystem metadata and content hash comparison",
        )
    for relative, expected_content in expectations.get("contents", {}).items():
        target = lab_root / safe_relative(relative, "content oracle")
        try:
            observed = target.read_text(encoding="utf-8")
        except OSError as exc:
            add(f"content:{relative}", False, f"cannot read marker: {exc}")
        else:
            add(
                f"content:{relative}",
                observed == expected_content,
                f"observed={observed!r}",
            )

    if timed_out:
        return "INCONCLUSIVE", checks
    return ("PASS" if checks and all(item["passed"] for item in checks) else "FAIL"), checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", help="JSON case below harness/cases")
    parser.add_argument("--target", help="explicit target binary or launcher path")
    parser.add_argument(
        "--trace",
        choices=("auto", "always", "never"),
        default="auto",
        help="capture child syscalls with strace when available",
    )
    parser.add_argument(
        "--isolated-lab-confirmed",
        action="store_true",
        help="confirm this invocation is already inside a disposable outer isolation boundary",
    )
    parser.add_argument(
        "--allow-root-in-disposable-lab",
        action="store_true",
        help="allow uid 0 only together with --isolated-lab-confirmed",
    )
    parser.add_argument("--validate-only", action="store_true", help="validate the case without executing it")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        case_path, case = load_case(args.case)
        validate_case(case)
        if args.validate_only:
            print(json.dumps({"case": case["id"], "status": "VALID", "path": str(case_path)}))
            return 0

        safety = case["safety"]
        if not safety["host_safe"] and not args.isolated_lab_confirmed:
            raise CaseError(
                "this case may execute vulnerable code; run it in a disposable VM/container and pass "
                "--isolated-lab-confirmed"
            )
        if os.geteuid() == 0 and not (
            args.isolated_lab_confirmed and args.allow_root_in_disposable_lab
        ):
            raise CaseError(
                "refusing to run as root; use an unprivileged lab user, or explicitly combine "
                "--isolated-lab-confirmed with --allow-root-in-disposable-lab"
            )

        target_path: Path | None = None
        target_hash: str | None = None
        target_config = case.get("target", {})
        if args.target:
            target_path = Path(args.target).expanduser().resolve()
            if not target_path.is_file():
                raise CaseError(f"target is not a file: {target_path}")
            if Path(args.target).expanduser().is_symlink():
                raise CaseError(
                    "target may not be a symlink; copy a pinned launcher/artifact into "
                    "harness/targets and hash that file"
                )
            target_hash = sha256_file(target_path)
            allowed_hashes = target_config.get("allowed_sha256", [])
            if allowed_hashes and target_hash not in allowed_hashes:
                raise CaseError(f"target SHA-256 is not allowed by the case: {target_hash}")
        elif target_config.get("required", False):
            raise CaseError("this case requires --target with an explicit binary or launcher")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = RUNS_ROOT / case["id"] / f"{timestamp}-{uuid.uuid4().hex[:8]}"
        lab_root = run_dir / "lab"
        artifacts = run_dir / "artifacts"
        workspace = lab_root / "workspace"
        outside = lab_root / "outside"
        fake_home = lab_root / "fake-home"
        fake_codex_home = fake_home / ".codex"
        temp_root = lab_root / "tmp"
        for directory in (workspace, outside, fake_codex_home, temp_root, artifacts):
            directory.mkdir(parents=True, exist_ok=True)

        variables = {
            "REPO_ROOT": str(REPO_ROOT),
            "HARNESS_ROOT": str(HARNESS_ROOT),
            "RUN_DIR": str(run_dir),
            "LAB_ROOT": str(lab_root),
            "WORKSPACE": str(workspace),
            "OUTSIDE": str(outside),
            "FAKE_HOME": str(fake_home),
            "FAKE_CODEX_HOME": str(fake_codex_home),
            "TMPDIR": str(temp_root),
            "PYTHON": sys.executable,
            "TARGET": str(target_path) if target_path else "",
        }

        fixture_dir = case.get("fixture_dir")
        if fixture_dir:
            source = require_within(REPO_ROOT / fixture_dir, FIXTURES_ROOT, "fixture directory")
            shutil.copytree(source, workspace, dirs_exist_ok=True, symlinks=True)
        for relative_text in case.get("template_files", []):
            relative = safe_relative(relative_text, "template file")
            template_path = require_within(workspace / relative, workspace, "template file")
            content = template_path.read_text(encoding="utf-8")
            template_path.write_text(substitute(content, variables), encoding="utf-8")

        execution = case["execution"]
        argv = [substitute(item, variables) for item in execution["argv"]]
        cwd_map = {"workspace": workspace, "fake_home": fake_home, "outside": outside}
        cwd = cwd_map[execution.get("cwd", "workspace")]

        environment = {key: os.environ[key] for key in SAFE_INHERITED_ENV if key in os.environ}
        environment.update(
            {
                "HOME": str(fake_home),
                "CODEX_HOME": str(fake_codex_home),
                "TMPDIR": str(temp_root),
                "HUNMA_RUN_DIR": str(run_dir),
            }
        )
        for key, value in execution.get("environment", {}).items():
            environment[key] = substitute(value, variables)
        for key in execution.get("unset_environment", []):
            environment.pop(key, None)
        for key in BLOCKED_ENV:
            environment.pop(key, None)

        before = snapshot(lab_root)
        json_dump(artifacts / "filesystem-before.json", before)
        json_dump(artifacts / "case.json", case)
        json_dump(
            artifacts / "environment.json",
            {
                "case": case["id"],
                "platform": platform.platform(),
                "python": platform.python_version(),
                "uid": os.geteuid(),
                "cwd": str(cwd),
                "environment_keys": sorted(environment),
                "unset_environment": sorted(execution.get("unset_environment", [])),
                "network_policy": safety["network"],
                "outer_isolation_confirmed": args.isolated_lab_confirmed,
                "target": str(target_path) if target_path else None,
                "target_sha256": target_hash,
            },
        )

        traced_argv = argv
        trace_enabled = False
        trace_reason = "disabled by option"
        strace_path = shutil.which("strace")
        if args.trace == "always" and not strace_path:
            raise CaseError("--trace always requested but strace is unavailable")
        if args.trace != "never" and strace_path:
            true_path = shutil.which("true") or "/bin/true"
            probe = subprocess.run(
                [strace_path, "-o", str(artifacts / "strace-probe.log"), "--", true_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if probe.returncode == 0:
                trace_enabled = True
                trace_reason = "strace probe succeeded"
                traced_argv = [
                    strace_path,
                    "-ff",
                    "-s",
                    "4096",
                    "-o",
                    str(artifacts / "process.strace"),
                    "--",
                    *argv,
                ]
            else:
                trace_reason = f"strace probe failed with exit {probe.returncode}"
                (artifacts / "strace-probe.stderr.log").write_text(
                    probe.stderr, encoding="utf-8"
                )
                if args.trace == "always":
                    raise CaseError(
                        "--trace always requested but strace cannot attach in this environment; "
                        f"see {artifacts / 'strace-probe.stderr.log'}"
                    )
        elif args.trace != "never":
            trace_reason = "strace executable not found"

        started = time.monotonic()
        timed_out = False
        observation_mode = "observation_seconds" in execution
        observation_window_elapsed = False
        exit_code: int | None = None
        stdout_text = ""
        stderr_text = ""
        process = subprocess.Popen(
            traced_argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            deadline = execution.get("observation_seconds", execution.get("timeout_seconds", 30))
            stdout_text, stderr_text = process.communicate(timeout=deadline)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            if observation_mode:
                observation_window_elapsed = True
            else:
                timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout_text, stderr_text = process.communicate()
            exit_code = process.returncode
        duration = time.monotonic() - started

        (artifacts / "stdout.log").write_text(stdout_text, encoding="utf-8")
        (artifacts / "stderr.log").write_text(stderr_text, encoding="utf-8")
        after = snapshot(lab_root)
        json_dump(artifacts / "filesystem-after.json", after)

        status, checks = evaluate(
            case["expectations"],
            lab_root,
            before,
            after,
            exit_code,
            timed_out,
            observation_mode,
            observation_window_elapsed,
        )
        result = {
            "schema_version": 1,
            "case": case["id"],
            "status": status,
            "run_dir": str(run_dir),
            "duration_seconds": round(duration, 6),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "observation_mode": observation_mode,
            "observation_window_elapsed": observation_window_elapsed,
            "trace_enabled": trace_enabled,
            "trace_reason": trace_reason,
            "target": str(target_path) if target_path else None,
            "target_sha256": target_hash,
            "checks": checks,
        }
        json_dump(artifacts / "result.json", result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if status == "PASS" else 1
    except CaseError as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
