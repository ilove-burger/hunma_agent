#!/usr/bin/env python3
"""CVE-2025-61260의 취약·수정·현재 버전을 동일 조건으로 비교한다."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_ROOT = REPO_ROOT / "harness"
RUNS_ROOT = HARNESS_ROOT / "runs"
TARGETS_ROOT = HARNESS_ROOT / "targets"
MANIFEST_PATH = HARNESS_ROOT / "versions" / "manifest.json"
RUN_ISOLATED = HARNESS_ROOT / "run-isolated"

COMPARISON_SPECS = (
    {
        "role": "known-vulnerable",
        "target_label": "codex-0.21.0",
        "case": "codex-61260-vulnerable.json",
        "expected_observation": "outside/mcp-started 생성",
    },
    {
        "role": "known-fixed",
        "target_label": "codex-0.22.0",
        "case": "codex-61260-fixed.json",
        "expected_observation": "outside/mcp-started 미생성",
    },
    {
        "role": "current",
        "target_label": "codex-current",
        "case": "codex-61260-current.json",
        "expected_observation": "outside/mcp-started 미생성",
    },
)


class ComparisonError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def json_dump(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def emit_event(stream: TextIO, event: str, **fields: Any) -> None:
    payload = {
        "schema_version": 1,
        "timestamp": utc_now(),
        "event": event,
        **fields,
    }
    stream.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
    stream.flush()


def positive_integer(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 10:
        raise argparse.ArgumentTypeError("반복 횟수는 1~10이어야 합니다")
    return parsed


def load_targets() -> dict[str, dict[str, Any]]:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"버전 manifest를 읽을 수 없습니다: {exc}") from exc

    targets = manifest.get("targets")
    if not isinstance(targets, list):
        raise ComparisonError("버전 manifest의 targets가 배열이 아닙니다")

    indexed: dict[str, dict[str, Any]] = {}
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("label"), str):
            raise ComparisonError("버전 manifest에 올바르지 않은 target 항목이 있습니다")
        label = target["label"]
        if label in indexed:
            raise ComparisonError(f"중복된 target label입니다: {label}")
        indexed[label] = target
    return indexed


def resolve_target(entry: dict[str, Any]) -> tuple[Path, str]:
    relative = entry.get("path")
    expected_hash = entry.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected_hash, str):
        raise ComparisonError(f"target 경로 또는 SHA-256이 없습니다: {entry.get('label')}")

    unresolved = REPO_ROOT / relative
    if unresolved.is_symlink():
        raise ComparisonError(f"target은 symlink일 수 없습니다: {unresolved}")
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(TARGETS_ROOT.resolve())
    except ValueError as exc:
        raise ComparisonError(f"target은 harness/targets 아래에 있어야 합니다: {resolved}") from exc
    if not resolved.is_file():
        raise ComparisonError(f"target 아티팩트가 없습니다: {resolved}")

    observed_hash = sha256_file(resolved)
    if observed_hash != expected_hash:
        raise ComparisonError(
            f"target SHA-256 불일치: {entry.get('label')}: "
            f"예상 {expected_hash}, 관찰 {observed_hash}"
        )
    return resolved, observed_hash


def parse_child_result(stdout: str) -> dict[str, Any] | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def parse_exists_after(detail: str) -> bool | None:
    match = re.search(r"실행 후=(True|False)", detail)
    if not match:
        return None
    return match.group(1) == "True"


def marker_state(exists_after: bool | None) -> str:
    if exists_after is True:
        return "present"
    if exists_after is False:
        return "absent"
    return "unknown"


def extract_marker_observations(child: dict[str, Any] | None) -> list[dict[str, Any]]:
    if child is None:
        return []
    checks = child.get("checks")
    if not isinstance(checks, list):
        return []

    observations: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        name = check.get("name")
        if not isinstance(name, str) or ":" not in name:
            continue
        expectation, path = name.split(":", 1)
        if expectation not in ("created", "absent"):
            continue
        detail = check.get("detail", "")
        detail_text = detail if isinstance(detail, str) else str(detail)
        exists_after = parse_exists_after(detail_text)
        observations.append(
            {
                "path": path,
                "expectation": expectation,
                "observed": marker_state(exists_after),
                "exists_after": exists_after,
                "passed": bool(check.get("passed")),
                "detail": detail_text,
            }
        )
    return observations


def format_marker_summary(observations: list[dict[str, Any]]) -> str:
    if not observations:
        return "none"
    return ", ".join(
        f"{item['path']}={item['observed']} expected={item['expectation']}"
        for item in observations
    )


def build_summary(
    status: str, repeat: int, comparison_results: list[dict[str, Any]]
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []

    for target in comparison_results:
        target_attempts = target["attempts"]
        passed_attempts = sum(1 for attempt in target_attempts if attempt["status"] == "PASS")
        failed_attempts = len(target_attempts) - passed_attempts
        targets.append(
            {
                "role": target["role"],
                "target_label": target["target_label"],
                "version": target["version"],
                **({"variant": target["variant"]} if "variant" in target else {}),
                "case": target["case"],
                "status": target["status"],
                "passed_attempts": passed_attempts,
                "failed_attempts": failed_attempts,
                "expected_observation": target["expected_observation"],
            }
        )
        for attempt in target_attempts:
            attempts.append(
                {
                    "role": target["role"],
                    "target_label": target["target_label"],
                    "version": target["version"],
                    **({"variant": target["variant"]} if "variant" in target else {}),
                    "case": target["case"],
                    "attempt": attempt["attempt"],
                    "status": attempt["status"],
                    "run_dir": attempt["child_run_dir"],
                    "result_path": attempt["child_result_path"],
                    "marker_summary": attempt["marker_summary"],
                    "marker_observations": attempt["marker_observations"],
                }
            )

    passed_attempts = sum(1 for attempt in attempts if attempt["status"] == "PASS")
    failed_attempts = len(attempts) - passed_attempts
    return {
        "status": status,
        "repeat": repeat,
        "total_attempts": len(attempts),
        "passed_attempts": passed_attempts,
        "failed_attempts": failed_attempts,
        "targets": targets,
        "attempts": attempts,
    }


def validate_case_target(case_path: Path, entry: dict[str, Any], expected_hash: str) -> None:
    try:
        case = json.loads(case_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"case 파일을 읽을 수 없습니다: {case_path}: {exc}") from exc
    if not isinstance(case, dict) or case.get("id") != case_path.stem:
        raise ComparisonError(f"case id와 파일명이 일치하지 않습니다: {case_path}")
    case_target = case.get("target")
    if not isinstance(case_target, dict):
        raise ComparisonError(f"case target 정의가 없습니다: {case_path}")
    if case_target.get("version") != entry.get("version"):
        raise ComparisonError(
            f"case와 manifest의 버전이 다릅니다: {case_path.stem}: "
            f"{case_target.get('version')} != {entry.get('version')}"
        )
    if expected_hash not in case_target.get("allowed_sha256", []):
        raise ComparisonError(f"manifest SHA-256이 case 허용 목록에 없습니다: {case_path.stem}")


def run_comparison(
    *,
    comparison_name: str,
    run_slug: str,
    specs: tuple[dict[str, str], ...],
    repeat: int,
    trace: str,
) -> int:
    started_at = utc_now()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_ROOT / run_slug / f"{timestamp}-{uuid.uuid4().hex[:8]}"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=False)
    events_path = artifacts_dir / "events.jsonl"

    try:
        targets = load_targets()
        prepared: list[dict[str, Any]] = []
        for spec in specs:
            label = spec["target_label"]
            entry = targets.get(label)
            if entry is None:
                raise ComparisonError(f"버전 manifest에 target이 없습니다: {label}")
            target_path, target_hash = resolve_target(entry)
            case_path = HARNESS_ROOT / "cases" / spec["case"]
            if not case_path.is_file():
                raise ComparisonError(f"case 파일이 없습니다: {case_path}")
            validate_case_target(case_path, entry, target_hash)
            prepared.append(
                {
                    **spec,
                    "target": entry,
                    "target_path": target_path,
                    "target_sha256": target_hash,
                    "case_path": case_path,
                }
            )

        comparison_results: list[dict[str, Any]] = []
        with events_path.open("w", encoding="utf-8") as events:
            emit_event(
                events,
                "comparison_started",
                comparison=comparison_name,
                repeat=repeat,
                run_dir=str(run_dir),
            )
            for item in prepared:
                attempts: list[dict[str, Any]] = []
                for attempt_number in range(1, repeat + 1):
                    stem = "-".join(
                        [
                            *([item["variant"]] if "variant" in item else []),
                            item["role"],
                            "attempt",
                            str(attempt_number),
                        ]
                    )
                    emit_event(
                        events,
                        "case_started",
                        role=item["role"],
                        target_label=item["target_label"],
                        version=item["target"]["version"],
                        **({"variant": item["variant"]} if "variant" in item else {}),
                        case=item["case_path"].stem,
                        attempt=attempt_number,
                    )
                    command = [
                        str(RUN_ISOLATED),
                        str(item["case_path"]),
                        "--target",
                        str(item["target_path"]),
                        "--trace",
                        trace,
                    ]
                    completed = subprocess.run(
                        command,
                        cwd=REPO_ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    (artifacts_dir / f"{stem}.stdout.log").write_text(
                        completed.stdout, encoding="utf-8"
                    )
                    (artifacts_dir / f"{stem}.stderr.log").write_text(
                        completed.stderr, encoding="utf-8"
                    )

                    child = parse_child_result(completed.stdout)
                    marker_observations = extract_marker_observations(child)
                    passed = bool(
                        completed.returncode == 0
                        and child is not None
                        and child.get("status") == "PASS"
                        and child.get("case") == item["case_path"].stem
                        and child.get("target_sha256") == item["target_sha256"]
                    )
                    attempt = {
                        "attempt": attempt_number,
                        "status": "PASS" if passed else "FAIL",
                        "return_code": completed.returncode,
                        "child_status": child.get("status") if child else "UNPARSEABLE",
                        **({"variant": item["variant"]} if "variant" in item else {}),
                        "child_run_dir": child.get("run_dir") if child else None,
                        "child_result_path": (
                            str(Path(child["run_dir"]) / "artifacts" / "result.json")
                            if child and isinstance(child.get("run_dir"), str)
                            else None
                        ),
                        "marker_summary": format_marker_summary(marker_observations),
                        "marker_observations": marker_observations,
                        "stdout_log": str(artifacts_dir / f"{stem}.stdout.log"),
                        "stderr_log": str(artifacts_dir / f"{stem}.stderr.log"),
                    }
                    attempts.append(attempt)
                    emit_event(
                        events,
                        "case_finished",
                        role=item["role"],
                        target_label=item["target_label"],
                        version=item["target"]["version"],
                        **({"variant": item["variant"]} if "variant" in item else {}),
                        case=item["case_path"].stem,
                        attempt=attempt_number,
                        status=attempt["status"],
                        return_code=completed.returncode,
                        child_run_dir=attempt["child_run_dir"],
                        child_result_path=attempt["child_result_path"],
                        marker_summary=attempt["marker_summary"],
                        marker_observations=attempt["marker_observations"],
                    )

                comparison_results.append(
                    {
                        "role": item["role"],
                        "target_label": item["target_label"],
                        "product": item["target"]["product"],
                        "version": item["target"]["version"],
                        **({"variant": item["variant"]} if "variant" in item else {}),
                        "target": str(item["target_path"]),
                        "target_sha256": item["target_sha256"],
                        "case": item["case_path"].stem,
                        "expected_observation": item["expected_observation"],
                        "status": (
                            "PASS" if all(attempt["status"] == "PASS" for attempt in attempts) else "FAIL"
                        ),
                        "attempts": attempts,
                    }
                )

            status = (
                "PASS" if all(item["status"] == "PASS" for item in comparison_results) else "FAIL"
            )
            emit_event(events, "comparison_finished", status=status, run_dir=str(run_dir))

        result = {
            "schema_version": 1,
            "comparison": comparison_name,
            "status": status,
            "summary": build_summary(status, repeat, comparison_results),
            "repeat": repeat,
            "trace_policy": trace,
            "started_at": started_at,
            "completed_at": utc_now(),
            "run_dir": str(run_dir),
            "events_path": str(events_path),
            "targets": comparison_results,
        }
        result_path = artifacts_dir / "result.json"
        json_dump(result_path, result)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0 if status == "PASS" else 1
    except (ComparisonError, OSError) as exc:
        error = {
            "schema_version": 1,
            "comparison": comparison_name,
            "status": "ERROR",
            "started_at": started_at,
            "completed_at": utc_now(),
            "run_dir": str(run_dir),
            "error": str(exc),
        }
        json_dump(artifacts_dir / "result.json", error)
        print(json.dumps(error, ensure_ascii=False), file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2025-61260을 Codex 0.21.0, 0.22.0, current에서 비교합니다."
    )
    parser.add_argument(
        "--repeat",
        type=positive_integer,
        default=1,
        help="각 버전의 반복 실행 횟수(기본값: 1, 최대: 10)",
    )
    parser.add_argument(
        "--trace",
        choices=("auto", "always", "never"),
        default="auto",
        help="각 case의 syscall trace 정책(기본값: auto)",
    )
    args = parser.parse_args()
    return run_comparison(
        comparison_name="CVE-2025-61260",
        run_slug="compare-codex-61260",
        specs=COMPARISON_SPECS,
        repeat=args.repeat,
        trace=args.trace,
    )


if __name__ == "__main__":
    raise SystemExit(main())
