#!/usr/bin/env python3
"""Hunma harness result JSON을 schema로 검증한다."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
except ImportError:  # pragma: no cover - dependency guard for minimal lab images.
    Draft202012Validator = None  # type: ignore[assignment]
    SchemaError = RuntimeError  # type: ignore[assignment,misc]


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_ROOT = REPO_ROOT / "harness" / "schemas"
SCHEMAS = {
    "case": SCHEMAS_ROOT / "case-result.schema.json",
    "compare": SCHEMAS_ROOT / "compare-result.schema.json",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(schema_path: Path, result_path: Path) -> list[str]:
    if Draft202012Validator is None:
        raise RuntimeError("Python package 'jsonschema'가 필요합니다")
    schema = load_json(schema_path)
    result = load_json(result_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=lambda error: list(error.path))
    messages = []
    for error in errors:
        location = "$"
        if error.path:
            location = "$." + ".".join(str(item) for item in error.path)
        messages.append(f"{location}: {error.message}")
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=sorted(SCHEMAS), help="검증할 result 종류")
    parser.add_argument("result", help="검증할 result.json 경로")
    args = parser.parse_args()

    result_path = Path(args.result)
    schema_path = SCHEMAS[args.kind]
    try:
        errors = validate(schema_path, result_path)
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "ERROR",
                    "kind": args.kind,
                    "result": str(result_path),
                    "error": str(exc),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2

    if errors:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "FAIL",
                    "kind": args.kind,
                    "result": str(result_path),
                    "schema": str(schema_path),
                    "errors": errors,
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": "PASS",
                "kind": args.kind,
                "result": str(result_path),
                "schema": str(schema_path),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
