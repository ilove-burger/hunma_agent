#!/usr/bin/env python3
"""CVE-2025-61260 golden case와 repository variant들을 한 번에 비교한다."""

from __future__ import annotations

import argparse

from compare_codex_61260 import positive_integer, run_comparison


ROLE_SPECS = (
    {
        "role": "known-vulnerable",
        "target_label": "codex-0.21.0",
        "short": "vulnerable",
        "expected_observation": "outside/mcp-started 생성",
    },
    {
        "role": "known-fixed",
        "target_label": "codex-0.22.0",
        "short": "fixed",
        "expected_observation": "outside/mcp-started 미생성",
    },
    {
        "role": "current",
        "target_label": "codex-current",
        "short": "current",
        "expected_observation": "outside/mcp-started 미생성",
    },
)

VARIANT_SPECS = (
    {
        "variant": "golden",
        "case_prefix": "codex-61260",
        "description": "skip git repo check를 사용한 최소 config loading golden control",
    },
    {
        "variant": "normal-repo",
        "case_prefix": "codex-61260-normal-repo",
        "description": "일반 .git directory repository",
    },
    {
        "variant": "worktree",
        "case_prefix": "codex-61260-worktree",
        "description": ".git file과 분리된 commondir worktree",
    },
    {
        "variant": "symlink-repo",
        "case_prefix": "codex-61260-symlink-repo",
        "description": ".git symlink가 내부 gitdir를 가리키는 repository",
    },
    {
        "variant": "nested-repo",
        "case_prefix": "codex-61260-nested-repo",
        "description": "outer repository 안의 inner repository",
    },
)


def build_specs() -> tuple[dict[str, str], ...]:
    specs: list[dict[str, str]] = []
    for variant in VARIANT_SPECS:
        for role in ROLE_SPECS:
            specs.append(
                {
                    "variant": variant["variant"],
                    "role": role["role"],
                    "target_label": role["target_label"],
                    "case": f"{variant['case_prefix']}-{role['short']}.json",
                    "expected_observation": (
                        f"{variant['variant']}: {role['expected_observation']}"
                    ),
                }
            )
    return tuple(specs)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "CVE-2025-61260 golden, normal repo, worktree, symlink repo, nested repo "
            "variant를 Codex 0.21.0, 0.22.0, current에서 비교합니다."
        )
    )
    parser.add_argument(
        "--repeat",
        type=positive_integer,
        default=1,
        help="각 variant·버전 조합의 반복 실행 횟수(기본값: 1, 최대: 10)",
    )
    parser.add_argument(
        "--trace",
        choices=("auto", "always", "never"),
        default="auto",
        help="각 case의 syscall trace 정책(기본값: auto)",
    )
    args = parser.parse_args()
    return run_comparison(
        comparison_name="CVE-2025-61260-variants",
        run_slug="compare-codex-61260-variants",
        specs=build_specs(),
        repeat=args.repeat,
        trace=args.trace,
    )


if __name__ == "__main__":
    raise SystemExit(main())
