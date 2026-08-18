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
    {
        "variant": "gitdir-commondir",
        "case_prefix": "codex-61260-gitdir-commondir",
        "description": ".git file, gitdir, commondir가 분리된 repository",
    },
    {
        "variant": "config-reload",
        "case_prefix": "codex-61260-config-reload",
        "description": "project .env가 CODEX_HOME을 reload-home으로 재지정한 뒤 config root가 다시 해석되는 boundary",
    },
    {
        "variant": "session-resume",
        "case_prefix": "codex-61260-session-resume",
        "description": "current CLI의 exec resume lifecycle boundary",
        "roles": ("current",),
    },
    {
        "variant": "preexisting-codex-home-negative",
        "case_prefix": "codex-61260-preexisting-codex-home-negative",
        "description": "기존 CODEX_HOME이 이미 설정된 경우 project .env가 override하지 못하는 negative control",
        "expected_observations": {
            "known-vulnerable": "outside/mcp-started 미생성",
            "known-fixed": "outside/mcp-started 미생성",
            "current": "outside/mcp-started 미생성",
        },
    },
    {
        "variant": "mcp-add-config-root",
        "case_prefix": "codex-61260-mcp-add-config-root",
        "description": "current 전용 `codex mcp add` config root negative control",
        "roles": ("current",),
        "expected_observations": {
            "current": "fake-home/.codex/config.toml 생성, workspace/reload-home/config.toml 미생성",
        },
    },
    {
        "variant": "mcp-list-config-root",
        "case_prefix": "codex-61260-mcp-list-config-root",
        "description": "current 전용 `codex mcp list` config root negative control",
        "roles": ("current",),
        "expected_observations": {
            "current": "reload-home/config.toml 불변, fake-home/.codex/config.toml 미생성",
        },
    },
)


def parse_variant_filter(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    requested = tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    if not requested:
        raise argparse.ArgumentTypeError("--variant에는 하나 이상의 variant 이름이 필요합니다")
    known = {item["variant"] for item in VARIANT_SPECS}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise argparse.ArgumentTypeError(
            "알 수 없는 variant입니다: "
            + ", ".join(unknown)
            + ". 가능한 값: "
            + ", ".join(sorted(known))
        )
    return requested


def parse_role_filter(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    requested = tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    if not requested:
        raise argparse.ArgumentTypeError("--role에는 하나 이상의 role 이름이 필요합니다")
    known = {item["role"] for item in ROLE_SPECS}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise argparse.ArgumentTypeError(
            "알 수 없는 role입니다: "
            + ", ".join(unknown)
            + ". 가능한 값: "
            + ", ".join(sorted(known))
        )
    return requested


def build_specs(
    selected_variants: tuple[str, ...] | None = None,
    selected_roles: tuple[str, ...] | None = None,
) -> tuple[dict[str, str], ...]:
    specs: list[dict[str, str]] = []
    for variant in VARIANT_SPECS:
        if selected_variants is not None and variant["variant"] not in selected_variants:
            continue
        enabled_roles = set(variant.get("roles", (role["role"] for role in ROLE_SPECS)))
        for role in ROLE_SPECS:
            if role["role"] not in enabled_roles:
                continue
            if selected_roles is not None and role["role"] not in selected_roles:
                continue
            expected_observations = variant.get("expected_observations", {})
            expected_observation = expected_observations.get(
                role["role"],
                role["expected_observation"],
            )
            specs.append(
                {
                    "variant": variant["variant"],
                    "role": role["role"],
                    "target_label": role["target_label"],
                    "case": f"{variant['case_prefix']}-{role['short']}.json",
                    "expected_observation": f"{variant['variant']}: {expected_observation}",
                }
            )
    if not specs:
        raise ValueError("선택된 variant에 실행할 case가 없습니다")
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
    parser.add_argument(
        "--variant",
        type=parse_variant_filter,
        help=(
            "실행할 variant를 쉼표로 제한합니다. 예: "
            "--variant symlink-repo,nested-repo"
        ),
    )
    parser.add_argument(
        "--role",
        type=parse_role_filter,
        help=(
            "실행할 role을 쉼표로 제한합니다. 예: "
            "--role current 또는 --role known-fixed,current"
        ),
    )
    args = parser.parse_args()
    try:
        specs = build_specs(args.variant, args.role)
    except ValueError as exc:
        parser.error(str(exc))
    return run_comparison(
        comparison_name="CVE-2025-61260-variants",
        run_slug="compare-codex-61260-variants",
        specs=specs,
        repeat=args.repeat,
        trace=args.trace,
    )


if __name__ == "__main__":
    raise SystemExit(main())
