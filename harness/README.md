# Hunma 하네스

이 하네스는 agent security 가설을 반복 가능한 marker-only 실험으로 변환한다. 연구용 agent와
분석 대상 제품을 의도적으로 분리하고, 기계적으로 검증할 수 있는 filesystem 및 process 증거를
기록한다.

## 안전 경계

`run-case`는 `harness/runs/` 아래에 `workspace`, `outside`, `fake-home`, `tmp`가 분리된 새로운
논리적 실험 환경을 만든다. 이 디렉터리 구조는 oracle이며 보안 sandbox 자체는 아니다.
`host_safe: false`인 case는 `--isolated-lab-confirmed`가 없으면 실행을 거부한다. 이러한 case는
실제 자격 증명이 없고 outbound network가 차단된 disposable VM 또는 전용 외부 container에서
비권한 사용자로 실행한다.

runner는 child environment에서 일반적인 API 및 repository 자격 증명을 제거한다. shell string은
실행하지 않으며 case command는 명시적인 argv 배열로 구성한다. filesystem snapshot은 최대
10,000개 항목으로 제한하고 8 MiB 이하의 파일만 hash한다.
각 case 결과에는 `environment_metadata`를 함께 저장한다. 여기에는 OS/kernel, architecture, uid/gid,
현재 namespace id, user/net/pid namespace 제한값, `bwrap`/`strace` 설치 및 버전, 실제 trace 활성화
여부, 외부 격리 확인값이 포함된다. 따라서 marker 결과가 target 동작 때문인지, 실험 환경 문제인지
나중에 구분할 수 있다.

환경 변수 기반 locator 동작을 시험하는 case는 `execution.unset_environment`를 사용해
`CODEX_HOME`을 명시적으로 제거할 수 있다. runner는 disposable `HOME`을 계속 강제하며 핵심 안전
변수는 제거하지 못하게 한다. `execution.observation_seconds`는 marker oracle을 위한 제한된 startup
관찰 시간을 제공하고, 관찰 후 대상 process group을 의도적으로 종료했다는 사실을 기록한다.

## 빠른 시작

Python과 모든 case manifest를 검증한 뒤 안전한 self-test를 실행한다.

```bash
./harness/test
```

self-test만 실행한다.

```bash
./harness/run-case harness/cases/selftest-marker.json
./harness/run-case harness/cases/selftest-negative.json
```

`selftest-marker`는 runner가 marker 생성과 content oracle을 관찰할 수 있는지 확인하는 양성
self-test다. `selftest-negative`는 대상 명령이 아무 작업도 하지 않을 때 `outside/negative-marker`가
끝까지 없어야 한다는 음성 대조군이다. 두 case가 모두 PASS여야 하네스의 기본 관찰 경로를 신뢰할 수
있다.

제공된 Linux 외부 sandbox 안에서 case를 실행한다.

```bash
./harness/run-isolated harness/cases/selftest-marker.json
./harness/run-isolated harness/cases/selftest-negative.json
```

`run-isolated`는 bubblewrap으로 user, PID, network, UTS, IPC namespace를 분리한다. host root를
read-only로 만들고, 실행한 사용자의 home을 가리고, 이 repository만 노출한다. 쓰기는
`harness/runs`에만 허용하고 `harness/targets`는 read-only로 mount하며 capability를 제거한다.
또한 새로운 `/tmp`, `/run`, `/proc`, `/dev` mount를 사용한다. Linux에서는 이 진입점을 우선
사용한다. 최종 sandbox escape 증거나 platform별 kernel 연구에는 disposable VM을 가장 바깥쪽
경계로 사용한다.

각 실행은 JSON 결과를 출력하고 전체 증거를 다음 경로에 저장한다.

```text
harness/runs/<case>/<timestamp-id>/artifacts/
```

CVE-2025-61260의 알려진 취약 버전, 수정 버전, 등록 시점의 current 버전을 한 번에 비교한다.

```bash
./harness/compare-codex-61260
```

각 버전을 반복해 결정성을 확인하려면 `--repeat`을 사용한다.

```bash
./harness/compare-codex-61260 --repeat 2
```

golden case와 repository variant 전체를 한 번에 비교한다.

```bash
./harness/compare-codex-61260-variants
./harness/compare-codex-61260-variants --repeat 2 --trace never
./harness/compare-codex-61260-variants --variant symlink-repo,nested-repo --trace never
./harness/compare-codex-61260-variants --role current --trace never
```

통합 결과와 이벤트 스트림은 각각
`harness/runs/compare-codex-61260/<timestamp-id>/artifacts/result.json`과 `events.jsonl`에 저장된다.
명령은 실행 전에 세 target이 `versions/manifest.json`에 등록되어 있는지, 실제 파일의 SHA-256이
manifest와 일치하는지 검증한다. 개별 case의 stdout·stderr와 원본 `result.json` 경로도 통합 결과에
기록한다.
`result.json`의 `summary.attempts`에는 반복 실행별 `status`, child `run_dir`, 원본 결과 경로,
`outside/mcp-started`의 관찰 상태가 납작하게 기록된다. `summary.targets`는 버전별 반복 성공·실패
수를 집계하므로 golden case가 취약·수정·current에서 기대대로 갈라졌는지 빠르게 확인할 수 있다.
variant 비교 결과에는 `summary.summary_table`도 포함된다. 이 matrix는 row를 variant로, column을
`known-vulnerable`, `known-fixed`, `current`로 두고 각 cell에 PASS/FAIL과 marker 관찰 요약을 저장한다.
특정 버전에 적용할 수 없는 lifecycle case는 cell을 `null`로 기록한다.
동일한 matrix는 `artifacts/summary-table.md`와 `artifacts/summary-table.csv`로도 export되며,
통합 `result.json`의 `exports` field에 경로가 기록된다. 필요한 경우 `--variant`와 `--role`을 함께
사용해 실행 범위를 줄인다.
case 결과와 비교 결과의 형식은 각각 `schemas/case-result.schema.json`,
`schemas/compare-result.schema.json`으로 고정한다. `validate-result`는 Python `jsonschema` package를
사용한다.

```bash
./harness/validate-result case harness/runs/<case>/<run>/artifacts/result.json
./harness/validate-result compare harness/runs/compare-codex-61260/<run>/artifacts/result.json
```

`strace`가 설치되어 있으면 syscall trace를 자동으로 수집한다. 비활성화하려면 `--trace never`,
필수로 요구하려면 `--trace always`를 사용한다.

## CVE-2025-61260 variant case

기본 golden case는 `--skip-git-repo-check`를 사용해 config loading 경계만 최소화해서 본다. variant
case는 실제 repository 형태를 바꿔 같은 primitive가 재현되는지 확인한다.

| Variant | Case prefix | Repository 형태 | 0.21.0 기대값 | 0.22.0/current 기대값 |
|---|---|---|---|---|
| normal repo | `codex-61260-normal-repo-*` | workspace 아래 일반 `.git/` directory | marker 생성 | marker 미생성 |
| worktree | `codex-61260-worktree-*` | `.git` file과 분리된 `commondir` | marker 생성 | marker 미생성 |
| symlink repo | `codex-61260-symlink-repo-*` | workspace `.git`이 내부 gitdir symlink | marker 생성 | marker 미생성 |
| nested repo | `codex-61260-nested-repo-*` | outer repo 안의 `inner/` 하위 repo를 cwd로 실행 | marker 생성 | marker 미생성 |
| gitdir/commondir | `codex-61260-gitdir-commondir-*` | `.git` file, gitdir, commondir가 분리된 repository | marker 생성 | marker 미생성 |
| config reload | `codex-61260-config-reload-*` | `.env`가 `CODEX_HOME=./reload-home`으로 config root를 재지정 | marker 생성 | marker 미생성 |
| session resume | `codex-61260-session-resume-current` | current CLI의 `exec resume` lifecycle | N/A | current에서 marker 미생성 |
| preexisting CODEX_HOME negative | `codex-61260-preexisting-codex-home-negative-*` | runner가 fake `CODEX_HOME`을 이미 제공한 상태 | marker 미생성 | marker 미생성 |

예시는 다음과 같다.

```bash
./harness/run-isolated \
  harness/cases/codex-61260-normal-repo-vulnerable.json \
  --target harness/targets/codex-0.21.0/bin/codex-x86_64-unknown-linux-musl \
  --trace never

./harness/run-isolated \
  harness/cases/codex-61260-worktree-current.json \
  --target harness/targets/codex-0.147.0/vendor/x86_64-unknown-linux-musl/bin/codex \
  --trace never
```

`compare-codex-61260-variants`는 golden, normal repo, worktree, symlink repo, nested repo,
gitdir/commondir, config reload를 세 target 버전에서 실행하고, session resume은 current 전용으로
실행한다. 통합 결과는
`harness/runs/compare-codex-61260-variants/<timestamp-id>/artifacts/result.json`에 저장되며,
`summary.attempts[*].variant`로 어느 repository 형태에서 나온 결과인지 구분할 수 있다. 전체 variant를
항상 돌릴 필요가 없으면 `--variant symlink-repo,nested-repo`처럼 쉼표로 범위를 제한한다. 특정 역할만
확인하려면 `--role current` 또는 `--role known-fixed,current`를 사용한다.

`local/executor MCP`와 `subagent`는 별도 설계 문서로 관리한다.

- `harness/designs/codex-61260-local-executor-mcp.md`
- `harness/designs/codex-61260-subagent-variant.md`

## 대상 아티팩트 등록

대상 다운로드는 의도적으로 자동화하지 않는다. vendor 약관에 따라 정확한 historical artifact를
확보하고 출처를 검증한 뒤 Git 외부 경로(예: `harness/targets/`)에 저장한다. 경로와 SHA-256은
`harness/versions/manifest.json`에 기록한다. 보고서 수준의 증거로 실행을 사용하기 전에는 해당
hash를 case의 `target.allowed_sha256` 목록에도 복사한다.

격리 환경에서 실행하는 예시는 다음과 같다.

```bash
./harness/run-isolated \
  harness/cases/codex-61260-vulnerable.json \
  --target harness/targets/codex-0.21.0/bin/codex-x86_64-unknown-linux-musl
```

비교 명령에 필요한 target은 다음 세 개다.

| 역할 | 버전 | 예상 결과 |
|---|---:|---|
| known-vulnerable | 0.21.0 | `outside/mcp-started` 생성 |
| known-fixed | 0.22.0 | `outside/mcp-started` 미생성 |
| current | 0.147.0 | `outside/mcp-started` 미생성 |

`current`는 자동으로 움직이는 별칭이 아니다. 실험 재현성을 위해 등록 시점의 공식 최신 버전과
배포 아티팩트 hash를 고정한다. 새 버전을 등록할 때는 아티팩트, manifest, current case의 버전과
허용 SHA-256을 함께 갱신한다.

CVE-2025-61260 case는 이 repository에 정리된 분석을 기반으로 만든 기본 골격이다. historical CLI의
packaging 또는 인증 동작에 따라 adapter 조정이 필요할 수 있다. historical artifact를 실행하기
위해 외부 실험 환경의 격리를 약화하지 않는다.

## 연구 agent 자동화

`harness/analyze`는 설치된 연구용 Codex를 ephemeral read-only session으로 실행한다. 사용자의
ambient config와 exec-policy rule은 무시하고 JSONL event를 출력하며, 최종 응답을
`harness/schemas/hypothesis.schema.json`으로 제한한다. tool subprocess는 ambient environment를
상속하지 않으며 고정된 `PATH`와 locale만 전달받는다. Codex 인증은 parent Codex process에만
남아 있어야 하며 case 또는 대상 environment에 복사해서는 안 된다.

```bash
./harness/analyze "harness/prompts/mapper.md를 사용해 config trust subsystem을 매핑하세요."
```

API key를 대상 process 또는 repository가 통제하는 코드에 노출하지 않는다. 전체 agent E2E가
필요하면 대상이 지원하는 경우 전용 test credential 또는 local deterministic model/API stub을
사용한다.

## Case 추가

1. `harness/cases/selftest-marker.json`을 복사한다.
2. command는 argv 배열로 유지하며 편의를 위해 `sh -c`를 추가하지 않는다.
3. 공격자가 통제하는 입력은 `harness/fixtures/` 아래에 둔다.
4. `.git` file처럼 Git에 직접 넣기 어려운 실행 시점 구조는 `generated_files`로 만든다.
5. symlink가 필요한 filesystem variant는 `generated_symlinks`로 만들고, 절대경로와 `..`를 쓰지 않는다.
6. 하위 repo에서 실행해야 하는 case는 `execution.cwd_relative`로 cwd를 명시한다.
7. 대상을 실행하는 case는 `host_safe: false`로 표시한다.
8. exit, 생성, 부재, 불변 또는 content oracle을 정확히 정의한다.
9. `run-case --validate-only`로 case를 검증한다.
10. 현재 build를 시험하기 전에 알려진 취약 버전과 수정 버전으로 하네스를 증명한다.
