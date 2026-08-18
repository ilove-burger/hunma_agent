# hunma_agent

> OpenAI Codex와 Anthropic Claude Code의 취약점을 **보안 불변식**, **취약 primitive**,
> **민감한 sink**, **패치 경계**, **variant hunting** 관점에서 분석하고 재현하는 보안 연구 저장소다.

이 프로젝트는 CVE 설명을 모아 놓은 목록이 아니다. 각 취약점에서 실제로 깨진 보안 경계를
추출하고, 공격자가 얻는 최소 capability와 최종 impact를 분리하며, 같은 root cause가 다른 기능에
남아 있는지 조사할 수 있는 형태로 정리한다. 공개 소스·배포 아티팩트·패치·동적 재현 결과를
구분하고, marker-only 하네스로 취약 버전과 수정 버전을 비교한다.

## 무엇을 연구하는가

Coding agent는 repository, shell, filesystem, network, MCP, 사용자 승인을 하나의 실행 흐름으로
연결한다. 이 과정에서 보안 검사가 이해한 대상과 실제 실행된 capability가 달라지면 경계가 깨진다.

이 저장소는 주로 다음 질문을 다룬다.

- 승인된 command identity와 실제 command capability가 같은가?
- 신뢰되지 않은 project state가 trust 결정 전에 control plane에 반영되는가?
- 문자열로 검사한 path와 실제 filesystem object가 같은가?
- local mutation이 없다는 사실이 attacker-observable side effect도 없음을 의미하는가?
- 패치가 특정 syntax만 막았는가, 아니면 깨진 invariant 전체를 복원했는가?

상세 분류와 전체 CVE 목록은 **[One-day Dataset Index](INDEX.md)**에서 확인할 수 있다.

## 현재 데이터셋

| 대상 | 분석 문서 | 범위 |
|---|---:|---|
| [OpenAI Codex](codex/) | 4 | CLI, IDE extension, approval, sandbox, config/MCP |
| [Anthropic Claude Code](claude/) | 21 | command policy, trust, filesystem, network, hooks/MCP |
| **합계** | **25** | root-cause 및 security-invariant 중심 분석 |

취약점은 하나의 주된 invariant family에 배치한다.

| Family | 핵심 불일치 | 전체 목록 |
|---|---|---|
| Command / Capability | 허용된 명령의 표면적 의미 `≠` 실제 실행 capability | [보기](INDEX.md#command--capability) |
| Trust / Initialization | untrusted state `≠` trusted control state | [보기](INDEX.md#trust--initialization) |
| Path / Filesystem | lexical path `≠` 실제 filesystem object identity | [보기](INDEX.md#path--filesystem) |
| Network / Exfiltration | local mutation 없음 `≠` 관찰 가능한 외부 효과 없음 | [보기](INDEX.md#network--exfiltration) |

## 분석 문서가 담는 내용

모든 CVE 문서는 가능한 한 같은 구조로 작성한다.

1. 공격자가 통제하는 입력과 진입 조건
2. agent의 처리 흐름과 보안 결정 지점
3. root cause와 `X ≠ Y` 형태의 invariant mismatch
4. 공격자가 실제로 획득하는 최소 primitive
5. host process, filesystem, network 등 민감한 sink
6. primitive가 결합되어 impact에 도달하는 exploit chain
7. patch가 바꾼 enforcement point와 version boundary
8. 인접 callsite 및 semantic variant 가설
9. 취약/수정 버전을 비교하기 위한 harness handoff

새 분석 문서는 **[ONE-DAY-TEMPLATE.md](ONE-DAY-TEMPLATE.md)**를 기준으로 작성한다.

## 대표 분석

처음 읽는다면 invariant family별로 다음 문서를 권장한다.

- [CVE-2025-66032](claude/CVE-2025-66032.md): validator와 shell/utility 해석 차이로 발생한 command policy 우회
- [CVE-2025-61260](codex/CVE-2025-61260.md): project `.env`가 trusted configuration root를 바꾸고 MCP process를 실행한 trust 경계 문제
- [CVE-2026-25725](claude/CVE-2026-25725.md): 아직 존재하지 않는 path에 대한 policy와 다음 lifecycle의 protected object write capability 차이
- [CVE-2026-21852](claude/CVE-2026-21852.md): untrusted project config가 credential-bearing network control plane에 영향을 준 사례

## 저장소 구조

```text
hunma_agent/
├── INDEX.md                 # invariant family별 전체 CVE 인덱스
├── ONE-DAY-TEMPLATE.md      # 신규 분석 문서 템플릿
├── codex/                   # OpenAI Codex CVE 분석
├── claude/                  # Anthropic Claude Code CVE 분석
├── harness/                 # 격리 실행, oracle, fixture, version manifest
│   ├── cases/               # 결정론적 실험 정의
│   ├── fixtures/            # 공격자가 통제하는 최소 입력
│   ├── prompts/             # mapper, variant generator, 반증 검토 프롬프트
│   ├── schemas/             # case, result, hypothesis JSON schema
│   ├── versions/            # 대상 버전과 SHA-256
│   └── runs/                # 실행 증거; Git 제외
└── AGENTS.md                # 연구 agent가 따라야 할 범위와 안전 규칙
```

## 재현 하네스

하네스는 논리적 `workspace`, `outside`, `fake-home`, `tmp`를 만들고 다음 증거를 보존한다.

- 대상 binary/package의 version과 SHA-256
- 정제된 environment key 목록과 OS/kernel, namespace, `bwrap`/`strace` metadata
- stdout, stderr, exit status
- 실행 전후 filesystem snapshot과 content hash
- 가능한 경우 `strace` process trace
- marker 생성·부재·불변·정확한 content oracle

기본 검증:

```bash
./harness/test
./harness/run-isolated harness/cases/selftest-marker.json
./harness/run-isolated harness/cases/selftest-negative.json
```

`selftest-marker`는 marker 생성 관찰이 동작하는지 확인하고, `selftest-negative`는 대상이 아무 작업도
하지 않을 때 하네스가 marker를 잘못 만들지 않는지 확인한다.

CVE-2025-61260의 취약·수정·current 골든 비교:

```bash
./harness/compare-codex-61260
./harness/compare-codex-61260-variants
```

비교 명령은 세 배포 아티팩트의 SHA-256을 먼저 검증하고 격리된 case를 순서대로 실행한다.
통합 `result.json`, 이벤트 `events.jsonl`, 각 실행의 stdout·stderr와 원본 결과 경로가 보존된다.
`normal repo`, `worktree`, `symlink repo`, `nested repo`, `gitdir/commondir`, `config reload`,
`session resume` 형태의 CVE-2025-61260 variant case도 포함되어 있어 repository 형태와 lifecycle이
바뀌어도 같은 trust boundary가 유지되는지 비교할 수 있다. Variant 비교 결과는
`summary.summary_table` matrix로도 요약된다.

설치와 case 작성 방법은 **[하네스 문서](harness/README.md)**를 참고한다. Historical binary와 실행
결과는 Git에 포함하지 않으며, hash와 manifest만 버전 관리한다.

## Codex를 이용한 variant hunting

`harness/analyze`는 연구용 Codex를 read-only·ephemeral session으로 실행하고 JSON schema에 맞는
후보를 출력하게 한다. 분석 범위를 subsystem 하나로 제한해 source → decision → sink 흐름을 먼저
매핑하는 방식이 권장된다.

```bash
./harness/analyze \
  "harness/prompts/mapper.md를 사용해 project trust → config layer → MCP spawn 경계를 매핑하세요."
```

제공되는 프롬프트:

- [보안 경계 매퍼](harness/prompts/mapper.md)
- [불변식 변형 생성기](harness/prompts/variant-generator.md)
- [취약점 반증 검토자](harness/prompts/skeptic.md)

## 연구 흐름

```text
공개 advisory / source / 배포 artifact
                ↓
attacker-controlled source 식별
                ↓
parser / normalizer / security decision 추적
                ↓
민감한 sink와 최소 primitive 확인
                ↓
known-vulnerable ↔ known-fixed 비교
                ↓
security invariant 추출
                ↓
현재 버전의 인접 callsite와 semantic variant 탐색
                ↓
반증, 중복 조사, vendor report
```

## 증거와 안전 기준

- 직접 확인한 사실, 소스 기반 추론, 미검증 가설을 구분한다.
- 실제 자격 증명, 사용자 데이터, 외부 시스템을 PoC에 사용하지 않는다.
- command execution 대신 가능한 한 marker file/process로 최소 primitive만 증명한다.
- 취약한 대상은 network가 차단된 disposable VM 또는 `run-isolated` 외부 경계에서 실행한다.
- `run-case`의 디렉터리 구조는 oracle이지 단독 security sandbox가 아니다.
- current/fixed negative control 없이 후보를 신규 취약점으로 단정하지 않는다.

세부 안전 규칙은 **[AGENTS.md](AGENTS.md)**에 정의되어 있다.
