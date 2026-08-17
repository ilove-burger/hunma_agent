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
```

제공된 Linux 외부 sandbox 안에서 case를 실행한다.

```bash
./harness/run-isolated harness/cases/selftest-marker.json
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

통합 결과와 이벤트 스트림은 각각
`harness/runs/compare-codex-61260/<timestamp-id>/artifacts/result.json`과 `events.jsonl`에 저장된다.
명령은 실행 전에 세 target이 `versions/manifest.json`에 등록되어 있는지, 실제 파일의 SHA-256이
manifest와 일치하는지 검증한다. 개별 case의 stdout·stderr와 원본 `result.json` 경로도 통합 결과에
기록한다.

`strace`가 설치되어 있으면 syscall trace를 자동으로 수집한다. 비활성화하려면 `--trace never`,
필수로 요구하려면 `--trace always`를 사용한다.

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
4. 대상을 실행하는 case는 `host_safe: false`로 표시한다.
5. exit, 생성, 부재, 불변 또는 content oracle을 정확히 정의한다.
6. `run-case --validate-only`로 case를 검증한다.
7. 현재 build를 시험하기 전에 알려진 취약 버전과 수정 버전으로 하네스를 증명한다.
