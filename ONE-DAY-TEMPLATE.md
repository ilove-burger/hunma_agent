# CVE-XXXX-XXXXX

> 분석 상태: `초안` / `소스 확인` / `패치 확인` / `동적 재현` / `Impact 입증`
>
> 증거 표기: **[확인]** 직접 확인한 사실 · **[추론]** 소스에 근거한 해석 · **[가설]** 추가 검증이 필요한 주장

## [1] 개요

| 항목 | 내용 |
|---|---|
| 제품 |  |
| 영향 버전 |  |
| 패치 버전 |  |
| CVSS |  |
| Advisory |  |
| Patch / Commit |  |
| 최종 확인일 | YYYY-MM-DD |

**한 줄 요약:**

<!-- 최종 Impact가 아니라, 깨진 boundary와 획득 primitive를 중심으로 작성한다. -->

## [2] Attack Vector

**공격자가 통제하는 입력 경로:**

- Vector: <!-- malicious repository / prompt / config / symlink / network / local attacker 등 -->
- 진입 조건:

**Attacker-controlled Object:**

- Object:
- Field / Argument / Path:
- 통제 범위:

## [3] Agent Attack Flow

```text
Attacker-controlled Input
        ↓
Context Ingestion / Agent Decision
        ↓
Tool / Config / Trust Processing
        ↓
Permission / Approval / Sandbox
        ↓
Vulnerable Primitive
        ↓
Sensitive Sink
        ↓
Impact
```

**깨진 Security Boundary:**

```text
[Untrusted side]
        ↓
[Security decision / enforcement point]
        ↓
[Trusted or privileged side]
```

## [4] OWASP Agentic 분류

- Primary:
- Secondary:
- 분류 이유:

<!-- ASI 번호를 붙이는 데 그치지 말고 실제 Agent behavior와 연결한다. -->

## [5] Root Cause

**한 문장:**

> [취약점이 발생한 구조적 원인]

**Invariant mismatch:**

```text
X ≠ Y
```

## [6] Vulnerable Primitive

- 최소 획득 capability:
- 필요한 전제조건:
- 공격자가 통제하는 결과:
- 이 primitive만으로 입증되지 않는 것:

<!-- RCE, sandbox escape 같은 최종 Impact와 최소 capability를 구분한다. -->

## [7] Sink

- Sensitive operation:
- 실행 주체 / 권한:
- 실행 위치: <!-- sandbox / host / remote / control plane 등 -->
- Sink까지 전달되는 attacker-controlled data:

## [8] Exploit Chain

```text
Primitive A
    +
Primitive B
    ↓
Composed Capability
    ↓
Impact
```

- 입증된 Impact:
- 조건부 또는 미검증 Impact:
- 성공 조건 / 관찰 가능한 결과:

## [9] Patch

- 변경된 코드 / 동작:
- 새로 추가된 validation 또는 ordering:
- 차단된 representation:
- 패치가 적용되는 enforcement point:
- 패치 범위: `semantic class` / `specific syntax` / `불명확`
- 남아 있는 한계 또는 미확인 사항:

## [10] Security Invariant

**복원된 보안 규칙:**

> [구현 세부사항과 독립적인 형태로 작성]

- invariant가 적용돼야 하는 주체:
- invariant가 검사돼야 하는 시점:
- invariant가 보호하는 boundary:
- 현재 패치의 충족 여부: `충족` / `부분 충족` / `미확인`

## [11] Variant Hunting

### Adjacent Callsites / 기능

| 후보 | 같은 invariant가 필요한 이유 | Attacker-controlled source | Sensitive sink | 상태 |
|---|---|---|---|---|
|  |  |  |  | 미검증 |

### Variant Hypotheses

1. **[가설]**
   - Semantic equivalent:
   - Alternate parser / path / tool / lifecycle stage:
   - 예상 primitive:
   - 최소 검증 방법:

### Harness Handoff

- 재현 대상 버전:
- 비교할 패치 버전:
- 필요한 OS / 설정:
- 준비할 attacker-controlled artifact:
- Trigger:
- Expected primitive:
- Success oracle:

---

## Sources

<!-- Advisory와 실제 patch/commit을 우선한다. 각 핵심 주장 가까이에 증거 표기를 남긴다. -->

- Advisory:
- CVE record:
- Patch / commit:
- Vulnerable source:
- Fixed source:
- Reproduction / additional reference:
