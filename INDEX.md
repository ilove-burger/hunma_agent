# One-day Dataset Index

Coding Agent 취약점을 주된 root-cause / security-invariant family로 분류한 인덱스다. 각 CVE의 근거, exploit chain, patch 분석과 variant hypothesis는 링크된 개별 문서에서 다룬다.

하나의 CVE가 여러 계열에 걸치더라도 이 인덱스에는 **주된 invariant family 한 곳**에만 배치한다. 보조 분류는 개별 문서의 Security Boundary와 OWASP Agentic 분류를 따른다.

## 분석 상태

- `소스 확인`: 취약 코드 또는 해당 버전의 실행 경로를 확인함
- `패치 확인`: 수정 PR·commit 또는 fixed version을 확인함
- `부분 동적 검증`: primitive 일부를 독립적으로 검증함
- `E2E 재현`: 취약 제품 버전에서 전체 attack flow를 재현함

## Command / Capability

명령 이름이나 표면적인 syntax가 실제 실행 capability보다 작게 평가되는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-54558](codex/CVE-2025-54558.md) | OpenAI Codex CLI | `command identity ≠ effective command capability` | 위험한 `rg` 인자의 auto-approval 및 host process spawn | 소스 확인 · 패치 확인 · 부분 동적 검증 |

## Trust / Initialization

아직 등록된 CVE 없음.

## Path / Filesystem

lexical path와 실제 filesystem object identity가 달라 권한 또는 sandbox 경계를 우회하는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-55345](codex/CVE-2025-55345.md) | OpenAI Codex CLI | `lexically in-root path ≠ filesystem object confined to that root` | auto-approved `apply_patch`를 통한 outside-workspace file overwrite | 소스 확인 · 패치 확인 · 부분 동적 검증 |

## Network / Exfiltration

아직 등록된 CVE 없음.
