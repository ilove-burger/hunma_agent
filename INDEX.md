# One-day Dataset Index

Coding Agent 취약점을 주된 root-cause / security-invariant family로 분류한 인덱스다. 각 CVE의 근거, exploit chain, patch 분석과 variant hypothesis는 링크된 개별 문서에서 다룬다.

하나의 CVE가 여러 계열에 걸치더라도 이 인덱스에는 **주된 invariant family 한 곳**에만 배치한다. 보조 분류는 개별 문서의 Security Boundary와 OWASP Agentic 분류를 따른다.

## 분석 상태

- `소스 확인`: 취약 코드 또는 해당 버전의 실행 경로를 확인함
- `배포 artifact 확인`: 공개 source가 없는 제품의 배포 package/binary에서 취약 실행 경로를 확인함
- `패치 확인`: 수정 PR·commit 또는 fixed version을 확인함
- `공개 PoC 확인`: 제3자의 동적 재현과 evidence를 검토했으나 독립 재현하지는 않음
- `부분 동적 검증`: primitive 일부를 독립적으로 검증함
- `E2E 재현`: 취약 제품 버전에서 전체 attack flow를 재현함

## Command / Capability

명령 이름이나 표면적인 syntax가 실제 실행 capability보다 작게 평가되는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-54558](codex/CVE-2025-54558.md) | OpenAI Codex CLI | `command identity ≠ effective command capability` | 위험한 `rg` 인자의 auto-approval 및 host process spawn | 소스 확인 · 패치 확인 · 부분 동적 검증 |

## Trust / Initialization

Untrusted state가 trust 또는 authority 결정 전에 소비되거나, execution state가 trusted policy/control state로 승격되는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-59532](codex/CVE-2025-59532.md) | OpenAI Codex CLI / IDE Extension | `logical command cwd ≠ trusted sandbox policy cwd` | model-controlled sandbox writable-root relocation 및 outside-workspace file write | 소스 확인 · 패치 확인 |
| [CVE-2025-61260](codex/CVE-2025-61260.md) | OpenAI Codex CLI | `untrusted project environment ≠ trusted configuration locator` | configuration-root redirection 및 attacker-controlled MCP host process spawn | 소스 확인 · 패치 확인 · E2E 재현 |

## Path / Filesystem

lexical path와 실제 filesystem object identity가 달라 권한 또는 sandbox 경계를 우회하는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-55345](codex/CVE-2025-55345.md) | OpenAI Codex CLI | `lexically in-root path ≠ filesystem object confined to that root` | auto-approved `apply_patch`를 통한 outside-workspace file overwrite | 소스 확인 · 패치 확인 · 부분 동적 검증 |
| [CVE-2025-54794](claude/CVE-2025-54794.md) | Anthropic Claude Code | `string prefix relation ≠ directory containment relation` | same-prefix sibling path의 outside-CWD file access 및 permission bypass | 배포 artifact 확인 · 패치 확인 · 공개 PoC 확인 · 부분 동적 검증 |

## Network / Exfiltration

Browser, local IPC 또는 outbound request가 trust/authorization boundary를 넘어 privileged agent capability나 attacker-observable channel로 연결되는 계열.

| CVE | 제품 | Root Cause | Vulnerable Primitive | 분석 상태 |
|---|---|---|---|---|
| [CVE-2025-52882](claude/CVE-2025-52882.md) | Anthropic Claude Code IDE Extensions | `loopback reachability ≠ authenticated trusted-client identity` | unauthenticated IDE MCP channel attachment 및 privileged tool invocation | 배포 artifact 확인 · 패치 확인 · 공개 PoC 확인 |
