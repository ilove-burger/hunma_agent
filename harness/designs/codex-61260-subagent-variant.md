# CVE-2025-61260 subagent variant 조사 및 case화 기준

## 확인한 사실

[CONFIRMED] Codex 0.21.0과 0.22.0의 CLI help에는 `resume`, `fork`, `features`, `subagent` 관련
안정 subcommand가 없다.

[CONFIRMED] current 0.147.0에는 `resume`, `fork`, `features`가 존재하고 `features list`에
`multi_agent`가 stable true로 표시된다. 하지만 `codex exec --help`, `codex --help`,
`codex features list` 어디에도 "subagent를 명시적으로 시작하는 deterministic CLI command"는
노출되지 않는다.

## 바로 case화하지 않는 이유

subagent는 model decision 또는 product-internal orchestration에 의해 발생하는 lifecycle이다. 지금
하네스는 실제 model 응답을 취약점 oracle로 쓰지 않고 marker-only filesystem/process oracle만 사용한다.

따라서 prompt에 "subagent를 사용해라"라고 쓰고 일반 `codex exec`를 실행하면 다음 문제가 생긴다.

1. subagent 생성 여부가 deterministic하지 않다.
2. marker가 생성되더라도 일반 MCP config loading 때문인지 subagent lifecycle 때문인지 분리되지 않는다.
3. 0.21.0/0.22.0에는 같은 lifecycle이 없어서 known-vulnerable/known-fixed 비교가 성립하지 않는다.

## case화 기준

다음 조건을 모두 만족할 때 `codex-61260-subagent-current.json` 또는 별도 lifecycle case로 추가한다.

1. current CLI에서 subagent 생성 또는 fanout을 강제하는 안정 입력이 확인된다.
2. parent session의 config root와 child/subagent session의 config root를 분리해서 관찰할 수 있다.
3. marker가 parent MCP spawn이 아니라 child/subagent MCP spawn에서만 생성되도록 fixture를 구성할 수 있다.
4. 반복 실행에서 같은 결과가 나온다.
5. 실제 자격 증명, 외부 network, real user config 없이 실행된다.

## 제안 oracle

- `outside/parent-mcp-started`는 absent
- `outside/subagent-mcp-started`는 current에서 absent가 기대값
- child run/session metadata가 있다면 `artifacts/session-events.jsonl`로 보존

## 현재 결론

[INFERRED] 현재 공개 CLI 표면만으로는 subagent 전용 deterministic case를 만들 수 없다. 현 단계에서는
case를 추가하지 않고 조사 결과와 case화 조건을 보존한다. 이후 current CLI에 subagent/fanout을 강제하는
안정 옵션이 확인되면 current-only negative lifecycle case부터 추가한다.
