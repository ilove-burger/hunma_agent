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

## source-level 조사 [CONFIRMED]

CLI `--help` 표면만으로는 결론을 낼 수 없어 `openai/codex` 공개 GitHub 저장소를 직접 확인했다
(commit `f47f77a`, 2026-08-18 clone; 이 저장소의 `harness/versions/manifest.json`에 등록된 배포
아티팩트가 아니라 vendor의 공개 source repository이므로 harness 대상 다운로드 자동화 금지 규칙과
무관하다. `harness/targets/`에는 추가하지 않았다). 소스에서 확인한 사실을 실제 `codex-0.147.0`
바이너리의 `codex features list` 출력과 교차 검증했다.

1. **`spawn_agent`는 CLI subcommand가 아니라 model tool 이름이다.** `codex-rs/protocol/src/models.rs`의
   tool schema에 `"name": "spawn_agent"`가 정의되어 있고, `codex-rs/protocol/src/items.rs`의
   `CollabAgentTool::SpawnAgent` variant가 이를 가리킨다. 실제 spawn은
   `codex-rs/core/src/thread_manager.rs`의 `AgentControl`이 처리하며 (`agent.rs`의
   `AgentControl`), 세션 메타데이터에는 `SessionSource::SubAgent(SubAgentSource::ThreadSpawn { .. })`가
   기록된다. 즉 subagent 생성은 여전히 model이 tool call을 실행할지 결정하는 지점에 있다.
2. **관련 feature flag 두 개가 존재하며 상태가 다르다.** `codex features list` (0.147.0, 실제 실행
   결과)를 보면 `multi_agent`는 `stable true` (기본 활성화), `multi_agent_v2`는 `stable false`
   (opt-in). 소스의 `codex-rs/features/src/lib.rs`는 `multi_agent_v2`를
   `Option<FeatureToml<MultiAgentV2ConfigToml>>`로 정의하고 `-c features.multi_agent_v2.enabled=true`
   또는 `--enable multi_agent_v2`로 켤 수 있다. **`multi_agent`가 이미 기본 stable=true이므로,
   추가 flag 없이도 model이 매 current 세션에서 `spawn_agent`류 tool을 호출할 잠재력을 이미 갖는다** —
   design doc 최초 조사(“CLI 표면에 subagent를 강제하는 안정 입력 없음”)는 여전히 맞지만, "잠재
   capability 자체가 기본 비활성"이라는 인상은 정정한다.
3. **`enable_fanout`, `multi_agent_mode`는 `removed` 상태다.** `codex features list` 출력에
   `enable_fanout  removed  false`, `multi_agent_mode  removed  false`로 나온다. 즉 "fanout"이라는
   이름의 flag가 과거에 존재했지만 현재는 dead code에 가깝다 — `codex-rs/cli/src/main.rs`의
   `feature_toggles_accept_removed_enable_fanout_flag` 테스트가 `--enable enable_fanout`을 여전히
   `features.enable_fanout=true`로 파싱만 하고 실질 동작에 연결하지 않는 하위호환 처리임을 보여준다.
   fanout을 강제하는 살아있는 CLI/config entry는 없다.
4. **subagent lifecycle 전용 hook이 이미 stable 기능(`hooks`, stable true)의 일부로 존재한다.**
   `codex-rs/config/src/hook_config.rs`의 `subagent_start`/`subagent_stop` 필드가 top-level
   `[hooks]` config 아래 매처 그룹으로 노출되고, `codex-rs/hooks/src/lib.rs`가
   `HookEventName::SubagentStart` → `"subagent_start"`로 직렬화한다.
   `codex-rs/core/tests/suite/subagent_notifications.rs`는 이 hook에 python script를 연결해
   `subagent_start_hook_log.jsonl`/`subagent_stop_hook_log.jsonl`로 관찰하는 패턴을 보여준다.

## 갱신된 결론

[INFERRED] source-level 조사로도 subagent 생성을 model 추론 없이 강제하는 deterministic 입력은
확인되지 않았다 — `spawn_agent`는 여전히 tool-call 결정이고, `enable_fanout`은 dead flag다. 따라서
현재 하네스(실제 model 응답을 oracle로 쓰지 않는 marker-only 원칙)의 제약 안에서는 여전히 case를
추가하지 않는다.

다만 향후 실제 model 응답을 곁들인 실험(하네스 범위 밖)을 하게 되면, `[hooks.subagent_start]`/
`[hooks.subagent_stop]`에 marker-writing 스크립트를 등록하고 `multi_agent`(기본 stable) 또는
`-c features.multi_agent_v2.enabled=true`로 명시적으로 조건을 통제한 뒤, "subagent를 사용해라"류
프롬프트로 관찰하는 조합이 가장 낮은 노이즈의 oracle 후보다. 이 hook은 이미 stable 기능의 일부이므로
당장의 case화 기준 4개 중 그 무엇도 이 발견만으로는 충족되지 않지만, 실험 설계 시 marker 지점으로
재사용할 수 있어 기록해 둔다.
