# CVE-2025-61260 local/executor MCP variant 설계

## 현재 상태

[CONFIRMED] 기존 golden 및 repository variant case는 project-controlled config에서
`[mcp_servers.marker]`를 정의하고 local command를 MCP server process로 spawn시키는 marker-only
oracle을 사용한다. 즉 이미 "local MCP command spawn" primitive를 측정하고 있다.

[CONFIRMED] Codex 0.21.0/0.22.0의 `mcp` subcommand는 "Codex itself as an MCP server" 실행
형태이며, current의 `mcp` subcommand는 `list/get/add/remove/login/logout` 관리 CLI다. 세 버전에
공통으로 존재하는 "executor MCP" 관리 lifecycle은 확인되지 않았다.

## 중복 위험

`local/executor MCP variant`를 단순히 다른 MCP server 이름이나 다른 local command로 만들면 기존
golden case와 동일한 sink를 다시 측정한다. 이 경우 variant hunting 관점의 새 coverage가 아니라
같은 primitive의 중복 case가 된다.

## case화 기준

다음 중 하나가 확인될 때 별도 case로 승격한다.

1. MCP server process가 일반 config loading 경로가 아니라 별도 executor 또는 tool runtime을 통해
   spawn된다.
2. project-controlled MCP definition이 session lifecycle 이후 reload되거나 executor registry에
   전달된다.
3. current에서만 존재하는 MCP 관리 CLI가 project-local state를 읽고 user config 또는 runtime registry에
   side effect를 남긴다.
4. local MCP server가 단순 process spawn이 아니라 tool invocation까지 도달했음을 marker-only로 관찰할
   수 있다.

## 최소 oracle 후보

- `outside/mcp-started`: MCP server process spawn 관찰
- `outside/mcp-tool-called`: MCP tool invocation까지 도달했을 때만 생성
- `fake-home/.codex/config.toml` unchanged: current MCP 관리 CLI가 trusted user config를 변경하지
  않았는지 확인

## 권장 다음 실험

current CLI에서 `codex mcp add/list/get`을 fake `CODEX_HOME`으로 실행해 다음을 확인한다.

- project `.env`가 MCP 관리 CLI의 config root에 영향을 주는가
- 관리 CLI가 user config를 쓰는가, project config를 쓰는가
- network credential이나 OAuth flow 없이 marker-only로 deterministic하게 끝낼 수 있는가

이 세 조건이 확인되기 전까지는 기존 golden case가 local MCP spawn coverage를 대표한다.

## 실험 결과 [CONFIRMED]

`codex-61260-mcp-add-config-root-current`와 `codex-61260-mcp-list-config-root-current` case로
위 세 질문을 확인했다. workspace `.env`가 `CODEX_HOME=./reload-home`으로 재지정하고
`reload-home/config.toml`에 `project-canary`라는 구분 가능한 MCP entry를 둔 상태에서:

- `codex mcp add hunma-probe -- true`는 `fake-home/.codex/config.toml`에
  `Added global MCP server 'hunma-probe'.`로 기록됐다. `workspace/reload-home/config.toml`은
  생성되지 않았다 — project `.env`의 reload가 관리 CLI의 config root에 영향을 주지 않았다.
- `codex mcp list --json`은 `[]`를 반환했다. `reload-home/config.toml`에 있던 `project-canary`
  entry가 노출되지 않았고, `fake-home/.codex/config.toml`도 새로 생성되지 않았다.
- 두 실행 모두 network나 OAuth 없이 exit 0으로 deterministic하게 끝났고, `--repeat 2`로 반복해도
  동일했다.

즉 관리 CLI는 project-controlled state가 아니라 trusted global(`$HOME/.codex`) config root만
읽고 쓴다. case화 기준 1~4 중 어느 것도 충족되지 않았으므로 별도 취약점 case가 아니라 **negative
control**로 등록한다. 새 vulnerability variant가 아니라 기존 golden case가 여전히 local MCP spawn
coverage를 대표하며, 이 실험은 관리 CLI 표면까지 같은 trust boundary가 유지됨을 추가로 확인한다.
