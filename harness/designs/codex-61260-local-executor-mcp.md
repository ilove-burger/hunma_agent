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
