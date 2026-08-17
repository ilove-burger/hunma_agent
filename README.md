# hunma_agent

Coding-agent 취약점을 security invariant, vulnerable primitive, sink, exploit chain, patch,
variant-hunting 관점에서 분석하는 연구 저장소다.

- [`INDEX.md`](INDEX.md): CVE family와 분석 상태 인덱스
- [`ONE-DAY-TEMPLATE.md`](ONE-DAY-TEMPLATE.md): 개별 분석 문서 템플릿
- [`harness/`](harness/README.md): 결정론적 marker-only 재현 하네스
- [`prompts/`](prompts/mapper.md): source mapping, variant generation, 반증용 Codex 프롬프트

하네스 자체 검증:

```bash
./harness/test
./harness/run-isolated harness/cases/selftest-marker.json
```

연구용 Codex를 읽기 전용·ephemeral·구조화 출력 모드로 실행:

```bash
./harness/analyze "Use prompts/mapper.md to map the config trust subsystem."
```

취약한 historical artifact를 실행하는 case는 논리적 workspace 밖에서 효과를 관찰하더라도
case runner 자체만으로는 호스트 격리를 제공하지 않는다. Linux에서는 `run-isolated`, 최종
sandbox-escape 증거에는 disposable VM을 사용한다.
