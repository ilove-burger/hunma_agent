# Hunma Harness

This harness turns agent-security hypotheses into repeatable, marker-only experiments. It deliberately
separates the research agent from the target product and records machine-verifiable filesystem and
process evidence.

## Safety boundary

`run-case` creates a fresh logical lab under `harness/runs/` with separate `workspace`, `outside`,
`fake-home`, and `tmp` directories. This directory layout is an oracle, not a security sandbox.
Cases with `host_safe: false` refuse to run unless `--isolated-lab-confirmed` is supplied. Run those
cases inside a disposable VM or a purpose-built outer container, as an unprivileged user, with no real
credentials and with outbound networking disabled.

The runner removes common API and repository credentials from the child environment. It never invokes
a shell string: case commands are explicit argv arrays. Filesystem snapshots are bounded to 10,000
entries and files up to 8 MiB are hashed.

Cases that test environment-derived locator behavior may explicitly remove `CODEX_HOME` with
`execution.unset_environment`; the runner still forces a disposable `HOME` and refuses to remove its
core safety variables. `execution.observation_seconds` provides a bounded startup window for a
marker oracle and records that the target process group was intentionally terminated afterward.

## Quick start

Validate Python and all case manifests, then run the harmless self-test:

```bash
./harness/test
```

Run only the self-test:

```bash
./harness/run-case harness/cases/selftest-marker.json
```

Run a case inside the supplied Linux outer sandbox:

```bash
./harness/run-isolated harness/cases/selftest-marker.json
```

`run-isolated` uses bubblewrap to create separate user, PID, network, UTS, and IPC namespaces. It
makes the host root read-only, masks the invoking user's home, exposes only this repository, gives
write access only to `harness/runs`, mounts `harness/targets` read-only, drops capabilities, and uses
fresh `/tmp`, `/run`, `/proc`, and `/dev` mounts. This is the preferred local entry point on Linux.
Use a disposable VM as the outermost boundary for final sandbox-escape evidence or platform-specific
kernel research.

Each run prints a JSON result and writes full evidence beneath:

```text
harness/runs/<case>/<timestamp-id>/artifacts/
```

When `strace` is installed, syscall traces are captured automatically. Use `--trace never` to disable
or `--trace always` to require it.

## Registering target artifacts

Target downloads are intentionally not automated. Acquire exact historical artifacts in accordance
with the vendor's terms, verify their provenance, store them outside Git (for example in
`harness/targets/`), and record the path and SHA-256 in `harness/versions/manifest.json`. Then copy the
hash into the case's `target.allowed_sha256` list before treating a run as report-quality evidence.

Example invocation inside an already isolated lab:

```bash
./harness/run-isolated \
  harness/cases/codex-61260-vulnerable.json \
  --target harness/targets/codex-0.21.0/bin/codex-x86_64-unknown-linux-musl
```

The CVE-2025-61260 cases are scaffolds based on the repository's documented handoff. Historical CLI
packaging and authentication behavior may require an adapter adjustment. Do not weaken the outer lab
to make a historical artifact run.

## Research-agent automation

`harness/analyze` invokes the installed research Codex with an ephemeral, read-only session, ignores
ambient user config and exec-policy rules, emits JSONL events, and constrains the final answer with
`harness/schemas/hypothesis.schema.json`. Tool subprocesses inherit no ambient environment; only a
fixed `PATH` and locale are injected. Codex authentication remains in the parent Codex process and
must never be copied into a case or target environment.

```bash
./harness/analyze "Use prompts/mapper.md to map the config trust subsystem."
```

Do not expose an API key to a target process or repository-controlled code. Full agent E2E should use
a dedicated test credential or a local deterministic model/API stub where the target supports one.

## Adding a case

1. Copy `harness/cases/selftest-marker.json`.
2. Keep commands as argv arrays; never add `sh -c` merely for convenience.
3. Put attacker-controlled input below `harness/fixtures/`.
4. Mark any target execution as `host_safe: false`.
5. Define exact exit, creation, absence, unchanged, or content oracles.
6. Validate the case with `run-case --validate-only`.
7. Prove the harness with a known-vulnerable and known-fixed version before testing current builds.
