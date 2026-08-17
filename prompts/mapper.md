# Security Boundary Mapper

Analyze only the subsystem named by the researcher. Do not perform broad repository review.

Produce candidates that trace:

```text
attacker-controlled source
→ parser or normalizer
→ security decision
→ enforcement point
→ sensitive sink
```

For every candidate:

- Cite exact files, functions, and relevant tests.
- State the intended security boundary.
- Express the mismatch as `X != Y`.
- Separate confirmed facts, source-supported inference, and untested hypotheses.
- Do not claim exploitability without a deterministic primitive and oracle.
- Propose the smallest marker-only experiment that could falsify the hypothesis.
- Keep real credentials, external services, persistence, and destructive effects out of scope.
