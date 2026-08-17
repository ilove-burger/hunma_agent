# Invariant Variant Generator

Given one confirmed historical vulnerability and one current subsystem, generate semantic variants of
the broken invariant. Do not generate arbitrary payload lists.

Vary only these dimensions when they are relevant:

- alternate callsite or tool
- alternate parser or representation
- lifecycle stage
- path or object identity
- platform/backend
- cache, retry, resume, or delegation state
- configuration provenance and merge precedence

For each hypothesis, include the attacker-controlled source, decision point, sink, required
preconditions, likely duplicate, and the smallest safe oracle. Prefer a negative test that can disprove
the candidate quickly.
