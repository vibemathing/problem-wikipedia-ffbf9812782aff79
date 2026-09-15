# Web Mathematical Skills Guide

This directory contains the fixed Skills available to the single-problem Web GPT + GitHub workflow. It does not import user-level Skills or activate upstream repositories.

Use `vibe-mathing-router` to choose exactly one primary owner Skill for the current obligation:

```text
math-discovery -> identify objects, exact statements, sources, and prior art
math-derivation -> derive intermediate claims from frozen definitions
math-computation -> design bounded checks and falsifiers; evidence ceiling applies
math-proof -> construct and adversarially audit proof/counterexample candidates
math-formalization -> encode frozen obligations and request kernel verification
solve -> broad candidate generation only
math-toolchain -> ToolPlan generation only
```

`math-computation` and `math-formalization` are constrained by runtime availability and receipts. `solve` never emits an admitted Result; `math-toolchain` never claims that its plan was executed. `nvidia-private-compute`, `auto-goal`, `auto-tmux`, compute-node orchestration, and session control are excluded from Web problem repositories.

Search registered mathematical knowledge sources before inventing new machinery. Respect exact versions, source maturity, operational status, external effects, and evidence ceilings. A Skill is a method contract, not a verifier identity or evidence level.
## Verified research foundation
<!-- VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1 -->
Every routed Skill inherits `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md`. It owns one bounded stage action in D01–D11, not a truth state. Candidate generation, typed verification, independent admission, and Result outcome must remain separate; chat, tool, GitHub, and CI completion cannot auto-promote mathematics.
## Formal verification infrastructure
<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->
Every routed Skill also inherits `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md`. Each active problem needs a formalization target/profile or precise obstruction. Unreviewed AI Lean source is potentially malicious: Candidate and verifier-side trusted challenge must be digest-bound and source-separated; statement identity is a trusted typed check, not string matching; statement faithfulness needs an independent reviewer. Non-sandbox native input is limited to registry-authorized `trusted_fixture_native` plus an allowlisted challenge digest. Native Lean build and `leanchecker --fresh` stop at same-domain `supported`; terminal AI proof admission additionally needs separate kernel, axiom/escape, identity, faithfulness and freshness capabilities plus sandbox-external, different-trust-domain replay with fixed checker/exporter/runner/config identities. Web Skills cannot sign these verifier capabilities, and unavailable or unqualified routes remain `blocked/undetermined`.
## Mandatory reasoning discipline
<!-- MATHEMATICAL_REASONING_DISCIPLINE_V1 -->
Every selected Skill inherits `governance/standards/MATHEMATICAL_REASONING_DISCIPLINE.md`: definition/scope freeze precedes derivation; dependencies and explicit witnesses must be reviewable; candidates must face counterexamples, invariants, monovariants/termination, extremal/symmetry/probability assumptions, scale/boundary checks, and evidence ceilings. Finite testing is not induction, and contraposition cannot reverse or invert an implication.
Use `vibe-mathing-router` to choose exactly one `active` or explicitly permitted `constrained` primary owner Skill for the current obligation. `inactive` Skills are bundled for review only and must not be selected:
outcome-space-search -> constrained candidate-planning-only; may classify and validate up to nine candidate slots, but may not create tasks, sessions, jobs, attempts, evidence or results
`math-computation` and `math-formalization` are constrained by runtime availability and receipts. `outcome-space-search` 0.3.0 is constrained to candidate planning and validation: its nine slots are a projection, not task/session/concurrency authorization, and this template-level profile change is not a fleet rollout. `solve` never emits an admitted Result; `math-toolchain` never claims that its plan was executed. `nvidia-private-compute`, `auto-goal`, `auto-tmux`, compute-node orchestration, and session control are excluded from Web problem repositories.
