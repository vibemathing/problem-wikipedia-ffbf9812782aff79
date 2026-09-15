# Web Single-Problem Research Space Guide

`research/` holds the research chain for the repository's one canonical ProblemContract.

## Verified discovery loop

<!-- VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1 -->

This space inherits `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md`. Every Attempt/Route/Obligation/Candidate/receipt/EvidenceLink/Result transition binds stable identity and statement digest. Steps are bounded and checkpointed; failed routes and conflicts remain first-class and may not be overwritten by later success logs.

## Formal verification infrastructure

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->

This space inherits `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md`. Formalization candidates bind the central Lean/Mathlib lock and an assurance profile. Treat unreviewed AI Lean source as potentially malicious: the frozen declaration and verifier-side trusted challenge stay outside Candidate control, challenge/Candidate digests are distinct, statement identity is established by a trusted typed probe rather than text matching, and semantic faithfulness requires independent review. Native kernel, axiom/escape audit, identity, faithfulness, freshness and replay stay separate. Non-sandbox native input requires registry-authorized `trusted_fixture_native` plus an allowlisted challenge digest; native `leanchecker --fresh` remains same-domain `lean-kernel`, not `proof_replay_check`. A terminal proof replay request must name fixed checker/exporter/runner/config identities, sandbox the Candidate and use a different trust domain. Missing, timed-out, stale or unqualified routes are `blocked/undetermined`, never a refutation or Evidence.

## Mandatory reasoning discipline

<!-- MATHEMATICAL_REASONING_DISCIPLINE_V1 -->

Every route and Candidate must follow `governance/standards/MATHEMATICAL_REASONING_DISCIPLINE.md`. Bind it to frozen definitions, quantifiers, assumptions and target; expose dependencies; record applicable witness/construction, minimal-counterexample, invariant, monovariant/termination, extremal/symmetry/probability and scale/boundary checks. Ordinary induction and contraposition must use their exact valid forms. Unresolved checks stay open and cannot be replaced by computation, model confidence, CI, transport, or self-review.

- `records/attempts.jsonl`: admitted research attempts and generators.
- `records/failed-routes.jsonl`: append-only blockers and dead routes.
- `records/obligation-graphs.jsonl`: acyclic claim dependencies.
- `records/candidate-artifacts.jsonl`: registered candidate metadata.
- `records/evidence-links.jsonl`: trusted candidate-to-receipt bindings.
- `artifacts/web-inbox/`, `candidates/`, `source-notes/`: bounded candidate-writable paths when allowed by the Web profile.
- `artifacts/receipts/`: verifier/importer-owned receipts.
- `schema/`: machine contracts; research agents do not edit them.

A Web candidate agent works on one Attempt, Route, graph, and Obligation at a time. It may write only profile-allowed candidate paths. It cannot append truth ledgers, self-sign evidence, or admit Results.

Every executable verification must freeze the candidate digest and record verifier trust domain, input, method/command, exact versions, timeout/resource/output limits, exit status, output digest, and limitations. Generator and independent verifier must not be the same trust domain.

Attempt completion, checkpoint, PR merge, CI success, finite computation, and model review do not mean the mathematical problem is complete. Failed or stalled routes preserve negative knowledge and select a different route; they do not close the problem.
