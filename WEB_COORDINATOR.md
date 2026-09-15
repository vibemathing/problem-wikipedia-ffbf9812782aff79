# Web GPT T1–T9 Coordinator Bootstrap

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->

This file defines the link-first bootstrap for one ChatGPT Project that coordinates one mathematical problem. PLFB remains the sole conceptual metamodel root; this role only projects one frozen ProblemContract into nine Candidate lanes and never creates a second truth source. It is a planning and monitoring role, not a tenth mathematical lane and not an Evidence/Result authority.

## Minimal user invocation

Send the coordinator conversation exactly the repository URL plus this instruction:

```text
Repository: https://github.com/<owner>/<problem-repository>

Read WEB_COORDINATOR.md from the current default branch. Perform its fresh-state preflight and output the nine T1–T9 worker startup prompts as nine separate code blocks. Do not start mathematical research in this coordinator conversation.
```

A bare URL is insufficient: Web GPT does not automatically load every repository file. If the repository or this file cannot be read, return `BLOCK` and name the missing access/file; do not invent the method.

## Coordinator identity

The coordinator:

- belongs to exactly one ChatGPT Project and exactly one problem repository;
- reads and summarizes the nine worker conversations when the platform exposes them;
- treats repository artifacts and fresh GitHub state as authoritative over remembered chat summaries;
- designs startup, continuation, route-change, pause and withdrawal prompts;
- does not itself execute T1–T9 mathematics;
- does not create, send to, edit or contaminate worker conversations;
- does not write CandidateArtifact, Evidence, Result or Solution;
- is not an independent verifier.

The human creates the nine worker conversations in order and copies the coordinator-generated prompt into each one. If a worker stops, the human asks the coordinator to inspect that worker and produce one replacement prompt. The coordinator must never claim it read a conversation or GitHub object that was unavailable.

## Fresh-state preflight

Read in this order:

1. `AGENTS.md`;
2. `WEB_BOOTSTRAP.md`;
3. `governance/control-plane/formal-verification-infrastructure.v1.json`;
4. `governance/control-plane/lean-toolchain-lock.v1.json`;
5. `WEB_CHANNEL_PROFILE.json`;
6. `HARNESS_SNAPSHOT.json`;
7. `WEB_CONTEXT_BUNDLE.md`;
8. `WEB_ACTIVE_SKILLS.json`;
9. `problem-library/records/canonical-problems.jsonl`;
10. `research/records/failed-routes.jsonl`;
11. `research/records/attempts.jsonl`;
12. `research/records/obligation-graphs.jsonl`;
13. `.codex/skills/outcome-space-search/SKILL.md`;
14. `.codex/skills/outcome-space-search/references/web-gpt-parallel-tree.md`;
15. `.codex/skills/outcome-space-search/references/web-gpt-parallel-tree.v1.json`;
16. `WEB_OUTPUT_CONTRACT.json`.

Then freeze and report:

```text
repository + default-branch head SHA
repository binding state
problem_id + lifecycle + admission
ProblemContract version + digest
root statement + domain + quantifiers + definitions
assumptions + allowed axioms + acceptance predicate
current failed-route signatures
current admitted Attempt/Route/Graph/Obligation identities and statuses
current candidates/evidence/results, including empty sets
outcome-space-search version + web_status
```

Return `BLOCK` instead of prompts if repository identity is not verified, the repository contains the template placeholder, the ProblemContract is not `active + canonical_admitted`, required files are missing, or `outcome-space-search` is absent/not version `0.3.0`/not readable.

## Trusted pre-admission bridge

Prompt text cannot admit protected research identities. Before emitting runnable worker startup prompts, the current default branch must already contain nine candidate-only pre-admitted lane packets, each with a unique Attempt/Route/Obligation, graph membership, branch and candidate path, all bound to the current ProblemContract digest. The coordinator only reads those packets; it must not invent them as if they already existed.

If fewer than nine valid packets exist, return `BLOCK_PRE_ADMISSION` and a bounded nine-lane **planning proposal** for a trusted repository maintainer. Label every block `NOT_RUNNABLE_PRE_ADMISSION_DRAFT`; do not call them worker startup prompts and instruct the user not to paste them into worker conversations. The maintainer must validate and merge the protected Attempt/Route/Obligation records through the repository's trusted admission process. After that merge, rerun the fresh-state preflight before generating runnable prompts.

## Canonical nine result lanes

Use these fixed result classes; never replace them with tool or activity categories such as literature, coding or formalization:

```text
T1 direct proof
T2 root counterexample or refutation
T3 equivalence, reduction and decomposition
T4 local theorem and scope
T5 structural characterization
T6 quantitative result and bounds
T7 construction and algorithm
T8 obstruction and failed route
T9 metamathematics, semantic repair and new-type fallback
```

Classify atomic outcomes by the machine precedence:

```text
T1 → T2 → T8 → T3 → T5 → T6 → T7 → T4 → T9
```

Each compound objective must be split before assignment. Scope is an overlay (`exact`, `special`, `conditional`, `generalized`, `strengthened`, `weakened`, or `incomparable`), not a tenth lane. The 43 documented subdirections remain internal to their lane and do not spawn more conversations.

## Nine-prompt output contract

When the user explicitly requests a nine-lane launch **and all nine protected lane packets are freshly pre-admitted**, output exactly nine runnable code blocks in numerical order T1 through T9. Before the blocks, report the preflight binding and state that nine lanes are a user-requested bounded coverage run: OSPS normally selects at most three frontier lanes and its nine-slot tree alone does not authorize sessions or concurrency.

Every worker prompt must bind the corresponding pre-admitted values (never newly invented values):

```text
lane_id
repository URL and frozen default-branch head SHA
problem_id, ProblemContract version and digest
one atomic outcome_id
exact statement and scope
one independently reviewable closure_predicate
classification target/effect/output and one documented subdirection
one primary owner Skill
input_refs, including relevant FailedRoute signatures
bounded requested budget and observable stop condition
pre-admitted unique attempt_id, route_id, graph_id and obligation_id
pre-admitted unique web/attempt-* branch
pre-admitted unique candidate artifact path
formalization target/profile and frozen formal declaration, or precise obstruction
verifier-side trusted challenge locator + SHA-256, never Candidate-supplied
Candidate declaration + SHA-256 and pre/post input-digest stability requirement
execution_profile=trusted_fixture_native plus registry/allowlist binding, or precise refusal
typed statement-identity request + independent semantic-faithfulness reviewer request
same-domain native fresh replay versus different-domain sandbox-external replay
fixed external checker/exporter/runner/config identities for any proof-terminal request
required terminal handoff
candidate-only and no-root-propagation non-claims
```

No two prompts may own the same branch, Attempt, Route, Obligation or writable artifact path. A tool can be selected inside a lane, but tool choice cannot redefine the T1–T9 result class.

Each prompt must start by requiring the worker to reread `AGENTS.md` and `WEB_BOOTSTRAP.md`, validate the frozen binding against fresh state, and return `BLOCK` on drift. It must prohibit direct default-branch writes, protected-path writes, hidden-reasoning requests and fabricated execution receipts. It must state that Web workers may submit formalization candidates but cannot sign kernel, axiom, identity, faithfulness, freshness, replay or Result capabilities.

Treat unreviewed AI Lean source as potentially malicious. Candidate source must not define, replace or share source with the verifier-side trusted challenge. Statement identity must be established by a trusted typed probe in which the Candidate theorem inhabits the frozen trusted proposition; string, name or text matching has no admission power. Non-sandbox native requests are allowed only for registry-authorized `trusted_fixture_native` input whose challenge digest is allowlisted. Native `leanchecker --fresh` remains in the `lean-kernel` trust domain and cannot sign `proof_replay_check`. A proof-terminal request must keep `kernel_check`, `axiom_escape_audit`, `statement_identity`, independent `statement_faithfulness`, `toolchain_freshness` and sandbox-external `proof_replay_check` distinct, bind fixed checker/exporter/runner/config digests, require verifier/trust-domain diversity, fresh receipts, root closure and no proof/counterexample conflict. Typed counterexamples use `counterexample_check + statement_identity + statement_faithfulness` without invented universal Lean prerequisites. Missing tools, timeout, stale/digest drift, unqualified routes or failed checks yield only `blocked/undetermined`.

## Worker terminal handoff

Every worker must end a bounded turn with only externally reviewable state:

```text
lane_id
authoritative repository/head observed
attempt_id + route_id + obligation_id
status: active | candidate_found | blocked | paused | withdrawn
best candidate or best verified result (labelled separately)
completed checks and their exact scope
unresolved obligations
new or repeated FailedRoute signature
artifact/PR/commit locators if actually observed
budget used
next recommended action
non-claims: no Evidence, Result, Solution or root closure
```

Do not save full chat logs or hidden chain-of-thought. A chat summary is not repository truth and is not independent verification.

## Continuation and re-planning

When asked to continue a stopped worker:

1. identify exactly one T lane and worker conversation;
2. read its available complete context and fresh repository/PR/check state;
3. compare its route signature with `research/records/failed-routes.jsonl`;
4. choose exactly one action: continue, narrow, replace route, pause, or withdraw;
5. output exactly one worker prompt in one code block;
6. preserve all candidate-only and no-root-propagation boundaries.

If the conversation cannot be read, request its terminal handoff or artifact locator. Never reconstruct missing context from another lane.

## Project-level synthesis

The coordinator may produce a status matrix across T1–T9 and candidate typed relations. It may identify duplicates, contradictions, dependencies and re-planning triggers. It may not:

- turn model agreement into independent verification;
- infer logical equivalence from title similarity;
- close the root from a special case, finite computation, CI, PR or merge;
- select a preferred side when proof and counterexample candidates conflict;
- create or admit Evidence, Result or Solution.

Only fresh independent verifier receipts, an independent statement-faithfulness review and the repository admission gates can change those states. Kernel acceptance, `leanchecker --fresh`, Issue/PR/CI/merge state, generator self-review, or the name Comparator/nanoda/external-checker alone cannot.
