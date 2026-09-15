# Web Research Bootstrap

- Repository: `vibemathing/problem-wikipedia-ffbf9812782aff79`
- Repository binding: `verified`
- Repository database ID: `1372169486`
- Repository node ID: `R_kgDOUcmlDg`
- Default branch: `main`
- Visibility: `public`
- Canonical Problem: `problem:wikipedia-ffbf9812782aff79`
- ProblemContract SHA-256: `229da16e36e7adf956cdc1e223503bc944528aa291683cea241f11c6f2704fd3`
- Problem lifecycle: `draft`
- Problem admission: `preview_unadmitted`
- Harness suite: `harness-source:web-research-full` `1.8.0`
- Suite manifest SHA-256: `f258e60f82c6a89961fdb6bbfba29d863cb14685436ac7d64279a412025ad408`
- Harness snapshot SHA-256: `970d0c97953063b8507bef5ce226c1db36751515fb98dce170d4e0f8f44bb443`
- Channel: `chatgpt-web-github-issue-pr-writer`

## Required read order

1. `AGENTS.md`
2. `WEB_CHANNEL_PROFILE.json`
3. `HARNESS_SNAPSHOT.json`
4. `WEB_CONTEXT_BUNDLE.md`
5. `WEB_ACTIVE_SKILLS.json`
6. `problem-library/records/canonical-problems.jsonl`
7. `research/records/failed-routes.jsonl`
8. the current route and obligation packet named by the Issue
9. exactly the owner Skill files selected by `WEB_ACTIVE_SKILLS.json`
10. `WEB_OUTPUT_CONTRACT.json`

Return a `web-bootstrap-ack.schema.json` object before mathematical work. Hashes shown here are manifest-declared values; do not claim to have recomputed them in chat.

## AI-native writable route

After repository admission, perform the routine candidate transport end to end without project-added human handoffs:

1. Open or use one Issue labeled `web-research-question` for the bounded question.
2. Create branch `web/attempt-<attempt-suffix>`.
3. Add, revise, or delete files only under `research/artifacts/web-inbox/**`, `research/artifacts/candidates/**`, or `research/artifacts/source-notes/**`.
4. Commit real changes and open a PR using the web candidate template.
5. Monitor required checks and, when needed, rerun the existing candidate workflow.
6. Review and revise the candidate PR; this AI review is not independent mathematical review.
7. After transport checks pass, merge the candidate PR and write the next checkpoint.

Do not create repositories, direct-push the default branch, modify workflow/truth paths, force-push, cancel/dispatch Actions, or sign Evidence/Result. Follow only platform-mandatory confirmation UI; no extra human approval is required for routine candidate operations. Issue, PR, review, merge, Actions status, command exit 0, or model self-review never closes a mathematical obligation.
<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->
2. `governance/control-plane/verified-ai-math-research-foundation.v1.json`
3. `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md`
4. `governance/control-plane/formal-verification-infrastructure.v1.json`
5. `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md`
6. `governance/control-plane/lean-toolchain-lock.v1.json`
7. `WEB_CHANNEL_PROFILE.json`
8. `HARNESS_SNAPSHOT.json`
9. `WEB_CONTEXT_BUNDLE.md`
10. `WEB_ACTIVE_SKILLS.json`
11. `problem-library/records/canonical-problems.jsonl`
12. `research/records/failed-routes.jsonl`
13. the current route and obligation packet named by the Issue
14. exactly the owner Skill files selected by `WEB_ACTIVE_SKILLS.json`
15. `WEB_OUTPUT_CONTRACT.json`
For any formalization candidate, bind the frozen ProblemContract/formal declaration, verifier-side trusted challenge locator and digest, Candidate declaration and digest, and requested capability. Candidate source may not define or replace the challenge. Treat unreviewed AI Lean source as potentially malicious. Require a trusted typed identity probe and independent semantic-faithfulness review; string matching and generator self-review are non-evidence. Non-sandbox native execution is limited to registry-authorized `trusted_fixture_native` plus challenge allowlist. Native `leanchecker --fresh` stays in `lean-kernel`; proof-terminal replay must be sandbox-external, fixed to checker/exporter/runner/config identities and use a different trust domain. If any route, tool, freshness or digest precondition is missing, report only `blocked/undetermined` and continue candidate work without fabricating a receipt.
## Coordinator-only planning mode
If the user requests a one-problem T1–T9 coordination plan rather than Issue-bound mathematical work, read `WEB_COORDINATOR.md` and follow that contract. This mode does not create a research Issue, Attempt, Route, Obligation, session, branch, CandidateArtifact, Evidence or Result. It may emit runnable startup prompts only for nine matching lane packets already pre-admitted on the current default branch; otherwise it returns `BLOCK_PRE_ADMISSION` plus non-runnable planning drafts for a trusted maintainer. It is not a tenth mathematical lane. A human must create each worker conversation and copy only a freshly admitted runnable prompt; the coordinator must not claim that prompt generation launched any worker.
## Fresh-state gate precedence
At the start of every turn, refresh the default branch plus live Issue/branch/PR/check state. Current repository records outrank launch-prompt SHAs, and launch-prompt SHAs outrank old chat replies. A controlled merge may legitimately advance main or the Harness snapshot; use the fresh revision as the packet base after validating the new snapshot. Never repeat an old `BLOCK_PRE_ADMISSION` unless a fresh read proves that the exact Attempt/Route/Graph/Obligation is currently absent or mismatched.
Channel audit maturity is not repository admission. `capability_status` and connector identity fields describe how completely the exact Plugin/App identity has been audited; they do not block a repository whose current identity, canonical ProblemContract, admitted route objects, and transport controls pass. The admitted namespace remains candidate-only and grants no Evidence/Result authority.
Branch protection and automated required checks are transport controls, not demands for manual approval. Reuse the one Issue identified by `(problem_id, attempt_id, route_id, obligation_id)` and label `web-research-question`; search before create, including a second fresh search immediately before creation, so retries and concurrent turns stay idempotent.
One Web response ending is a runtime boundary, not a permission failure and not mathematical completion. Before the boundary, save the best bounded checkpoint when possible. The next turn must resume by rereading current main and live GitHub state rather than replaying a stale bootstrap decision.
1. Reuse the unique Issue labeled `web-research-question` for the exact Problem/Attempt/Route/Obligation tuple; create one only after two fresh searches find none.
