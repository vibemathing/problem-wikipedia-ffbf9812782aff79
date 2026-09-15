# Web Research Context Bundle

This file is generated from repository truth and bounded for the web channel. It is navigation context, not a Result, EvidenceLink, verifier receipt, or permission grant.

## Mandatory order

1. Read `AGENTS.md`, `governance/harness/PROJECT_AGENTS.md`, and `WEB_BOOTSTRAP.md`.
2. Check the exact ProblemContract and its SHA-256 below.
3. Select exactly one pre-admitted Attempt/Route/ObligationGraph/Obligation.
4. Search registered mathematical knowledge sources before inventing a new theorem.
5. After repository admission, autonomously complete Issue, candidate branch/file edits, commit, PR review, checks/rerun, merge, and checkpoint within the profile.
6. Write only candidate files under the profile allowlist and one `WEB_ATTEMPT_PACKET`; do not wait for project-added routine human approvals.
7. Never claim that Issue, PR, AI review, merge, Actions status, package build, search hit, test success, or this context closes mathematics.

## Compiled repository truth

```json
{
  "active_skills": [
    {
      "entry": ".codex/skills/math-computation/SKILL.md",
      "entry_sha256": "7a4127ce27adc9929a3734774a41d7a91c283ca1d1d779ab894e56cac94efbe4",
      "skill_id": "math-computation",
      "version": "0.7.0",
      "web_status": "constrained"
    },
    {
      "entry": ".codex/skills/math-derivation/SKILL.md",
      "entry_sha256": "0373b44afd941250fbb09fb305ca29dfa2cf40b1398cfbbd3bcbd4587316c302",
      "skill_id": "math-derivation",
      "version": "0.5.0",
      "web_status": "active"
    },
    {
      "entry": ".codex/skills/math-discovery/SKILL.md",
      "entry_sha256": "b2ab9fc56b0b227bc42e62346ea112d5fd3ae17c3d4822779c3ccb53e580354e",
      "skill_id": "math-discovery",
      "version": "0.5.0",
      "web_status": "active"
    },
    {
      "entry": ".codex/skills/math-formalization/SKILL.md",
      "entry_sha256": "d206425b677e72e4037da7da02bdb3ce00064c6c10f6c60b0cf3527440b626be",
      "skill_id": "math-formalization",
      "version": "0.8.0",
      "web_status": "constrained"
    },
    {
      "entry": ".codex/skills/math-proof/SKILL.md",
      "entry_sha256": "0955a202eb5631b44501c57624f62fa93a5e24e863d245f3e5122b2d3a45727a",
      "skill_id": "math-proof",
      "version": "0.8.0",
      "web_status": "active"
    },
    {
      "entry": ".codex/skills/math-toolchain/SKILL.md",
      "entry_sha256": "f6514e01358aa2e40f8b7e3bb9221fd9abca6b7ff37ec6920f2c2cf537533f7b",
      "skill_id": "math-toolchain",
      "version": "0.2.0",
      "web_status": "constrained"
    },
    {
      "entry": ".codex/skills/outcome-space-search/SKILL.md",
      "entry_sha256": "cd86de9b4d416014be95b22b08d95d372c2512355cfecd2bd01302e4c463287e",
      "skill_id": "outcome-space-search",
      "version": "0.3.0",
      "web_status": "constrained"
    },
    {
      "entry": ".codex/skills/solve/SKILL.md",
      "entry_sha256": "ff557dc3fc2fa10df4b21e8bef251a37928f5572ccf0092c79f0d9ab90a00ec0",
      "skill_id": "solve",
      "version": "0.3.0",
      "web_status": "active"
    },
    {
      "entry": ".codex/skills/vibe-mathing-router/SKILL.md",
      "entry_sha256": "d343497990616b438defb572e233a1585b1ef17d0e3a512e0740f14e4e03ce97",
      "skill_id": "vibe-mathing-router",
      "version": "0.7.0",
      "web_status": "active"
    }
  ],
  "attempts": [],
  "failed_routes": [],
  "knowledge_operators": [
    {
      "evidence_ceiling": "discovery_only",
      "external_effect": "none",
      "operator_id": "op:identify-mathematical-object",
      "owner_skill": "math-discovery"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "read_local",
      "operator_id": "op:search-formal-theorem",
      "owner_skill": "math-discovery"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "read_network",
      "operator_id": "op:search-mathematical-database",
      "owner_skill": "math-discovery"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "read_local",
      "operator_id": "op:resolve-formal-package",
      "owner_skill": "math-formalization"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "none",
      "operator_id": "op:compare-statements",
      "owner_skill": "math-proof"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "none",
      "operator_id": "op:compose-reuse-plan",
      "owner_skill": "math-proof"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "none",
      "operator_id": "op:prove-reuse-gap",
      "owner_skill": "math-proof"
    },
    {
      "evidence_ceiling": "candidate_only",
      "external_effect": "bounded_candidate_build",
      "operator_id": "op:build-formal-candidate",
      "owner_skill": "math-formalization"
    },
    {
      "evidence_ceiling": "verifier_receipt",
      "external_effect": "bounded_candidate_build",
      "operator_id": "op:verify-formal-candidate",
      "owner_skill": "math-formalization"
    },
    {
      "evidence_ceiling": "verifier_receipt",
      "external_effect": "none",
      "operator_id": "op:review-reuse-semantics",
      "owner_skill": "math-proof"
    }
  ],
  "knowledge_sources": [
    {
      "evidence_ceiling": "candidate_only",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "formal_package_registry",
      "source_id": "lean-reservoir"
    },
    {
      "evidence_ceiling": "verifier_input",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "proof_archive",
      "source_id": "isabelle-afp"
    },
    {
      "evidence_ceiling": "candidate_only",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "mathematical_object_database",
      "source_id": "oeis"
    },
    {
      "evidence_ceiling": "candidate_only",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "formal_library_index",
      "source_id": "mathlib-docs-search"
    },
    {
      "evidence_ceiling": "candidate_only",
      "maturity": "surveyed",
      "operational_status": "available",
      "source_class": "formula_reference",
      "source_id": "nist-dlmf"
    },
    {
      "evidence_ceiling": "computation_evidence",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "algorithm_distribution",
      "source_id": "sagemath"
    },
    {
      "evidence_ceiling": "candidate_only",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "mathematical_object_database",
      "source_id": "lmfdb"
    },
    {
      "evidence_ceiling": "verifier_input",
      "maturity": "installed",
      "operational_status": "available",
      "source_class": "formal_library_index",
      "source_id": "lean-mathlib-local"
    },
    {
      "evidence_ceiling": "verifier_input",
      "maturity": "surveyed",
      "operational_status": "design_only",
      "source_class": "formal_package_registry",
      "source_id": "rocq-mathcomp"
    }
  ],
  "obligation_graphs": [],
  "problem_contract": {
    "acceptance": {
      "policy": "solution-admission-v1"
    },
    "aliases": [
      "wikipedia:wikipedia-ffbf9812782aff79"
    ],
    "allowed_axioms": [
      "source-explicit-definitions-only"
    ],
    "assumptions": [
      "DRAFT ONLY: no mathematical assumptions beyond the source text are admitted.",
      "A separate statement-fidelity and current-status review is required before canonical admission."
    ],
    "constraints": {
      "allowed_adapters": [
        "source-fidelity-review-v1"
      ],
      "allowed_methods": [
        "discovery"
      ],
      "max_attempts": 1,
      "runtime": {
        "max_output_bytes": 262144,
        "max_retries": 1,
        "max_transitions": 20,
        "timeout_seconds": 300
      }
    },
    "created_at": "2026-09-15T21:28:00.195364Z",
    "definitions": [
      {
        "definition": "Draft only. Use the exact source record and do not infer, strengthen, or repair definitions, quantifiers, assumptions, or status.",
        "term": "source-native interpretation"
      }
    ],
    "domain": {
      "description": "Draft source observation in Geometry, Euclidean geometry; domain extraction is unresolved.",
      "objects": [
        "UNRESOLVED: extract mathematical objects from the exact source statement during review"
      ]
    },
    "lifecycle": "draft",
    "msc": [
      "51-01"
    ],
    "problem_id": "problem:wikipedia-ffbf9812782aff79",
    "quantifiers": [
      {
        "domain": "UNRESOLVED: source quantifier scope must be extracted and reviewed before canonical admission.",
        "kind": "decide",
        "variables": []
      }
    ],
    "schema_version": "1.0.0",
    "sources": [
      {
        "retrieved_at": "2026-09-02T00:06:33Z",
        "source": "Wikipedia source observation",
        "source_record_id": "wikipedia-ffbf9812782aff79",
        "url": "https://en.wikipedia.org/wiki/Borromean_rings"
      }
    ],
    "statement": {
      "language": "en",
      "text": "Borromean rings — are there three unknotted space curves, not all three circles, which cannot be arranged to form this link?",
      "version": 1
    },
    "title": "Borromean rings",
    "updated_at": "2026-09-15T21:28:00.195364Z"
  },
  "problem_contract_sha256": "229da16e36e7adf956cdc1e223503bc944528aa291683cea241f11c6f2704fd3"
}
```
