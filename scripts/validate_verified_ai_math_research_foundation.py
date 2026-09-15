#!/usr/bin/env python3
"""Fail-closed validator for the Verified AI Mathematical Research Foundation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from vibe_mathing.formal_assurance import (
    COUNTEREXAMPLE_TERMINAL_CAPABILITIES,
    PROOF_TERMINAL_CAPABILITIES,
    missing_terminal_capabilities,
)
from vibe_mathing.web_channel import load_json, validate_schema

POLICY_PATH = Path("governance/control-plane/verified-ai-math-research-foundation.v1.json")
SCHEMA_PATH = Path("governance/control-plane/verified-ai-math-research-foundation.schema.json")
EXPECTED_INVARIANTS = [f"FND-{index:02d}" for index in range(1, 15)]
EXPECTED_STAGES = [f"D{index:02d}" for index in range(1, 12)]
EXPECTED_STAGE_NAMES = [
    "discover", "identify", "model", "plan", "explore", "formalize",
    "prove_refute", "verify", "admit", "synthesize", "feedback",
]
REQUIRED_STANDARD_SNIPPETS = [
    "PLFB 仍是唯一概念元模型根",
    "生成、验证、准入、结论四层分离",
    "kernel check 不替代 statement-faithfulness",
    "Job succeeded",
    "冲突冻结",
    "可撤回、非单调真相",
    "D08 verifier 成功不自动触发 D09",
]
REQUIRED_PROOF_CAPABILITIES = set(PROOF_TERMINAL_CAPABILITIES)
REQUIRED_REFUTATION_CAPABILITIES = set(COUNTEREXAMPLE_TERMINAL_CAPABILITIES)


def regular_inside(root: Path, relative: str) -> Path | None:
    candidate = root / relative
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return None
    if candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate


def _accepted_independent_capabilities(result: dict[str, Any]) -> set[str]:
    """Return capabilities from accepted independent evidence not explicitly invalidated.

    Receipt authenticity remains the owner verifier gate's responsibility. This
    conservative pass treats every explicit invalidation as effective so this
    policy validator can never promote through a stale accepted record.
    """
    evidence = [item for item in result.get("evidence", []) if isinstance(item, dict)]
    invalidated = {
        target
        for item in evidence
        for target in item.get("invalidates", [])
        if isinstance(target, str)
    }
    capabilities: set[str] = set()
    for item in evidence:
        if item.get("evidence_id") in invalidated:
            continue
        if item.get("verdict") == "accept" and item.get("independent") is True:
            capability = item.get("capability")
            if isinstance(capability, str):
                capabilities.add(capability)
    return capabilities


def _accepted_independent_capability_verifiers(result: dict[str, Any]) -> dict[str, set[str]]:
    evidence = [item for item in result.get("evidence", []) if isinstance(item, dict)]
    invalidated = {
        target
        for item in evidence
        for target in item.get("invalidates", [])
        if isinstance(target, str)
    }
    verifiers: dict[str, set[str]] = {}
    for item in evidence:
        if item.get("evidence_id") in invalidated:
            continue
        capability = item.get("capability")
        verifier = item.get("verifier")
        if (
            item.get("verdict") == "accept"
            and item.get("independent") is True
            and isinstance(capability, str)
            and isinstance(verifier, str)
        ):
            verifiers.setdefault(capability, set()).add(verifier)
    return verifiers


def validate_result(result: Any, label: str = "result") -> list[str]:
    """Enforce the non-substitutable minimum promotion matrix on one Result."""
    if not isinstance(result, dict):
        return [f"{label}: record must be an object"]
    errors: list[str] = []
    outcome = result.get("outcome")
    if outcome not in {"established", "refuted"}:
        return errors

    for field in ("obligation_graph_id", "root_obligation_id", "statement_sha256", "evidence_link_ids"):
        if not result.get(field):
            errors.append(f"{label}: {outcome} result lacks root-bound field {field}")

    evidence_ids = [
        item.get("evidence_id")
        for item in result.get("evidence", [])
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append(f"{label}: duplicate evidence_id in Result evidence ledger")
    capabilities = _accepted_independent_capabilities(result)
    if outcome == "established":
        if result.get("kind") != "proof":
            errors.append(f"{label}: established result must have kind=proof")
        missing = missing_terminal_capabilities("proof", capabilities)
        verifiers = _accepted_independent_capability_verifiers(result)
        kernel_verifiers = verifiers.get("kernel_check", set())
        replay_verifiers = verifiers.get("proof_replay_check", set())
        if kernel_verifiers and replay_verifiers and not replay_verifiers - kernel_verifiers:
            errors.append(
                f"{label}: proof_replay_check must use a verifier distinct from kernel_check"
            )
    else:
        if result.get("kind") != "counterexample":
            errors.append(f"{label}: refuted result must have kind=counterexample")
        missing = missing_terminal_capabilities("counterexample", capabilities)
    if missing:
        errors.append(f"{label}: {outcome} result lacks independent accepted capabilities: {sorted(missing)}")
    return errors


def validate_result_ledger(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.is_file() or path.is_symlink():
        return [f"result ledger missing or unsafe: {path}"]
    seen: set[str] = set()
    terminal_by_statement: dict[tuple[str, str], set[str]] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        label = f"{path}:{number}"
        try:
            result = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{label}: invalid JSON: {exc}")
            continue
        result_id = result.get("result_id") if isinstance(result, dict) else None
        if isinstance(result_id, str):
            if result_id in seen:
                errors.append(f"{label}: duplicate result_id {result_id}")
            seen.add(result_id)
        errors.extend(validate_result(result, label))
        if isinstance(result, dict) and result.get("outcome") in {"established", "refuted"}:
            key = (str(result.get("problem_id")), str(result.get("statement_sha256")))
            terminal_by_statement.setdefault(key, set()).add(str(result.get("outcome")))
    for (problem_id, statement_sha256), outcomes in terminal_by_statement.items():
        if {"established", "refuted"}.issubset(outcomes):
            errors.append(
                f"{path}: conflict freeze required for {problem_id} statement={statement_sha256}: "
                "established and refuted both present"
            )
    return errors


def validate(root: Path, result_ledgers: list[Path] | None = None) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    policy_file = regular_inside(root, POLICY_PATH.as_posix())
    schema_file = regular_inside(root, SCHEMA_PATH.as_posix())
    if policy_file is None:
        return [f"required regular file missing: {POLICY_PATH.as_posix()}"]
    if schema_file is None:
        return [f"required regular file missing: {SCHEMA_PATH.as_posix()}"]
    try:
        policy = load_json(policy_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"foundation policy invalid: {exc}"]
    errors.extend(f"foundation policy schema: {message}" for message in validate_schema(policy, schema_file))

    invariant_ids = [item.get("id") for item in policy.get("invariants", []) if isinstance(item, dict)]
    if invariant_ids != EXPECTED_INVARIANTS:
        errors.append("foundation invariant sequence drift")
    stages = policy.get("loop", [])
    stage_ids = [item.get("id") for item in stages if isinstance(item, dict)]
    stage_names = [item.get("name") for item in stages if isinstance(item, dict)]
    if stage_ids != EXPECTED_STAGES or stage_names != EXPECTED_STAGE_NAMES:
        errors.append("verified discovery loop sequence drift")
    if any(item.get("may_auto_promote_result") is not False for item in stages if isinstance(item, dict)):
        errors.append("a discovery-loop stage permits automatic Result promotion")

    profiles = policy.get("promotion_profiles", {})
    proof_caps = set(profiles.get("established_proof", {}).get("required_capabilities", []))
    refutation_caps = set(profiles.get("refuted_counterexample", {}).get("required_capabilities", []))
    if proof_caps != REQUIRED_PROOF_CAPABILITIES:
        errors.append("established-proof capability boundary drift")
    if refutation_caps != REQUIRED_REFUTATION_CAPABILITIES:
        errors.append("refuted-counterexample capability boundary drift")
    for key in ("established_proof", "refuted_counterexample"):
        profile = profiles.get(key, {})
        if profile.get("require_independent") is not True or profile.get("require_root_closure") is not True:
            errors.append(f"{key} no longer requires independent root closure")
        if profile.get("conflict_policy") != "freeze":
            errors.append(f"{key} conflict policy is not fail-closed")

    marker = policy.get("marker", "VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1")
    standard_relative = policy.get("normative_standard_path")
    standard = regular_inside(root, standard_relative) if isinstance(standard_relative, str) else None
    if standard is None:
        errors.append(f"foundation standard missing or unsafe: {standard_relative}")
    else:
        text = standard.read_text(encoding="utf-8")
        if text.count(marker) < 2:
            errors.append("foundation standard lacks paired policy markers")
        for snippet in REQUIRED_STANDARD_SNIPPETS:
            if snippet not in text:
                errors.append(f"foundation standard lacks required rule: {snippet}")

    for relative in policy.get("required_agent_surfaces", []):
        if not isinstance(relative, str):
            errors.append("foundation policy contains a non-string Agent surface")
            continue
        surface = regular_inside(root, relative)
        if surface is None:
            errors.append(f"required foundation Agent surface missing or unsafe: {relative}")
            continue
        text = surface.read_text(encoding="utf-8")
        if marker not in text:
            errors.append(f"Agent surface does not inherit foundation policy: {relative}")
        if standard_relative not in text:
            errors.append(f"Agent surface does not link foundation standard: {relative}")

    for ledger in result_ledgers or []:
        resolved = ledger if ledger.is_absolute() else root / ledger
        errors.extend(validate_result_ledger(resolved))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the Verified AI Mathematical Research Foundation.")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--result-ledger", type=Path, action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = validate(args.project_root, args.result_ledger)
    report = {"decision": "PASS" if not errors else "BLOCK", "errors": errors}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"verified AI math research foundation: {report['decision']}")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
