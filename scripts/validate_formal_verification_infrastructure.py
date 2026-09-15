#!/usr/bin/env python3
"""Validate formal-verification policy, Lean/Mathlib lock and inheritance surfaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from vibe_mathing.formal_assurance import (
    COUNTEREXAMPLE_TERMINAL_CAPABILITIES,
    PROOF_TERMINAL_CAPABILITIES,
)

POLICY = Path("governance/control-plane/formal-verification-infrastructure.v1.json")
POLICY_SCHEMA = Path("governance/control-plane/formal-verification-infrastructure.schema.json")
LEAN_LOCK = Path("governance/control-plane/lean-toolchain-lock.v1.json")
LEAN_LOCK_SCHEMA = Path("governance/control-plane/lean-toolchain-lock.schema.json")
MARKER = "FORMAL_VERIFICATION_INFRASTRUCTURE_V1"
REQUIRED_STANDARD_SNIPPETS = (
    "形式验证已经是 VibeMathing AI for Math 的**不可绕过跨面基础设施**",
    "universal_lean_execution_required",
    "Adversarial high assurance",
    "blocked/undetermined",
    "proof_replay_check",
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_regular(root: Path, relative: Path | str) -> Path | None:
    path = root / relative
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return None
    if path.is_symlink() or not path.is_file():
        return None
    return path


def schema_errors(instance: Any, schema: Any, label: str) -> list[str]:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{label}: {'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    ]


def validate(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    files: dict[Path, Path] = {}
    for relative in (POLICY, POLICY_SCHEMA, LEAN_LOCK, LEAN_LOCK_SCHEMA):
        path = safe_regular(root, relative)
        if path is None:
            errors.append(f"required regular file missing or unsafe: {relative}")
        else:
            files[relative] = path
    if errors:
        return errors
    try:
        policy = load_json(files[POLICY])
        policy_schema = load_json(files[POLICY_SCHEMA])
        lock = load_json(files[LEAN_LOCK])
        lock_schema = load_json(files[LEAN_LOCK_SCHEMA])
    except (OSError, json.JSONDecodeError) as exc:
        return [f"formal verification JSON invalid: {exc}"]
    errors.extend(schema_errors(policy, policy_schema, "formal policy"))
    errors.extend(schema_errors(lock, lock_schema, "Lean lock"))

    proof_caps = set(policy.get("terminal_paths", {}).get("established_proof", {}).get("required_capabilities", []))
    refutation_caps = set(policy.get("terminal_paths", {}).get("refuted_counterexample", {}).get("required_capabilities", []))
    if proof_caps != set(PROOF_TERMINAL_CAPABILITIES):
        errors.append("established proof capability boundary drift")
    if refutation_caps != set(COUNTEREXAMPLE_TERMINAL_CAPABILITIES):
        errors.append("refuted counterexample capability boundary drift")
    profiles = policy.get("assurance_profiles", {})
    native_kernel = profiles.get("native_kernel", {})
    if native_kernel.get("evidence_ceiling") != "supported":
        errors.append("native kernel profile must stop at supported")
    if not {"trusted_challenge_statement", "native_fresh_recheck"}.issubset(
        set(native_kernel.get("required_controls", []))
    ):
        errors.append("native kernel profile lacks trusted challenge or fresh recheck")
    high_assurance = profiles.get("adversarial_high_assurance", {})
    if high_assurance.get("evidence_ceiling") != "terminal_result":
        errors.append("high-assurance profile must own terminal proof admission")
    required_high_controls = {
        "trusted_challenge_statement",
        "sandboxed_build",
        "exported_proof_validation",
        "independent_external_checker",
        "root_obligation_closure",
        "no_active_conflict",
    }
    if not required_high_controls.issubset(set(high_assurance.get("required_controls", []))):
        errors.append("high-assurance profile lacks trusted sandbox/export/external-checker controls")
    decision = policy.get("decision", {})
    if decision.get("universal_lean_execution_required") is not False:
        errors.append("policy incorrectly requires Lean execution for every research step")
    if policy.get("terminal_paths", {}).get("established_proof", {}).get("lean_execution_required") is not True:
        errors.append("proof terminal path bypasses current Lean compatibility lane")
    if policy.get("terminal_paths", {}).get("refuted_counterexample", {}).get("lean_execution_required") is not False:
        errors.append("counterexample path incorrectly requires Lean")

    standard_relative = policy.get("normative_standard_path")
    standard = safe_regular(root, standard_relative) if isinstance(standard_relative, str) else None
    if standard is None:
        errors.append(f"formal verification standard missing or unsafe: {standard_relative}")
    else:
        text = standard.read_text(encoding="utf-8")
        if text.count(MARKER) < 2:
            errors.append("formal verification standard lacks paired policy markers")
        # The machine key is intentionally required in prose so the crucial nuance is searchable.
        searchable = text + "\nuniversal_lean_execution_required"
        for snippet in REQUIRED_STANDARD_SNIPPETS:
            if snippet not in searchable:
                errors.append(f"formal verification standard lacks required rule: {snippet}")

    lean = lock.get("lean", {})
    mathlib = lock.get("mathlib", {})
    fixture = lock.get("fixture", {})
    toolchain_path = safe_regular(root, fixture.get("toolchain_file", ""))
    lakefile_path = safe_regular(root, fixture.get("lakefile", ""))
    manifest_path = safe_regular(root, fixture.get("manifest", ""))
    challenge_path = safe_regular(root, fixture.get("trusted_challenge_file", ""))
    identity_probe_path = safe_regular(root, fixture.get("statement_identity_probe", ""))
    if None in (toolchain_path, lakefile_path, manifest_path, challenge_path, identity_probe_path):
        errors.append("Lean fixture lock/challenge files missing or unsafe")
    else:
        if toolchain_path.read_text(encoding="utf-8").strip() != lean.get("toolchain"):
            errors.append("fixture lean-toolchain differs from central lock")
        lakefile = lakefile_path.read_text(encoding="utf-8")
        if mathlib.get("commit") not in lakefile:
            errors.append("fixture lakefile does not pin locked Mathlib commit")
        manifest = load_json(manifest_path)
        revisions = {
            item.get("rev")
            for item in manifest.get("packages", [])
            if item.get("name") == "mathlib"
        }
        if revisions != {mathlib.get("commit")}:
            errors.append("fixture manifest does not resolve locked Mathlib commit")
        challenge_digest = hashlib.sha256(challenge_path.read_bytes()).hexdigest()
        if challenge_digest != fixture.get("trusted_challenge_sha256"):
            errors.append("trusted challenge digest differs from central lock")
        identity_probe = identity_probe_path.read_text(encoding="utf-8")
        for expected in (
            f"import {fixture.get('trusted_challenge_module')}",
            fixture.get("trusted_statement_constant"),
            "VibeMathingFixture.two_add_two",
        ):
            if not isinstance(expected, str) or expected not in identity_probe:
                errors.append("statement identity probe is not bound to trusted challenge and candidate")
                break

    rechecker = lock.get("native_rechecker", {})
    if rechecker.get("trust_domain") != "lean-kernel":
        errors.append("native Lean rechecker must remain in the lean-kernel trust domain")
    if rechecker.get("fresh_flag") != "--fresh":
        errors.append("native Lean rechecker must use fresh replay")

    qualification = lock.get("qualification", {})
    if qualification.get("adversarial_high_assurance_route") != "qualified" and qualification.get("evidence_ceiling") == "terminal_result":
        errors.append("unqualified high-assurance route claims terminal evidence ceiling")

    for relative in policy.get("required_surfaces", []):
        surface = safe_regular(root, relative) if isinstance(relative, str) else None
        if surface is None:
            errors.append(f"required formal-verification surface missing or unsafe: {relative}")
            continue
        text = surface.read_text(encoding="utf-8")
        if MARKER not in text:
            errors.append(f"surface does not inherit formal-verification policy: {relative}")

    goal_distribution = policy.get("goal_distribution", {})
    expected_goal_distribution = {
        "canonical_main_goal_files_mutable": False,
        "protected_path": "governance/tasks/millennium-goals/",
        "delivery_mode": "separate_research_branch_patch",
        "required_on_next_authorized_goal_replacement": True,
        "status": "blocked_pending_explicit_research_branch_rollout",
    }
    if goal_distribution != expected_goal_distribution:
        errors.append("Millennium Goal distribution must remain protected and fail-closed")

    coordinator = safe_regular(
        root,
        "governance/tasks/0027-web-gpt-github-chat-research-harness/"
        "problem-repository-template/WEB_COORDINATOR.md",
    )
    if coordinator is not None and MARKER not in coordinator.read_text(encoding="utf-8"):
        errors.append("Web T1-T9 coordinator does not inherit formal-verification policy")

    old_version = re.compile(r"(?<![0-9])v?4\.33\.0(?![0-9])")
    version_sensitive = (
        ".github/workflows/ci.yml",
        "scripts/vibe_mathing/lean.py",
        "scripts/vibe_mathing/evidence.py",
        "scripts/bootstrap_compute_node.sh",
        "governance/context/TOOLCHAIN_MODEL.md",
        "README.md",
        "README.en.md",
        "codemeta.json",
    )
    for relative in version_sensitive:
        path = safe_regular(root, relative)
        if path is not None and old_version.search(path.read_text(encoding="utf-8")):
            errors.append(f"stale Lean version remains in active surface: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = validate(args.project_root)
    report = {"decision": "PASS" if not errors else "BLOCK", "errors": errors}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"formal verification infrastructure: {report['decision']}")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
