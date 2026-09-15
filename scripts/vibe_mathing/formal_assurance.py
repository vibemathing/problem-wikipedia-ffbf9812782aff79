"""Shared terminal-assurance requirements for proof and counterexample Results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


POLICY_RELATIVE = Path("governance/control-plane/formal-verification-infrastructure.v1.json")
LEAN_LOCK_RELATIVE = Path("governance/control-plane/lean-toolchain-lock.v1.json")

PROOF_TERMINAL_CAPABILITIES = frozenset(
    {
        "kernel_check",
        "axiom_escape_audit",
        "statement_identity",
        "statement_faithfulness",
        "toolchain_freshness",
        "proof_replay_check",
    }
)
COUNTEREXAMPLE_TERMINAL_CAPABILITIES = frozenset(
    {"counterexample_check", "statement_identity", "statement_faithfulness"}
)


def load_formal_verification_policy(project_root: Path) -> dict[str, Any]:
    return json.loads((project_root / POLICY_RELATIVE).read_text(encoding="utf-8"))


def load_lean_toolchain_lock(project_root: Path) -> dict[str, Any]:
    return json.loads((project_root / LEAN_LOCK_RELATIVE).read_text(encoding="utf-8"))


def terminal_capabilities(kind: str) -> frozenset[str]:
    if kind == "proof":
        return PROOF_TERMINAL_CAPABILITIES
    if kind == "counterexample":
        return COUNTEREXAMPLE_TERMINAL_CAPABILITIES
    return frozenset()


def missing_terminal_capabilities(kind: str, capabilities: set[str]) -> set[str]:
    return set(terminal_capabilities(kind) - capabilities)


def has_terminal_assurance(kind: str, capabilities: set[str]) -> bool:
    required = terminal_capabilities(kind)
    return bool(required) and required.issubset(capabilities)


def has_terminal_trust_diversity(
    kind: str,
    capability_domains: dict[str, set[str]],
) -> bool:
    """Require external proof replay to use a trust domain distinct from the native kernel."""
    if kind != "proof":
        return True
    kernel_domains = capability_domains.get("kernel_check", set())
    replay_domains = capability_domains.get("proof_replay_check", set())
    return bool(kernel_domains and replay_domains - kernel_domains)
