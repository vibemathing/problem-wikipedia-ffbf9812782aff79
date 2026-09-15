"""Admission checks for future Comparator/external-checker replay receipts."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .evidence import sha256_file
from .formal_assurance import load_lean_toolchain_lock


SCHEMA = Path("research/schema/lean-external-replay-receipt.schema.json")


class LeanReplayError(RuntimeError):
    """The replay receipt is malformed, stale, or not policy-eligible."""


def _trusted_file(project_root: Path, locator: str) -> Path:
    pure = PurePosixPath(locator)
    if pure.is_absolute() or ".." in pure.parts or "\\" in locator:
        raise LeanReplayError(f"external replay locator 非法：{locator}")
    path = project_root.joinpath(*pure.parts)
    try:
        path.resolve(strict=True).relative_to(project_root.resolve())
    except (OSError, ValueError) as exc:
        raise LeanReplayError(f"external replay locator 不存在或逃逸：{locator}") from exc
    if path.is_symlink() or not path.is_file():
        raise LeanReplayError(f"external replay input 必须是 regular file：{locator}")
    return path


def validate_external_replay_receipt(
    project_root: Path,
    receipt: dict[str, Any],
) -> None:
    """Validate structure, live input identity, trust diversity, and route admission."""
    project_root = project_root.resolve()
    try:
        schema = json.loads((project_root / SCHEMA).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LeanReplayError("无法读取 external replay schema") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(receipt),
        key=lambda item: list(item.path),
    )
    if errors:
        raise LeanReplayError(f"external replay receipt 无效：{errors[0].message}")

    for key in ("challenge", "candidate_bundle"):
        ref = receipt[key]
        path = _trusted_file(project_root, ref["locator"])
        if sha256_file(path) != ref["sha256"]:
            raise LeanReplayError(f"{key} digest 与现场文件不一致")

    checkers = receipt["checkers"]
    verifier_ids = [item["verifier"] for item in checkers]
    if len(verifier_ids) != len(set(verifier_ids)):
        raise LeanReplayError("external replay checker verifier identity 重复")
    native_domains = {
        item["trust_domain"] for item in checkers if item["role"] == "native_kernel"
    }
    external_domains = {
        item["trust_domain"] for item in checkers if item["role"] == "external_checker"
    }
    if receipt["evidence_eligible"] and not (
        native_domains and external_domains - native_domains
    ):
        raise LeanReplayError("proof replay 缺少区别于 native kernel 的 external trust domain")
    if (
        receipt["challenge"]["statement_constant"]
        != receipt["statement_correspondence"]["trusted_statement_constant"]
    ):
        raise LeanReplayError("statement correspondence 未绑定 trusted challenge constant")

    lock = load_lean_toolchain_lock(project_root)
    if (
        receipt["evidence_eligible"]
        and lock["qualification"]["adversarial_high_assurance_route"] != "qualified"
    ):
        raise LeanReplayError("adversarial high-assurance route 未准入")
