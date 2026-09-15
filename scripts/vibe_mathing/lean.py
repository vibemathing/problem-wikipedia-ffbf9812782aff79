"""固定 Lean/Mathlib fixture 的 kernel、逃逸和公理审计 adapter。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from .evidence import create_evidence_receipt
from .formal_assurance import load_lean_toolchain_lock
from .runtime import execute_bounded, now


ESCAPE_PATTERN = re.compile(r"\b(?:sorry|admit|unsafe)\b")
SOURCE_ROOT = Path(__file__).resolve().parents[2]


def _resolve_tool(name: str) -> str:
    """从 PATH 或 elan 官方默认目录解析 Lean 工具，不修改进程环境。"""
    resolved = shutil.which(name)
    if resolved:
        return resolved
    elan_tool = Path.home() / ".elan" / "bin" / name
    if elan_tool.is_file() and os.access(elan_tool, os.X_OK):
        return str(elan_tool)
    raise RuntimeError(
        f"找不到 {name}；请安装 elan/Lean，或将 ~/.elan/bin 加入 PATH"
    )


def _write_output(project_root: Path, run_key: str, name: str, payload: dict[str, Any]) -> str:
    relative = f"research/artifacts/outputs/{run_key}/{name}.json"
    path = project_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path.is_file():
        if path.read_text(encoding="utf-8") != encoded:
            raise RuntimeError(f"Lean verifier 输出已存在且内容不同：{relative}")
        return relative
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return relative


def verify_lean_fixture(
    *, project_root: Path, fixture_root: Path, result: dict[str, Any]
) -> list[dict[str, Any]]:
    """运行固定 Lean 命令，签发四类 native evidence；不签发外部 replay。"""
    lock = load_lean_toolchain_lock(SOURCE_ROOT)
    expected_toolchain = lock["lean"]["toolchain"]
    expected_version_fragment = lock["lean"]["version_fragment"]
    expected_mathlib_rev = lock["mathlib"]["commit"]
    expected_declaration = lock["fixture"]["declaration"]
    expected_axiom_audit = lock["fixture"]["axiom_audit"]
    challenge = SOURCE_ROOT / lock["fixture"]["trusted_challenge_file"]
    identity_probe = SOURCE_ROOT / lock["fixture"]["statement_identity_probe"]
    rechecker = lock["native_rechecker"]
    if lock["qualification"]["native_kernel_route"] != "qualified":
        raise RuntimeError("Lean native route 尚未完成当前实现资格复验")
    source = fixture_root / "VibeMathingFixture.lean"
    axiom_audit = fixture_root / "AxiomAudit.lean"
    toolchain = (fixture_root / "lean-toolchain").read_text(encoding="utf-8").strip()
    lakefile = (fixture_root / "lakefile.toml").read_text(encoding="utf-8")
    manifest = json.loads((fixture_root / "lake-manifest.json").read_text(encoding="utf-8"))
    source_text = source.read_text(encoding="utf-8")
    axiom_audit_text = axiom_audit.read_text(encoding="utf-8")
    challenge_digest = hashlib.sha256(challenge.read_bytes()).hexdigest()
    checked_inputs = [source, axiom_audit, challenge, identity_probe]
    input_digests_before = {
        path.relative_to(SOURCE_ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in checked_inputs
    }
    try:
        challenge.relative_to(fixture_root)
        identity_probe.relative_to(fixture_root)
    except ValueError as exc:
        raise RuntimeError("trusted challenge 或 statement probe 不属于固定 Lean fixture") from exc
    mathlib_revisions = {
        item.get("rev") for item in manifest.get("packages", []) if item.get("name") == "mathlib"
    }
    if (
        toolchain != expected_toolchain
        or expected_mathlib_rev not in lakefile
        or mathlib_revisions != {expected_mathlib_rev}
        or expected_axiom_audit not in axiom_audit_text
        or challenge_digest != lock["fixture"]["trusted_challenge_sha256"]
    ):
        raise RuntimeError("Lean/Mathlib 固定版本契约漂移")
    escapes = ESCAPE_PATTERN.findall(source_text)
    budgets = {"timeout_seconds": 600, "max_output_bytes": 2_000_000}
    lake = _resolve_tool("lake")
    version = execute_bounded(
        [lake, "env", "lean", "--version"], cwd=fixture_root, **budgets
    )
    build = execute_bounded([lake, "--quiet", "build"], cwd=fixture_root, **budgets)
    challenge_build = execute_bounded(
        [lake, "--quiet", "build", lock["fixture"]["trusted_challenge_module"]],
        cwd=fixture_root,
        **budgets,
    )
    native_recheck = execute_bounded(
        [lake, "env", rechecker["command"], rechecker["fresh_flag"], "VibeMathingFixture"],
        cwd=fixture_root,
        **budgets,
    )
    identity = execute_bounded(
        [lake, "env", "lean", identity_probe.relative_to(fixture_root).as_posix()],
        cwd=fixture_root,
        **budgets,
    )
    axioms = execute_bounded(
        [lake, "env", "lean", "AxiomAudit.lean"],
        cwd=fixture_root,
        **budgets,
    )
    input_digests_after = {
        path.relative_to(SOURCE_ROOT).as_posix(): (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() and not path.is_symlink()
            else None
        )
        for path in checked_inputs
    }
    inputs_stable = input_digests_after == input_digests_before
    version_text = version["stdout"] + version["stderr"]
    if (
        version["exit_code"] != 0
        or expected_version_fragment not in version_text
        or build["exit_code"] != 0
        or challenge_build["exit_code"] != 0
        or native_recheck["exit_code"] != 0
        or identity["exit_code"] != 0
        or axioms["exit_code"] != 0
        or not inputs_stable
    ):
        raise RuntimeError("Lean 工具链或 fixture 构建失败")
    axiom_text = axioms["stdout"] + axioms["stderr"]
    axiom_clean = "does not depend on any axioms" in axiom_text
    declaration_match = identity["exit_code"] == 0
    run_key = result["result_id"].removeprefix("result:")
    kernel_locator = _write_output(
        project_root,
        run_key,
        "lean-kernel",
        {
            "toolchain": toolchain,
            "version": version,
            "build": build,
            "trusted_challenge_build": challenge_build,
            "native_recheck": native_recheck,
            "native_rechecker_trust_domain": rechecker["trust_domain"],
            "input_digests_before": input_digests_before,
            "input_digests_after": input_digests_after,
            "inputs_stable": inputs_stable,
        },
    )
    audit_locator = _write_output(
        project_root,
        run_key,
        "lean-axiom-audit",
        {"escapes": escapes, "axiom_output": axiom_text, "axiom_clean": axiom_clean},
    )
    identity_locator = _write_output(
        project_root,
        run_key,
        "lean-statement-identity",
        {
            "expected_declaration": expected_declaration,
            "trusted_challenge": challenge.relative_to(SOURCE_ROOT).as_posix(),
            "trusted_challenge_sha256": challenge_digest,
            "trusted_statement_constant": lock["fixture"]["trusted_statement_constant"],
            "identity_probe": identity,
            "match": declaration_match,
        },
    )
    freshness_locator = _write_output(
        project_root,
        run_key,
        "lean-toolchain-freshness",
        {
            "lock_as_of": lock["as_of"],
            "lean": lock["lean"],
            "mathlib": lock["mathlib"],
            "qualification": lock["qualification"],
            "actual_version": version,
            "exact_match": toolchain == expected_toolchain and mathlib_revisions == {expected_mathlib_rev},
        },
    )
    checked_at = now()
    return [
        create_evidence_receipt(
            project_root=project_root,
            result=result,
            generator="lean-generator",
            evidence_id=f"evidence:{run_key}.kernel",
            capability="kernel_check",
            verdict="accept",
            verifier="lean-kernel",
            checked_at=checked_at,
            output_locator=kernel_locator,
            command=[lake, "--quiet", "build"],
            notes="固定 Lean/Mathlib 的真实 build 与 same-domain native fresh replay",
        ),
        create_evidence_receipt(
            project_root=project_root,
            result=result,
            generator="lean-generator",
            evidence_id=f"evidence:{run_key}.axioms",
            capability="axiom_escape_audit",
            verdict="accept" if not escapes and axiom_clean else "reject",
            verifier="lean-axiom-auditor",
            checked_at=checked_at,
            output_locator=audit_locator,
            command=[lake, "env", "lean", "AxiomAudit.lean"],
            notes="源码逃逸扫描与已编译模块上的 #print axioms",
        ),
        create_evidence_receipt(
            project_root=project_root,
            result=result,
            generator="lean-generator",
            evidence_id=f"evidence:{run_key}.identity",
            capability="statement_identity",
            verdict="accept" if declaration_match else "reject",
            verifier="lean-statement-identity",
            checked_at=checked_at,
            output_locator=identity_locator,
            command=[lake, "env", "lean", identity_probe.relative_to(fixture_root).as_posix()],
            notes="候选 theorem 必须 inhabit 受信 challenge 中的固定 proposition；不代表自然语言陈述忠实性",
        ),
        create_evidence_receipt(
            project_root=project_root,
            result=result,
            generator="lean-generator",
            evidence_id=f"evidence:{run_key}.freshness",
            capability="toolchain_freshness",
            verdict="accept",
            verifier="lean-toolchain-freshness-auditor",
            checked_at=checked_at,
            output_locator=freshness_locator,
            command=["vibe-mathing", "verify-lean-toolchain-lock"],
            executor="in_process",
            notes="Lean/Mathlib exact pair matches the reviewed central lock; this is not an external proof replay",
        ),
    ]
