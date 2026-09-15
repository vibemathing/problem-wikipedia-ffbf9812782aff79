"""Pure contracts for formal-method routing and bounded Lean verification.

This module is deliberately a *builder/validator* only.  It reads schemas and
source artifacts when a caller asks for validation, but it does not execute
Lean, call a network service, append a ledger, or create Evidence/Result
records.  The three independent Lean admission capabilities remain outside
this module: kernel replay, axiom auditing, and statement-faithfulness review.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_VERSION = "1.0.0"
_DEFAULT_TIMESTAMP = "1970-01-01T00:00:00Z"
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{1,255}$")
_IMPORT = re.compile(r"^[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$")
_FORBIDDEN_LEAN = re.compile(
    r"\b(?:sorry|admit|axiom|unsafe|partial|extern|native_decide|implemented_by)\b"
    r"|#\s*eval"
)
_FORBIDDEN_COMMAND_WORDS = frozenset(
    {
        "bash",
        "cmd",
        "curl",
        "git",
        "nc",
        "netcat",
        "powershell",
        "scp",
        "sh",
        "ssh",
        "wget",
    }
)
_FORBIDDEN_LEAN_FLAGS = frozenset(
    {"--unsafe", "--trust", "--plugin", "--run", "--load-dynlib", "-R"}
)
_TRUTH_PATH_PARTS = frozenset(
    {
        "evidence",
        "evidence-links.jsonl",
        "results.jsonl",
        "solutions.json",
        "attempts.jsonl",
        "canonical-problems.jsonl",
        "problems.jsonl",
    }
)
_FAILURE_CLASSES = frozenset(
    {
        "TOOLCHAIN_UNAVAILABLE",
        "ENVIRONMENT_MISMATCH",
        "PARSE_ERROR",
        "ELABORATION_ERROR",
        "PROOF_GAP",
        "SORRY_OR_ADMIT",
        "AXIOM_ESCAPE",
        "SELF_REFERENCE",
        "STATEMENT_MISMATCH",
        "TIMEOUT",
        "RESOURCE_EXCEEDED",
        "TRANSPORT_FAILURE",
        "EXTERNAL_VERDICT_UNREPLAYED",
        "KERNEL_REJECTED",
        "FAITHFULNESS_NEEDS_REVIEW",
        "CHECKER_ERROR",
        "TOOL_ERROR",
    }
)
_METHODS = frozenset(
    {"lean", "smt", "sat", "exact_cas", "interval", "finite_model", "certificate", "human_review"}
)
_OPERATIONS = frozenset({"generate", "repair", "replay", "axiom_audit", "faithfulness_review"})


class FormalizationContractError(ValueError):
    """A formalization contract is malformed, stale, unsafe, or inconsistent."""


class DigestMismatchError(FormalizationContractError):
    """A declared content digest does not match the supplied content."""


class UnsafeLocatorError(FormalizationContractError):
    """A locator escapes the trusted project artifact root or follows a link."""


class ContractChainError(FormalizationContractError):
    """Cross-contract identity or trust-boundary validation failed."""


# Friendly aliases used by callers that prefer the shorter error names.
FormalizationError = FormalizationContractError
FormalizationValidationError = FormalizationContractError


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON in the same digest form used by the research DAG."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FormalizationContractError("值不能编码为有限 JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    if not isinstance(value, str):
        raise FormalizationContractError("文本摘要输入必须是 string")
    return sha256_bytes(value.encode("utf-8"))


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise FormalizationContractError(f"无法读取文件：{path}") from exc
    return digest.hexdigest()


def _schema_root(project_root: Path | None) -> Path:
    if project_root is not None:
        candidate = project_root.resolve() / "research" / "schema"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parents[2] / "research" / "schema"


def _load_schema(project_root: Path | None, filename: str) -> dict[str, Any]:
    path = _schema_root(project_root) / filename
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FormalizationContractError(f"无法读取 schema：{path}") from exc
    if not isinstance(value, dict):
        raise FormalizationContractError(f"schema 不是 JSON object：{path}")
    try:
        Draft202012Validator.check_schema(value)
    except Exception as exc:  # jsonschema exposes several schema error classes.
        raise FormalizationContractError(f"schema 本身无效：{path}") from exc
    return value


def _validate_schema(
    value: Mapping[str, Any],
    filename: str,
    *,
    project_root: Path | None = None,
    label: str,
) -> None:
    errors = sorted(
        Draft202012Validator(
            _load_schema(project_root, filename), format_checker=FormatChecker()
        ).iter_errors(dict(value)),
        key=lambda item: list(item.path),
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise FormalizationContractError(
            f"{label} schema 无效 ({path})：{errors[0].message}"
        )


def _copy(value: Any) -> Any:
    """Copy JSON-shaped values without accepting arbitrary mutable objects."""
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise FormalizationContractError("合同字段必须是有限 JSON 值") from exc


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise FormalizationContractError(f"{label} 必须是稳定标识")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise FormalizationContractError(f"{label} 必须是 64 位小写 SHA-256")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormalizationContractError(f"{label} 必须是非空文本")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormalizationContractError(f"{label} 必须是带时区时间戳")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FormalizationContractError(f"{label} 不是 ISO 8601 时间") from exc
    if parsed.tzinfo is None:
        raise FormalizationContractError(f"{label} 必须包含时区")
    return value


def _alias(value: Mapping[str, Any], names: Sequence[str], label: str) -> Any:
    present = [(name, value[name]) for name in names if name in value]
    if not present:
        raise FormalizationContractError(f"缺少 {label}")
    first = present[0][1]
    for name, item in present[1:]:
        if item != first:
            raise ContractChainError(f"{label} 的别名字段不一致：{name}")
    return first


def _optional_alias(value: Mapping[str, Any], names: Sequence[str], label: str) -> Any:
    present = [(name, value[name]) for name in names if name in value]
    if not present:
        return None
    first = present[0][1]
    for name, item in present[1:]:
        if item != first:
            raise ContractChainError(f"{label} 的别名字段不一致：{name}")
    return first


def _list_of_text(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise FormalizationContractError(f"{label} 必须是字符串数组")
    if any(not isinstance(item, str) or not item for item in value):
        raise FormalizationContractError(f"{label} 必须是无重复非空字符串数组")
    if len(set(value)) != len(value):
        raise FormalizationContractError(f"{label} 必须是无重复非空字符串数组")
    return list(value)


def _nonempty_json(value: Any, label: str) -> Any:
    if isinstance(value, (str, list, dict)) and not value:
        raise FormalizationContractError(f"{label} 不能为空")
    if value is None:
        raise FormalizationContractError(f"{label} 不能为 null")
    return value


def _record(record: Mapping[str, Any] | None, label: str) -> Mapping[str, Any] | None:
    if record is None:
        return None
    if not isinstance(record, Mapping):
        raise FormalizationContractError(f"{label} 必须是 object")
    return record


def _record_digest(record: Mapping[str, Any] | None, label: str) -> str | None:
    if record is None:
        return None
    return sha256_json(dict(record))


def _record_from_context(
    context: Mapping[str, Any] | None, name: str, direct: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    if direct is not None:
        return direct
    if context is not None and isinstance(context.get(name), Mapping):
        return context[name]
    return None


def _trusted_artifact_path(
    project_root: Path, locator: str, *, must_exist: bool = True
) -> Path:
    """Resolve a project-relative regular file without following any symlink."""
    if not isinstance(locator, str) or not locator:
        raise UnsafeLocatorError("artifact locator 必须是非空文本")
    if "\x00" in locator or "\\" in locator:
        raise UnsafeLocatorError(f"artifact locator 含非法字符：{locator}")
    pure = PurePosixPath(locator)
    if pure.is_absolute() or not pure.parts or "." in pure.parts or ".." in pure.parts:
        raise UnsafeLocatorError(f"artifact locator 禁止绝对路径或路径逃逸：{locator}")
    if pure.parts[:2] != ("research", "artifacts"):
        raise UnsafeLocatorError(f"artifact 不在 research/artifacts：{locator}")
    root = project_root.resolve()
    trusted_root = root / "research" / "artifacts"
    if trusted_root.is_symlink():
        raise UnsafeLocatorError("research/artifacts 不能是符号链接")
    lexical = root
    for part in pure.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise UnsafeLocatorError(f"artifact 路径禁止 symlink：{locator}")
    path = root.joinpath(*pure.parts)
    if not must_exist:
        try:
            path.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise UnsafeLocatorError(f"artifact 逃逸 project root：{locator}") from exc
        return path
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafeLocatorError(f"artifact 不存在：{locator}") from exc
    try:
        resolved.relative_to(trusted_root)
    except ValueError as exc:
        raise UnsafeLocatorError(f"artifact 逃逸可信根：{locator}") from exc
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise UnsafeLocatorError(f"artifact 无法 stat：{locator}") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise UnsafeLocatorError(f"artifact 必须是 regular file：{locator}")
    return path


def _validate_ref(
    value: Mapping[str, Any],
    label: str,
    *,
    project_root: Path | None = None,
    must_exist: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FormalizationContractError(f"{label} 必须是 digest ref")
    locator = _text(value.get("locator"), f"{label}.locator")
    if "\x00" in locator or "\\" in locator:
        raise UnsafeLocatorError(f"{label}.locator 含非法路径字符")
    pure = PurePosixPath(locator)
    if pure.is_absolute() or not pure.parts or "." in pure.parts or ".." in pure.parts:
        raise UnsafeLocatorError(f"{label}.locator 路径逃逸")
    if pure.parts[:2] != ("research", "artifacts"):
        raise UnsafeLocatorError(f"{label}.locator 不在 research/artifacts")
    declared = _digest(value.get("sha256"), f"{label}.sha256")
    result = {"locator": locator, "sha256": declared}
    if "media_type" in value:
        result["media_type"] = _text(value["media_type"], f"{label}.media_type")
    if project_root is not None:
        path = _trusted_artifact_path(project_root, locator, must_exist=must_exist)
        if path.is_file() and sha256_file(path) != declared:
            raise DigestMismatchError(f"{label} 文件摘要漂移：{locator}")
    return result


def _ref_from_input(
    value: Mapping[str, Any] | str | Path | None,
    *,
    project_root: Path | None,
    label: str,
    media_type: str | None = None,
    must_exist: bool = True,
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        ref = dict(value)
        if media_type is not None:
            ref.setdefault("media_type", media_type)
        return _validate_ref(ref, label, project_root=project_root, must_exist=must_exist)
    if isinstance(value, Path):
        if project_root is None:
            raise FormalizationContractError(f"{label} 使用 Path 时必须提供 project_root")
        try:
            # Keep the lexical path here; resolving first would hide a symlink
            # and defeat the no-follow check in _trusted_artifact_path.
            locator = value.absolute().relative_to(project_root.absolute()).as_posix()
        except ValueError as exc:
            raise UnsafeLocatorError(f"{label} 不在 project root：{value}") from exc
        value = locator
    if not isinstance(value, str) or not value:
        raise FormalizationContractError(f"{label} 必须是 locator 或 digest ref")
    if project_root is None:
        raise FormalizationContractError(f"{label} 只有 locator 时必须提供 project_root 以重算摘要")
    path = _trusted_artifact_path(project_root, value, must_exist=must_exist)
    ref = {"locator": value, "sha256": sha256_file(path)}
    if media_type is not None:
        ref["media_type"] = media_type
    return ref


def _strip_lean_comments_and_strings(text: str) -> str:
    """Conservatively remove Lean comments and strings before keyword scanning."""
    output: list[str] = []
    index = 0
    block_depth = 0
    in_string = False
    while index < len(text):
        pair = text[index : index + 2]
        if block_depth:
            if pair == "/-":
                block_depth += 1
                output.extend("  ")
                index += 2
            elif pair == "-/":
                block_depth -= 1
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        if in_string:
            if text[index] == "\\" and index + 1 < len(text):
                output.extend("  ")
                index += 2
            elif text[index] == '"':
                in_string = False
                output.append(" ")
                index += 1
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        if pair == "--":
            end = text.find("\n", index)
            if end == -1:
                output.extend(" " * (len(text) - index))
                break
            output.extend(" " * (end - index))
            index = end
        elif pair == "/-":
            block_depth = 1
            output.extend("  ")
            index += 2
        elif text[index] == '"':
            in_string = True
            output.append(" ")
            index += 1
        else:
            output.append(text[index])
            index += 1
    return "".join(output)


def scan_lean_source(text: str) -> list[str]:
    """Return executable escape tokens found in Lean source, ignoring comments/strings."""
    if not isinstance(text, str):
        raise FormalizationContractError("Lean source 必须是文本")
    stripped = _strip_lean_comments_and_strings(text)
    return sorted(set(_FORBIDDEN_LEAN.findall(stripped)))


def extract_lean_imports(text: str) -> list[str]:
    """Extract and validate top-level Lean imports without executing Lean."""
    if not isinstance(text, str):
        raise FormalizationContractError("Lean source 必须是文本")
    stripped = _strip_lean_comments_and_strings(text)
    imports: list[str] = []
    for line in stripped.splitlines():
        match = re.match(r"^\\s*import\\s+(.+?)\\s*$", line)
        if match is None:
            continue
        for item in match.group(1).split():
            imports.append(_safe_import(item))
    if len(set(imports)) != len(imports):
        raise FormalizationContractError("Lean source imports 重复")
    return imports


def _safe_import(name: Any) -> str:
    if not isinstance(name, str) or not _IMPORT.fullmatch(name):
        raise FormalizationContractError(f"Lean import 名称非法：{name!r}")
    return name


def _command_tokens(value: str | Sequence[str], label: str) -> list[str]:
    if isinstance(value, str):
        tokens = value.strip().split()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        tokens = list(value)
    else:
        raise FormalizationContractError(f"{label} 必须是非空命令或 argv 数组")
    if not tokens or any(not isinstance(item, str) or not item for item in tokens):
        raise FormalizationContractError(f"{label} 必须是非空命令或 argv 数组")
    return tokens


def _safe_command(value: Any, label: str) -> list[str] | str:
    tokens = _command_tokens(value, label)
    for item in tokens:
        if any(char in item for char in (";", "|", "&", "`", "$", "\n", "\r")):
            raise FormalizationContractError(f"{label} 禁止 shell 组合语法")
        if "http://" in item or "https://" in item or ".." in item:
            raise FormalizationContractError(f"{label} 禁止网络或路径逃逸")
        if item in _FORBIDDEN_LEAN_FLAGS or any(item.startswith(flag + "=") for flag in _FORBIDDEN_LEAN_FLAGS):
            raise FormalizationContractError(f"{label} 禁止不安全 Lean flag：{item}")
        if Path(item).name.lower() in _FORBIDDEN_COMMAND_WORDS:
            raise FormalizationContractError(f"{label} 禁止 shell/网络/Git 子命令：{item}")
    executable = tokens[0]
    word = Path(executable).name.lower()
    if word in _FORBIDDEN_COMMAND_WORDS:
        raise FormalizationContractError(f"{label} 禁止外部 shell/网络/Git 命令：{word}")
    if word not in {"lake", "lean"}:
        raise FormalizationContractError(f"{label} 只能允许 lake/lean 命令")
    if Path(executable).is_absolute():
        raise FormalizationContractError(f"{label} 不得固化绝对可执行路径")
    if word == "lake":
        command_tokens = [item for item in tokens[1:] if not item.startswith("-")]
        if not command_tokens or command_tokens[0] not in {"build", "env"}:
            raise FormalizationContractError(f"{label} 只允许 lake build 或 lake env lean")
        if command_tokens[0] == "env" and (len(command_tokens) < 2 or Path(command_tokens[1]).name != "lean"):
            raise FormalizationContractError(f"{label} lake env 只能调用 lean")
    return value if isinstance(value, str) else tokens


def _safe_write_scope(value: Any, label: str) -> str:
    scope = _text(value, label)
    if "\x00" in scope or "\\" in scope:
        raise FormalizationContractError(f"{label} 含非法路径字符")
    pure = PurePosixPath(scope)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise UnsafeLocatorError(f"{label} 路径逃逸")
    lowered = {part.lower() for part in pure.parts}
    if lowered.intersection(_TRUTH_PATH_PARTS) or "result-library" in lowered or "evidence" in lowered:
        raise FormalizationContractError(f"{label} 不得写入数学真相或 Evidence 路径")
    if pure.parts[:2] not in (("research", "artifacts"), ("research", "runs")):
        raise FormalizationContractError(f"{label} 必须位于受限 research 路径")
    return scope


def _cost(value: Any) -> Any:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, Mapping):
        result = dict(value)
        _text(result.get("level"), "cost.level")
        _text(result.get("description"), "cost.description")
        for name in ("estimated_wall_seconds", "estimated_memory_bytes", "repair_budget"):
            if name in result and (not isinstance(result[name], int) or result[name] < 0):
                raise FormalizationContractError(f"cost.{name} 必须是非负整数")
        return _copy(result)
    raise FormalizationContractError("cost 必须是文本或 object")


def _decision_common(
    *,
    problem: Mapping[str, Any] | None,
    problem_id: str | None,
    contract_sha256: str | None,
    claim_id: str | None,
    obligation_id: str | None,
) -> tuple[str, str, str | None, str | None]:
    if problem is not None:
        derived_problem_id = problem.get("problem_id")
        if problem_id is None:
            problem_id = derived_problem_id
        elif derived_problem_id != problem_id:
            raise ContractChainError("problem_id 与 ProblemContract 不一致")
        derived_digest = sha256_json(dict(problem))
        if contract_sha256 is None:
            contract_sha256 = derived_digest
        elif contract_sha256 != derived_digest:
            raise DigestMismatchError("ProblemContract digest 不匹配")
    return (
        _identifier(problem_id, "problem_id"),
        _digest(contract_sha256, "problem_contract_sha256"),
        _identifier(claim_id, "claim_id") if claim_id is not None else None,
        _identifier(obligation_id, "obligation_id") if obligation_id is not None else None,
    )


def _subject_id(claim_id: str | None, obligation_id: str | None) -> str:
    if claim_id is None and obligation_id is None:
        raise FormalizationContractError("必须绑定 claim_id 或 obligation_id")
    return claim_id or obligation_id or "subject"


def validate_formal_method_decision(
    decision: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    problem: Mapping[str, Any] | None = None,
    formalization_decision: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate applicability, rationale, capabilities and follow-up obligations."""
    if not isinstance(decision, Mapping):
        raise FormalizationContractError("FormalMethodDecision 必须是 object")
    value = dict(decision)
    _validate_schema(value, "formal-method-decision.schema.json", project_root=project_root, label="FormalMethodDecision")
    contract = _alias(value, ("problem_contract_sha256", "contract_sha256"), "ProblemContract digest")
    _digest(contract, "ProblemContract digest")
    if problem is not None:
        if value.get("problem_id") != problem.get("problem_id"):
            raise ContractChainError("FormalMethodDecision problem_id 与 ProblemContract 不一致")
        if contract != sha256_json(dict(problem)):
            raise DigestMismatchError("FormalMethodDecision 的 ProblemContract digest 漂移")
    claim_id = value.get("claim_id")
    obligation_id = value.get("obligation_id")
    _subject_id(claim_id, obligation_id)
    if claim_id is not None:
        _identifier(claim_id, "claim_id")
    if obligation_id is not None:
        _identifier(obligation_id, "obligation_id")
    classification = value["classification"]
    _list_of_text(value["reason_codes"], "reason_codes", allow_empty=False)
    selected = _list_of_text(value["selected_methods"], "selected_methods")
    if any(item not in _METHODS for item in selected):
        raise FormalizationContractError("selected_methods 含未知形式化方法")
    profiles = value["method_profiles"]
    if not isinstance(profiles, list) or len({json.dumps(item, sort_keys=True) for item in profiles}) != len(profiles):
        raise FormalizationContractError("method_profiles 必须是无重复数组")
    profile_methods: list[str] = []
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise FormalizationContractError("method_profile 必须是 object")
        method = profile.get("method")
        if method in profile_methods or method not in _METHODS:
            raise FormalizationContractError("method_profiles 的方法重复或未知")
        profile_methods.append(method)
        _list_of_text(profile.get("capabilities"), "method_profile.capabilities", allow_empty=False)
        _list_of_text(profile.get("evidence_ceiling"), "method_profile.evidence_ceiling", allow_empty=False)
        _cost(profile.get("cost"))
        _list_of_text(profile.get("risks"), "method_profile.risks", allow_empty=False)
        _list_of_text(profile.get("next_obligations"), "method_profile.next_obligations")
    if set(profile_methods) != set(selected):
        raise ContractChainError("method_profiles 必须逐一覆盖 selected_methods")
    capabilities = _optional_alias(value, ("capabilities", "required_capabilities"), "capabilities")
    _list_of_text(capabilities, "capabilities", allow_empty=False)
    if "capabilities" in value and "required_capabilities" in value and value["capabilities"] != value["required_capabilities"]:
        raise ContractChainError("capabilities 与 required_capabilities 不一致")
    _cost(value["cost"])
    _list_of_text(value["risks"], "risks", allow_empty=False)
    _list_of_text(value["next_obligations"], "next_obligations", allow_empty=False)
    _list_of_text(value["evidence_ceilings"], "evidence_ceilings", allow_empty=False)
    _nonempty_json(value["alternative_verification_path"], "alternative_verification_path")
    blockers = _list_of_text(value["blockers"], "blockers")
    if classification == "blocked" and (not blockers or not value["next_obligations"]):
        raise FormalizationContractError("blocked 决策必须记录 blockers 和 next_obligations")
    if classification == "formalize_now" and not selected:
        raise FormalizationContractError("formalize_now 不能没有 selected_methods")
    _timestamp(value["created_at"], "created_at")
    if value.get("supersedes") is not None:
        _identifier(value["supersedes"], "supersedes")
    if formalization_decision is not None:
        validate_formalization_decision(
            formalization_decision,
            project_root=project_root,
            problem=problem,
            parent_decision=value,
        )
    return _copy(value)


def build_formal_method_decision(
    *,
    classification: str,
    reason: str | None = None,
    reason_codes: Sequence[str] | None = None,
    problem: Mapping[str, Any] | None = None,
    problem_id: str | None = None,
    contract_sha256: str | None = None,
    claim_id: str | None = None,
    obligation_id: str | None = None,
    selected_methods: Sequence[str] | None = None,
    method_profiles: Sequence[Mapping[str, Any]] | None = None,
    capabilities: Sequence[str] | None = None,
    required_capabilities: Sequence[str] | None = None,
    cost: Any = None,
    risks: Sequence[str] | None = None,
    next_obligations: Sequence[str] | None = None,
    evidence_ceilings: Sequence[str] | None = None,
    alternative_verification_path: Any = None,
    blockers: Sequence[str] | None = None,
    owner: str = "coordinator",
    created_at: str = _DEFAULT_TIMESTAMP,
    decision_id: str | None = None,
    claim_type: str | None = None,
    evidence_target: str | None = None,
    source_claim_sha256: str | None = None,
    supersedes: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete applicability decision without consulting external state."""
    problem_id, contract, claim_id, obligation_id = _decision_common(
        problem=problem,
        problem_id=problem_id,
        contract_sha256=contract_sha256,
        claim_id=claim_id,
        obligation_id=obligation_id,
    )
    classification = {"required": "formalize_now", "recommended": "formalize_later"}.get(classification, classification)
    if classification not in {"formalize_now", "formalize_later", "not_applicable", "blocked"}:
        raise FormalizationContractError("未知 FormalMethodDecision classification")
    selected = _list_of_text(list(selected_methods or []), "selected_methods")
    if any(item not in _METHODS for item in selected):
        raise FormalizationContractError("selected_methods 无效")
    reason = _text(reason, "reason") if reason is not None else "显式记录该主张的形式化适用性与边界。"
    reason_codes_value = list(reason_codes or [f"classification:{classification}"])
    _list_of_text(reason_codes_value, "reason_codes", allow_empty=False)
    caps = list(capabilities or required_capabilities or ["applicability_review"])
    if capabilities is not None and required_capabilities is not None and list(capabilities) != list(required_capabilities):
        raise ContractChainError("capabilities 与 required_capabilities 不一致")
    risks_value = list(risks or ["形式陈述、定义域和证据上限仍需独立复核。"])
    default_next = {
        "formalize_now": ["生成并独立重放 Lean candidate，随后完成公理与陈述忠实性审查。"],
        "formalize_later": ["在定义和预算稳定后建立最小形式化回归。"],
        "not_applicable": ["沿记录的来源、计算或人工审查路线继续验证。"],
        "blocked": ["冻结最小可行定义并重新评估形式化路线。"],
    }
    next_value = list(next_obligations) if next_obligations is not None else list(default_next[classification])
    _list_of_text(next_value, "next_obligations", allow_empty=False)
    blockers_value = list(blockers or [])
    if classification == "blocked" and not blockers_value:
        blockers_value = ["当前路线的编码、定义、工具链或预算条件尚未闭合。"]
    if classification == "blocked" and not next_value:
        next_value = ["冻结最小可行定义并重新评估形式化路线。"]
    ceilings = list(evidence_ceilings or ["candidate-only until an admitted verifier closes the declared capability"])
    alt = alternative_verification_path or "保留人工、来源或其他已准入方法路线，并记录其证据上限。"
    cost_value = _cost(cost if cost is not None else "bounded assessment")
    profiles: list[dict[str, Any]] = []
    if method_profiles is not None:
        profiles = [_copy(item) for item in method_profiles]
    else:
        for method in selected:
            profiles.append(
                {
                    "method": method,
                    "capabilities": list(caps),
                    "evidence_ceiling": list(ceilings),
                    "cost": _copy(cost_value),
                    "risks": list(risks_value),
                    "next_obligations": list(next_value),
                }
            )
    subject = _subject_id(claim_id, obligation_id)
    identity = {
        "problem_id": problem_id,
        "problem_contract_sha256": contract,
        "claim_id": claim_id,
        "obligation_id": obligation_id,
        "subject": subject,
        "classification": classification,
        "reason_codes": reason_codes_value,
        "selected_methods": selected,
        "source_claim_sha256": source_claim_sha256,
    }
    identifier = decision_id or f"formal-decision:{sha256_json(identity)}"
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": _identifier(identifier, "decision_id"),
        "problem_id": problem_id,
        "claim_id": claim_id,
        "obligation_id": obligation_id,
        "problem_contract_sha256": contract,
        "contract_sha256": contract,
        "classification": classification,
        "selected_methods": selected,
        "method_profiles": profiles,
        "reason": reason,
        "rationale": reason,
        "reason_codes": reason_codes_value,
        "capabilities": list(caps),
        "required_capabilities": list(caps),
        "cost": cost_value,
        "risks": risks_value,
        "next_obligations": next_value,
        "evidence_ceilings": ceilings,
        "alternative_verification_path": _copy(alt),
        "blockers": blockers_value,
        "owner": _text(owner, "owner"),
        "created_at": _timestamp(created_at, "created_at"),
        "supersedes": supersedes,
    }
    if claim_type is not None:
        value["claim_type"] = _text(claim_type, "claim_type")
    if evidence_target is not None:
        value["evidence_target"] = _text(evidence_target, "evidence_target")
    if source_claim_sha256 is not None:
        value["source_claim_sha256"] = _digest(source_claim_sha256, "source_claim_sha256")
    if metadata is not None:
        value["metadata"] = _copy(dict(metadata))
    for optional_key in ("claim_id", "obligation_id"):
        if value.get(optional_key) is None:
            value.pop(optional_key, None)
    return validate_formal_method_decision(value, problem=problem)


# Common spelling used in some coordinator code.
make_formal_method_decision = build_formal_method_decision


def _canonical_formalization_classification(value: str) -> str:
    return {
        "formalize_now": "required",
        "formalize_later": "recommended",
        "required": "required",
        "recommended": "recommended",
        "not_applicable": "not_applicable",
        "blocked": "blocked",
    }.get(value, value)


def validate_formalization_decision(
    decision: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    problem: Mapping[str, Any] | None = None,
    parent_decision: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(decision, Mapping):
        raise FormalizationContractError("FormalizationDecision 必须是 object")
    value = dict(decision)
    _validate_schema(value, "formalization-decision.schema.json", project_root=project_root, label="FormalizationDecision")
    if "formalization_decision_id" in value and "decision_id" in value and value["formalization_decision_id"] != value["decision_id"]:
        raise ContractChainError("FormalizationDecision ID 别名不一致")
    contract = _alias(value, ("problem_contract_sha256", "contract_sha256"), "ProblemContract digest")
    _digest(contract, "ProblemContract digest")
    if problem is not None and contract != sha256_json(dict(problem)):
        raise DigestMismatchError("FormalizationDecision 的 ProblemContract digest 漂移")
    if parent_decision is not None:
        parent_contract = _alias(parent_decision, ("problem_contract_sha256", "contract_sha256"), "parent contract digest")
        if value.get("formal_method_decision_id") != parent_decision.get("decision_id"):
            raise ContractChainError("FormalizationDecision 未绑定父 FormalMethodDecision")
        if contract != parent_contract or value.get("problem_id") != parent_decision.get("problem_id"):
            raise ContractChainError("FormalizationDecision 与父决策身份不一致")
        for field in ("claim_id", "obligation_id"):
            if value.get(field) is not None and parent_decision.get(field) != value.get(field):
                raise ContractChainError(f"FormalizationDecision {field} 与父决策不一致")
    _subject_id(value.get("claim_id"), value.get("obligation_id"))
    if value.get("method") != "lean":
        raise FormalizationContractError("FormalizationDecision.method 必须为 lean")
    classification = _canonical_formalization_classification(value["classification"])
    _list_of_text(value["reason_codes"], "reason_codes", allow_empty=False)
    if "decision" in value and _canonical_formalization_classification(value["decision"]) != classification:
        raise ContractChainError("FormalizationDecision classification/decision 不一致")
    caps = _optional_alias(value, ("capabilities", "required_capabilities"), "Lean capabilities")
    _list_of_text(caps, "Lean capabilities", allow_empty=False)
    if "capabilities" in value and "required_capabilities" in value and value["capabilities"] != value["required_capabilities"]:
        raise ContractChainError("capabilities 与 required_capabilities 不一致")
    _cost(value["cost"])
    _list_of_text(value["risks"], "risks", allow_empty=False)
    _list_of_text(value["next_obligations"], "next_obligations", allow_empty=False)
    _list_of_text(value["evidence_ceilings"], "evidence_ceilings", allow_empty=False)
    _nonempty_json(value["alternative_verification_path"], "alternative_verification_path")
    blockers = _list_of_text(value["blockers"], "blockers")
    if classification == "blocked" and (not blockers or not value["next_obligations"]):
        raise FormalizationContractError("blocked Lean 决策必须记录 blockers 和 next_obligations")
    lean_target = value.get("lean")
    if lean_target is not None:
        if lean_target.get("language") != "Lean4" or not isinstance(lean_target.get("required"), bool):
            raise FormalizationContractError("Lean target profile 无效")
        if classification == "required" and lean_target["required"] is not True:
            raise FormalizationContractError("required Lean 决策必须标记 required=true")
    _timestamp(value["created_at"], "created_at")
    if value.get("supersedes") is not None:
        _identifier(value["supersedes"], "supersedes")
    return _copy(value)


def build_formalization_decision(
    *,
    formal_method_decision: Mapping[str, Any] | None = None,
    formal_method_decision_id: str | None = None,
    classification: str | None = None,
    decision: str | None = None,
    problem: Mapping[str, Any] | None = None,
    problem_id: str | None = None,
    contract_sha256: str | None = None,
    claim_id: str | None = None,
    obligation_id: str | None = None,
    reason: str | None = None,
    reason_codes: Sequence[str] | None = None,
    capabilities: Sequence[str] | None = None,
    required_capabilities: Sequence[str] | None = None,
    cost: Any = None,
    risks: Sequence[str] | None = None,
    next_obligations: Sequence[str] | None = None,
    evidence_ceilings: Sequence[str] | None = None,
    alternative_verification_path: Any = None,
    blockers: Sequence[str] | None = None,
    owner: str = "coordinator",
    created_at: str = _DEFAULT_TIMESTAMP,
    formalization_decision_id: str | None = None,
    lean_required: bool | None = None,
    lean_profile: Mapping[str, Any] | None = None,
    supersedes: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    parent = formal_method_decision
    if parent is not None:
        validate_formal_method_decision(parent, problem=problem)
        if problem_id is None:
            problem_id = parent.get("problem_id")
        if contract_sha256 is None:
            contract_sha256 = parent.get("problem_contract_sha256", parent.get("contract_sha256"))
        if claim_id is None:
            claim_id = parent.get("claim_id")
        if obligation_id is None:
            obligation_id = parent.get("obligation_id")
        if formal_method_decision_id is None:
            formal_method_decision_id = parent.get("decision_id")
        if classification is None and decision is None:
            classification = _canonical_formalization_classification(parent["classification"])
    if classification is None:
        classification = decision
    if classification is None:
        raise FormalizationContractError("缺少 FormalizationDecision classification")
    classification = _canonical_formalization_classification(classification)
    if classification not in {"required", "recommended", "not_applicable", "blocked"}:
        raise FormalizationContractError("未知 Lean formalization classification")
    if decision is not None and _canonical_formalization_classification(decision) != classification:
        raise ContractChainError("classification 与 decision 不一致")
    problem_id, contract, claim_id, obligation_id = _decision_common(
        problem=problem,
        problem_id=problem_id,
        contract_sha256=contract_sha256,
        claim_id=claim_id,
        obligation_id=obligation_id,
    )
    if formal_method_decision_id is None:
        raise FormalizationContractError("FormalizationDecision 必须绑定既有 FormalMethodDecision")
    _identifier(formal_method_decision_id, "formal_method_decision_id")
    caps = list(capabilities or required_capabilities or ["kernel_check", "axiom_escape_audit", "statement_faithfulness"])
    if capabilities is not None and required_capabilities is not None and list(capabilities) != list(required_capabilities):
        raise ContractChainError("capabilities 与 required_capabilities 不一致")
    risks_value = list(risks or ["Lean statement may diverge from the frozen ProblemContract."])
    default_next = {
        "required": ["生成并独立重放 Lean candidate，随后完成公理与陈述忠实性审查。"],
        "recommended": ["在定义和预算稳定后建立最小 Lean 回归。"],
        "not_applicable": ["沿记录的来源、计算或人工审查路线继续验证。"],
        "blocked": ["冻结定义/工具链后重新运行 Lean 适用性评估。"],
    }
    next_value = list(next_obligations) if next_obligations is not None else list(default_next[classification])
    _list_of_text(next_value, "next_obligations", allow_empty=False)
    blockers_value = list(blockers or [])
    if classification == "blocked" and not blockers_value:
        blockers_value = ["Lean statement、库覆盖、工具链或预算尚未闭合。"]
    if classification == "blocked" and not next_value:
        next_value = ["冻结定义/工具链后重新运行 Lean 适用性评估。"]
    ceilings = list(evidence_ceilings or ["kernel_check only; axiom audit and statement-faithfulness remain separate gates"])
    reason_codes_value = list(reason_codes or [f"classification:{classification}"])
    _list_of_text(reason_codes_value, "reason_codes", allow_empty=False)
    cost_value = _cost(cost if cost is not None else "bounded Lean assessment")
    required_value = classification == "required" if lean_required is None else bool(lean_required)
    target = {"language": "Lean4", "required": required_value}
    if lean_profile is not None:
        target.update(_copy(dict(lean_profile)))
        target["language"] = "Lean4"
        target["required"] = required_value
    identity = {
        "parent": formal_method_decision_id,
        "problem_id": problem_id,
        "contract": contract,
        "claim_id": claim_id,
        "obligation_id": obligation_id,
        "classification": classification,
        "reason_codes": reason_codes_value,
    }
    decision_id = formalization_decision_id or f"lean-decision:{sha256_json(identity)}"
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "formalization_decision_id": _identifier(decision_id, "formalization_decision_id"),
        "decision_id": _identifier(decision_id, "decision_id"),
        "formal_method_decision_id": formal_method_decision_id,
        "problem_id": problem_id,
        "claim_id": claim_id,
        "obligation_id": obligation_id,
        "problem_contract_sha256": contract,
        "contract_sha256": contract,
        "classification": classification,
        "decision": classification,
        "method": "lean",
        "reason": _text(reason, "reason") if reason is not None else "Lean is selected only within this frozen statement and environment boundary.",
        "reason_codes": reason_codes_value,
        "capabilities": caps,
        "required_capabilities": list(caps),
        "cost": cost_value,
        "risks": risks_value,
        "next_obligations": next_value,
        "evidence_ceilings": ceilings,
        "alternative_verification_path": _copy(alternative_verification_path or "Use the parent decision's admitted non-Lean route when Lean is not yet sufficient."),
        "blockers": blockers_value,
        "lean": target,
        "owner": _text(owner, "owner"),
        "created_at": _timestamp(created_at, "created_at"),
        "supersedes": supersedes,
    }
    if metadata is not None:
        value["metadata"] = _copy(dict(metadata))
    for optional_key in ("claim_id", "obligation_id"):
        if value.get(optional_key) is None:
            value.pop(optional_key, None)
    return validate_formalization_decision(value, problem=problem, parent_decision=parent)


make_lean_formalization_decision = build_formalization_decision
make_formalization_decision = build_formalization_decision
validate_lean_formalization_decision = validate_formalization_decision


def _normalise_normalized_statement(
    normalized_statement: Mapping[str, Any] | None,
    problem: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if normalized_statement is None and problem is not None:
        normalized_statement = {
            "objects": list(problem.get("domain", {}).get("objects", [])),
            "domain": problem.get("domain", {}).get("description"),
            "quantifiers": list(problem.get("quantifiers", [])),
            "assumptions": list(problem.get("assumptions", [])),
            "conclusion": problem.get("statement", {}).get("text"),
        }
    if not isinstance(normalized_statement, Mapping):
        raise FormalizationContractError("必须提供 normalized_statement")
    result = _copy(dict(normalized_statement))
    objects = result.get("objects")
    if not isinstance(objects, list) or not objects or any(not isinstance(item, str) or not item for item in objects):
        raise FormalizationContractError("normalized_statement.objects 无效")
    if len(set(objects)) != len(objects):
        raise FormalizationContractError("normalized_statement.objects 无效")
    _text(result.get("domain"), "normalized_statement.domain")
    quantifiers = result.get("quantifiers")
    if not isinstance(quantifiers, list) or not quantifiers or any(
        (isinstance(item, str) and not item) or (isinstance(item, Mapping) and not item) or not isinstance(item, (str, Mapping))
        for item in quantifiers
    ):
        raise FormalizationContractError("normalized_statement.quantifiers 无效")
    if not isinstance(result.get("assumptions"), list) or any(not isinstance(item, str) or not item for item in result["assumptions"]):
        raise FormalizationContractError("normalized_statement.assumptions 无效")
    _text(result.get("conclusion"), "normalized_statement.conclusion")
    return result


def _normalise_toolchain(
    toolchain: Mapping[str, Any] | None,
    *,
    lean_version: str | None,
    lake_version: str | None,
    mathlib_commit: str | None,
    manifest_sha256: str | None,
    toolchain_fingerprint: str | None,
) -> dict[str, Any]:
    source = dict(toolchain or {})
    values = {
        "lean_version": source.get("lean_version", lean_version),
        "lake_version": source.get("lake_version", lake_version),
        "mathlib_commit": source.get("mathlib_commit", mathlib_commit),
        "manifest_sha256": source.get("manifest_sha256", manifest_sha256 or source.get("manifest_digest")),
        "fingerprint": source.get("fingerprint", toolchain_fingerprint),
    }
    for name in ("lean_version", "lake_version", "mathlib_commit"):
        _text(values[name], f"toolchain.{name}")
    _digest(values["manifest_sha256"], "toolchain.manifest_sha256")
    expected_fingerprint = sha256_json(
        {key: values[key] for key in ("lean_version", "lake_version", "mathlib_commit", "manifest_sha256")}
    )
    if values["fingerprint"] is None:
        values["fingerprint"] = expected_fingerprint
    _digest(values["fingerprint"], "toolchain.fingerprint")
    if values["fingerprint"] != expected_fingerprint:
        raise DigestMismatchError("toolchain.fingerprint 与 Lean/Lake/Mathlib/manifest 身份不一致")
    result = {
        "lean_version": values["lean_version"],
        "lake_version": values["lake_version"],
        "mathlib_commit": values["mathlib_commit"],
        "manifest_sha256": values["manifest_sha256"],
        "fingerprint": values["fingerprint"],
    }
    for key in ("profile",):
        if key in source:
            result[key] = _text(source[key], f"toolchain.{key}")
    return result


def _normalise_budget(value: Mapping[str, Any] | None, problem: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(value or {})
    runtime = problem.get("constraints", {}).get("runtime", {}) if problem is not None else {}
    aliases = {
        "timeout_seconds": source.get("timeout_seconds", source.get("wall_time_seconds", runtime.get("timeout_seconds", 60))),
        "max_output_bytes": source.get("max_output_bytes", runtime.get("max_output_bytes", 1_048_576)),
        "max_memory_bytes": source.get("max_memory_bytes", source.get("memory_bytes", 256 * 1024 * 1024)),
        "max_cpu_seconds": source.get("max_cpu_seconds", source.get("cpu_seconds", 60)),
        "max_retries": source.get("max_retries", runtime.get("max_retries", 2)),
    }
    for name, item in aliases.items():
        minimum = 0 if name == "max_retries" else 1
        if not isinstance(item, int) or item < minimum:
            raise FormalizationContractError(f"budget.{name} 必须是非负/正整数")
    result = {
        "timeout_seconds": aliases["timeout_seconds"],
        "max_output_bytes": aliases["max_output_bytes"],
        "max_memory_bytes": aliases["max_memory_bytes"],
        "max_cpu_seconds": aliases["max_cpu_seconds"],
        "max_retries": aliases["max_retries"],
    }
    if "max_files" in source:
        if not isinstance(source["max_files"], int) or source["max_files"] <= 0:
            raise FormalizationContractError("budget.max_files 必须为正整数")
        result["max_files"] = source["max_files"]
    return result


def _validate_symbol_map(value: Any) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise FormalizationContractError("symbol_map 必须是非空数组")
    normalized: list[Any] = []
    for index, item in enumerate(value):
        if isinstance(item, Mapping):
            natural = item.get("natural_language", item.get("source", item.get("nl")))
            lean = item.get("lean", item.get("target", item.get("lean_symbol")))
            _text(natural, f"symbol_map[{index}].natural_language")
            _text(lean, f"symbol_map[{index}].lean")
            normalized.append(_copy(dict(item)))
        elif isinstance(item, list) and len(item) == 2:
            _text(item[0], f"symbol_map[{index}][0]")
            _text(item[1], f"symbol_map[{index}][1]")
            normalized.append(_copy(item))
        else:
            raise FormalizationContractError("symbol_map 项必须包含自然语言与 Lean 符号")
    return normalized


def _normalise_lean(
    lean: Mapping[str, Any] | None,
    *,
    lean_declaration: str | None,
    lean_statement: str | None,
    obligation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    source = dict(lean or {})
    declaration = source.get("declaration", lean_declaration)
    statement = source.get("statement", lean_statement)
    if declaration is None and obligation is not None:
        formal = obligation.get("statement", {}).get("formal_declaration")
        if isinstance(formal, str):
            declaration = formal.split(":", 1)[0].replace("theorem", "").strip()
    _text(declaration, "lean.declaration")
    _text(statement, "lean.statement")
    result: dict[str, Any] = {"declaration": declaration, "statement": statement}
    if source.get("module") is not None:
        result["module"] = _text(source["module"], "lean.module")
    result["statement_sha256"] = sha256_text(statement)
    return result


def _package_self_digest(package: Mapping[str, Any]) -> str:
    value = {key: item for key, item in package.items() if key != "package_sha256"}
    return sha256_json(value)


def validate_formalization_package(
    package: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    problem: Mapping[str, Any] | None = None,
    attempt: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
    obligation: Mapping[str, Any] | None = None,
    candidate: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate all lineage digests and every local source ref in a package."""
    if context is not None:
        problem = _record_from_context(context, "problem", problem)
        attempt = _record_from_context(context, "attempt", attempt)
        graph = _record_from_context(context, "graph", graph)
        obligation = _record_from_context(context, "obligation", obligation)
        candidate = _record_from_context(context, "candidate", candidate)
    if not isinstance(package, Mapping):
        raise FormalizationContractError("FormalizationPackage 必须是 object")
    value = dict(package)
    _validate_schema(value, "formalization-package.schema.json", project_root=project_root, label="FormalizationPackage")
    for field in ("package_id", "problem_id", "attempt_id", "graph_id", "obligation_id", "candidate_id"):
        _identifier(value[field], field)
    digest_names = {
        "problem_contract_sha256": ("problem_contract_sha256", "contract_sha256"),
        "attempt_sha256": ("attempt_sha256", "attempt_digest"),
        "graph_sha256": ("graph_sha256", "graph_digest"),
        "obligation_sha256": ("obligation_sha256", "obligation_digest"),
        "candidate_sha256": ("candidate_sha256", "candidate_digest"),
    }
    digests: dict[str, str] = {}
    for canonical, names in digest_names.items():
        digests[canonical] = _digest(_alias(value, names, canonical), canonical)
    if "package_sha256" in value and _digest(value["package_sha256"], "package_sha256") != _package_self_digest(value):
        raise DigestMismatchError("FormalizationPackage package_sha256 漂移")
    if value.get("obligation_statement_sha256") is not None:
        _digest(value["obligation_statement_sha256"], "obligation_statement_sha256")
    if problem is not None and (
        value["problem_id"] != problem.get("problem_id")
        or digests["problem_contract_sha256"] != sha256_json(dict(problem))
    ):
        raise ContractChainError("FormalizationPackage 与 ProblemContract 不一致")
    if attempt is not None:
        if value["attempt_id"] != attempt.get("attempt_id") or digests["attempt_sha256"] != sha256_json(dict(attempt)):
            raise ContractChainError("FormalizationPackage 与 Attempt 不一致")
        if attempt.get("problem_id") != value["problem_id"]:
            raise ContractChainError("FormalizationPackage Attempt 跨 Problem")
        if attempt.get("problem_contract_sha256") is not None and attempt.get("problem_contract_sha256") != digests["problem_contract_sha256"]:
            raise ContractChainError("Attempt 的 ProblemContract digest 不一致")
        if attempt.get("obligation_graph_id") is not None and attempt.get("obligation_graph_id") != value["graph_id"]:
            raise ContractChainError("Attempt obligation_graph_id 与 package 不一致")
    if graph is not None:
        if value["graph_id"] != graph.get("graph_id") or digests["graph_sha256"] != sha256_json(dict(graph)):
            raise ContractChainError("FormalizationPackage 与 ObligationGraph 不一致")
        if graph.get("problem_id") != value["problem_id"] or graph.get("problem_contract_sha256") != digests["problem_contract_sha256"]:
            raise ContractChainError("ObligationGraph 的 Problem 身份不一致")
        if graph.get("root_obligation_id") is not None and graph.get("root_obligation_id") != value["obligation_id"]:
            raise ContractChainError("ObligationGraph root 与 package obligation 不一致")
        graph_obligations = graph.get("obligations")
        if isinstance(graph_obligations, list) and graph_obligations and not any(
            isinstance(item, Mapping) and item.get("obligation_id") == value["obligation_id"]
            for item in graph_obligations
        ):
            raise ContractChainError("package obligation 不在 ObligationGraph 中")
    if obligation is not None:
        if value["obligation_id"] != obligation.get("obligation_id") or digests["obligation_sha256"] != sha256_json(dict(obligation)):
            raise ContractChainError("FormalizationPackage 与 Obligation 不一致")
        statement = obligation.get("statement")
        if isinstance(statement, Mapping):
            statement_digest = sha256_json(dict(statement))
            if obligation.get("statement_sha256") is not None and obligation.get("statement_sha256") != statement_digest:
                raise DigestMismatchError("Obligation statement_sha256 漂移")
            declared = value.get("obligation_statement_sha256")
            if declared is not None and declared != statement_digest:
                raise DigestMismatchError("obligation_statement_sha256 漂移")
            if candidate is not None and candidate.get("statement_sha256") != statement_digest:
                raise ContractChainError("Candidate 的 statement digest 与 Obligation 不一致")
    if candidate is not None:
        if value["candidate_id"] != candidate.get("candidate_id") or digests["candidate_sha256"] != sha256_json(dict(candidate)):
            raise ContractChainError("FormalizationPackage 与 Candidate 不一致")
        if candidate.get("problem_id") != value["problem_id"] or candidate.get("attempt_id") != value["attempt_id"] or candidate.get("graph_id") != value["graph_id"] or candidate.get("obligation_id") != value["obligation_id"]:
            raise ContractChainError("Candidate lineage 与 package 不一致")
    source_claim = value.get("source_claim")
    source_text = source_claim.get("text") if isinstance(source_claim, Mapping) else value.get("source_claim_text")
    source_digest = source_claim.get("sha256") if isinstance(source_claim, Mapping) else value.get("source_claim_sha256")
    _text(source_text, "source_claim_text")
    if sha256_text(source_text) != _digest(source_digest, "source_claim_sha256"):
        raise DigestMismatchError("source_claim_sha256 漂移")
    if source_claim is not None and value.get("source_claim_text") is not None and value["source_claim_text"] != source_text:
        raise ContractChainError("source_claim_text 与 source_claim 不一致")
    if source_claim is not None and value.get("source_claim_sha256") is not None and value["source_claim_sha256"] != source_digest:
        raise ContractChainError("source_claim_sha256 与 source_claim 不一致")
    nested_claim_locator = source_claim.get("locator") if isinstance(source_claim, Mapping) else None
    top_claim_locator = value.get("source_claim_locator")
    if nested_claim_locator is not None and top_claim_locator is not None and nested_claim_locator != top_claim_locator:
        raise ContractChainError("source_claim locator 别名漂移")
    source_claim_locator = nested_claim_locator or top_claim_locator
    if source_claim_locator is not None:
        claim_ref = {"locator": source_claim_locator, "sha256": source_digest}
        claim_path_ref = _validate_ref(claim_ref, "source_claim", project_root=project_root)
        if project_root is not None:
            try:
                claim_text = _trusted_artifact_path(project_root, claim_path_ref["locator"], must_exist=True).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise FormalizationContractError("source_claim locator 必须指向 UTF-8 文本") from exc
            if sha256_text(claim_text) != claim_path_ref["sha256"]:
                raise DigestMismatchError("source_claim locator 内容摘要漂移")
    normalized = value.get("normalized_statement", value.get("normalized"))
    normalized = _normalise_normalized_statement(normalized, None)
    if "normalized" in value and value["normalized"] != normalized:
        raise ContractChainError("normalized_statement 与 normalized 不一致")
    lean = value.get("lean")
    if lean is None:
        lean = {"declaration": value.get("lean_declaration"), "statement": value.get("lean_statement")}
    else:
        lean = dict(lean)
    declaration = _text(lean.get("declaration"), "lean.declaration")
    lean_statement = _text(lean.get("statement"), "lean.statement")
    if value.get("lean_declaration") is not None and value["lean_declaration"] != declaration:
        raise ContractChainError("lean_declaration 与 lean 不一致")
    if value.get("lean_statement") is not None and value["lean_statement"] != lean_statement:
        raise ContractChainError("lean_statement 与 lean 不一致")
    expected_lean_digest = sha256_text(lean_statement)
    if lean.get("statement_sha256") is not None and lean["statement_sha256"] != expected_lean_digest:
        raise DigestMismatchError("Lean statement digest 漂移")
    if value.get("lean_statement_sha256") is not None and value["lean_statement_sha256"] != expected_lean_digest:
        raise DigestMismatchError("lean_statement_sha256 漂移")
    for import_name in value["imports"]:
        _safe_import(import_name)
    _validate_symbol_map(value["symbol_map"])
    _list_of_text(value["allowed_axioms"], "allowed_axioms")
    toolchain = value.get("toolchain")
    if toolchain is None:
        toolchain = {
            "lean_version": value.get("lean_version"),
            "lake_version": value.get("lake_version"),
            "mathlib_commit": value.get("mathlib_commit"),
            "manifest_sha256": value.get("manifest_sha256"),
            "fingerprint": value.get("toolchain_fingerprint"),
        }
    toolchain = _normalise_toolchain(toolchain, lean_version=None, lake_version=None, mathlib_commit=None, manifest_sha256=None, toolchain_fingerprint=None)
    for name in ("lean_version", "lake_version", "mathlib_commit"):
        if toolchain[name].strip().lower() in {"unknown", "latest", "current", "n/a"}:
            raise FormalizationContractError(f"toolchain.{name} 不能使用占位身份")
    for key, alias_name in (("lean_version", "lean_version"), ("lake_version", "lake_version"), ("mathlib_commit", "mathlib_commit"), ("manifest_sha256", "manifest_sha256"), ("fingerprint", "toolchain_fingerprint")):
        if value.get(alias_name) is not None and value[alias_name] != toolchain[key]:
            raise ContractChainError(f"toolchain.{key} 别名漂移")
    budget = value.get("budgets", value.get("budget"))
    _normalise_budget(budget, None)
    if "budgets" in value and "budget" in value and value["budgets"] != value["budget"]:
        raise ContractChainError("budgets 与 budget 不一致")
    proof = value.get("proof_source")
    if proof is None:
        proof = {"locator": value.get("proof_source_locator"), "sha256": value.get("proof_source_sha256")}
    proof_ref = _validate_ref(proof, "proof_source", project_root=project_root)
    if value.get("proof_source_locator") is not None and value["proof_source_locator"] != proof_ref["locator"]:
        raise ContractChainError("proof_source_locator 漂移")
    if value.get("proof_source_sha256") is not None and value["proof_source_sha256"] != proof_ref["sha256"]:
        raise ContractChainError("proof_source_sha256 漂移")
    source_files = value.get("source_files", [])
    validated_source_files: list[dict[str, Any]] = []
    for index, item in enumerate(source_files):
        validated_source_files.append(_validate_ref(item, f"source_files[{index}]", project_root=project_root))
    if not validated_source_files:
        raise ContractChainError("FormalizationPackage 必须列出至少一个 source_files")
    if proof_ref["locator"] not in {item["locator"] for item in validated_source_files}:
        raise ContractChainError("proof_source 必须列入 source_files")
    refs = value["source_refs"]
    for index, item in enumerate(refs):
        if isinstance(item, str):
            if "\x00" in item or "\\" in item or item.startswith("/") or ".." in PurePosixPath(item).parts:
                raise UnsafeLocatorError(f"source_refs[{index}] 路径逃逸")
            if item.startswith("research/artifacts/") and project_root is not None:
                _ref_from_input(item, project_root=project_root, label=f"source_refs[{index}]")
            else:
                _text(item, f"source_refs[{index}]")
        else:
            _validate_ref(item, f"source_refs[{index}]", project_root=project_root)
    if candidate is not None and isinstance(candidate.get("artifact"), Mapping):
        artifact = candidate["artifact"]
        if proof_ref["locator"] != artifact.get("locator"):
            raise ContractChainError("package proof_source 必须绑定 Candidate artifact")
        if proof_ref["sha256"] != artifact.get("sha256"):
            raise DigestMismatchError("Candidate artifact 与 package proof_source 摘要不一致")
    source_path = None
    if project_root is not None:
        source_path = _trusted_artifact_path(project_root, proof_ref["locator"], must_exist=True)
        try:
            source_text_value = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise FormalizationContractError("Lean proof source 必须是 UTF-8 文本") from exc
        escapes = scan_lean_source(source_text_value)
        if escapes:
            raise FormalizationContractError(f"Lean source 含禁止占位/逃逸：{', '.join(escapes)}")
        declared_imports = set(value["imports"])
        source_imports = extract_lean_imports(source_text_value)
        undeclared = sorted(set(source_imports).difference(declared_imports))
        if undeclared:
            raise ContractChainError(f"Lean source import 未列入 package imports：{', '.join(undeclared)}")
        declaration_name = declaration.rsplit(".", 1)[-1]
        declaration_pattern = rf"^\s*(?:theorem|lemma|example|def|abbrev|opaque|instance|class|structure|inductive)\s+{re.escape(declaration_name)}\b"
        if re.search(declaration_pattern, _strip_lean_comments_and_strings(source_text_value), re.MULTILINE) is None:
            raise ContractChainError("Lean proof source 未包含 package top-level 声明")
    # Reuse entries are checked for statement identity, not trusted as proof evidence.
    for index, reuse in enumerate(value["reused_declarations"]):
        statement_value = reuse.get("statement")
        if sha256_text(statement_value) != reuse.get("statement_sha256"):
            raise DigestMismatchError(f"reused_declarations[{index}] statement_sha256 漂移")
        if reuse.get("relation") not in {"exact", "stronger", "weaker", "analogy", "unknown"}:
            raise FormalizationContractError("未知 declaration reuse relation")
        if reuse.get("imports") is not None:
            for import_name in reuse["imports"]:
                _safe_import(import_name)
    if not isinstance(value["blueprint"], (Mapping, str)) or not value["blueprint"]:
        raise FormalizationContractError("blueprint 不能为空")
    if not isinstance(value["unresolved_obligations"], list):
        raise FormalizationContractError("unresolved_obligations 必须是数组")
    if not isinstance(value["claim_ceiling"], (Mapping, str)) or not value["claim_ceiling"]:
        raise FormalizationContractError("claim_ceiling 不能为空")
    _timestamp(value["created_at"], "created_at")
    return _copy(value)


def build_formalization_package(
    *,
    problem: Mapping[str, Any] | None = None,
    attempt: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
    obligation: Mapping[str, Any] | None = None,
    candidate: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
    problem_id: str | None = None,
    contract_sha256: str | None = None,
    attempt_id: str | None = None,
    graph_id: str | None = None,
    obligation_id: str | None = None,
    candidate_id: str | None = None,
    attempt_sha256: str | None = None,
    graph_sha256: str | None = None,
    obligation_sha256: str | None = None,
    candidate_sha256: str | None = None,
    obligation_statement_sha256: str | None = None,
    source_claim_text: str | None = None,
    source_claim_sha256: str | None = None,
    source_claim_locator: str | Path | None = None,
    normalized_statement: Mapping[str, Any] | None = None,
    lean: Mapping[str, Any] | None = None,
    lean_declaration: str | None = None,
    lean_statement: str | None = None,
    symbol_map: Sequence[Any] | None = None,
    allowed_axioms: Sequence[str] | None = None,
    imports: Sequence[str] | None = None,
    toolchain: Mapping[str, Any] | None = None,
    lean_version: str | None = None,
    lake_version: str | None = None,
    mathlib_commit: str | None = None,
    manifest_sha256: str | None = None,
    toolchain_fingerprint: str | None = None,
    reused_declarations: Sequence[Mapping[str, Any]] | None = None,
    proof_source: Mapping[str, Any] | str | Path | None = None,
    proof_source_locator: str | None = None,
    proof_source_sha256: str | None = None,
    source_files: Sequence[Mapping[str, Any]] | None = None,
    blueprint: Any = None,
    unresolved_obligations: Sequence[Any] | None = None,
    claim_ceiling: Any = "candidate-only",
    budgets: Mapping[str, Any] | None = None,
    source_refs: Sequence[Any] | None = None,
    project_root: Path | None = None,
    formalization_decision_id: str | None = None,
    generator: str | None = None,
    created_at: str = _DEFAULT_TIMESTAMP,
    package_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a digest-bound package from supplied records and a local Lean source."""
    if context is not None:
        problem = _record_from_context(context, "problem", problem)
        attempt = _record_from_context(context, "attempt", attempt)
        graph = _record_from_context(context, "graph", graph)
        obligation = _record_from_context(context, "obligation", obligation)
        candidate = _record_from_context(context, "candidate", candidate)
    if problem is not None:
        problem_id = problem.get("problem_id", problem_id)
        contract_sha256 = sha256_json(dict(problem)) if contract_sha256 is None else contract_sha256
    if attempt is not None:
        attempt_id = attempt.get("attempt_id", attempt_id)
    if graph is not None:
        graph_id = graph.get("graph_id", graph_id)
    if obligation is not None:
        obligation_id = obligation.get("obligation_id", obligation_id)
    if candidate is not None:
        candidate_id = candidate.get("candidate_id", candidate_id)
    problem_id, contract, _, _ = _decision_common(
        problem=problem,
        problem_id=problem_id,
        contract_sha256=contract_sha256,
        claim_id=None,
        obligation_id=obligation_id,
    )
    ids = {
        "attempt_id": _identifier(attempt_id, "attempt_id"),
        "graph_id": _identifier(graph_id, "graph_id"),
        "obligation_id": _identifier(obligation_id, "obligation_id"),
        "candidate_id": _identifier(candidate_id, "candidate_id"),
    }
    records = {"attempt": attempt, "graph": graph, "obligation": obligation, "candidate": candidate}
    for name, record in records.items():
        if record is not None and record.get({"attempt": "attempt_id", "graph": "graph_id", "obligation": "obligation_id", "candidate": "candidate_id"}[name]) != ids[{"attempt": "attempt_id", "graph": "graph_id", "obligation": "obligation_id", "candidate": "candidate_id"}[name]]:
            raise ContractChainError(f"{name} record ID 与 package 参数不一致")
    if attempt is not None and attempt.get("problem_id") != problem_id:
        raise ContractChainError("Attempt problem_id 与 package 不一致")
    if graph is not None and (graph.get("problem_id") != problem_id or graph.get("attempt_id") != ids["attempt_id"]):
        raise ContractChainError("ObligationGraph lineage 与 package 不一致")
    if obligation is None and obligation_sha256 is None:
        raise FormalizationContractError("必须提供 obligation 或 obligation_sha256")
    if candidate is None and candidate_sha256 is None:
        raise FormalizationContractError("必须提供 candidate 或 candidate_sha256")
    if attempt is None and attempt_sha256 is None:
        raise FormalizationContractError("必须提供 attempt 或 attempt_sha256")
    if graph is None and graph_sha256 is None:
        raise FormalizationContractError("必须提供 graph 或 graph_sha256")
    if attempt is not None and attempt.get("attempt_id") != ids["attempt_id"]:
        raise ContractChainError("Attempt ID 与 package 不一致")
    lineage_digests = {
        "attempt_sha256": attempt_sha256 or _record_digest(attempt, "Attempt"),
        "graph_sha256": graph_sha256 or _record_digest(graph, "ObligationGraph"),
        "obligation_sha256": obligation_sha256 or _record_digest(obligation, "Obligation"),
        "candidate_sha256": candidate_sha256 or _record_digest(candidate, "Candidate"),
    }
    for name, digest_value in lineage_digests.items():
        _digest(digest_value, name)
    if obligation is not None:
        derived_obligation_statement_sha256 = sha256_json(dict(obligation.get("statement", {})))
        if obligation_statement_sha256 is not None and obligation_statement_sha256 != derived_obligation_statement_sha256:
            raise DigestMismatchError("obligation_statement_sha256 与 Obligation 不一致")
        obligation_statement_sha256 = obligation_statement_sha256 or derived_obligation_statement_sha256
    else:
        _digest(obligation_statement_sha256, "obligation_statement_sha256")
    if candidate is not None and candidate.get("artifact") is not None and proof_source is None and proof_source_locator is None:
        proof_source = candidate["artifact"]
    if proof_source is None and proof_source_locator is not None:
        proof_source = {"locator": proof_source_locator, "sha256": proof_source_sha256}
    proof_ref = _ref_from_input(proof_source, project_root=project_root, label="proof_source", media_type="text/x-lean")
    if proof_source_sha256 is not None and proof_source_sha256 != proof_ref["sha256"]:
        raise DigestMismatchError("proof_source_sha256 与现场文件不一致")
    if candidate is not None and candidate.get("artifact") is not None:
        candidate_artifact = candidate["artifact"]
        if candidate_artifact.get("locator") != proof_ref["locator"] or candidate_artifact.get("sha256") != proof_ref["sha256"]:
            raise ContractChainError("Candidate artifact 与 proof source 不一致")
    source_text = source_claim_text
    if source_text is None and problem is not None:
        source_text = problem.get("statement", {}).get("text")
    source_text = _text(source_text, "source_claim_text")
    derived_source_claim_sha256 = sha256_text(source_text)
    if source_claim_sha256 is not None and source_claim_sha256 != derived_source_claim_sha256:
        raise DigestMismatchError("source_claim_sha256 与 source_claim_text 不一致")
    source_claim_ref = None
    if source_claim_locator is not None:
        source_claim_ref = _ref_from_input(
            source_claim_locator,
            project_root=project_root,
            label="source_claim",
            media_type="text/plain",
        )
        if source_claim_ref["sha256"] != derived_source_claim_sha256:
            raise DigestMismatchError("source_claim locator 与 source_claim_text 不一致")
    normalized = _normalise_normalized_statement(normalized_statement, problem)
    lean_value = _normalise_lean(lean, lean_declaration=lean_declaration, lean_statement=lean_statement, obligation=obligation)
    toolchain_value = _normalise_toolchain(
        toolchain,
        lean_version=lean_version,
        lake_version=lake_version,
        mathlib_commit=mathlib_commit,
        manifest_sha256=manifest_sha256,
        toolchain_fingerprint=toolchain_fingerprint,
    )
    budget_value = _normalise_budget(budgets, problem)
    imports_value = list(imports or [])
    for import_name in imports_value:
        _safe_import(import_name)
    if allowed_axioms is not None:
        axioms_value = list(allowed_axioms)
    elif problem is not None:
        axioms_value = list(problem.get("allowed_axioms", []))
    else:
        axioms_value = []
    _list_of_text(axioms_value, "allowed_axioms")
    reuse_value = [_copy(item) for item in (reused_declarations or [])]
    for item in reuse_value:
        if not isinstance(item, Mapping):
            raise FormalizationContractError("reused_declarations 必须是 object 数组")
        if "statement_sha256" not in item or sha256_text(item.get("statement")) != item["statement_sha256"]:
            raise DigestMismatchError("reused declaration statement digest 无效")
    source_files_value: list[dict[str, Any]] = []
    for index, item in enumerate(source_files or [proof_ref]):
        if isinstance(item, (str, Path)):
            source_files_value.append(_ref_from_input(item, project_root=project_root, label=f"source_files[{index}]", media_type="text/x-lean"))
        else:
            source_files_value.append(_validate_ref(item, f"source_files[{index}]", project_root=project_root))
    if proof_ref["locator"] not in {item["locator"] for item in source_files_value}:
        source_files_value.insert(0, proof_ref)
    refs_value = list(source_refs or [proof_ref])
    # Normalize source refs to structured refs whenever they point at local artifact files.
    normalized_refs: list[Any] = []
    for index, item in enumerate(refs_value):
        if isinstance(item, Mapping):
            normalized_refs.append(_validate_ref(item, f"source_refs[{index}]", project_root=project_root))
        else:
            if not isinstance(item, str):
                raise FormalizationContractError(f"source_refs[{index}] 必须是 locator 或 digest ref")
            if project_root is not None and item.startswith("research/artifacts/"):
                normalized_refs.append(_ref_from_input(item, project_root=project_root, label=f"source_refs[{index}]"))
            else:
                if "\x00" in item or "\\" in item or item.startswith("/") or ".." in PurePosixPath(item).parts:
                    raise UnsafeLocatorError(f"source_refs[{index}] 路径逃逸")
                normalized_refs.append(_text(item, f"source_refs[{index}]"))
    blueprint_value = blueprint if blueprint is not None else {"root_obligation_id": ids["obligation_id"], "nodes": []}
    unresolved_value = list(unresolved_obligations or [])
    if not isinstance(claim_ceiling, (Mapping, str)) or not claim_ceiling:
        raise FormalizationContractError("claim_ceiling 不能为空")
    if formalization_decision_id is not None:
        _identifier(formalization_decision_id, "formalization_decision_id")
    identity = {
        "problem_id": problem_id,
        "problem_contract_sha256": contract,
        "attempt_id": ids["attempt_id"],
        "graph_id": ids["graph_id"],
        "obligation_id": ids["obligation_id"],
        "candidate_id": ids["candidate_id"],
        "source_claim_sha256": sha256_text(source_text),
        "lean": lean_value,
        "proof_source": proof_ref,
        "toolchain": toolchain_value,
        "imports": imports_value,
        "budgets": budget_value,
    }
    package_identifier = package_id or f"package:{sha256_json(identity)}"
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "package_id": _identifier(package_identifier, "package_id"),
        "problem_id": problem_id,
        "attempt_id": ids["attempt_id"],
        "graph_id": ids["graph_id"],
        "obligation_id": ids["obligation_id"],
        "candidate_id": ids["candidate_id"],
        "problem_contract_sha256": contract,
        "contract_sha256": contract,
        "attempt_sha256": lineage_digests["attempt_sha256"],
        "attempt_digest": lineage_digests["attempt_sha256"],
        "graph_sha256": lineage_digests["graph_sha256"],
        "graph_digest": lineage_digests["graph_sha256"],
        "obligation_sha256": lineage_digests["obligation_sha256"],
        "obligation_digest": lineage_digests["obligation_sha256"],
        "candidate_sha256": lineage_digests["candidate_sha256"],
        "candidate_digest": lineage_digests["candidate_sha256"],
        "obligation_statement_sha256": obligation_statement_sha256,
        "source_claim": {
            "text": source_text,
            "sha256": derived_source_claim_sha256,
            **({"locator": source_claim_ref["locator"]} if source_claim_ref is not None else {}),
        },
        "source_claim_text": source_text,
        "source_claim_sha256": derived_source_claim_sha256,
        "normalized_statement": normalized,
        "normalized": _copy(normalized),
        "lean": lean_value,
        "lean_declaration": lean_value["declaration"],
        "lean_statement": lean_value["statement"],
        "lean_statement_sha256": lean_value["statement_sha256"],
        "symbol_map": _validate_symbol_map(list(symbol_map) if symbol_map is not None else []),
        "allowed_axioms": axioms_value,
        "imports": imports_value,
        "toolchain": toolchain_value,
        "lean_version": toolchain_value["lean_version"],
        "lake_version": toolchain_value["lake_version"],
        "mathlib_commit": toolchain_value["mathlib_commit"],
        "manifest_sha256": toolchain_value["manifest_sha256"],
        "toolchain_fingerprint": toolchain_value["fingerprint"],
        "reused_declarations": reuse_value,
        "proof_source": proof_ref,
        "proof_source_locator": proof_ref["locator"],
        "proof_source_sha256": proof_ref["sha256"],
        "source_files": source_files_value,
        "blueprint": _copy(blueprint_value),
        "unresolved_obligations": _copy(unresolved_value),
        "claim_ceiling": _copy(claim_ceiling),
        "budgets": budget_value,
        "budget": _copy(budget_value),
        "source_refs": normalized_refs,
        "created_at": _timestamp(created_at, "created_at"),
    }
    if source_claim_ref is not None:
        value["source_claim_locator"] = source_claim_ref["locator"]
    if formalization_decision_id is not None:
        value["formalization_decision_id"] = formalization_decision_id
    if generator is not None:
        value["generator"] = _identifier(generator, "generator")
    if metadata is not None:
        value["metadata"] = _copy(dict(metadata))
    value["package_sha256"] = _package_self_digest(value)
    return validate_formalization_package(
        value,
        project_root=project_root,
        problem=problem,
        attempt=attempt,
        graph=graph,
        obligation=obligation,
        candidate=candidate,
    )


make_formalization_package = build_formalization_package


def _coordinator_identity(
    coordinator: Mapping[str, Any] | None,
    *,
    coordinator_job_id: str | None,
    coordinator_run_instance_id: str | None,
    coordinator_session_id: str | None,
    coordinator_attempt_id: str | None,
    coordinator_dedupe_key: str | None,
) -> dict[str, str]:
    source = dict(coordinator or {})
    nested = source.get("coordinator_identity")
    if isinstance(nested, Mapping):
        source = {**dict(nested), **source}
    aliases = {
        "job_id": coordinator_job_id or source.get("coordinator_job_id") or source.get("job_id"),
        "run_instance_id": coordinator_run_instance_id or source.get("coordinator_run_instance_id") or source.get("run_instance_id"),
        "session_id": coordinator_session_id or source.get("coordinator_session_id") or source.get("session_id"),
        "attempt_id": coordinator_attempt_id or source.get("coordinator_attempt_id") or source.get("attempt_id"),
        "dedupe_key": coordinator_dedupe_key or source.get("coordinator_dedupe_key") or source.get("dedupe_key"),
    }
    return {key: _identifier(item, f"coordinator.{key}") for key, item in aliases.items()}


def _job_budget(value: Mapping[str, Any] | None, package: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(value or package.get("budgets", package.get("budget", {})))
    wall = source.get("wall_time_seconds", source.get("timeout_seconds"))
    max_output = source.get("max_output_bytes")
    retries = source.get("max_retries")
    if not isinstance(wall, int) or wall <= 0 or not isinstance(max_output, int) or max_output <= 0 or not isinstance(retries, int) or retries < 0:
        raise FormalizationContractError("LeanJob budgets 缺少 wall_time_seconds/max_output_bytes/max_retries")
    result: dict[str, Any] = {
        "wall_time_seconds": wall,
        "max_output_bytes": max_output,
        "max_retries": retries,
    }
    for canonical, aliases in (("memory_bytes", ("memory_bytes", "max_memory_bytes")), ("cpu_seconds", ("cpu_seconds", "max_cpu_seconds")), ("max_files", ("max_files",))):
        for name in aliases:
            if name in source:
                if not isinstance(source[name], int) or source[name] <= 0:
                    raise FormalizationContractError(f"LeanJob budgets.{name} 无效")
                result[canonical] = source[name]
                break
    result["timeout_seconds"] = wall
    if "memory_bytes" in result:
        result["max_memory_bytes"] = result["memory_bytes"]
    if "cpu_seconds" in result:
        result["max_cpu_seconds"] = result["cpu_seconds"]
    return result


def _job_input_material(job: Mapping[str, Any]) -> dict[str, Any]:
    principal = job.get("principal")
    return {
        "package_id": job.get("package_id"),
        "operation": job.get("operation"),
        "principal": principal,
        "trust_domain": job.get("trust_domain"),
        "readonly_inputs": job.get("readonly_inputs", []),
        "budgets": job.get("budgets", job.get("budget")),
        "command_allowlist": job.get("command_allowlist", []),
        "expected_artifacts": job.get("expected_artifacts", []),
        "write_scopes": job.get("write_scopes", []),
        "network_policy": job.get("network_policy"),
        "execution_profile": job.get("execution_profile", {}),
    }


def _principal_id(principal: Any) -> str:
    if isinstance(principal, Mapping):
        return _text(principal.get("id"), "principal.id")
    return _text(principal, "principal")


def validate_lean_job(
    job: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    package: Mapping[str, Any] | None = None,
    coordinator_job: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(job, Mapping):
        raise FormalizationContractError("LeanJob 必须是 object")
    value = dict(job)
    _validate_schema(value, "lean-job.schema.json", project_root=project_root, label="LeanJob")
    _identifier(value["lean_job_id"], "lean_job_id")
    _identifier(value["package_id"], "package_id")
    coord = value.get("coordinator_identity")
    if coord is None:
        coord = {
            "job_id": value.get("coordinator_job_id", value.get("job_id")),
            "run_instance_id": value.get("coordinator_run_instance_id", value.get("run_instance_id")),
            "session_id": value.get("coordinator_session_id", value.get("session_id")),
            "attempt_id": value.get("coordinator_attempt_id", value.get("attempt_id")),
            "dedupe_key": value.get("coordinator_dedupe_key", value.get("dedupe_key")),
        }
    coord = _coordinator_identity(coord, coordinator_job_id=None, coordinator_run_instance_id=None, coordinator_session_id=None, coordinator_attempt_id=None, coordinator_dedupe_key=None)
    flat_aliases = {
        "job_id": ("coordinator_job_id", "job_id"),
        "run_instance_id": ("coordinator_run_instance_id", "run_instance_id"),
        "session_id": ("coordinator_session_id", "session_id"),
        "attempt_id": ("coordinator_attempt_id", "attempt_id"),
        "dedupe_key": ("coordinator_dedupe_key",),
    }
    for key, names in flat_aliases.items():
        for name in names:
            if value.get(name) is not None and value[name] != coord[key]:
                raise ContractChainError(f"LeanJob coordinator {key} 别名不一致")
    nested_identity = value.get("coordinator_identity")
    if isinstance(nested_identity, Mapping):
        for key in flat_aliases:
            if nested_identity.get(key) is not None and nested_identity[key] != coord[key]:
                raise ContractChainError(f"LeanJob coordinator_identity.{key} 别名不一致")
    if coordinator_job is not None:
        for key in ("job_id", "run_instance_id", "session_id", "attempt_id", "dedupe_key"):
            expected = coordinator_job.get(key)
            if expected is not None and coord[key] != expected:
                raise ContractChainError(f"LeanJob 与 Coordinator {key} 不一致")
    if value["lean_job_id"] in set(coord.values()):
        raise ContractChainError("LeanJob identity 必须与 Coordinator job/run/session/attempt/dedupe 分离")
    if value.get("attempt_id") is not None and value["attempt_id"] != coord["attempt_id"]:
        raise ContractChainError("LeanJob attempt_id 必须是 Coordinator attempt 的别名")
    if value.get("problem_contract_sha256") is not None:
        _digest(value["problem_contract_sha256"], "problem_contract_sha256")
    if value.get("problem_id") is not None:
        _identifier(value["problem_id"], "problem_id")
    _principal_id(value["principal"])
    if isinstance(value["principal"], Mapping):
        role = value["principal"].get("role")
        if value["operation"] in {"replay", "axiom_audit", "faithfulness_review"} and role != "verifier":
            raise ContractChainError("验证操作必须由 verifier principal 承担")
        if value["operation"] in {"generate", "repair"} and role not in {"generator", "coordinator"}:
            raise ContractChainError("生成/修补操作不能伪装成 verifier")
    if value["network_policy"] != "disabled":
        raise FormalizationContractError("LeanJob 必须禁用网络")
    budget = value.get("budgets", value.get("budget"))
    normalized_budget = _job_budget(budget, {"budgets": budget})
    if "budgets" in value and "budget" in value and value["budgets"] != value["budget"]:
        raise ContractChainError("LeanJob budgets/budget 不一致")
    for index, item in enumerate(value["readonly_inputs"]):
        _validate_ref(item, f"readonly_inputs[{index}]", project_root=project_root, must_exist=project_root is not None)
    for index, item in enumerate(value["expected_artifacts"]):
        _validate_ref(item, f"expected_artifacts[{index}]", project_root=project_root, must_exist=False)
    for index, item in enumerate(value["write_scopes"]):
        _safe_write_scope(item, f"write_scopes[{index}]")
    for index, item in enumerate(value["command_allowlist"]):
        _safe_command(item, f"command_allowlist[{index}]")
    expected_input = sha256_json(_job_input_material({**value, "budgets": normalized_budget}))
    if value["input_digest"] != expected_input:
        raise DigestMismatchError("LeanJob input_digest 漂移")
    if value.get("dedupe_key", "").startswith("lean-dedupe:"):
        expected_dedupe = f"lean-dedupe:{sha256_json({'package_id': value['package_id'], 'operation': value['operation'], 'input_digest': value['input_digest'], 'coordinator_attempt_id': coord['attempt_id']})}"
        if value["dedupe_key"] != expected_dedupe:
            raise DigestMismatchError("LeanJob dedupe_key 与输入不一致")
    status = value["status"]
    failure = value.get("failure_class")
    if failure is not None and failure not in _FAILURE_CLASSES:
        raise FormalizationContractError("未知 LeanJob failure_class")
    if status in {"blocked", "failed", "rejected", "tool_error"} and failure is None:
        raise FormalizationContractError("失败/阻塞 LeanJob 必须有 failure_class")
    if status in {"planned", "ready", "running", "checkpointed", "completed", "checked"} and failure is not None:
        raise FormalizationContractError("非失败 LeanJob 不得携带 failure_class")
    _timestamp(value["created_at"], "created_at")
    _timestamp(value["updated_at"], "updated_at")
    if value.get("causation_id") is not None:
        _identifier(value["causation_id"], "causation_id")
    if value.get("retry_count") is not None and (not isinstance(value["retry_count"], int) or value["retry_count"] < 0):
        raise FormalizationContractError("retry_count 无效")
    if package is not None:
        validate_formalization_package(package, project_root=project_root)
        if package.get("package_id") != value["package_id"]:
            raise ContractChainError("LeanJob package_id 不一致")
        if value.get("problem_id") is not None and package.get("problem_id") != value["problem_id"]:
            raise ContractChainError("LeanJob problem_id 不一致")
        if value.get("problem_contract_sha256") is not None and package.get("problem_contract_sha256") != value["problem_contract_sha256"]:
            raise ContractChainError("LeanJob ProblemContract digest 不一致")
        if coord["attempt_id"] != package.get("attempt_id"):
            raise ContractChainError("LeanJob Coordinator attempt 与 package 不一致")
        package_budget = _normalise_budget(package.get("budgets", package.get("budget")), None)
        for job_name, package_name in (
            ("wall_time_seconds", "timeout_seconds"),
            ("max_output_bytes", "max_output_bytes"),
            ("memory_bytes", "max_memory_bytes"),
            ("cpu_seconds", "max_cpu_seconds"),
            ("max_retries", "max_retries"),
        ):
            if job_name in normalized_budget and normalized_budget[job_name] > package_budget[package_name]:
                raise ContractChainError(f"LeanJob budget.{job_name} 超过 FormalizationPackage 上限")
        proof_locator = package["proof_source"]["locator"]
        if proof_locator not in {item["locator"] for item in value["readonly_inputs"]}:
            raise ContractChainError("LeanJob readonly_inputs 必须包含 package proof_source")
    return _copy(value)


def build_lean_job(
    *,
    package: Mapping[str, Any],
    coordinator_job: Mapping[str, Any] | None = None,
    coordinator_job_id: str | None = None,
    coordinator_run_instance_id: str | None = None,
    coordinator_session_id: str | None = None,
    coordinator_attempt_id: str | None = None,
    coordinator_dedupe_key: str | None = None,
    operation: str = "replay",
    principal: str | Mapping[str, Any] = "lean-kernel",
    principal_role: str | None = None,
    trust_domain: str | None = None,
    readonly_inputs: Sequence[Mapping[str, Any]] | None = None,
    budgets: Mapping[str, Any] | None = None,
    command_allowlist: Sequence[Any] | None = None,
    expected_artifacts: Sequence[Mapping[str, Any]] | None = None,
    write_scopes: Sequence[str] | None = None,
    execution_profile: Mapping[str, Any] | None = None,
    created_at: str = _DEFAULT_TIMESTAMP,
    lean_job_id: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(package, Mapping):
        raise FormalizationContractError("package 必须是 object")
    validate_formalization_package(package)
    if operation not in _OPERATIONS:
        raise FormalizationContractError("未知 LeanJob operation")
    coord = _coordinator_identity(
        coordinator_job,
        coordinator_job_id=coordinator_job_id,
        coordinator_run_instance_id=coordinator_run_instance_id,
        coordinator_session_id=coordinator_session_id,
        coordinator_attempt_id=coordinator_attempt_id,
        coordinator_dedupe_key=coordinator_dedupe_key,
    )
    if coord["attempt_id"] != package.get("attempt_id"):
        raise ContractChainError("Coordinator attempt 必须绑定 package attempt")
    if isinstance(principal, Mapping):
        principal_value = _copy(dict(principal))
        principal_value.setdefault("role", principal_role or ("verifier" if operation in {"replay", "axiom_audit", "faithfulness_review"} else "generator"))
        _text(principal_value.get("id"), "principal.id")
    else:
        role = principal_role or ("verifier" if operation in {"replay", "axiom_audit", "faithfulness_review"} else "generator")
        principal_value = {"id": _text(principal, "principal"), "role": role}
    if principal_value["role"] not in {"generator", "verifier", "coordinator"}:
        raise FormalizationContractError("principal.role 无效")
    domain = trust_domain or ("lean-kernel" if operation == "replay" else "lean-audit" if operation == "axiom_audit" else "semantic-review" if operation == "faithfulness_review" else "lean-generation")
    _text(domain, "trust_domain")
    source_inputs = list(readonly_inputs or package.get("source_files", []))
    if not source_inputs:
        source_inputs = [package["proof_source"]]
    inputs = [_validate_ref(item, f"readonly_inputs[{index}]") for index, item in enumerate(source_inputs)]
    budget = _job_budget(budgets, package)
    commands = list(command_allowlist or [["lake", "env", "lean"], ["lake", "--quiet", "build"]])
    for index, item in enumerate(commands):
        _safe_command(item, f"command_allowlist[{index}]")
    artifacts = [_copy(item) for item in (expected_artifacts or [])]
    for index, item in enumerate(artifacts):
        _validate_ref(item, f"expected_artifacts[{index}]", must_exist=False)
    scopes = [_safe_write_scope(item, f"write_scopes[{index}]") for index, item in enumerate(write_scopes or [])]
    profile = _copy(dict(execution_profile or {"name": "lean-verifier", "network": "disabled"}))
    input_material = {
        "package_id": package["package_id"],
        "operation": operation,
        "principal": principal_value,
        "trust_domain": domain,
        "readonly_inputs": inputs,
        "budgets": budget,
        "command_allowlist": commands,
        "expected_artifacts": artifacts,
        "write_scopes": scopes,
        "network_policy": "disabled",
        "execution_profile": profile,
    }
    input_digest = sha256_json(input_material)
    dedupe_payload = {
        "package_id": package["package_id"],
        "operation": operation,
        "input_digest": input_digest,
        "coordinator_attempt_id": coord["attempt_id"],
    }
    dedupe = f"lean-dedupe:{sha256_json(dedupe_payload)}"
    identity = {
        "package_id": package["package_id"],
        "operation": operation,
        "input_digest": input_digest,
        "coordinator": coord,
    }
    job_identifier = lean_job_id or f"lean-job:{sha256_json(identity)}"
    _identifier(job_identifier, "lean_job_id")
    timestamp = _timestamp(created_at, "created_at")
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lean_job_id": job_identifier,
        "job_id": coord["job_id"],
        "package_id": package["package_id"],
        "problem_id": package.get("problem_id"),
        "problem_contract_sha256": package.get("problem_contract_sha256"),
        "attempt_id": coord["attempt_id"],
        "operation": operation,
        "principal": principal_value,
        "trust_domain": domain,
        "coordinator_identity": coord,
        "coordinator_job_id": coord["job_id"],
        "coordinator_run_instance_id": coord["run_instance_id"],
        "coordinator_session_id": coord["session_id"],
        "coordinator_attempt_id": coord["attempt_id"],
        "coordinator_dedupe_key": coord["dedupe_key"],
        "run_instance_id": coord["run_instance_id"],
        "session_id": coord["session_id"],
        "dedupe_key": dedupe,
        "readonly_inputs": inputs,
        "budgets": budget,
        "budget": _copy(budget),
        "command_allowlist": commands,
        "expected_artifacts": artifacts,
        "write_scopes": scopes,
        "network_policy": "disabled",
        "execution_profile": profile,
        "input_digest": input_digest,
        "status": "planned",
        "failure_class": None,
        "retry_count": 0,
        "correlation_id": correlation_id or f"correlation:{sha256_json({'job': coord['job_id'], 'package': package['package_id'], 'operation': operation})}",
        "causation_id": causation_id,
        "created_at": timestamp,
        "updated_at": timestamp,
    }
    if metadata is not None:
        value["metadata"] = _copy(dict(metadata))
    return validate_lean_job(value, package=package)


make_lean_job = build_lean_job


def _normalise_receipt_toolchain(value: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(value or {})
    if "toolchain_fingerprint" in source and "fingerprint" not in source:
        source["fingerprint"] = source.pop("toolchain_fingerprint")
    normalized = _normalise_toolchain(
        source,
        lean_version=None,
        lake_version=None,
        mathlib_commit=None,
        manifest_sha256=None,
        toolchain_fingerprint=None,
    )
    result = {
        "lean_version": normalized["lean_version"],
        "lake_version": normalized["lake_version"],
        "mathlib_commit": normalized["mathlib_commit"],
        "manifest_sha256": normalized["manifest_sha256"],
        "toolchain_fingerprint": normalized["fingerprint"],
    }
    if "profile" in normalized:
        result["profile"] = normalized["profile"]
    return result


def _receipt_toolchain(value: Mapping[str, Any] | None, package: Mapping[str, Any] | None) -> dict[str, Any]:
    source = value
    if source is None and package is not None:
        package_toolchain = dict(package.get("toolchain", {}))
        if "fingerprint" in package_toolchain:
            package_toolchain["toolchain_fingerprint"] = package_toolchain.pop("fingerprint")
        source = package_toolchain
    return _normalise_receipt_toolchain(source)


def _freshness_timestamp(value: Any) -> str:
    if isinstance(value, str):
        return _timestamp(value, "freshness")
    if isinstance(value, Mapping):
        return _timestamp(value.get("checked_at"), "freshness.checked_at")
    raise FormalizationContractError("freshness 必须是时间戳或 object")


def _receipt_declaration(value: Mapping[str, Any] | None, package: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(value or {})
    if package is not None:
        lean = package.get("lean", {})
        source.setdefault("name", lean.get("declaration"))
        source.setdefault("statement", lean.get("statement"))
    name = _text(source.get("name"), "verified_declaration.name")
    statement = _text(source.get("statement"), "verified_declaration.statement")
    declared = source.get("statement_sha256", sha256_text(statement))
    if declared != sha256_text(statement):
        raise DigestMismatchError("verified_declaration.statement_sha256 漂移")
    return {"name": name, "statement": statement, "statement_sha256": declared}


def _receipt_material_digest(toolchain: Mapping[str, Any]) -> str:
    return sha256_json(dict(toolchain))


def validate_kernel_verification_receipt(
    receipt: Mapping[str, Any],
    *,
    project_root: Path | None = None,
    package: Mapping[str, Any] | None = None,
    job: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a receipt, including local ref hashes when a project root is supplied."""
    if not isinstance(receipt, Mapping):
        raise FormalizationContractError("KernelVerificationReceipt 必须是 object")
    value = dict(receipt)
    _validate_schema(value, "lean-kernel-receipt.schema.json", project_root=project_root, label="KernelVerificationReceipt")
    _identifier(value["receipt_id"], "receipt_id")
    _identifier(value["lean_job_id"], "lean_job_id")
    if value.get("job_id") is not None and value.get("coordinator_job_id") is not None and value["job_id"] != value["coordinator_job_id"]:
        raise ContractChainError("receipt job_id 与 coordinator_job_id 不一致")
    for field in ("package_id", "problem_id", "attempt_id", "graph_id", "obligation_id", "candidate_id"):
        _identifier(value[field], field)
    _digest(value["problem_contract_sha256"], "problem_contract_sha256")
    toolchain_source = value.get("toolchain", value.get("environment"))
    toolchain = dict(toolchain_source)
    normalized_toolchain = _normalise_receipt_toolchain(toolchain)
    if normalized_toolchain != toolchain:
        raise ContractChainError("receipt toolchain identity 不能含未声明或漂移字段")
    for name in ("lean_version", "lake_version", "mathlib_commit"):
        if toolchain[name].strip().lower() in {"unknown", "latest", "current", "n/a"}:
            raise FormalizationContractError(f"receipt.toolchain.{name} 不能是占位身份")
    if value.get("environment") is not None and value["environment"] != toolchain:
        raise ContractChainError("environment 与 toolchain 不一致")
    environment_digest = _digest(value["execution_environment_digest"], "execution_environment_digest")
    if environment_digest != _receipt_material_digest(toolchain):
        raise DigestMismatchError("execution_environment_digest 与实际 toolchain 不一致")
    if value.get("environment_digest") is not None and value["environment_digest"] != environment_digest:
        raise DigestMismatchError("environment_digest 漂移")
    command = dict(value["command"])
    _safe_command(command["argv"], "command.argv")
    if command.get("executor") is not None and command["executor"] not in {"subprocess", "in_process"}:
        raise FormalizationContractError("command.executor 无效")
    declaration_source = value.get("verified_declaration", value.get("declaration"))
    declaration = dict(declaration_source)
    normalized_declaration = _receipt_declaration(declaration, None)
    if normalized_declaration != declaration:
        raise ContractChainError("verified_declaration 含未绑定字段或摘要漂移")
    for key in ("proof_artifact", "stdout", "stderr"):
        _validate_ref(value[key], key, project_root=project_root, must_exist=project_root is not None)
    freshness = _freshness_timestamp(value["freshness"])
    if value.get("checked_at") is not None and value["checked_at"] != freshness:
        raise ContractChainError("checked_at 与 freshness 不一致")
    input_digests = value["input_digests"]
    if isinstance(input_digests, list):
        for item in input_digests:
            _digest(item, "input_digests item")
    else:
        for key, item in input_digests.items():
            _digest(item, f"input_digests.{key}")
        if "package_sha256" not in input_digests or "source_sha256" not in input_digests:
            raise ContractChainError("input_digests 必须包含 package_sha256/source_sha256")
    verdict = value["verdict"]
    failure = value.get("failure_class")
    if failure is not None and failure not in _FAILURE_CLASSES:
        raise FormalizationContractError("未知 receipt failure_class")
    if verdict == "checked":
        if command["exit_code"] != 0 or failure is not None:
            raise ContractChainError("checked receipt 必须是零退出且无 failure_class")
    else:
        if failure is None:
            raise ContractChainError("rejected/tool_error receipt 必须记录 failure_class")
        if verdict == "tool_error" and failure not in {"TOOLCHAIN_UNAVAILABLE", "ENVIRONMENT_MISMATCH", "TIMEOUT", "RESOURCE_EXCEEDED", "CHECKER_ERROR", "TOOL_ERROR"}:
            raise ContractChainError("tool_error 的 failure_class 必须是基础设施/资源错误")
    principal = value["principal"]
    if isinstance(principal, Mapping) and principal.get("role") != "verifier":
        raise ContractChainError("kernel receipt principal 必须是 verifier")
    if verdict == "checked" and project_root is not None:
        proof_path = _trusted_artifact_path(project_root, value["proof_artifact"]["locator"], must_exist=True)
        try:
            proof_text = proof_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise FormalizationContractError("proof_artifact 必须是 UTF-8 Lean source") from exc
        escapes = scan_lean_source(proof_text)
        if escapes:
            raise FormalizationContractError(f"checked receipt 绑定了禁止 Lean escape：{', '.join(escapes)}")
    if package is not None:
        validate_formalization_package(package, project_root=project_root)
        expected = {
            "package_id": package.get("package_id"),
            "problem_id": package.get("problem_id"),
            "problem_contract_sha256": package.get("problem_contract_sha256"),
            "attempt_id": package.get("attempt_id"),
            "graph_id": package.get("graph_id"),
            "obligation_id": package.get("obligation_id"),
            "candidate_id": package.get("candidate_id"),
        }
        for key, expected_value in expected.items():
            if value.get(key) != expected_value:
                raise ContractChainError(f"receipt {key} 与 package 不一致")
        package_proof = package.get("proof_source", {})
        if value["proof_artifact"] != package_proof:
            raise ContractChainError("receipt proof_artifact 未绑定 package proof_source")
        package_lean = package.get("lean", {})
        if declaration["name"] != package_lean.get("declaration") or declaration["statement"] != package_lean.get("statement"):
            raise ContractChainError("receipt verified_declaration 与 package Lean statement 不一致")
        if not isinstance(input_digests, Mapping):
            raise ContractChainError("package-bound receipt input_digests 必须是 object")
        package_digest = package.get("package_sha256", _package_self_digest(package))
        expected_input_digests = {
            "package_sha256": package_digest,
            "source_sha256": value["proof_artifact"]["sha256"],
            "problem_contract_sha256": package.get("problem_contract_sha256"),
            "attempt_sha256": package.get("attempt_sha256"),
            "graph_sha256": package.get("graph_sha256"),
            "obligation_sha256": package.get("obligation_sha256"),
            "candidate_sha256": package.get("candidate_sha256"),
            "manifest_sha256": toolchain["manifest_sha256"],
        }
        for key, expected_value in expected_input_digests.items():
            if input_digests.get(key) != expected_value:
                raise DigestMismatchError(f"receipt input_digests.{key} 与 package/environment 不一致")
    if job is not None:
        validate_lean_job(job, project_root=project_root, package=package)
        if value["lean_job_id"] != job["lean_job_id"] or value["package_id"] != job["package_id"]:
            raise ContractChainError("receipt 与 LeanJob identity 不一致")
        expected_job_id = job.get("coordinator_job_id", job.get("job_id"))
        if value.get("job_id") is not None and value["job_id"] != expected_job_id:
            raise ContractChainError("receipt job_id 与 LeanJob 不一致")
        if job["operation"] != "replay":
            raise ContractChainError("kernel receipt 必须由 replay LeanJob 产生")
        actual_argv = _command_tokens(command["argv"], "command.argv")
        allowed_commands = {
            tuple(_command_tokens(item, f"LeanJob command_allowlist[{index}]"))
            for index, item in enumerate(job["command_allowlist"])
        }
        if tuple(actual_argv) not in allowed_commands:
            raise ContractChainError("receipt exact command 不在 LeanJob command_allowlist")
        principal_job = _principal_id(job["principal"])
        principal_receipt = _principal_id(principal)
        if principal_job != principal_receipt:
            raise ContractChainError("receipt principal 与 LeanJob 不一致")
        for key in ("coordinator_job_id", "coordinator_run_instance_id", "coordinator_session_id", "coordinator_attempt_id", "coordinator_dedupe_key"):
            if value.get(key) != job.get(key):
                raise ContractChainError(f"receipt {key} 与 LeanJob 不一致")
    _timestamp(value["created_at"], "created_at")
    return _copy(value)


validate_kernel_receipt = validate_kernel_verification_receipt


def build_kernel_verification_receipt(
    *,
    job: Mapping[str, Any],
    package: Mapping[str, Any],
    verdict: str | None = None,
    command: Mapping[str, Any] | Sequence[str] | None = None,
    toolchain: Mapping[str, Any] | None = None,
    verified_declaration: Mapping[str, Any] | None = None,
    proof_artifact: Mapping[str, Any] | str | Path | None = None,
    stdout: Mapping[str, Any] | str | Path | None = None,
    stderr: Mapping[str, Any] | str | Path | None = None,
    checked_at: str | Mapping[str, Any] | None = None,
    failure_class: str | None = None,
    principal: Mapping[str, Any] | str | None = None,
    receipt_id: str | None = None,
    created_at: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Build a receipt for an already-observed command; never runs that command."""
    validate_formalization_package(package, project_root=project_root)
    validate_lean_job(job, project_root=project_root, package=package)
    if job.get("operation") != "replay":
        raise ContractChainError("kernel receipt 只接受 replay LeanJob")
    if command is None:
        raise FormalizationContractError("必须提供 exact command")
    if isinstance(command, Mapping):
        command_value = dict(command)
        argv = command_value.get("argv")
        exit_code = command_value.get("exit_code")
    else:
        argv = list(command)
        exit_code = 0
        command_value = {"argv": argv, "exit_code": exit_code}
    _safe_command(argv, "command.argv")
    if not isinstance(exit_code, int):
        raise FormalizationContractError("command.exit_code 必须是整数")
    command_value["argv"] = list(argv) if isinstance(argv, list) else argv
    command_value["exit_code"] = exit_code
    if "executor" not in command_value:
        command_value["executor"] = "subprocess"
    package_proof = package.get("proof_source")
    proof_ref = _ref_from_input(proof_artifact or package_proof, project_root=project_root, label="proof_artifact", media_type="text/x-lean")
    stdout_ref = _ref_from_input(stdout, project_root=project_root, label="stdout", media_type="text/plain")
    stderr_ref = _ref_from_input(stderr, project_root=project_root, label="stderr", media_type="text/plain")
    if proof_ref != package_proof:
        raise ContractChainError("proof_artifact 必须与 package proof_source 完全一致")
    when = checked_at if checked_at is not None else created_at
    if when is None:
        raise FormalizationContractError("必须提供 checked_at/freshness timestamp；builder 不伪造运行时间")
    freshness = _freshness_timestamp(when)
    if verdict is None:
        verdict = "checked" if exit_code == 0 else "rejected"
    if verdict not in {"checked", "rejected", "tool_error"}:
        raise FormalizationContractError("kernel verdict 只能是 checked/rejected/tool_error")
    if verdict == "checked":
        if exit_code != 0 or failure_class is not None:
            raise ContractChainError("tool_error/rejected 不能伪装为 checked")
    elif failure_class is None:
        failure_class = "KERNEL_REJECTED" if verdict == "rejected" else "TOOL_ERROR"
    if verdict == "tool_error" and failure_class not in {"TOOLCHAIN_UNAVAILABLE", "ENVIRONMENT_MISMATCH", "TIMEOUT", "RESOURCE_EXCEEDED", "CHECKER_ERROR", "TOOL_ERROR"}:
        raise ContractChainError("tool_error failure_class 无效")
    environment = _receipt_toolchain(toolchain, package)
    env_digest = _receipt_material_digest(environment)
    declaration = _receipt_declaration(verified_declaration, package)
    principal_value = principal if principal is not None else job["principal"]
    if isinstance(principal_value, Mapping):
        principal_value = _copy(dict(principal_value))
    else:
        principal_value = _text(principal_value, "principal")
    input_digests = {
        "package_sha256": package.get("package_sha256", _package_self_digest(package)),
        "source_sha256": proof_ref["sha256"],
        "problem_contract_sha256": package["problem_contract_sha256"],
        "attempt_sha256": package["attempt_sha256"],
        "graph_sha256": package["graph_sha256"],
        "obligation_sha256": package["obligation_sha256"],
        "candidate_sha256": package["candidate_sha256"],
        "manifest_sha256": environment["manifest_sha256"],
    }
    identity = {
        "lean_job_id": job["lean_job_id"],
        "package_id": package["package_id"],
        "input_digests": input_digests,
        "toolchain": environment,
        "command": command_value,
        "verified_declaration": declaration,
        "proof_artifact": proof_ref,
        "stdout": stdout_ref,
        "stderr": stderr_ref,
        "freshness": freshness,
        "verdict": verdict,
        "failure_class": failure_class,
    }
    identifier = receipt_id or f"kernel-receipt:{sha256_json(identity)}"
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": _identifier(identifier, "receipt_id"),
        "lean_job_id": job["lean_job_id"],
        "job_id": job.get("coordinator_job_id", job.get("job_id")),
        "package_id": package["package_id"],
        "problem_id": package["problem_id"],
        "problem_contract_sha256": package["problem_contract_sha256"],
        "attempt_id": package["attempt_id"],
        "graph_id": package["graph_id"],
        "obligation_id": package["obligation_id"],
        "candidate_id": package["candidate_id"],
        "coordinator_job_id": job.get("coordinator_job_id", job.get("job_id")),
        "coordinator_run_instance_id": job.get("coordinator_run_instance_id", job.get("run_instance_id")),
        "coordinator_session_id": job.get("coordinator_session_id", job.get("session_id")),
        "coordinator_attempt_id": job.get("coordinator_attempt_id", job.get("attempt_id")),
        "coordinator_dedupe_key": job.get("coordinator_dedupe_key", job.get("dedupe_key")),
        "input_digests": input_digests,
        "toolchain": environment,
        "environment": _copy(environment),
        "command": command_value,
        "verified_declaration": declaration,
        "declaration": _copy(declaration),
        "proof_artifact": proof_ref,
        "proof_source": _copy(proof_ref),
        "stdout": stdout_ref,
        "stderr": stderr_ref,
        "freshness": freshness,
        "checked_at": freshness,
        "verdict": verdict,
        "failure_class": failure_class,
        "principal": principal_value,
        "execution_environment_digest": env_digest,
        "environment_digest": env_digest,
        "created_at": _timestamp(created_at or freshness, "created_at"),
    }
    if metadata is not None:
        value["metadata"] = _copy(dict(metadata))
    return validate_kernel_verification_receipt(value, project_root=project_root, package=package, job=job)


build_kernel_receipt = build_kernel_verification_receipt
make_kernel_verification_receipt = build_kernel_verification_receipt
make_kernel_receipt = build_kernel_verification_receipt


def validate_formalization_chain(
    *,
    method_decision: Mapping[str, Any],
    formalization_decision: Mapping[str, Any] | None = None,
    package: Mapping[str, Any] | None = None,
    job: Mapping[str, Any] | None = None,
    receipt: Mapping[str, Any] | None = None,
    project_root: Path | None = None,
    records: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate a supplied chain and return only status metadata, never Evidence."""
    validate_formal_method_decision(method_decision, project_root=project_root, formalization_decision=formalization_decision)
    result: dict[str, Any] = {"formal_method_decision": "valid"}
    if formalization_decision is not None:
        validate_formalization_decision(formalization_decision, project_root=project_root, parent_decision=method_decision)
        result["formalization_decision"] = "valid"
    if package is not None:
        validate_formalization_package(package, project_root=project_root, context=records)
        result["package"] = "valid"
    if job is not None:
        validate_lean_job(job, project_root=project_root, package=package)
        result["job"] = "valid"
    if receipt is not None:
        validate_kernel_verification_receipt(receipt, project_root=project_root, package=package, job=job)
        result["receipt"] = "valid"
    return result


# Short aliases make the module convenient in small coordinator adapters.
validate_package = validate_formalization_package
validate_job = validate_lean_job
validate_receipt = validate_kernel_verification_receipt
build_package = build_formalization_package


__all__ = [
    "SCHEMA_VERSION",
    "ContractChainError",
    "DigestMismatchError",
    "FormalizationContractError",
    "FormalizationError",
    "FormalizationValidationError",
    "UnsafeLocatorError",
    "build_formal_method_decision",
    "build_formalization_decision",
    "build_formalization_package",
    "build_kernel_receipt",
    "build_kernel_verification_receipt",
    "build_lean_job",
    "build_package",
    "canonical_json_bytes",
    "extract_lean_imports",
    "make_formal_method_decision",
    "make_formalization_decision",
    "make_formalization_package",
    "make_kernel_receipt",
    "make_kernel_verification_receipt",
    "make_lean_formalization_decision",
    "make_lean_job",
    "scan_lean_source",
    "sha256_bytes",
    "sha256_file",
    "sha256_json",
    "sha256_text",
    "validate_formal_method_decision",
    "validate_formalization_chain",
    "validate_formalization_decision",
    "validate_formalization_package",
    "validate_job",
    "validate_kernel_receipt",
    "validate_kernel_verification_receipt",
    "validate_lean_formalization_decision",
    "validate_lean_job",
    "validate_package",
    "validate_receipt",
]
