"""Strict, pure quality gates for Lean proof admission.

The module deliberately keeps three decisions separate:

* :func:`audit_axiom_escape` checks source lexically (comments and strings are
  ignored) and checks the supplied, digest-bound environment report;
* :func:`compare_statement_faithfulness` compares an explicit normalized
  statement contract field by field; and
* :func:`evaluate_formal_proof_admission` composes the three receipts without
  allowing a kernel result to override either of the other gates.

These checks are structural admission guards, not a complete semantic theorem
prover.  A missing or ambiguous field is reported as ``needs_review`` or
``undetermined`` and is never upgraded to a pass.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "1.0.0"
_MODULE_ROOT = Path(__file__).resolve().parents[2]
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_']*$")

FAITHFUL_COMPONENTS = (
    "objects",
    "domain",
    "quantifiers",
    "definitions",
    "assumptions",
    "conclusion",
    "conclusion_strength",
    "boundary_cases",
    "source_identity",
)

# These are deliberately token names, not a substring expression.  The lexer
# below removes comments and quoted strings before these names are inspected.
_FORBIDDEN_TOKENS = {
    "sorry": "SORRY",
    "admit": "ADMIT",
    "unsafe": "UNSAFE",
    "partial": "PARTIAL_DEFINITION",
    "extern": "EXTERN_IMPLEMENTATION",
    "native_decide": "NATIVE_DECIDE",
    "implemented_by": "IMPLEMENTED_BY",
}

# Fields which identify the mathematical subject rather than a particular
# verifier's output.  Gate-specific source/environment digests are checked
# separately when supplied as expected digests.
_IDENTITY_FIELDS = (
    "problem_id",
    "attempt_id",
    "candidate_id",
    "obligation_id",
    "problem_contract_sha256",
    "statement_sha256",
    "formal_statement_sha256",
    "proof_source_sha256",
)
_REQUIRED_IDENTITY_FIELDS = (
    "problem_id",
    "attempt_id",
    "candidate_id",
    "obligation_id",
    "problem_contract_sha256",
    "statement_sha256",
    "formal_statement_sha256",
)

_MISSING = object()

# Gate inputs are admission inputs, not arbitrary status reports.  The source
# receipt schemas are intentionally kept separate because a kernel receipt is
# produced by the formalization contract while the axiom and faithfulness
# receipts have their own producers and verdict vocabularies.
_GATE_SCHEMA_NAMES = {
    "kernel": "lean-kernel-receipt.schema.json",
    "axiom_audit": "axiom-escape-audit-receipt.schema.json",
    "statement_faithfulness": "statement-faithfulness-receipt.schema.json",
}

# A statement may use these legacy aliases at the comparison boundary, but no
# other top-level field is allowed to carry silent semantic payload.  The
# canonical ``components`` object is checked separately below.
_STATEMENT_ALLOWED_FIELDS = frozenset(
    {
        *FAITHFUL_COMPONENTS,
        "components",
        "statement",
        "formal_statement",
        "claim",
        "exception_cases",
        "edge_cases",
        "identity",
        "problem_id",
        "attempt_id",
        "candidate_id",
        "obligation_id",
        "problem_contract_sha256",
        "contract_sha256",
        "statement_version",
        "version",
        "source_id",
        "statement_sha256",
        "original_statement_sha256",
        "formal_statement_sha256",
    }
)

# The canonical Lean receipt has no field for the natural-language statement
# digest: it binds the formal declaration instead.  Aggregate identity
# checking therefore requires each digest from the gate types that can carry
# it, rather than demanding a field that the source schema cannot represent.
_GATE_REQUIRED_IDENTITY_FIELDS = {
    "kernel": frozenset(
        set(_REQUIRED_IDENTITY_FIELDS) - {"statement_sha256"}
    ),
    "axiom_audit": frozenset(_REQUIRED_IDENTITY_FIELDS),
    "statement_faithfulness": frozenset(_REQUIRED_IDENTITY_FIELDS),
}


class QualityGateError(ValueError):
    """Raised when a quality-gate input or generated receipt is malformed."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _canonical(value: Any) -> Any:
    """Convert JSON-like values to a deterministic, JSON-serializable shape."""
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, (set, frozenset)):
        values = [_canonical(item) for item in value]
        return sorted(values, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))
    if isinstance(value, Path):
        return value.as_posix()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise QualityGateError(f"不能为非 JSON 值生成稳定摘要：{type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.fullmatch(value))


def _require_digest(value: Any, label: str) -> str:
    if not _valid_digest(value):
        raise QualityGateError(f"{label} 必须是 64 位小写 SHA-256")
    return value


def _schema_path(name: str) -> Path:
    return _MODULE_ROOT / "research" / "schema" / name


def validate_receipt(receipt: Mapping[str, Any], schema_name: str) -> None:
    """Validate a generated receipt using the repository's Draft 2020-12 schema."""
    path = _schema_path(schema_name)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualityGateError(f"无法读取质量门 schema：{path}") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(receipt),
        key=lambda item: list(item.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise QualityGateError(f"{schema_name} 无效（{location}）：{errors[0].message}")


def _subject(value: Mapping[str, Any] | None, *, include_nulls: bool = False) -> dict[str, Any]:
    value = value or {}
    allowed = {
        "problem_id",
        "attempt_id",
        "candidate_id",
        "obligation_id",
        "problem_contract_sha256",
        "statement_sha256",
        "formal_statement_sha256",
    }
    result: dict[str, Any] = {}
    for key in allowed:
        if key in value:
            result[key] = value[key]
        elif include_nulls:
            result[key] = None
    return result


# ---------------------------------------------------------------------------
# Lean lexical audit


def _advance(text: str, index: int, line: int, column: int) -> tuple[int, int, int]:
    if text[index] == "\n":
        return index + 1, line + 1, 1
    return index + 1, line, column + 1


def _lex_lean(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return identifier/command tokens and lexer findings.

    This is intentionally only a conservative scanner.  It is not a Lean
    parser, but it handles nested ``/- -/`` comments, line comments, escaped
    strings, and command tokens so words hidden in comments or strings cannot
    trigger or evade the audit.
    """
    tokens: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    index = 0
    line = 1
    column = 1
    length = len(text)
    block_depth = 0
    string_start: tuple[int, int] | None = None

    while index < length:
        pair = text[index : index + 2]
        if block_depth:
            if pair == "/-":
                block_depth += 1
                index, line, column = _advance(text, index, line, column)
                index, line, column = _advance(text, index, line, column)
            elif pair == "-/":
                block_depth -= 1
                index, line, column = _advance(text, index, line, column)
                index, line, column = _advance(text, index, line, column)
            else:
                index, line, column = _advance(text, index, line, column)
            continue

        if string_start is not None:
            if text[index] == "\\" and index + 1 < length:
                index, line, column = _advance(text, index, line, column)
                index, line, column = _advance(text, index, line, column)
            elif text[index] == '"':
                string_start = None
                index, line, column = _advance(text, index, line, column)
            else:
                index, line, column = _advance(text, index, line, column)
            continue

        if pair == "--":
            while index < length and text[index] != "\n":
                index, line, column = _advance(text, index, line, column)
            continue
        if pair == "/-":
            block_depth = 1
            index, line, column = _advance(text, index, line, column)
            index, line, column = _advance(text, index, line, column)
            continue
        if text[index] == '"':
            string_start = (line, column)
            index, line, column = _advance(text, index, line, column)
            continue

        # A standalone character literal is not a source identifier.  Lean
        # identifiers containing apostrophes are consumed by the identifier
        # branch below and therefore remain intact.
        if text[index] == "'" and (
            index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_'")
        ):
            start_line, start_column = line, column
            index, line, column = _advance(text, index, line, column)
            escaped = False
            while index < length:
                if escaped:
                    escaped = False
                    index, line, column = _advance(text, index, line, column)
                elif text[index] == "\\":
                    escaped = True
                    index, line, column = _advance(text, index, line, column)
                elif text[index] == "'":
                    index, line, column = _advance(text, index, line, column)
                    break
                else:
                    index, line, column = _advance(text, index, line, column)
            else:
                findings.append(
                    {
                        "code": "UNTERMINATED_CHARACTER",
                        "severity": "error",
                        "message": "Lean character literal is unterminated",
                        "line": start_line,
                        "column": start_column,
                    }
                )
            continue

        if text[index] == "#":
            match = re.match(r"#[A-Za-z_][A-Za-z0-9_']*", text[index:])
            if match:
                value = match.group(0)
                tokens.append(
                    {"value": value, "line": line, "column": column, "index": index}
                )
                for _ in value:
                    index, line, column = _advance(text, index, line, column)
                continue

        if text[index].isalpha() or text[index] == "_":
            start = index
            start_line, start_column = line, column
            while index < length and (
                text[index].isalnum() or text[index] in "_'"
            ):
                index, line, column = _advance(text, index, line, column)
            tokens.append(
                {
                    "value": text[start:index],
                    "line": start_line,
                    "column": start_column,
                    "index": start,
                }
            )
            continue

        index, line, column = _advance(text, index, line, column)

    if block_depth:
        findings.append(
            {
                "code": "UNTERMINATED_COMMENT",
                "severity": "error",
                "message": "Lean block comment is unterminated",
                "line": line,
                "column": column,
            }
        )
    if string_start is not None:
        findings.append(
            {
                "code": "UNTERMINATED_STRING",
                "severity": "error",
                "message": "Lean string literal is unterminated",
                "line": string_start[0],
                "column": string_start[1],
            }
        )
    return tokens, findings


def strip_lean_comments_and_strings(text: str) -> str:
    """Mask comments and strings while preserving character offsets.

    The function is useful to callers that need an auditable display.  The
    admission decision itself uses token positions from :func:`_lex_lean`.
    """
    chars = list(text)
    index = 0
    length = len(text)
    block_depth = 0
    in_string = False
    while index < length:
        pair = text[index : index + 2]
        if block_depth:
            if pair == "/-":
                block_depth += 1
                chars[index] = chars[index + 1] = " "
                index += 2
            elif pair == "-/":
                block_depth -= 1
                chars[index] = chars[index + 1] = " "
                index += 2
            else:
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            continue
        if in_string:
            if text[index] == "\\" and index + 1 < length:
                if chars[index] != "\n":
                    chars[index] = " "
                if chars[index + 1] != "\n":
                    chars[index + 1] = " "
                index += 2
            elif text[index] == '"':
                chars[index] = " "
                in_string = False
                index += 1
            else:
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            continue
        if pair == "--":
            end = text.find("\n", index)
            if end == -1:
                end = length
            for position in range(index, end):
                chars[position] = " "
            index = end
        elif pair == "/-":
            block_depth = 1
            chars[index] = chars[index + 1] = " "
            index += 2
        elif text[index] == '"':
            chars[index] = " "
            in_string = True
            index += 1
        else:
            index += 1
    return "".join(chars)


def scan_lean_source(
    source: str,
    *,
    allowed_axioms: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Find proof escapes in actual Lean tokens, never in comments/strings."""
    if not isinstance(source, str):
        raise QualityGateError("Lean source 必须是字符串")
    allowed = {str(item) for item in allowed_axioms}
    tokens, findings = _lex_lean(source)
    for position, token in enumerate(tokens):
        value = token["value"]
        if value in _FORBIDDEN_TOKENS:
            findings.append(
                {
                    "code": _FORBIDDEN_TOKENS[value],
                    "severity": "error",
                    "message": f"禁止的 Lean escape token：{value}",
                    "line": token["line"],
                    "column": token["column"],
                }
            )
        elif value == "#eval":
            findings.append(
                {
                    "code": "EVAL_COMMAND",
                    "severity": "error",
                    "message": "#eval 不能作为形式证明准入依据",
                    "line": token["line"],
                    "column": token["column"],
                }
            )
        elif value == "sorryAx" or value.startswith("sorryAx_"):
            findings.append(
                {
                    "code": "DECLARATION_USES_SORRY",
                    "severity": "error",
                    "message": f"声明直接使用 sorry axiom：{value}",
                    "line": token["line"],
                    "column": token["column"],
                }
            )
        elif value == "axiom":
            # Read a qualified declaration name from the original source so
            # ``axiom Namespace.permitted`` cannot be confused with a bare
            # ``permitted`` policy entry.  The lexer still decides where the
            # keyword came from, so comments/strings remain excluded.
            after_keyword = source[token["index"] + len(value) :]
            declaration_match = re.match(
                r"\s*([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)",
                after_keyword,
            )
            if declaration_match is not None:
                name = declaration_match.group(1)
            elif position + 1 < len(tokens):
                name = tokens[position + 1]["value"]
            else:
                name = "<missing>"
            if name not in allowed:
                findings.append(
                    {
                        "code": "TEMPORARY_AXIOM",
                        "severity": "error",
                        "message": f"源码声明的 axiom 不在冻结允许策略中：{name}",
                        "line": token["line"],
                        "column": token["column"],
                        "details": {"name": name, "allowed": False},
                    }
                )
            else:
                findings.append(
                    {
                        "code": "ALLOWED_SOURCE_AXIOM",
                        "severity": "info",
                        "message": f"源码 axiom 按冻结策略允许：{name}",
                        "line": token["line"],
                        "column": token["column"],
                        "details": {"name": name, "allowed": True},
                    }
                )
    return findings


# ---------------------------------------------------------------------------
# Axiom audit receipt


def _finding(
    code: str,
    severity: str,
    message: str,
    *,
    locator: str | None = None,
    line: int | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {"code": code, "severity": severity, "message": message}
    if locator is not None:
        value["locator"] = locator
    if line is not None:
        value["line"] = line
    if details is not None:
        value["details"] = dict(details)
    return value


def _source_item(item: Any, index: int) -> tuple[str, str | None, str | None]:
    """Return locator, source text (if available), and caller-claimed digest."""
    if isinstance(item, Path):
        locator = item.as_posix()
        try:
            return locator, item.read_text(encoding="utf-8"), None
        except OSError:
            return locator, None, None
    if isinstance(item, Mapping):
        locator_value = item.get("locator", item.get("path"))
        locator = str(locator_value) if locator_value else f"inline:source-{index}"
        claimed = item.get("sha256", item.get("digest"))
        claimed_digest = str(claimed) if claimed is not None else None
        if "content" in item:
            return locator, str(item["content"]), claimed_digest
        if "text" in item:
            return locator, str(item["text"]), claimed_digest
        if locator_value:
            path = Path(str(locator_value))
            try:
                return locator, path.read_text(encoding="utf-8"), claimed_digest
            except OSError:
                return locator, None, claimed_digest
        return locator, None, claimed_digest
    if isinstance(item, str):
        path = Path(item)
        if "\n" not in item and path.is_file():
            try:
                return item, path.read_text(encoding="utf-8"), None
            except OSError:
                return item, None, None
        return f"inline:source-{index}", item, None
    raise QualityGateError(f"source_files 含不支持的条目：{type(item).__name__}")


def _source_items(source: Any, source_files: Any) -> list[Any]:
    values: list[Any] = []
    for candidate in (source_files, source):
        if candidate is None:
            continue
        if isinstance(candidate, Mapping) and not set(candidate).intersection(
            {"locator", "path", "content", "text", "sha256", "digest"}
        ):
            values.extend(
                {"locator": str(key), "content": value}
                for key, value in candidate.items()
            )
        elif isinstance(candidate, (str, Path, Mapping)):
            values.append(candidate)
        else:
            try:
                values.extend(list(candidate))
            except TypeError as exc:
                raise QualityGateError("source/source_files 必须是文本、路径、映射或序列") from exc
    return values


def _parse_axiom_output(text: str) -> tuple[str, list[str]]:
    if not isinstance(text, str) or not text.strip():
        return "missing", []
    if "does not depend on any axioms" in text:
        return "parsed", []
    match = re.search(r"depends\s+on\s+axioms\s*:\s*\[([^\]]*)\]", text, re.I | re.S)
    if match is None:
        return "unparsed", []
    names: list[str] = []
    for raw in match.group(1).split(","):
        name = raw.strip().strip("`'\"")
        if name:
            names.append(name)
    return "parsed", sorted(set(names))


def _normalize_axiom_names(values: Iterable[str] | None) -> list[str]:
    if values is None:
        return []
    result = sorted({str(value).strip() for value in values if str(value).strip()})
    return result


def audit_axiom_escape(
    source: Any = None,
    *,
    source_files: Any = None,
    environment: Mapping[str, Any] | None = None,
    environment_receipt: Mapping[str, Any] | None = None,
    allowed_axioms: Iterable[str] | None = None,
    expected_source_digests: Mapping[str, str] | None = None,
    expected_environment_digest: str | None = None,
    observed_environment_digest: str | None = None,
    observed_axioms: Iterable[str] | None = None,
    axiom_output: str | None = None,
    allowed_axioms_policy_sha256: str | None = None,
    expected_identity: Mapping[str, Any] | None = None,
    observed_identity: Mapping[str, Any] | None = None,
    subject: Mapping[str, Any] | None = None,
    receipt_id: str | None = None,
    auditor: str = "lean-axiom-auditor",
    audited_at: str | None = None,
) -> dict[str, Any]:
    """Build an axiom-escape receipt from source and a fresh environment report.

    ``source`` may be inline Lean text, a path, a source mapping, or a sequence
    of those.  A source digest supplied by the caller is always recomputed.
    ``environment`` is an opaque-but-structured report; only its listed axioms,
    command status, identity and digests are consumed.
    """
    environment = dict(
        environment_receipt if environment_receipt is not None else (environment or {})
    )
    allowed = _normalize_axiom_names(
        allowed_axioms if allowed_axioms is not None else environment.get("allowed_axioms")
    )
    policy_digest = sha256_json(allowed)
    findings: list[dict[str, Any]] = []
    source_set: list[dict[str, str]] = []
    source_declarations: list[dict[str, Any]] = []
    lexical_failed = False
    source_missing = False
    frozen_sources = (
        expected_source_digests
        if expected_source_digests is not None
        else environment.get("expected_source_digests", environment.get("source_digests", {}))
    )
    expected_sources = {
        str(key): str(value) for key, value in dict(frozen_sources or {}).items()
    }

    items = _source_items(source, source_files)
    for index, item in enumerate(items):
        locator, text, claimed_digest = _source_item(item, index)
        if text is None or not text.strip():
            source_missing = True
            findings.append(
                _finding(
                    "MISSING_SOURCE",
                    "warning",
                    f"待审计 Lean source 缺失或为空：{locator}",
                    locator=locator,
                )
            )
            continue
        actual_digest = sha256_text(text)
        source_set.append({"locator": locator, "sha256": actual_digest})
        expected_digest = expected_sources.get(locator)
        if claimed_digest is not None and claimed_digest != actual_digest:
            findings.append(
                _finding(
                    "SOURCE_DIGEST_DRIFT",
                    "error",
                    f"source caller digest 与现场内容不一致：{locator}",
                    locator=locator,
                    details={"claimed": claimed_digest, "observed": actual_digest},
                )
            )
        if expected_digest is not None and expected_digest != actual_digest:
            findings.append(
                _finding(
                    "SOURCE_DIGEST_DRIFT",
                    "error",
                    f"source 冻结摘要与现场内容不一致：{locator}",
                    locator=locator,
                    details={"expected": expected_digest, "observed": actual_digest},
                )
            )
        file_findings = scan_lean_source(text, allowed_axioms=allowed)
        for item_finding in file_findings:
            item_finding = dict(item_finding)
            item_finding["locator"] = locator
            findings.append(item_finding)
            if item_finding["severity"] == "error":
                lexical_failed = True
            if item_finding["code"] in {"TEMPORARY_AXIOM", "ALLOWED_SOURCE_AXIOM"}:
                name = str(item_finding.get("details", {}).get("name", "<missing>"))
                source_declarations.append(
                    {
                        "name": name,
                        "allowed": item_finding["code"] == "ALLOWED_SOURCE_AXIOM",
                        "line": int(item_finding.get("line") or 1),
                    }
                )

    source_set = sorted(source_set, key=lambda item: item["locator"])
    source_set_digest = sha256_json(source_set)
    observed_locators = {item["locator"] for item in source_set}
    if expected_sources:
        expected_locators = set(expected_sources)
        if observed_locators != expected_locators:
            findings.append(
                _finding(
                    "SOURCE_SET_DRIFT",
                    "error",
                    "source locator 集合与冻结 source receipt 不一致",
                    details={
                        "expected": sorted(expected_locators),
                        "observed": sorted(observed_locators),
                    },
                )
            )

    raw_output = axiom_output
    if raw_output is None:
        raw_output = environment.get(
            "axiom_output", environment.get("print_axioms", environment.get("axiom_report"))
        )
    explicit_axioms = observed_axioms
    if explicit_axioms is None:
        explicit_axioms = environment.get("observed_axioms", environment.get("axioms"))
    parsed_status, parsed_axioms = _parse_axiom_output(raw_output or "")
    if explicit_axioms is not None:
        observed = _normalize_axiom_names(explicit_axioms)
        axiom_parse_status = "provided"
        if parsed_status == "parsed" and observed != parsed_axioms:
            findings.append(
                _finding(
                    "AXIOM_OUTPUT_DRIFT",
                    "error",
                    "显式 axiom 列表与 #print axioms 输出不一致",
                    details={"provided": observed, "parsed": parsed_axioms},
                )
            )
    else:
        observed = parsed_axioms
        axiom_parse_status = parsed_status

    unauthorized = sorted(set(observed) - set(allowed))
    for name in unauthorized:
        findings.append(
            _finding(
                "UNAUTHORIZED_AXIOM",
                "error",
                f"观察到未获冻结策略允许的 axiom：{name}",
                details={"name": name},
            )
        )
    always_forbidden = sorted(
        name for name in observed if name in {"sorryAx", "Lean.ofReduceBool", "Lean.trustCompiler"}
    )
    for name in always_forbidden:
        findings.append(
            _finding(
                "AXIOM_ESCAPE",
                "error",
                f"观察到不可通过允许策略放行的信任逃逸 axiom：{name}",
                details={"name": name},
            )
        )

    expected_env = (
        expected_environment_digest
        if expected_environment_digest is not None
        else environment.get(
            "expected_environment_digest",
            environment.get(
                "environment_digest_expected",
                environment.get("expected_digest", environment.get("expected_environment_sha256")),
            ),
        )
    )
    observed_env = (
        observed_environment_digest
        if observed_environment_digest is not None
        else environment.get(
            "observed_environment_digest",
            environment.get(
                "environment_digest",
                environment.get("digest", environment.get("environment_sha256")),
            ),
        )
    )
    if expected_env is None or observed_env is None:
        findings.append(
            _finding(
                "MISSING_ENVIRONMENT_BINDING",
                "warning",
                "environment receipt 必须同时提供冻结 expected digest 与现场 observed digest",
                details={"expected": expected_env, "observed": observed_env},
            )
        )
    elif observed_env != expected_env:
        findings.append(
            _finding(
                "ENVIRONMENT_DIGEST_DRIFT",
                "error",
                "Lean/Mathlib environment digest 与冻结值不一致",
                details={"expected": expected_env, "observed": observed_env},
            )
        )

    expected_policy = allowed_axioms_policy_sha256 or environment.get(
        "allowed_axioms_policy_sha256"
    )
    if expected_policy is not None and expected_policy != policy_digest:
        findings.append(
            _finding(
                "AXIOM_POLICY_DRIFT",
                "error",
                "允许 axiom policy digest 与实际允许列表不一致",
                details={"expected": expected_policy, "observed": policy_digest},
            )
        )

    # If a prebuilt environment receipt carries a source-set binding, it must
    # be the binding for the source bytes that were actually scanned.  The
    # composer performs the same check on the resulting receipt, so omitting
    # this field from a hand-written receipt cannot become an accepted pass.
    expected_source_set = environment.get(
        "source_set_sha256", environment.get("expected_source_set_sha256")
    )
    if expected_source_set is not None and expected_source_set != source_set_digest:
        findings.append(
            _finding(
                "SOURCE_ENVIRONMENT_BINDING_DRIFT",
                "error",
                "axiom environment source-set digest 与现场扫描集合不一致",
                details={"expected": expected_source_set, "observed": source_set_digest},
            )
        )

    expected_id = dict(expected_identity or environment.get("expected_identity", {}) or {})
    observed_id = dict(
        observed_identity
        or environment.get("observed_identity", environment.get("identity", {}))
        or {}
    )
    for key, expected_value in expected_id.items():
        if observed_id.get(key) != expected_value:
            findings.append(
                _finding(
                    "IDENTITY_DIGEST_DRIFT",
                    "error",
                    f"环境 identity 字段不一致：{key}",
                    details={"expected": expected_value, "observed": observed_id.get(key)},
                )
            )

    command_status = str(environment.get("command_status", ""))
    command_status = {
        "success": "pass",
        "accepted": "pass",
        "ok": "pass",
        "error": "tool_error",
        "failed": "fail",
    }.get(command_status, command_status)
    if not command_status:
        command_status = "pass" if explicit_axioms is not None or parsed_status == "parsed" else "missing"
    if command_status not in {"pass", "fail", "tool_error", "missing", "unknown"}:
        command_status = "unknown"
    if command_status in {"fail", "tool_error"} and not any(
        item["code"] == "ENVIRONMENT_COMMAND_ERROR" for item in findings
    ):
        findings.append(
            _finding(
                "ENVIRONMENT_COMMAND_ERROR",
                "warning",
                f"axiom environment 命令状态不可作为新鲜审计依据：{command_status}",
            )
        )

    if source_missing or not source_set:
        source_lex_status = "missing"
    elif lexical_failed:
        source_lex_status = "fail"
    else:
        source_lex_status = "pass"

    hard_failure_codes = {
        "SORRY",
        "ADMIT",
        "UNSAFE",
        "PARTIAL_DEFINITION",
        "EXTERN_IMPLEMENTATION",
        "NATIVE_DECIDE",
        "IMPLEMENTED_BY",
        "EVAL_COMMAND",
        "DECLARATION_USES_SORRY",
        "TEMPORARY_AXIOM",
        "UNAUTHORIZED_AXIOM",
        "AXIOM_ESCAPE",
        "SOURCE_DIGEST_DRIFT",
        "SOURCE_SET_DRIFT",
        "ENVIRONMENT_DIGEST_DRIFT",
        "AXIOM_POLICY_DRIFT",
        "AXIOM_OUTPUT_DRIFT",
        "SOURCE_ENVIRONMENT_BINDING_DRIFT",
        "IDENTITY_DIGEST_DRIFT",
        "UNTERMINATED_COMMENT",
        "UNTERMINATED_STRING",
        "UNTERMINATED_CHARACTER",
    }
    if any(item["code"] in hard_failure_codes for item in findings):
        verdict = "fail"
    elif (
        source_missing
        or not source_set
        or command_status in {"tool_error", "missing", "unknown"}
        or expected_env is None
        or observed_env is None
    ):
        verdict = "undetermined"
    elif axiom_parse_status in {"unparsed", "missing", "empty"}:
        verdict = "needs_review"
    elif command_status == "fail":
        verdict = "undetermined"
    else:
        verdict = "pass"

    environment_record = {
        "command_status": command_status,
        "axiom_parse_status": axiom_parse_status,
        "toolchain_id": environment.get("toolchain_id", environment.get("toolchain")),
        "toolchain_version": environment.get("toolchain_version", environment.get("version")),
        "environment_digest": expected_env,
        "expected_environment_digest": expected_env,
        "observed_environment_digest": observed_env,
        "axiom_output_sha256": sha256_text(raw_output) if raw_output is not None else None,
        "source_set_sha256": source_set_digest,
        "identity": observed_id,
    }
    receipt_subject = _subject(subject or expected_id or observed_id, include_nulls=False)
    if "statement_sha256" not in receipt_subject and "statement_sha256" in expected_id:
        receipt_subject["statement_sha256"] = expected_id["statement_sha256"]
    generated_id = receipt_id or f"axiom-audit:{source_set_digest[:24]}"
    if not re.fullmatch(r"axiom-audit:[a-z0-9][a-z0-9.-]*", generated_id):
        raise QualityGateError("axiom receipt_id 不符合稳定 ID 格式")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": generated_id,
        "receipt_type": "axiom_escape_audit",
        "subject": receipt_subject,
        "source_set": source_set,
        "source_set_sha256": source_set_digest,
        "allowed_axioms": allowed,
        "allowed_axioms_policy_sha256": policy_digest,
        "observed_axioms": observed,
        "source_declarations": source_declarations,
        "environment": environment_record,
        "source_lex_status": source_lex_status,
        "findings": findings,
        "verdict": verdict,
        "auditor": auditor,
        "audited_at": audited_at or _now(),
        "capability_boundary": "lexical escape scan plus digest-bound environment axiom report; not a complete Lean parser",
    }
    validate_receipt(receipt, "axiom-escape-audit-receipt.schema.json")
    return receipt


# Friendly aliases used by callers that name the operation rather than the
# receipt type.
run_axiom_escape_audit = audit_axiom_escape
audit_axioms = audit_axiom_escape
check_axiom_escape = audit_axiom_escape
build_axiom_escape_audit_receipt = audit_axiom_escape


# ---------------------------------------------------------------------------
# Statement-faithfulness receipt


def _unknown_statement_fields(value: Mapping[str, Any], label: str) -> list[str]:
    """Return semantic fields that the normalized comparator would ignore.

    The comparator supports a small compatibility vocabulary, but accepting
    arbitrary keys would let a producer hide a domain restriction or a second
    conclusion outside ``FAITHFUL_COMPONENTS``.  Nested ``components`` keys
    are checked as well because they are the canonical representation.
    """
    if not isinstance(value, Mapping):
        raise QualityGateError(f"{label} statement 必须是 JSON object")
    unknown = sorted(str(key) for key in set(value) - _STATEMENT_ALLOWED_FIELDS)
    components = value.get("components")
    if components is not None:
        if not isinstance(components, Mapping):
            unknown.append(f"{label}.components")
        else:
            unknown.extend(
                f"{label}.components.{key}"
                for key in sorted(set(components) - set(FAITHFUL_COMPONENTS), key=str)
            )
    for key in ("statement", "formal_statement"):
        nested = value.get(key)
        if not isinstance(nested, Mapping):
            continue
        # Raw statement aliases are intentionally narrow.  A producer may
        # carry presentation metadata, but not an unmodelled semantic key.
        allowed_nested = {"text", "language", "version", "formal_declaration"}
        unknown.extend(
            f"{label}.{key}.{nested_key}"
            for nested_key in sorted(set(nested) - allowed_nested, key=str)
        )
    return unknown


def _component_value(value: Mapping[str, Any], name: str) -> Any:
    components = value.get("components")
    if isinstance(components, Mapping) and name in components:
        return components[name]
    if name == "objects":
        if "objects" in value:
            return value["objects"]
        domain = value.get("domain")
        if isinstance(domain, Mapping) and "objects" in domain:
            return domain["objects"]
        return _MISSING
    if name == "domain":
        return value.get("domain", _MISSING)
    if name == "quantifiers":
        return value.get("quantifiers", _MISSING)
    if name == "definitions":
        return value.get("definitions", _MISSING)
    if name == "assumptions":
        return value.get("assumptions", _MISSING)
    if name == "conclusion":
        if "conclusion" in value:
            return value["conclusion"]
        statement = value.get("statement")
        if isinstance(statement, Mapping) and "text" in statement:
            return statement["text"]
        if isinstance(statement, str):
            return statement
        if "claim" in value:
            return value["claim"]
        return _MISSING
    if name == "conclusion_strength":
        return value.get("conclusion_strength", _MISSING)
    if name == "boundary_cases":
        for key in ("boundary_cases", "exception_cases", "edge_cases"):
            if key in value:
                return value[key]
        return _MISSING
    if name == "source_identity":
        for key in ("source_identity", "identity"):
            if isinstance(value.get(key), Mapping):
                return dict(value[key])
        identity: dict[str, Any] = {}
        for key in (
            "problem_id",
            "attempt_id",
            "candidate_id",
            "obligation_id",
            "problem_contract_sha256",
            "contract_sha256",
            "statement_version",
            "version",
            "source_id",
        ):
            if key in value:
                normalized_key = "problem_contract_sha256" if key == "contract_sha256" else key
                identity[normalized_key] = value[key]
        statement = value.get("statement")
        if isinstance(statement, Mapping) and "version" in statement:
            identity.setdefault("statement_version", statement["version"])
        return identity if identity else _MISSING
    raise QualityGateError(f"未知 statement component：{name}")


def _statement_components(
    value: Mapping[str, Any],
    *,
    contract_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise QualityGateError("statement 必须是 JSON object")
    result = {name: _component_value(value, name) for name in FAITHFUL_COMPONENTS}
    if contract_sha256 is not None:
        current = result["source_identity"]
        if current is _MISSING:
            current = {}
        if not isinstance(current, Mapping):
            raise QualityGateError("source_identity 必须是 JSON object")
        current = dict(current)
        # Preserve a contract digest already present in either statement.  A
        # caller-supplied expected digest must expose drift, never overwrite it
        # before the comparison runs.
        current.setdefault("problem_contract_sha256", contract_sha256)
        result["source_identity"] = current
    return result


def _component_digest(value: Any) -> str | None:
    if value is _MISSING:
        return None
    return sha256_json(value)


def _statement_digest(components: Mapping[str, Any]) -> str:
    return sha256_json(
        {
            "statement_components": {
                name: None if components[name] is _MISSING else components[name]
                for name in FAITHFUL_COMPONENTS
            }
        }
    )


def _raw_statement_digest(value: Mapping[str, Any]) -> str:
    """Return the project-compatible digest for an explicit statement object."""
    if isinstance(value.get("statement"), (Mapping, list, tuple, str)):
        return sha256_json(value["statement"])
    if isinstance(value.get("formal_statement"), (Mapping, list, tuple, str)):
        return sha256_json(value["formal_statement"])
    payload = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "statement_sha256",
            "original_statement_sha256",
            "formal_statement_sha256",
        }
    }
    return sha256_json(payload)


def _statement_digest_candidates(
    value: Mapping[str, Any], components: Mapping[str, Any]
) -> set[str]:
    return {_statement_digest(components), _raw_statement_digest(value)}


def _comparison(
    original: Any,
    formal: Any,
    name: str,
    *,
    force_status: str | None = None,
    force_reason: str | None = None,
) -> dict[str, Any]:
    original_digest = _component_digest(original)
    formal_digest = _component_digest(formal)
    if force_status is not None:
        status = force_status
        reason = force_reason or f"{name}：{status}"
    elif original is _MISSING or formal is _MISSING:
        if name in {"objects", "boundary_cases"} and original is _MISSING and formal is _MISSING:
            status = "pass"
            reason = f"{name} 未作为独立字段提供于原题或形式化合同；没有静默删除可比较内容"
        else:
            status = "needs_review"
            reason = f"{name} 缺少原题或形式化字段；不能从缺失推断忠实"
    elif original_digest == formal_digest:
        status = "pass"
        reason = f"{name} 的规范化摘要完全一致"
    else:
        status = "fail"
        reason = f"{name} 的规范化摘要不一致，需拒绝弱化、缩域或改写"
    return {
        "status": status,
        "original_sha256": original_digest,
        "formal_sha256": formal_digest,
        "reason": reason,
    }


def compare_statement_faithfulness(
    original: Mapping[str, Any],
    formal: Mapping[str, Any],
    *,
    problem_contract_sha256: str | None = None,
    original_contract_sha256: str | None = None,
    formal_contract_sha256: str | None = None,
    original_statement_sha256: str | None = None,
    formal_statement_sha256: str | None = None,
    subject: Mapping[str, Any] | None = None,
    receipt_id: str | None = None,
    reviewer: str = "structural-faithfulness-reviewer",
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    """Compare the frozen statement components without trusting model claims.

    A pass means the supplied normalized fields are exactly equal.  It does
    not claim that arbitrary Lean syntax is semantically equivalent to natural
    language; missing normalization or source identity remains ``needs_review``.
    Unknown fields are a hard mismatch rather than silently ignored metadata.
    """
    unknown_fields = [
        *_unknown_statement_fields(original, "original"),
        *_unknown_statement_fields(formal, "formal"),
    ]
    original_contract_sha256 = original_contract_sha256 or problem_contract_sha256
    formal_contract_sha256 = formal_contract_sha256 or problem_contract_sha256
    original_components = _statement_components(
        original, contract_sha256=original_contract_sha256
    )
    formal_components = _statement_components(
        formal, contract_sha256=formal_contract_sha256
    )
    normalized_original_digest = _statement_digest(original_components)
    normalized_formal_digest = _statement_digest(formal_components)
    expected_original_digest = original_statement_sha256 or original.get(
        "original_statement_sha256", original.get("statement_sha256")
    )
    expected_formal_digest = formal_statement_sha256 or formal.get(
        "formal_statement_sha256", formal.get("statement_sha256")
    )
    original_candidates = _statement_digest_candidates(original, original_components)
    formal_candidates = _statement_digest_candidates(formal, formal_components)
    original_digest = (
        expected_original_digest
        if isinstance(expected_original_digest, str) and expected_original_digest in original_candidates
        else normalized_original_digest
    ) if expected_original_digest is not None else (
        _raw_statement_digest(original)
        if "statement" in original or "formal_statement" in original
        else normalized_original_digest
    )
    formal_digest = (
        expected_formal_digest
        if isinstance(expected_formal_digest, str) and expected_formal_digest in formal_candidates
        else normalized_formal_digest
    ) if expected_formal_digest is not None else (
        _raw_statement_digest(formal)
        if "statement" in formal or "formal_statement" in formal
        else normalized_formal_digest
    )
    reasons: list[str] = []
    digest_mismatch = False
    if (
        expected_original_digest is not None
        and (
            not isinstance(expected_original_digest, str)
            or expected_original_digest not in original_candidates
        )
    ):
        digest_mismatch = True
        reasons.append("原题 statement digest 与现场原始/规范化内容均不一致")
    if (
        expected_formal_digest is not None
        and (
            not isinstance(expected_formal_digest, str)
            or expected_formal_digest not in formal_candidates
        )
    ):
        digest_mismatch = True
        reasons.append("形式化 statement digest 与现场原始/规范化内容均不一致")

    comparisons: dict[str, dict[str, Any]] = {}
    for name in FAITHFUL_COMPONENTS:
        comparisons[name] = _comparison(
            original_components[name], formal_components[name], name
        )

    # A declared weakening/strengthening is a hard mismatch even if an
    # upstream normalizer accidentally omitted the conclusion text.
    original_strength = original_components["conclusion_strength"]
    formal_strength = formal_components["conclusion_strength"]
    weakening_labels = {
        "weaker",
        "weakened",
        "conditional",
        "narrower",
        "restricted",
        "stronger",
        "strengthened",
        "broader",
    }
    if formal_strength is not _MISSING and isinstance(formal_strength, str):
        if formal_strength.strip().lower() in weakening_labels:
            comparisons["conclusion_strength"] = _comparison(
                original_strength,
                formal_strength,
                "conclusion_strength",
                force_status="fail",
                force_reason="形式化陈述显式标记为非 exact 结论强度",
            )
    elif (
        original_strength is _MISSING
        and formal_strength is _MISSING
        and comparisons["conclusion"]["status"] == "pass"
    ):
        comparisons["conclusion_strength"] = _comparison(
            original_strength,
            formal_strength,
            "conclusion_strength",
            force_status="pass",
            force_reason="未声明独立强度字段；仅因结论规范化文本相同而暂按 exact，仍受结构比较边界约束",
        )

    if digest_mismatch:
        reasons.extend(
            [
                "调用者提供的 statement digest 漂移；不能以字段相等覆盖摘要失败",
            ]
        )
    statuses = [item["status"] for item in comparisons.values()]
    if unknown_fields:
        reasons.extend(
            f"statement 含未声明字段，拒绝静默忽略：{field}"
            for field in unknown_fields
        )
    if "fail" in statuses or digest_mismatch or unknown_fields:
        verdict = "fail"
    elif "needs_review" in statuses:
        verdict = "needs_review"
    else:
        verdict = "pass"
    if not reasons:
        reasons.append(
            "objects/domain/quantifiers/definitions/assumptions/conclusion/boundary/source identity 均逐项一致"
        )
    else:
        reasons = list(dict.fromkeys(reasons + [item["reason"] for item in comparisons.values() if item["status"] != "pass"]))

    original_identity = original_components["source_identity"]
    formal_identity = formal_components["source_identity"]
    contract_value = problem_contract_sha256
    if contract_value is None and isinstance(original_identity, Mapping):
        value = original_identity.get("problem_contract_sha256")
        if isinstance(value, str):
            contract_value = value

    component_digests = {
        name: {
            "original": comparisons[name]["original_sha256"],
            "formal": comparisons[name]["formal_sha256"],
        }
        for name in FAITHFUL_COMPONENTS
    }
    receipt_subject = _subject(subject or {}, include_nulls=False)
    for key in ("problem_id", "attempt_id", "candidate_id", "obligation_id"):
        if key not in receipt_subject:
            for candidate in (original, formal):
                if key in candidate:
                    receipt_subject[key] = candidate[key]
                    break
    generated_id = receipt_id or f"faithfulness:{original_digest[:16]}-{formal_digest[:16]}"
    if not re.fullmatch(r"faithfulness:[a-z0-9][a-z0-9.-]*", generated_id):
        raise QualityGateError("faithfulness receipt_id 不符合稳定 ID 格式")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": generated_id,
        "receipt_type": "statement_faithfulness",
        "subject": receipt_subject,
        "original_statement_sha256": original_digest,
        "formal_statement_sha256": formal_digest,
        "statement_sha256": original_digest,
        "problem_contract_sha256": contract_value,
        "component_digests": component_digests,
        "comparisons": comparisons,
        "verdict": verdict,
        "reasons": reasons,
        "reviewer": reviewer,
        "reviewed_at": reviewed_at or _now(),
        "capability_boundary": "deterministic normalized-field comparison; not a complete semantic equivalence proof for arbitrary Lean syntax",
    }
    validate_receipt(receipt, "statement-faithfulness-receipt.schema.json")
    return receipt


review_statement_faithfulness = compare_statement_faithfulness
check_statement_faithfulness = compare_statement_faithfulness
build_statement_faithfulness_receipt = compare_statement_faithfulness


# ---------------------------------------------------------------------------
# Three-gate formal admission


def _unwrap_gate(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if "receipt" not in value:
        return value
    nested = value.get("receipt")
    # A wrapper may not add an unvalidated status, identity, or digest beside
    # the receipt.  Merging those fields was the original status-only bypass.
    if not isinstance(nested, Mapping) or set(value) != {"receipt"}:
        return None
    return nested


def _identity_missing(gate: Mapping[str, Any], gate_name: str) -> list[str]:
    identity = _identity_from_gate(gate, gate_name)
    missing: list[str] = []
    required = _GATE_REQUIRED_IDENTITY_FIELDS.get(gate_name, _REQUIRED_IDENTITY_FIELDS)
    for key in required:
        value = identity.get(key)
        if key.endswith("_sha256"):
            if not _valid_digest(value):
                missing.append(key)
        elif not isinstance(value, str) or not value:
            missing.append(key)
    return missing


def _validate_gate_input(
    value: Any, gate_name: str
) -> tuple[Mapping[str, Any] | None, str | None, str | None]:
    """Validate a source receipt before reading its claimed status.

    The JSON schemas provide shape validation; this function supplies the
    cross-field invariants which JSON Schema cannot express conveniently:
    receipt identity, executed-command evidence, source/environment binding,
    and the complete subject shared by all three gates.
    """
    gate = _unwrap_gate(value)
    if gate is None:
        return None, "missing", f"{gate_name} receipt missing or wrapper is not exact"
    schema_name = _GATE_SCHEMA_NAMES[gate_name]
    try:
        validate_receipt(gate, schema_name)
    except QualityGateError as exc:
        return gate, "undetermined", f"{gate_name} receipt schema invalid: {exc}"

    receipt_id = gate.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return gate, "undetermined", f"{gate_name} receipt_id missing"

    raw = gate.get("verdict")
    if gate_name == "kernel":
        if raw not in {"checked", "rejected", "tool_error"}:
            return gate, "undetermined", "kernel receipt verdict vocabulary invalid"
    elif gate_name == "axiom_audit":
        if raw not in {"pass", "fail", "needs_review", "undetermined"}:
            return gate, "undetermined", "axiom_audit receipt verdict vocabulary invalid"
    else:
        if raw not in {"pass", "fail", "needs_review"}:
            return gate, "undetermined", "statement_faithfulness receipt verdict vocabulary invalid"

    # A non-positive receipt is still useful evidence of rejection or review;
    # only a positive source receipt needs the complete admission invariants.
    positive = (gate_name == "kernel" and raw == "checked") or (
        gate_name != "kernel" and raw == "pass"
    )
    if not positive:
        return gate, None, None

    missing_identity = _identity_missing(gate, gate_name)
    if missing_identity:
        return gate, "undetermined", f"{gate_name} identity incomplete: {', '.join(missing_identity)}"

    if gate_name == "kernel":
        command = gate.get("command")
        if not isinstance(command, Mapping) or not isinstance(command.get("executor"), str):
            return gate, "undetermined", "kernel checked receipt lacks explicit command executor"
        if command.get("executor") not in {"subprocess", "in_process"}:
            return gate, "undetermined", "kernel command executor invalid"
        if command.get("exit_code") != 0 or not command.get("argv"):
            return gate, "fail", "kernel checked receipt command did not succeed"
        principal = gate.get("principal")
        if not isinstance(principal, Mapping) or principal.get("role") != "verifier":
            return gate, "undetermined", "kernel checked receipt principal is not an explicit verifier"
        toolchain = gate.get("toolchain")
        if not isinstance(toolchain, Mapping):
            return gate, "undetermined", "kernel checked receipt lacks toolchain identity"
        execution_digest = gate.get("execution_environment_digest")
        if not _valid_digest(execution_digest) or sha256_json(toolchain) != execution_digest:
            return gate, "fail", "kernel execution environment digest is not bound to toolchain"
        if gate.get("environment") is not None and gate.get("environment") != toolchain:
            return gate, "fail", "kernel environment/toolchain identity drift"
        inputs = gate.get("input_digests")
        proof = gate.get("proof_artifact")
        if not isinstance(inputs, Mapping) or not isinstance(proof, Mapping):
            return gate, "undetermined", "kernel checked receipt lacks package/source digest object"
        if inputs.get("source_sha256") != proof.get("sha256"):
            return gate, "fail", "kernel proof artifact is not bound to input source digest"

    elif gate_name == "axiom_audit":
        source_set = gate.get("source_set")
        environment = gate.get("environment")
        if not isinstance(source_set, list) or not source_set:
            return gate, "undetermined", "axiom_audit pass requires a non-empty source_set"
        if not isinstance(environment, Mapping):
            return gate, "undetermined", "axiom_audit pass requires an environment receipt"
        source_digest = gate.get("source_set_sha256")
        if not _valid_digest(source_digest) or sha256_json(source_set) != source_digest:
            return gate, "fail", "axiom_audit source_set_sha256 does not match source_set"
        if environment.get("source_set_sha256") != source_digest:
            return gate, "fail", "axiom_audit environment is not bound to source_set_sha256"
        expected_environment = environment.get(
            "expected_environment_digest", environment.get("environment_digest")
        )
        observed_environment = environment.get("observed_environment_digest")
        if (
            not _valid_digest(expected_environment)
            or not _valid_digest(observed_environment)
            or expected_environment != observed_environment
        ):
            return gate, "undetermined", "axiom_audit environment expected/observed digest missing or drifted"
        if not _valid_digest(environment.get("axiom_output_sha256")):
            return gate, "undetermined", "axiom_audit lacks hashed command output"
        if environment.get("command_status") != "pass":
            return gate, "tool_error", "axiom_audit command did not report success"
        if environment.get("axiom_parse_status") not in {"parsed", "provided"}:
            return gate, "needs_review", "axiom_audit axiom output was not parsed"
        if gate.get("source_lex_status") != "pass":
            return gate, "needs_review", "axiom_audit source lexical scan is not pass"
        if any(
            isinstance(item, Mapping) and item.get("severity") == "error"
            for item in gate.get("findings", [])
        ):
            return gate, "fail", "axiom_audit contains error findings"
        if set(gate.get("observed_axioms", [])) - set(gate.get("allowed_axioms", [])):
            return gate, "fail", "axiom_audit contains unauthorized axioms"

    else:  # statement_faithfulness
        if gate.get("problem_contract_sha256") is None:
            return gate, "undetermined", "statement_faithfulness pass lacks ProblemContract digest"
        comparisons = gate.get("comparisons")
        if not isinstance(comparisons, Mapping) or set(comparisons) != set(FAITHFUL_COMPONENTS):
            return gate, "undetermined", "statement_faithfulness comparisons are incomplete"
        if any(
            not isinstance(item, Mapping) or item.get("status") != "pass"
            for item in comparisons.values()
        ):
            return gate, "needs_review", "statement_faithfulness has a non-pass component"
        if gate.get("statement_sha256") != gate.get("original_statement_sha256"):
            return gate, "fail", "statement_faithfulness statement digest alias drift"

    return gate, None, None


def _gate_status(value: Any, gate_name: str) -> tuple[str, str]:
    gate, validation_status, validation_reason = _validate_gate_input(value, gate_name)
    if gate is None:
        return validation_status or "missing", validation_reason or f"{gate_name} receipt missing"
    if validation_status is not None:
        return validation_status, validation_reason or f"{gate_name} receipt failed input validation"
    if gate.get("tool_error") is True or gate.get("native_status") in {
        "tool_error",
        "checker_error",
        "timeout",
        "resource_error",
        "unsupported",
    }:
        return "tool_error", f"{gate_name} reports tool/runtime error"
    raw = gate.get("verdict")
    if isinstance(raw, bool):
        raw = "pass" if raw else "fail"
    normalized = str(raw).strip().lower() if raw is not None else "missing"
    mapping = {
        "accept": "pass",
        "accepted": "pass",
        "checked": "pass",
        "pass": "pass",
        "ok": "pass",
        "reject": "fail",
        "rejected": "fail",
        "fail": "fail",
        "false": "fail",
        "needs_review": "needs_review",
        "review": "needs_review",
        "undetermined": "undetermined",
        "unknown": "undetermined",
        "missing": "missing",
        "tool_error": "tool_error",
    }
    status = mapping.get(normalized, "undetermined")
    if status == "pass":
        findings = gate.get("findings")
        if isinstance(findings, Sequence) and any(
            isinstance(item, Mapping) and item.get("severity") == "error" for item in findings
        ):
            return "fail", f"{gate_name} 含 error finding，不能被自报 pass 覆盖"
    return status, f"{gate_name} status={status}"

def _gate_receipt_id(value: Any) -> str | None:
    gate = _unwrap_gate(value)
    if gate is None:
        return None
    for key in ("receipt_id", "evidence_id", "admission_id"):
        item = gate.get(key)
        if isinstance(item, str):
            return item
    return None


def _identity_from_gate(value: Any, gate_name: str) -> dict[str, Any]:
    gate = _unwrap_gate(value) or {}
    identity: dict[str, Any] = {}
    sections: list[Mapping[str, Any]] = [gate]
    for key in (
        "subject",
        "identity",
        "digests",
        "input_identity",
        "package_identity",
        "metadata",
    ):
        section = gate.get(key)
        if isinstance(section, Mapping):
            sections.append(section)
    for section in sections:
        for key in _IDENTITY_FIELDS:
            if key in section and section[key] is not None:
                identity[key] = section[key]
        if "contract_sha256" in section and "problem_contract_sha256" not in identity:
            identity["problem_contract_sha256"] = section["contract_sha256"]

    # The canonical Lean receipt stores the formal declaration and source
    # binding in nested fields rather than in the generic subject object.
    input_digests = gate.get("input_digests")
    if isinstance(input_digests, Mapping):
        for key in (
            "problem_contract_sha256",
            "statement_sha256",
            "formal_statement_sha256",
        ):
            if key in input_digests and key not in identity:
                identity[key] = input_digests[key]
        if "source_sha256" in input_digests and "proof_source_sha256" not in identity:
            identity["proof_source_sha256"] = input_digests["source_sha256"]
    declaration = gate.get("verified_declaration", gate.get("declaration"))
    if isinstance(declaration, Mapping):
        if (
            "formal_statement_sha256" not in identity
            and isinstance(declaration.get("statement_sha256"), str)
        ):
            identity["formal_statement_sha256"] = declaration["statement_sha256"]
    proof_ref = gate.get("proof_artifact", gate.get("proof_source"))
    if (
        "proof_source_sha256" not in identity
        and isinstance(proof_ref, Mapping)
        and isinstance(proof_ref.get("sha256"), str)
    ):
        identity["proof_source_sha256"] = proof_ref["sha256"]

    if gate_name == "statement_faithfulness":
        if "statement_sha256" not in identity:
            for key in ("original_statement_sha256", "statement_sha256"):
                if isinstance(gate.get(key), str):
                    identity["statement_sha256"] = gate[key]
                    break
        if "formal_statement_sha256" not in identity and isinstance(
            gate.get("formal_statement_sha256"), str
        ):
            identity["formal_statement_sha256"] = gate["formal_statement_sha256"]
    return identity


def _compare_identity(
    gates: Mapping[str, Any],
    expected: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    per_gate = {name: _identity_from_gate(value, name) for name, value in gates.items()}
    explicit = {key: value for key, value in (expected or {}).items() if value is not None}
    mismatches: list[str] = []
    observed: dict[str, Any] = {}
    expected_values: dict[str, Any] = dict(explicit)

    for key in _IDENTITY_FIELDS:
        values = {
            name: identity[key]
            for name, identity in per_gate.items()
            if key in identity
        }
        is_core = key in _REQUIRED_IDENTITY_FIELDS
        is_explicit = key in explicit
        # Optional digests are compared whenever at least two gates bind them;
        # a one-gate proof-source digest is gate-specific and is handled by
        # the explicit proof_source_sha256 argument instead.
        if not is_explicit and not is_core and len(values) < 2:
            continue
        target = explicit.get(key, next(iter(values.values()), None))
        if not values:
            mismatches.append(f"identity 缺少 {key}")
            continue
        if not is_explicit and len(values) >= 2:
            distinct = {
                json.dumps(_canonical(value), ensure_ascii=False, sort_keys=True)
                for value in values.values()
            }
            if len(distinct) > 1:
                mismatches.append(f"identity {key} 在三门之间漂移")
        for name, value in values.items():
            if value != target:
                mismatches.append(f"identity {key} 在 {name} 与 expected 不一致")
        required_gates = {
            name
            for name in per_gate
            if key in _GATE_REQUIRED_IDENTITY_FIELDS.get(name, _REQUIRED_IDENTITY_FIELDS)
        }
        if (is_core or is_explicit) and not required_gates.issubset(values):
            missing_gates = sorted(required_gates - set(values))
            mismatches.append(
                f"identity {key} 未绑定要求的门：{', '.join(missing_gates)}"
            )
        expected_values[key] = target
        observed[key] = target

    # An explicitly supplied identity field outside the known set is still
    # checked exactly; silently dropping it would make the admission receipt
    # unable to prove that the caller's contract was the one audited.
    for key, target in explicit.items():
        if key in _IDENTITY_FIELDS:
            continue
        values = {
            name: identity.get(key)
            for name, identity in per_gate.items()
            if key in identity
        }
        if not values:
            mismatches.append(f"identity 缺少 {key}")
            continue
        for name, value in values.items():
            if value != target:
                mismatches.append(f"identity {key} 在 {name} 与 expected 不一致")
        if len(values) < len(per_gate):
            mismatches.append(f"identity {key} 未绑定全部三门")
        expected_values[key] = target
        observed[key] = target

    if mismatches:
        status = "fail" if any("不一致" in item or "漂移" in item for item in mismatches) else "needs_review"
    else:
        status = "pass"
    return (
        {
            "status": status,
            "expected": expected_values,
            "observed": observed,
            "mismatches": mismatches,
        },
        observed,
        mismatches,
    )


def _compare_digests(
    gates: Mapping[str, Any],
    expected: Mapping[str, Any] | None,
    observed_identity: Mapping[str, Any],
) -> dict[str, Any]:
    expected_values = dict(expected or {})
    for key in ("problem_contract_sha256", "statement_sha256", "formal_statement_sha256", "proof_source_sha256"):
        if key in observed_identity and key not in expected_values:
            expected_values[key] = observed_identity[key]
    mismatches: list[str] = []
    observed: dict[str, Any] = {}
    for key, expected_value in sorted(expected_values.items()):
        values: dict[str, Any] = {}
        for name, gate_value in gates.items():
            identity = _identity_from_gate(gate_value, name)
            if key in identity:
                values[name] = identity[key]
        if not values:
            mismatches.append(f"digest 缺少 {key}")
            continue
        for name, value in values.items():
            if value != expected_value:
                mismatches.append(f"digest {key} 在 {name} 与 expected 不一致")
        required_gates = {
            name
            for name in gates
            if key in _GATE_REQUIRED_IDENTITY_FIELDS.get(name, _REQUIRED_IDENTITY_FIELDS)
        }
        if not required_gates.issubset(values):
            missing_gates = sorted(required_gates - set(values))
            mismatches.append(
                f"digest {key} 未绑定要求的门：{', '.join(missing_gates)}"
            )
        observed[key] = next(iter(values.values()))
    if mismatches:
        status = "fail" if any("不一致" in item for item in mismatches) else "needs_review"
    else:
        status = "pass"
    return {
        "status": status,
        "expected": expected_values,
        "observed": observed,
        "mismatches": mismatches,
    }


def evaluate_formal_proof_admission(
    kernel_receipt: Mapping[str, Any] | None = None,
    axiom_audit_receipt: Mapping[str, Any] | None = None,
    statement_faithfulness_receipt: Mapping[str, Any] | None = None,
    *,
    kernel: Mapping[str, Any] | None = None,
    axiom_audit: Mapping[str, Any] | None = None,
    faithfulness: Mapping[str, Any] | None = None,
    expected_identity: Mapping[str, Any] | None = None,
    expected_digests: Mapping[str, Any] | None = None,
    proof_source_sha256: str | None = None,
    admission_id: str | None = None,
    decider: str = "formal-proof-admission-gate",
    decided_at: str | None = None,
) -> dict[str, Any]:
    """Compose kernel, axiom and faithfulness gates fail-closed.

    ``accept`` is possible only when all three statuses are ``pass`` and all
    required identity/digest comparisons pass.  A missing, tool-error or
    needs-review gate produces ``undetermined``; explicit rejects and identity
    drift produce ``reject``.
    """
    kernel_receipt = kernel_receipt or kernel
    axiom_audit_receipt = axiom_audit_receipt or axiom_audit
    statement_faithfulness_receipt = statement_faithfulness_receipt or faithfulness
    gates_input = {
        "kernel": kernel_receipt,
        "axiom_audit": axiom_audit_receipt,
        "statement_faithfulness": statement_faithfulness_receipt,
    }
    gates: dict[str, dict[str, Any]] = {}
    statuses: dict[str, str] = {}
    for name, value in gates_input.items():
        status, reason = _gate_status(value, name)
        statuses[name] = status
        gates[name] = {
            "status": status,
            "receipt_id": _gate_receipt_id(value),
            "reason": reason,
        }

    identity_check, observed_identity, identity_mismatches = _compare_identity(
        gates_input, expected_identity
    )
    digest_check = _compare_digests(gates_input, expected_digests, observed_identity)
    if proof_source_sha256 is not None:
        _require_digest(proof_source_sha256, "proof_source_sha256")
        actual = _identity_from_gate(kernel_receipt, "kernel").get("proof_source_sha256")
        if actual != proof_source_sha256:
            digest_check["mismatches"].append("kernel proof source digest 与 expected 不一致")
            digest_check["status"] = "fail" if actual is not None else "needs_review"
            digest_check["expected"]["proof_source_sha256"] = proof_source_sha256
            digest_check["observed"]["proof_source_sha256"] = actual

    hard_reject = any(status == "fail" for status in statuses.values())
    if identity_check["status"] == "fail" or digest_check["status"] == "fail":
        hard_reject = True
    unresolved = any(
        status in {"missing", "tool_error", "needs_review", "undetermined"}
        for status in statuses.values()
    )
    unresolved = unresolved or identity_check["status"] == "needs_review" or digest_check["status"] == "needs_review"
    if hard_reject:
        verdict = "reject"
    elif unresolved:
        verdict = "undetermined"
    else:
        verdict = "accept"

    reasons: list[str] = []
    for name, status in statuses.items():
        if status != "pass":
            reasons.append(f"{name} gate={status}")
    reasons.extend(identity_check["mismatches"])
    reasons.extend(digest_check["mismatches"])
    if not reasons:
        reasons.append("kernel=pass, axiom_audit=pass, statement_faithfulness=pass 且身份/摘要完全一致")
    else:
        reasons = list(dict.fromkeys(reasons))

    subject = _subject(observed_identity, include_nulls=True)
    recorded_proof_source = proof_source_sha256 or _identity_from_gate(
        kernel_receipt, "kernel"
    ).get("proof_source_sha256")
    identity_for_id = {
        "subject": subject,
        "gates": gates,
        "identity": identity_check,
        "digests": digest_check,
    }
    generated_id = admission_id or f"formal-admission:{sha256_json(identity_for_id)[:24]}"
    if not re.fullmatch(r"formal-admission:[a-z0-9][a-z0-9.-]*", generated_id):
        raise QualityGateError("formal admission_id 不符合稳定 ID 格式")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "admission_id": generated_id,
        "receipt_type": "formal_proof_admission",
        "subject": subject,
        "gates": gates,
        "identity_check": identity_check,
        "digest_check": digest_check,
        "proof_source_sha256": recorded_proof_source,
        "verdict": verdict,
        "admitted": verdict == "accept",
        "reasons": reasons,
        "decider": decider,
        "decided_at": decided_at or _now(),
        "capability_boundary": "composition gate only; kernel pass does not prove natural-language statement faithfulness",
    }
    validate_receipt(receipt, "formal-proof-admission.schema.json")
    return receipt


admit_formal_proof = evaluate_formal_proof_admission
formal_proof_admission = evaluate_formal_proof_admission
admit_proof = evaluate_formal_proof_admission


__all__ = [
    "FAITHFUL_COMPONENTS",
    "QualityGateError",
    "admit_formal_proof",
    "admit_proof",
    "audit_axiom_escape",
    "audit_axioms",
    "build_axiom_escape_audit_receipt",
    "check_axiom_escape",
    "build_statement_faithfulness_receipt",
    "canonical_json",
    "check_statement_faithfulness",
    "compare_statement_faithfulness",
    "evaluate_formal_proof_admission",
    "formal_proof_admission",
    "run_axiom_escape_audit",
    "scan_lean_source",
    "sha256_json",
    "sha256_text",
    "strip_lean_comments_and_strings",
    "validate_receipt",
]
