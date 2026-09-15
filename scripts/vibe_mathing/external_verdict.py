"""Pure, candidate-only normalization for Prove2me external verdicts.

This module is intentionally a boundary, not an importer/ledger writer.  It
accepts an already collected response bundle plus read-only local records,
recomputes the local and response digests, and returns a detached
``ExternalVerdictReceipt`` only when every binding is consistent.  It never
opens a network connection, starts a subprocess, creates a file, appends a
ledger line, or emits Evidence/Result state.

The production schema is deliberately strict, but JSON Schema cannot compare
values at two different paths.  The application checks below therefore enforce
those equalities and, importantly, enforce the complete twelve-member
``forbidden_effects`` set rather than relying on the schema's cardinality.

Response digest convention used here (and by the v1 contract) is:

* ``request_sha256`` = SHA-256 of canonical JSON
  ``{"method": request_method, "endpoint": endpoint}``;
* ``body_sha256`` = SHA-256 of the exact response bytes, when a body exists;
* ``response_sha256`` = SHA-256 of the response object with its own
  ``response_sha256`` field removed.

The returned object contains no response body or credential.  A remote
``ACCEPTED``, ``CE``, ``WA``, or any other status remains
``status_scope=remote_only``, ``claim_ceiling=candidate_only``, and
``admission_status=unadmitted``.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import stat
import unicodedata
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "1.0.0"
RECORD_TYPE = "ExternalVerdictReceipt"
SCHEMA_FILENAME = "external-verdict-receipt.schema.json"

RESPONSE_SLOTS: tuple[str, ...] = ("target", "submission", "source", "environment")

# This is a policy set, not merely a list of examples.  The normalizer checks
# length, uniqueness, and exact set equality, in addition to schema validation.
FORBIDDEN_EFFECTS: tuple[str, ...] = (
    "remote_write",
    "canonical_problem_mutation",
    "attempt_mutation",
    "graph_mutation",
    "obligation_closure",
    "kernel_verification",
    "axiom_audit",
    "statement_faithfulness_decision",
    "evidence_link_creation",
    "result_creation",
    "solution_index_update",
    "credential_persistence",
)
_ALLOWED_EFFECTS = frozenset(
    {
        "append_external_verdict_receipt",
        "append_importer_journal",
        "append_candidate_only_intake",
    }
)

_IDENTITY_FIELDS: tuple[str, ...] = (
    "problem_id",
    "attempt_id",
    "graph_id",
    "obligation_id",
    "candidate_id",
    "route_id",
)
_DIGEST_FIELDS: tuple[str, ...] = (
    "problem_contract_sha256",
    "attempt_sha256",
    "graph_sha256",
    "obligation_sha256",
    "candidate_sha256",
    "statement_sha256",
    "source_sha256",
    "environment_remote_sha256",
    "environment_local_sha256",
    "target_response_sha256",
    "submission_response_sha256",
    "source_response_sha256",
    "environment_response_sha256",
    "normalization_input_sha256",
    "idempotency_key_sha256",
)

_LOCAL_FILES: dict[str, tuple[str, str]] = {
    "problem": ("problem-library/records/canonical-problems.jsonl", "problem_id"),
    "attempt": ("research/records/attempts.jsonl", "attempt_id"),
    "graph": ("research/records/obligation-graphs.jsonl", "graph_id"),
    "candidate": ("research/records/candidate-artifacts.jsonl", "candidate_id"),
}

_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_SAFE_LOCATOR = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
_SECRET_TEXT = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"(?i:\b(?:password|passphrase|token|access[_ -]?token|api[_ -]?key|secret|cookie|authorization|mfa)\s*[:=])|"
    r"(?i:(?:^|[?&])(?:token|access_token|api_key|password|secret|cookie|authorization|mfa)=))"
)
_SECRET_KEYS = frozenset(
    {
        "authorization",
        "bearer",
        "cookie",
        "cookies",
        "mfa",
        "password",
        "passphrase",
        "token",
        "accesstoken",
        "apikey",
        "secret",
        "privatekey",
        "clientsecret",
    }
)
_UPGRADE_KEYS = frozenset(
    {
        "result_id",
        "solution_id",
        "evidence_link_id",
        "kernel_checked",
        "independent",
        "result_admission",
        "kernel_verdict",
        "axiom_audit_pass",
        "statement_faithfulness_pass",
        "solution_index_id",
    }
)
_MISSING = object()


class ExternalVerdictError(ValueError):
    """Base class for a receipt that cannot be safely normalized."""


class ExternalVerdictSchemaError(ExternalVerdictError):
    """The input is not strict JSON or fails the receipt schema."""


class ExternalVerdictPrivacyError(ExternalVerdictError):
    """The input contains credential/private material or raw sensitive data."""


class ExternalVerdictPolicyError(ExternalVerdictError):
    """The candidate-only or principal policy was violated."""


class ExternalVerdictIdentityError(ExternalVerdictError):
    """A local record, source, statement, environment, or response drifted."""


# Friendly names for callers that use the shorter terminology.
ExternalVerdictNormalizationError = ExternalVerdictError
ExternalVerdictBindingError = ExternalVerdictIdentityError
EXPECTED_FORBIDDEN_EFFECTS = FORBIDDEN_EFFECTS
FORBIDDEN_EFFECT_SET = frozenset(FORBIDDEN_EFFECTS)


def _path(path: Any) -> str:
    if not path:
        return "<root>"
    return ".".join(str(item) for item in path)


def _strict_value(value: Any, path: str = "$") -> Any:
    """Copy JSON-shaped data while rejecting non-finite/invalid Unicode values."""
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ExternalVerdictSchemaError(f"non-finite number at {path}")
        return value
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ExternalVerdictSchemaError(f"surrogate Unicode at {path}")
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ExternalVerdictSchemaError(f"invalid UTF-8 Unicode at {path}") from exc
        # The contract's canonical representation is NFC.  Rejecting rather
        # than silently rewriting makes a caller prove which bytes it meant.
        if unicodedata.normalize("NFC", value) != value:
            raise ExternalVerdictSchemaError(f"non-NFC Unicode at {path}")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ExternalVerdictSchemaError(f"JSON object key is not a string at {path}")
            clean_key = _strict_value(key, f"{path}.<key>")
            if clean_key in result:
                # This branch is mostly for custom Mapping implementations;
                # raw JSON duplicate keys are caught by _pairs below.
                raise ExternalVerdictSchemaError(f"duplicate JSON key at {path}.{clean_key}")
            result[clean_key] = _strict_value(child, f"{path}.{clean_key}")
        return result
    if isinstance(value, list):
        return [_strict_value(child, f"{path}[{index}]") for index, child in enumerate(value)]
    # Tuples, sets, bytes, Decimal, and custom objects must not be silently
    # coerced into a different JSON value.
    raise ExternalVerdictSchemaError(f"value is not strict JSON at {path}")


def _reject_constant(value: str) -> None:
    raise ExternalVerdictSchemaError(f"non-finite JSON constant is forbidden: {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalVerdictSchemaError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_value(raw: bytes | bytearray | str, *, require_object: bool) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ExternalVerdictSchemaError("JSON input is not valid UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise ExternalVerdictSchemaError("JSON input must be UTF-8 bytes or text")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except ExternalVerdictError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExternalVerdictSchemaError("invalid JSON input") from exc
    value = _strict_value(value)
    if require_object and not isinstance(value, dict):
        raise ExternalVerdictSchemaError("receipt JSON must be an object")
    return value


def _as_plain_json(value: Any) -> Any:
    """Make a detached strict JSON value from a Python object."""
    return _strict_value(value)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the project's finite, NFC, sorted canonical JSON bytes."""
    clean = _as_plain_json(value)
    try:
        return json.dumps(
            clean,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExternalVerdictSchemaError("value cannot be encoded as canonical JSON") from exc


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(value: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def canonical_request_sha256(method: str, endpoint: str) -> str:
    """Digest the request metadata used by the receipt response convention."""
    return canonical_json_sha256({"method": method, "endpoint": endpoint})


def canonical_response_sha256(response: Mapping[str, Any]) -> str:
    """Digest a response object without trusting its claimed response digest."""
    clean = _as_plain_json(response)
    if not isinstance(clean, dict):
        raise ExternalVerdictSchemaError("response must be an object")
    clean.pop("response_sha256", None)
    return canonical_json_sha256(clean)


def _schema_path(schema_path: Path | str | None) -> Path:
    if schema_path is None:
        path = Path(__file__).resolve().parents[2] / "research" / "schema" / SCHEMA_FILENAME
    else:
        path = Path(schema_path).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ExternalVerdictSchemaError(f"schema is missing or unsafe: {path}")
    return path


def _load_schema(schema_path: Path | str | None = None) -> dict[str, Any]:
    path = _schema_path(schema_path)
    try:
        schema = _parse_json_value(path.read_bytes(), require_object=True)
        Draft202012Validator.check_schema(schema)
    except ExternalVerdictError:
        raise
    except Exception as exc:  # jsonschema raises several schema-error classes
        raise ExternalVerdictSchemaError(f"invalid Draft 2020-12 schema: {path}") from exc
    return schema


def _sensitive_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            folded = re.sub(r"[-_]", "", key.casefold())
            if folded in _SECRET_KEYS:
                errors.append(f"credential-bearing key at {path}.{key}")
            errors.extend(_sensitive_errors(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_sensitive_errors(child, f"{path}[{index}]"))
    elif isinstance(value, str) and _SECRET_TEXT.search(value):
        errors.append(f"credential-bearing text at {path}")
    return errors


def _upgrade_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _UPGRADE_KEYS:
                errors.append(f"upgrade field is forbidden at {path}.{key}")
            errors.extend(_upgrade_errors(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_upgrade_errors(child, f"{path}[{index}]"))
    return errors


def _validate_exact_principal_policy(receipt: Mapping[str, Any]) -> None:
    try:
        importer = receipt["principals"]["importer"]
        effects = importer["forbidden_effects"]
        allowed = importer["allowed_effects"]
    except (KeyError, TypeError) as exc:
        raise ExternalVerdictPolicyError("receipt principal policy is incomplete") from exc
    if not isinstance(effects, list) or len(effects) != len(FORBIDDEN_EFFECTS):
        raise ExternalVerdictPolicyError(
            "forbidden_effects must contain exactly all twelve policy effects"
        )
    if len(set(effects)) != len(FORBIDDEN_EFFECTS) or set(effects) != set(FORBIDDEN_EFFECTS):
        raise ExternalVerdictPolicyError(
            "forbidden_effects is not the exact twelve-member policy set"
        )
    if not isinstance(allowed, list) or len(set(allowed)) != len(allowed):
        raise ExternalVerdictPolicyError("allowed_effects must be a unique list")
    if set(allowed) - _ALLOWED_EFFECTS:
        raise ExternalVerdictPolicyError("allowed_effects contains an unadmitted effect")
    if set(allowed) & set(FORBIDDEN_EFFECTS):
        raise ExternalVerdictPolicyError("allowed_effects contains a forbidden effect")


def _validate_policy(receipt: Mapping[str, Any]) -> None:
    if receipt.get("claim_ceiling") != "candidate_only":
        raise ExternalVerdictPolicyError("external receipt claim ceiling is not candidate_only")
    if receipt.get("admission_status") != "unadmitted":
        raise ExternalVerdictPolicyError("external receipt cannot be admitted by itself")
    _validate_exact_principal_policy(receipt)
    replay = receipt.get("replay_boundary")
    if not isinstance(replay, dict):
        raise ExternalVerdictPolicyError("missing replay boundary")
    if replay.get("local_replay_status") != "not_run":
        raise ExternalVerdictPolicyError("external receipt cannot claim local replay")
    for field in (
        "kernel_receipt_ref",
        "axiom_audit_ref",
        "statement_faithfulness_ref",
        "evidence_link_ref",
        "result_ref",
    ):
        if replay.get(field) is not None:
            raise ExternalVerdictPolicyError(f"external receipt populated local field: {field}")
    if replay.get("promotion") != "forbidden_from_this_receipt":
        raise ExternalVerdictPolicyError("external receipt promotion boundary was changed")
    transport = receipt.get("transport")
    if not isinstance(transport, dict) or transport.get("mode") != "read_only":
        raise ExternalVerdictPolicyError("external receipt transport is not read-only")
    if transport.get("request_policy") != "GET_only":
        raise ExternalVerdictPolicyError("external receipt is not GET-only")
    for field in (
        "remote_mutation_attempted",
        "writes_performed",
        "credential_material_persisted",
        "raw_response_persisted",
    ):
        if transport.get(field) is not False:
            raise ExternalVerdictPolicyError(f"transport policy violation: {field}")
    if receipt.get("observation_status") == "observed":
        if receipt.get("failure", {}).get("class") != "none":
            raise ExternalVerdictPolicyError("observed receipt has a failure class")
        if receipt.get("platform", {}).get("version_status") != "locked":
            raise ExternalVerdictPolicyError("observed receipt requires a locked platform version")
    elif receipt.get("failure", {}).get("class") == "none":
        raise ExternalVerdictPolicyError("blocked/quarantined receipt must record a failure class")


def validate_external_verdict(
    receipt: Mapping[str, Any] | bytes | bytearray | str,
    *,
    schema_path: Path | str | None = None,
) -> dict[str, Any]:
    """Strictly validate an external receipt and return a detached copy.

    This is schema/policy validation only.  ``normalize_external_verdict``
    additionally binds the receipt to local records and raw response/source
    bytes.
    """
    if isinstance(receipt, Mapping):
        value = _as_plain_json(receipt)
    else:
        value = _parse_json_value(receipt, require_object=True)
    if not isinstance(value, dict):  # defensive for type checkers
        raise ExternalVerdictSchemaError("receipt must be an object")
    sensitive = _sensitive_errors(value)
    upgrades = _upgrade_errors(value)
    if sensitive:
        raise ExternalVerdictPrivacyError("; ".join(sensitive))
    if upgrades:
        raise ExternalVerdictPolicyError("; ".join(upgrades))
    schema = _load_schema(schema_path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: [str(part) for part in item.path],
    )
    if errors:
        first = errors[0]
        raise ExternalVerdictSchemaError(f"{_path(first.path)}: {first.message}")
    _validate_policy(value)
    return copy.deepcopy(value)


def _require_digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ExternalVerdictIdentityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ExternalVerdictIdentityError(f"{label} is not a safe identifier")
    return value


def _safe_locator(locator: Any, label: str) -> str:
    if not isinstance(locator, str) or not _SAFE_LOCATOR.fullmatch(locator):
        raise ExternalVerdictIdentityError(f"{label} is an unsafe locator")
    raw_parts = locator.split("/")
    pure = PurePosixPath(locator)
    if (
        pure.is_absolute()
        or "\\" in locator
        or any(part in {"", ".", ".."} for part in raw_parts)
        or "." in pure.parts
        or ".." in pure.parts
        or pure.parts[:2] != ("research", "artifacts")
    ):
        raise ExternalVerdictIdentityError(f"{label} must be a safe research/artifacts path")
    return locator


def _safe_remote_path(value: Any) -> str:
    raw_parts = value.split("/") if isinstance(value, str) else []
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\\" in value
        or "?" in value
        or "#" in value
        or any(part in {"", ".", ".."} for part in raw_parts[1:])
        or "." in PurePosixPath(value).parts
        or ".." in PurePosixPath(value).parts
        or not re.fullmatch(r"/[A-Za-z0-9._~:/-]+", value)
    ):
        raise ExternalVerdictIdentityError("source.remote_path is unsafe")
    return value


def _root(project_root: Path | str | None) -> Path | None:
    if project_root is None:
        return None
    path = Path(project_root).expanduser().resolve()
    if not path.is_dir():
        raise ExternalVerdictIdentityError(f"project root is not a directory: {path}")
    return path


def _read_jsonl(root: Path, relative: str) -> list[dict[str, Any]]:
    path = root / relative
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ExternalVerdictIdentityError(f"local record source is not a regular file: {relative}")
    if not path.exists():
        return []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ExternalVerdictIdentityError(f"cannot read local record source: {relative}") from exc
    if raw and not raw.endswith(b"\n"):
        raise ExternalVerdictIdentityError(f"local JSONL has a truncated final line: {relative}")
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.split(b"\n")[:-1], 1):
        if not line.strip():
            continue
        value = _parse_json_value(line, require_object=True)
        if not isinstance(value, dict):
            raise ExternalVerdictIdentityError(f"local record is not an object: {relative}:{line_number}")
        values.append(value)
    return values


def _unique_record(records: list[dict[str, Any]], field: str, identity: str, label: str) -> dict[str, Any]:
    matches = [record for record in records if record.get(field) == identity]
    if not matches:
        raise ExternalVerdictIdentityError(f"{label} not found: {identity}")
    if len(matches) != 1:
        raise ExternalVerdictIdentityError(f"{label} is not unique: {identity}")
    return matches[0]


def _record_from_root(root: Path, role: str, identity: str) -> dict[str, Any] | None:
    relative, field = _LOCAL_FILES[role]
    records = _read_jsonl(root, relative)
    if not records:
        return None
    return _unique_record(records, field, identity, role)


def _context_value(
    supplied: Mapping[str, Any],
    aliases: tuple[str, ...],
    *,
    root: Path | None,
    role: str,
    identity: str,
) -> dict[str, Any]:
    value: Any = _MISSING
    for alias in aliases:
        if alias in supplied:
            if value is not _MISSING and supplied[alias] != value:
                raise ExternalVerdictIdentityError(f"conflicting local {role} aliases")
            value = supplied[alias]
    local = _record_from_root(root, role, identity) if root is not None and value is _MISSING else None
    if value is _MISSING:
        value = local
    elif local is not None and canonical_json_sha256(value) != canonical_json_sha256(local):
        raise ExternalVerdictIdentityError(f"supplied {role} differs from authoritative project record")
    if not isinstance(value, Mapping):
        raise ExternalVerdictIdentityError(f"local {role} record is required")
    return _as_plain_json(value)


def _resolve_context(
    receipt: Mapping[str, Any],
    *,
    project_root: Path | str | None,
    local_records: Mapping[str, Any] | None,
    problem: Mapping[str, Any] | None,
    attempt: Mapping[str, Any] | None,
    graph: Mapping[str, Any] | None,
    obligation: Mapping[str, Any] | None,
    candidate: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    root = _root(project_root)
    supplied: dict[str, Any] = dict(local_records or {})
    for key, value in {
        "problem": problem,
        "attempt": attempt,
        "graph": graph,
        "obligation": obligation,
        "candidate": candidate,
    }.items():
        if value is not None:
            if key in supplied and supplied[key] != value:
                raise ExternalVerdictIdentityError(f"conflicting supplied local {key} record")
            supplied[key] = value
    identity = receipt["identity"]
    context: dict[str, dict[str, Any]] = {}
    context["problem"] = _context_value(
        supplied,
        ("problem", "problem_contract"),
        root=root,
        role="problem",
        identity=identity["problem_id"],
    )
    context["attempt"] = _context_value(
        supplied,
        ("attempt",),
        root=root,
        role="attempt",
        identity=identity["attempt_id"],
    )
    context["graph"] = _context_value(
        supplied,
        ("graph", "obligation_graph"),
        root=root,
        role="graph",
        identity=identity["graph_id"],
    )
    context["candidate"] = _context_value(
        supplied,
        ("candidate",),
        root=root,
        role="candidate",
        identity=identity["candidate_id"],
    )

    graph_obligations = context["graph"].get("obligations")
    if not isinstance(graph_obligations, list):
        raise ExternalVerdictIdentityError("ObligationGraph obligations must be a list")
    graph_matches = [
        item for item in graph_obligations
        if isinstance(item, Mapping) and item.get("obligation_id") == identity["obligation_id"]
    ]
    if len(graph_matches) != 1:
        raise ExternalVerdictIdentityError(
            f"Obligation is not uniquely present in graph: {identity['obligation_id']}"
        )
    graph_obligation = _as_plain_json(graph_matches[0])
    supplied_obligation = supplied.get("obligation")
    if supplied_obligation is not None and canonical_json_sha256(supplied_obligation) != canonical_json_sha256(graph_obligation):
        raise ExternalVerdictIdentityError("supplied obligation differs from graph obligation")
    context["obligation"] = graph_obligation
    return context


def _validate_graph(context: Mapping[str, Mapping[str, Any]]) -> None:
    graph = context["graph"]
    obligations_raw = graph.get("obligations")
    root_id = graph.get("root_obligation_id")
    if not isinstance(obligations_raw, list) or not isinstance(root_id, str):
        raise ExternalVerdictIdentityError("ObligationGraph lacks a root and obligation list")
    obligations: dict[str, Mapping[str, Any]] = {}
    for item in obligations_raw:
        if not isinstance(item, Mapping):
            raise ExternalVerdictIdentityError("ObligationGraph contains a non-object obligation")
        oid = item.get("obligation_id")
        if not isinstance(oid, str) or oid in obligations:
            raise ExternalVerdictIdentityError("ObligationGraph has a missing or duplicate obligation ID")
        obligations[oid] = item
    if root_id not in obligations:
        raise ExternalVerdictIdentityError("ObligationGraph root is absent")
    for oid, item in obligations.items():
        dependencies = item.get("dependencies")
        if not isinstance(dependencies, list) or not all(isinstance(dependency, str) for dependency in dependencies):
            raise ExternalVerdictIdentityError(f"obligation dependencies are invalid: {oid}")
        if len(set(dependencies)) != len(dependencies):
            raise ExternalVerdictIdentityError(f"obligation dependencies are duplicated: {oid}")
        if any(dependency not in obligations for dependency in dependencies):
            raise ExternalVerdictIdentityError(f"obligation dependency is foreign: {oid}")
        statement = item.get("statement")
        declared = item.get("statement_sha256")
        if not isinstance(statement, Mapping) or canonical_json_sha256(statement) != declared:
            raise ExternalVerdictIdentityError(f"obligation statement digest is invalid: {oid}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(oid: str) -> None:
        if oid in visiting:
            raise ExternalVerdictIdentityError(f"ObligationGraph contains a dependency cycle: {oid}")
        if oid in visited:
            return
        visiting.add(oid)
        for dependency in obligations[oid]["dependencies"]:
            visit(dependency)
        visiting.remove(oid)
        visited.add(oid)

    visit(root_id)
    if visited != set(obligations):
        missing = sorted(set(obligations) - visited)[0]
        raise ExternalVerdictIdentityError(f"ObligationGraph root cannot reach: {missing}")


def _bind_local_identity(receipt: Mapping[str, Any], context: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    problem = context["problem"]
    attempt = context["attempt"]
    graph = context["graph"]
    obligation = context["obligation"]
    candidate = context["candidate"]
    identity = receipt["identity"]
    expected_contract = canonical_json_sha256(problem)
    if problem.get("problem_id") != identity["problem_id"]:
        raise ExternalVerdictIdentityError("ProblemContract problem_id drift")
    expected = {
        "problem_id": problem.get("problem_id"),
        "attempt_id": attempt.get("attempt_id"),
        "graph_id": graph.get("graph_id"),
        "obligation_id": obligation.get("obligation_id"),
        "candidate_id": candidate.get("candidate_id"),
        "route_id": graph.get("route_id"),
    }
    for field in _IDENTITY_FIELDS:
        if identity.get(field) != expected[field]:
            raise ExternalVerdictIdentityError(
                f"identity.{field} drift: expected {expected[field]}, got {identity.get(field)}"
            )
    if attempt.get("problem_id") != problem.get("problem_id"):
        raise ExternalVerdictIdentityError("Attempt crosses ProblemContract")
    if attempt.get("obligation_graph_id", attempt.get("graph_id")) != graph.get("graph_id"):
        raise ExternalVerdictIdentityError("Attempt is not bound to the selected graph")
    if attempt.get("route_id") != graph.get("route_id"):
        raise ExternalVerdictIdentityError("Attempt route differs from graph route")
    if attempt.get("problem_contract_sha256") != expected_contract:
        raise ExternalVerdictIdentityError("Attempt ProblemContract digest drift")
    for field in ("problem_id", "attempt_id", "route_id", "problem_contract_sha256"):
        if graph.get(field) != (expected_contract if field == "problem_contract_sha256" else expected.get(field)):
            raise ExternalVerdictIdentityError(f"ObligationGraph {field} drift")
    if candidate.get("problem_id") != problem.get("problem_id"):
        raise ExternalVerdictIdentityError("Candidate crosses ProblemContract")
    if any(candidate.get(field) != graph.get(field) for field in ("graph_id", "problem_id", "attempt_id")):
        raise ExternalVerdictIdentityError("Candidate crosses ObligationGraph identity")
    if candidate.get("problem_contract_sha256") != expected_contract:
        raise ExternalVerdictIdentityError("Candidate ProblemContract digest drift")
    statement = obligation.get("statement")
    statement_digest = obligation.get("statement_sha256")
    if not isinstance(statement, Mapping) or canonical_json_sha256(statement) != statement_digest:
        raise ExternalVerdictIdentityError("Obligation statement digest drift")
    if candidate.get("obligation_id") != obligation.get("obligation_id"):
        raise ExternalVerdictIdentityError("Candidate crosses Obligation")
    if candidate.get("statement_sha256") != statement_digest:
        raise ExternalVerdictIdentityError("Candidate statement digest drift")
    _require_digest(statement_digest, "statement_sha256")
    return {
        "problem_contract_sha256": expected_contract,
        "attempt_sha256": canonical_json_sha256(attempt),
        "graph_sha256": canonical_json_sha256(graph),
        "obligation_sha256": canonical_json_sha256(obligation),
        "candidate_sha256": canonical_json_sha256(candidate),
        "statement_sha256": statement_digest,
    }


def _coerce_bytes(value: Any, label: str) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ExternalVerdictIdentityError(f"{label} is not valid UTF-8") from exc
    if isinstance(value, (Mapping, list)):
        return canonical_json_bytes(value)
    raise ExternalVerdictIdentityError(f"{label} must be bytes, UTF-8 text, or JSON")


def _artifact_path(root: Path, locator: str) -> Path:
    _safe_locator(locator, "artifact.locator")
    path = root.joinpath(*PurePosixPath(locator).parts)
    lexical = root
    for part in PurePosixPath(locator).parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise ExternalVerdictIdentityError(f"artifact path traverses a symlink: {locator}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root / "research" / "artifacts")
    except (OSError, ValueError) as exc:
        raise ExternalVerdictIdentityError(f"artifact path is outside the trusted root: {locator}") from exc
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ExternalVerdictIdentityError(f"cannot stat artifact: {locator}") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise ExternalVerdictIdentityError(f"artifact is not a regular file: {locator}")
    return path


def _maybe_read_artifact(root: Path | None, locator: str) -> bytes | object:
    if root is None:
        return _MISSING
    # Validate the lexical path before checking existence.  A genuinely
    # absent regular path is allowed when the caller supplies transient bytes;
    # a broken symlink or an escaping path is never silently ignored.
    _safe_locator(locator, "artifact.locator")
    path = root.joinpath(*PurePosixPath(locator).parts)
    if not path.exists() and not path.is_symlink():
        return _MISSING
    checked = _artifact_path(root, locator)
    try:
        return checked.read_bytes()
    except OSError as exc:
        raise ExternalVerdictIdentityError(f"cannot read artifact: {locator}") from exc


def _validate_text_bytes(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ExternalVerdictSchemaError(f"{label} is not valid UTF-8") from exc


def _reject_secret_bytes(value: bytes, label: str, *, text_required: bool = False) -> None:
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        if text_required:
            raise ExternalVerdictSchemaError(f"{label} is not valid UTF-8") from exc
        text = ""
    if _SECRET_TEXT.search(text):
        raise ExternalVerdictPrivacyError(f"credential-bearing bytes at {label}")


def _bind_artifacts(
    receipt: Mapping[str, Any],
    context: Mapping[str, Mapping[str, Any]],
    *,
    root: Path | None,
    source_bytes: Any,
    candidate_artifact_bytes: Any,
) -> str | None:
    source = receipt["source"]
    candidate_artifact = context["candidate"].get("artifact")
    if not isinstance(candidate_artifact, Mapping):
        raise ExternalVerdictIdentityError("Candidate artifact is missing")
    candidate_locator = _safe_locator(candidate_artifact.get("locator"), "Candidate artifact.locator")
    candidate_bytes = (
        _MISSING
        if candidate_artifact_bytes is _MISSING or candidate_artifact_bytes is None
        else _coerce_bytes(candidate_artifact_bytes, "candidate_artifact_bytes")
    )
    if candidate_bytes is _MISSING:
        candidate_bytes = _maybe_read_artifact(root, candidate_locator)
    if candidate_bytes is not _MISSING:
        _reject_secret_bytes(
            candidate_bytes,
            "candidate_artifact_bytes",
            text_required=candidate_artifact.get("media_type") in {"text/plain", "text/x-lean"},
        )
        actual_candidate = sha256_bytes(candidate_bytes)
        if actual_candidate != candidate_artifact.get("sha256"):
            raise ExternalVerdictIdentityError("Candidate artifact SHA-256 mismatch")
    status = source["retrieval_status"]
    artifact = source.get("artifact")
    locator = artifact.get("locator") if isinstance(artifact, Mapping) else None
    if status == "unavailable":
        if source_bytes is not _MISSING and source_bytes is not None:
            raise ExternalVerdictIdentityError("unavailable source cannot have source bytes")
        if source.get("content_sha256") is not None or source.get("artifact") is not None:
            raise ExternalVerdictIdentityError("unavailable source must have null digest and artifact")
        return None
    if status != "retrieved":
        raise ExternalVerdictIdentityError("unknown source retrieval status")
    if not isinstance(locator, str):
        raise ExternalVerdictIdentityError("retrieved source lacks an artifact locator")
    _safe_locator(locator, "source.artifact.locator")
    if source_bytes is _MISSING:
        source_value = _maybe_read_artifact(root, locator)
    else:
        source_value = _coerce_bytes(source_bytes, "source_bytes")
    if source_value is _MISSING or source_value is None:
        raise ExternalVerdictIdentityError("retrieved source bytes are required to recompute source_sha256")
    _reject_secret_bytes(
        source_value,
        "source_bytes",
        text_required=artifact.get("media_type") in {"text/plain", "text/x-lean"}
        if isinstance(artifact, Mapping)
        else False,
    )
    actual_source = sha256_bytes(source_value)
    if actual_source != source.get("content_sha256"):
        raise ExternalVerdictIdentityError("source content SHA-256 mismatch")
    if not isinstance(artifact, Mapping) or artifact.get("sha256") != actual_source:
        raise ExternalVerdictIdentityError("source artifact SHA-256 mismatch")
    if context["candidate"].get("kind") in {"proof", "counterexample", "formalization", "computation"} and source.get("source_kind") == "submitted_solution":
        if candidate_artifact.get("sha256") != actual_source:
            raise ExternalVerdictIdentityError("submitted source differs from Candidate artifact")
    if candidate_bytes is not _MISSING and sha256_bytes(candidate_bytes) != actual_source and source.get("source_kind") == "submitted_solution":
        raise ExternalVerdictIdentityError("submitted source bytes differ from Candidate artifact bytes")
    return actual_source


def _validate_endpoint(endpoint: Any) -> str:
    if not isinstance(endpoint, str):
        raise ExternalVerdictIdentityError("response endpoint is not a string")
    parsed = urlsplit(endpoint)
    raw_path_parts = parsed.path.split("/")
    path_parts = PurePosixPath(parsed.path).parts
    if (
        parsed.scheme != "https"
        or parsed.hostname != "prove2.me"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/api/v1")
        or any(part in {"", ".", ".."} for part in raw_path_parts[1:])
        or "." in path_parts
        or ".." in path_parts
    ):
        raise ExternalVerdictIdentityError("response endpoint is outside the exact read-only Prove2me API")
    return endpoint


def _check_response_body(
    slot: str,
    response: Mapping[str, Any],
    body: Any,
) -> None:
    provided = body is not _MISSING
    if provided:
        body_bytes = _coerce_bytes(body, f"response_bodies.{slot}")
        if body_bytes is None:
            actual = None
        else:
            actual = sha256_bytes(body_bytes)
            if response.get("media_type") == "application/json":
                # A malformed endpoint response is itself not a receipt; it
                # is rejected here rather than silently becoming a verdict.
                parsed_body = _parse_json_value(body_bytes, require_object=False)
                sensitive = _sensitive_errors(parsed_body)
                if sensitive:
                    raise ExternalVerdictPrivacyError("; ".join(sensitive))
            else:
                text_body = _validate_text_bytes(
                    body_bytes,
                    f"response_bodies.{slot}",
                ) if response.get("media_type") == "text/plain" else body_bytes.decode("utf-8", "ignore")
                if _SECRET_TEXT.search(text_body):
                    raise ExternalVerdictPrivacyError(
                        f"credential-bearing response body at responses.{slot}"
                    )
        if actual != response.get("body_sha256"):
            raise ExternalVerdictIdentityError(f"{slot} response body SHA-256 mismatch")
    elif response.get("body_sha256") is not None:
        raise ExternalVerdictIdentityError(
            f"{slot} response body is omitted, so its claimed body digest cannot be recomputed"
        )
    if response.get("response_kind") == "success" and response.get("body_sha256") is None:
        raise ExternalVerdictIdentityError(f"successful {slot} response must have a body")


def _check_known_response_identity(slot: str, parsed: Any, receipt: Mapping[str, Any]) -> None:
    if not isinstance(parsed, Mapping):
        return
    if slot in {"target", "source"}:
        expected = receipt["target"]["target_id"]
        for key in ("target_id", "theorem_id", "definition_id", "item_id"):
            if key in parsed and parsed[key] != expected:
                raise ExternalVerdictIdentityError(f"{slot} response {key} crosses target identity")
    if slot == "submission":
        expected_id = receipt["submission"]["submission_id"]
        for key in ("submission_id", "id"):
            if key in parsed and parsed[key] != expected_id:
                raise ExternalVerdictIdentityError(f"submission response {key} crosses submission identity")
        status = parsed.get("status")
        external = receipt["submission"]["external_status"]
        if isinstance(status, str) and status.upper() in {
            "PENDING", "ACCEPTED", "SKETCH_ACCEPTED", "CE", "WA", "SORRY", "FAILED", "ERROR",
        } and status.upper() != external:
            raise ExternalVerdictIdentityError("submission response status differs from receipt status")
    if slot == "environment":
        version = parsed.get("server_version", parsed.get("version"))
        if version is not None and version != receipt["platform"]["server_version"]:
            raise ExternalVerdictIdentityError("environment response version differs from platform")


def _bind_responses(
    receipt: Mapping[str, Any],
    *,
    response_bodies: Mapping[str, Any] | None,
) -> dict[str, str]:
    bodies = dict(response_bodies or {})
    unknown = set(bodies) - set(RESPONSE_SLOTS)
    if unknown:
        raise ExternalVerdictIdentityError(f"unknown response body slot: {sorted(unknown)[0]}")
    result: dict[str, str] = {}
    for slot in RESPONSE_SLOTS:
        response = receipt["responses"][slot]
        if not isinstance(response, Mapping):
            raise ExternalVerdictIdentityError(f"response slot is not an object: {slot}")
        endpoint = _validate_endpoint(response.get("endpoint"))
        if response.get("request_method") != "GET":
            raise ExternalVerdictPolicyError(f"response slot is not GET-only: {slot}")
        expected_request = canonical_request_sha256("GET", endpoint)
        if response.get("request_sha256") != expected_request:
            raise ExternalVerdictIdentityError(f"{slot} request digest mismatch")
        body = bodies.get(slot, _MISSING)
        _check_response_body(slot, response, body)
        if body is not _MISSING and body is not None and response.get("media_type") == "application/json":
            body_bytes = _coerce_bytes(body, f"response_bodies.{slot}")
            if body_bytes is not None:
                parsed = _parse_json_value(body_bytes, require_object=False)
                _check_known_response_identity(slot, parsed, receipt)
        expected_response = canonical_response_sha256(response)
        if response.get("response_sha256") != expected_response:
            raise ExternalVerdictIdentityError(f"{slot} response digest mismatch")
        result[f"{slot}_response_sha256"] = expected_response
    source_path = _safe_remote_path(receipt["source"]["remote_path"])
    source_endpoint = urlsplit(receipt["responses"]["source"]["endpoint"]).path
    if source_endpoint != "/api/v1" + source_path:
        raise ExternalVerdictIdentityError("source remote_path is not bound to source response endpoint")
    return result


def _bind_environment(receipt: Mapping[str, Any]) -> tuple[str | None, str]:
    environment = receipt["environment"]
    remote = environment["remote"]
    local = environment["local_expected"]
    remote_manifest = remote.get("manifest_sha256")
    remote_digest = None if remote_manifest is None else canonical_json_sha256(remote)
    local_digest = canonical_json_sha256(local)
    comparison = environment["comparison"]
    comparable = (
        remote.get("toolchain") == local.get("toolchain")
        and remote.get("mathlib_revision") == local.get("mathlib_revision")
        and remote_manifest is not None
        and remote_manifest == local.get("manifest_sha256")
    )
    if comparison == "match" and not comparable:
        raise ExternalVerdictIdentityError("environment claims match without matching pinned fields")
    if comparison == "mismatch" and comparable:
        raise ExternalVerdictIdentityError("environment claims mismatch although pinned fields match")
    return remote_digest, local_digest


def _normalization_input_basis(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "observation_status": receipt["observation_status"],
        "identity": receipt["identity"],
        "platform": receipt["platform"],
        "target": receipt["target"],
        "submission": receipt["submission"],
        "source": receipt["source"],
        "environment": receipt["environment"],
        "responses": receipt["responses"],
        "failure": receipt["failure"],
    }


def _observation_key_basis(receipt: Mapping[str, Any]) -> dict[str, Any]:
    identity = receipt["identity"]
    return {
        "problem_id": identity["problem_id"],
        "problem_contract_sha256": identity["problem_contract_sha256"],
        "attempt_id": identity["attempt_id"],
        "graph_id": identity["graph_id"],
        "obligation_id": identity["obligation_id"],
        "candidate_id": identity["candidate_id"],
        "route_id": identity["route_id"],
        "target_kind": receipt["target"]["target_kind"],
        "target_id": receipt["target"]["target_id"],
        "submission_id": receipt["submission"]["submission_id"],
    }


def _idempotency_basis(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": receipt["schema_version"],
        "identity": receipt["identity"],
        "platform.provider": receipt["platform"]["provider"],
        "platform.api_base": receipt["platform"]["api_base"],
        "target.target_kind": receipt["target"]["target_kind"],
        "target.target_id": receipt["target"]["target_id"],
        "submission.submission_id": receipt["submission"]["submission_id"],
        "submission.external_status": receipt["submission"]["external_status"],
        "source.content_sha256": receipt["source"]["content_sha256"],
        "environment.remote": receipt["environment"]["remote"],
        "environment.local_expected": receipt["environment"]["local_expected"],
        "response_sha256s": {
            slot: receipt["responses"][slot]["response_sha256"] for slot in RESPONSE_SLOTS
        },
    }


def _bind_digest_fields(
    receipt: Mapping[str, Any],
    local_digests: Mapping[str, str],
    source_digest: str | None,
    environment_digests: tuple[str | None, str],
    response_digests: Mapping[str, str],
) -> None:
    expected: dict[str, Any] = dict(local_digests)
    expected["source_sha256"] = source_digest
    expected["environment_remote_sha256"] = environment_digests[0]
    expected["environment_local_sha256"] = environment_digests[1]
    expected.update(response_digests)
    expected["normalization_input_sha256"] = canonical_json_sha256(_normalization_input_basis(receipt))
    observation_key = canonical_json_sha256(_observation_key_basis(receipt))
    expected["idempotency_key_sha256"] = canonical_json_sha256(_idempotency_basis(receipt))
    claimed = receipt["digests"]
    for field in _DIGEST_FIELDS:
        if claimed.get(field) != expected.get(field):
            raise ExternalVerdictIdentityError(
                f"digest mismatch for {field}: expected {expected.get(field)}, got {claimed.get(field)}"
            )
    if receipt["identity"]["problem_contract_sha256"] != local_digests["problem_contract_sha256"]:
        raise ExternalVerdictIdentityError("identity.problem_contract_sha256 drift")
    if receipt["identity"]["statement_sha256"] != local_digests["statement_sha256"]:
        raise ExternalVerdictIdentityError("identity.statement_sha256 drift")
    if receipt["target"]["statement"]["local_statement_sha256"] != local_digests["statement_sha256"]:
        raise ExternalVerdictIdentityError("target local statement binding drift")
    expected_receipt_id = "evr:v1:" + expected["idempotency_key_sha256"]
    if receipt["receipt_id"] != expected_receipt_id:
        raise ExternalVerdictIdentityError("receipt_id is not bound to idempotency_key_sha256")
    normalization = receipt["normalization"]
    if normalization["observation_key_sha256"] != observation_key:
        raise ExternalVerdictIdentityError("observation_key_sha256 mismatch")


def _bind_semantic_status(receipt: Mapping[str, Any]) -> None:
    statement = receipt["target"]["statement"]
    source = receipt["source"]
    environment = receipt["environment"]
    failure_class = receipt["failure"]["class"]
    if receipt["observation_status"] == "observed":
        if statement["retrieval_status"] != "present" or statement["comparison"] != "match":
            raise ExternalVerdictIdentityError("observed receipt lacks a matching remote statement")
        if source["retrieval_status"] != "retrieved":
            raise ExternalVerdictIdentityError("observed receipt lacks a retrieved source")
        if environment["comparison"] != "match":
            raise ExternalVerdictIdentityError("observed receipt lacks a matching environment")
        if failure_class != "none":
            raise ExternalVerdictPolicyError("observed receipt has a failure class")
    else:
        if failure_class == "none":
            raise ExternalVerdictPolicyError("blocked/quarantined receipt must remain failed/blocked")
        if receipt["admission_status"] != "unadmitted":
            raise ExternalVerdictPolicyError("blocked receipt cannot be admitted")


def normalize_external_verdict(
    receipt: Mapping[str, Any] | bytes | bytearray | str,
    *,
    project_root: Path | str | None = None,
    local_records: Mapping[str, Any] | None = None,
    problem: Mapping[str, Any] | None = None,
    attempt: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
    obligation: Mapping[str, Any] | None = None,
    candidate: Mapping[str, Any] | None = None,
    source_bytes: Any = _MISSING,
    candidate_artifact_bytes: Any = _MISSING,
    response_bodies: Mapping[str, Any] | None = None,
    schema_path: Path | str | None = None,
) -> dict[str, Any]:
    """Normalize and bind one receipt without any external side effect.

    ``local_records`` may contain ``problem``, ``attempt``, ``graph``,
    ``obligation``, and ``candidate`` mappings.  When ``project_root`` is
    supplied, omitted Problem/Attempt/Graph/Candidate records are read from
    their normal JSONL truth sources; supplied records must agree byte-for-byte
    (under canonical JSON) with those sources.

    ``source_bytes`` and ``candidate_artifact_bytes`` are transient inputs.
    For a retrieved source, source bytes are mandatory unless the trusted local
    artifact can be read from ``project_root``.  ``response_bodies`` is also
    transient; response bodies are hashed/validated and never returned.
    """
    if isinstance(receipt, Mapping):
        parsed = _as_plain_json(receipt)
    else:
        parsed = _parse_json_value(receipt, require_object=True)
    if not isinstance(parsed, dict):
        raise ExternalVerdictSchemaError("receipt must be an object")
    normalized = validate_external_verdict(parsed, schema_path=schema_path)
    root = _root(project_root)
    context = _resolve_context(
        normalized,
        project_root=root,
        local_records=local_records,
        problem=problem,
        attempt=attempt,
        graph=graph,
        obligation=obligation,
        candidate=candidate,
    )
    _validate_graph(context)
    local_digests = _bind_local_identity(normalized, context)
    source_digest = _bind_artifacts(
        normalized,
        context,
        root=root,
        source_bytes=source_bytes,
        candidate_artifact_bytes=candidate_artifact_bytes,
    )
    response_digests = _bind_responses(normalized, response_bodies=response_bodies)
    environment_digests = _bind_environment(normalized)
    _bind_digest_fields(
        normalized,
        local_digests,
        source_digest,
        environment_digests,
        response_digests,
    )
    _bind_semantic_status(normalized)
    # Canonicalize only the policy list after proving it is the exact set.  No
    # caller object is mutated, and this makes equivalent list order produce
    # the same returned receipt.
    normalized["principals"]["importer"]["forbidden_effects"] = list(FORBIDDEN_EFFECTS)
    normalized["claim_ceiling"] = "candidate_only"
    normalized["admission_status"] = "unadmitted"
    return normalized


# Explicit aliases make the capability discoverable without creating alternate
# semantics or a second protocol.
normalize_external_verdict_receipt = normalize_external_verdict
normalize_receipt = normalize_external_verdict
normalize_and_bind = normalize_external_verdict
bind_external_verdict = normalize_external_verdict
validate_external_verdict_receipt = validate_external_verdict


__all__ = [
    "EXPECTED_FORBIDDEN_EFFECTS",
    "FORBIDDEN_EFFECTS",
    "FORBIDDEN_EFFECT_SET",
    "RESPONSE_SLOTS",
    "ExternalVerdictBindingError",
    "ExternalVerdictError",
    "ExternalVerdictIdentityError",
    "ExternalVerdictNormalizationError",
    "ExternalVerdictPolicyError",
    "ExternalVerdictPrivacyError",
    "ExternalVerdictSchemaError",
    "bind_external_verdict",
    "canonical_json_bytes",
    "canonical_json_sha256",
    "canonical_request_sha256",
    "canonical_response_sha256",
    "normalize_and_bind",
    "normalize_external_verdict",
    "normalize_external_verdict_receipt",
    "normalize_receipt",
    "sha256_bytes",
    "validate_external_verdict",
    "validate_external_verdict_receipt",
]
