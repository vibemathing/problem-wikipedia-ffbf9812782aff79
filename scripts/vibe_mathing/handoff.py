"""Pure validation and normalization for cross-channel handoff envelopes.

A HandoffEnvelope is a transport/control-plane object.  It can describe a
candidate, a blocked route, or a transport failure, but this module never
appends a ledger record and never promotes an outcome to Evidence or Result.
"""
from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "1.0.0"
_HANDOFF_SCHEMA = "handoff-envelope.schema.json"
_CANDIDATE_SCHEMA = "candidate-artifact.schema.json"
_HEX64 = set("0123456789abcdef")
_PROHIBITED_UPGRADE_KEYS = frozenset(
    {
        "result_id",
        "solution_id",
        "evidence_link_id",
        "kernel_checked",
        "independent",
        "result_admission",
    }
)


class HandoffError(ValueError):
    """The envelope is invalid or cannot be safely normalized."""


class HandoffSchemaError(HandoffError):
    """The envelope does not satisfy the discriminated-union schema."""


class HandoffIdentityError(HandoffError):
    """The envelope identity does not match the local research snapshot."""


class HandoffUpgradeError(HandoffError):
    """A non-candidate outcome was incorrectly promoted to a Candidate."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON deterministically without accepting NaN or Infinity."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HandoffError("handoff value is not finite JSON") from exc


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repository_root(project_root: Path | str) -> Path:
    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise HandoffError(f"project root is not a directory: {root}")
    return root


def _schema_path(project_root: Path | None, filename: str) -> Path:
    if project_root is not None:
        candidate = project_root / "research" / "schema" / filename
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    fallback = Path(__file__).resolve().parents[2] / "research" / "schema" / filename
    if not fallback.is_file() or fallback.is_symlink():
        raise HandoffError(f"schema is missing or unsafe: {filename}")
    return fallback


def _schema_errors(value: Any, schema_path: Path) -> list[str]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffError(f"cannot load schema: {schema_path}") from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    return [
        f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in errors
    ]


def _scan_prohibited_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _PROHIBITED_UPGRADE_KEYS:
                errors.append(f"prohibited upgrade key {path}.{key}")
            errors.extend(_scan_prohibited_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_scan_prohibited_keys(child, f"{path}[{index}]"))
    return errors


def normalize_handoff(
    envelope: Mapping[str, Any],
    *,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Return a detached, schema-validated JSON copy of an envelope.

    Normalization is deliberately conservative: it does not invent identity,
    change paths, or fill missing claims.  It only makes a detached copy and
    applies the explicit schema and upgrade-key restrictions.
    """
    if not isinstance(envelope, Mapping):
        raise HandoffSchemaError("handoff envelope must be an object")
    try:
        normalized = copy.deepcopy(dict(envelope))
        canonical_json_bytes(normalized)
    except HandoffError:
        raise
    except Exception as exc:  # pragma: no cover - defensive boundary
        raise HandoffError("handoff envelope cannot be copied as JSON") from exc
    errors = _schema_errors(normalized, schema_path or _schema_path(None, _HANDOFF_SCHEMA))
    errors.extend(_scan_prohibited_keys(normalized))
    if errors:
        raise HandoffSchemaError("; ".join(errors))
    return normalized


def _read_jsonl(project_root: Path, relative_path: str) -> list[dict[str, Any]]:
    path = project_root / relative_path
    if path.is_symlink():
        raise HandoffIdentityError(f"record source must not be a symlink: {relative_path}")
    if not path.exists():
        return []
    if not path.is_file():
        raise HandoffIdentityError(f"record source must be a regular file: {relative_path}")
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise HandoffIdentityError(f"cannot read record source: {relative_path}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HandoffIdentityError(f"invalid JSON at {relative_path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise HandoffIdentityError(f"record at {relative_path}:{line_number} is not an object")
        records.append(value)
    return records


def _find_record(records: list[dict[str, Any]], key: str, value: str, label: str) -> dict[str, Any]:
    matches = [record for record in records if record.get(key) == value]
    if not matches:
        raise HandoffIdentityError(f"{label} not found: {value}")
    if len(matches) != 1:
        raise HandoffIdentityError(f"{label} is not unique: {value}")
    return matches[0]


def _require_hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HEX64 for char in value):
        raise HandoffIdentityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_fingerprint_status(producer: Mapping[str, Any]) -> None:
    for name in ("tool", "model", "environment"):
        item = producer[name]
        if item["fingerprint_status"] == "verified" and not item.get("fingerprint"):
            raise HandoffIdentityError(f"verified {name} fingerprint cannot be empty")


def _validate_identity(project_root: Path, envelope: Mapping[str, Any]) -> dict[str, Any]:
    problem_id = envelope["problem_id"]
    attempt_id = envelope["attempt_id"]
    graph_id = envelope["graph_id"]
    obligation_id = envelope["obligation_id"]
    contract_digest = _require_hex64(
        envelope["problem_contract_sha256"], "problem_contract_sha256"
    )

    problems = _read_jsonl(project_root, "problem-library/records/canonical-problems.jsonl")
    problem = _find_record(problems, "problem_id", problem_id, "ProblemContract")
    actual_contract_digest = canonical_json_sha256(problem)
    if actual_contract_digest != contract_digest:
        raise HandoffIdentityError(
            f"ProblemContract digest mismatch: expected {actual_contract_digest}, got {contract_digest}"
        )

    attempts = _read_jsonl(project_root, "research/records/attempts.jsonl")
    attempt = _find_record(attempts, "attempt_id", attempt_id, "Attempt")
    expected_attempt_fields = {
        "problem_id": problem_id,
        "route_id": envelope["route_id"],
        "obligation_graph_id": graph_id,
    }
    for field, expected in expected_attempt_fields.items():
        if attempt.get(field) != expected:
            raise HandoffIdentityError(
                f"Attempt {field} drift: expected {expected}, got {attempt.get(field)}"
            )
    if attempt.get("problem_contract_sha256") != contract_digest:
        raise HandoffIdentityError("Attempt problem_contract_sha256 drift")

    graphs = _read_jsonl(project_root, "research/records/obligation-graphs.jsonl")
    graph = _find_record(graphs, "graph_id", graph_id, "ObligationGraph")
    expected_graph_fields = {
        "problem_id": problem_id,
        "attempt_id": attempt_id,
        "route_id": envelope["route_id"],
        "problem_contract_sha256": contract_digest,
    }
    for field, expected in expected_graph_fields.items():
        if graph.get(field) != expected:
            raise HandoffIdentityError(
                f"ObligationGraph {field} drift: expected {expected}, got {graph.get(field)}"
            )

    obligations = graph.get("obligations")
    if not isinstance(obligations, list):
        raise HandoffIdentityError("ObligationGraph obligations must be an array")
    obligation = _find_record(obligations, "obligation_id", obligation_id, "Obligation")
    statement = obligation.get("statement")
    if not isinstance(statement, dict):
        raise HandoffIdentityError(f"Obligation statement must be an object: {obligation_id}")
    statement_digest = _require_hex64(
        obligation.get("statement_sha256"), f"{obligation_id}.statement_sha256"
    )
    if canonical_json_sha256(statement) != statement_digest:
        raise HandoffIdentityError(f"Obligation statement digest is invalid: {obligation_id}")
    if envelope["outcome"] == "candidate":
        candidate_digest = envelope["candidate"]["statement_sha256"]
        if candidate_digest != statement_digest:
            raise HandoffIdentityError(
                f"candidate statement_sha256 drift: expected {statement_digest}, got {candidate_digest}"
            )
    _validate_fingerprint_status(envelope["producer"])
    return {
        "problem": problem,
        "attempt": attempt,
        "graph": graph,
        "obligation": obligation,
        "statement_sha256": statement_digest,
    }


def _trusted_artifact(project_root: Path, locator: str) -> Path:
    if not isinstance(locator, str) or not locator:
        raise HandoffError("artifact locator must be a non-empty string")
    pure = PurePosixPath(locator)
    if (
        pure.is_absolute()
        or not pure.parts
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in locator
        or pure.parts[:2] != ("research", "artifacts")
    ):
        raise HandoffError(f"artifact locator must be a canonical research/artifacts path: {locator}")

    lexical = project_root
    for part in pure.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise HandoffError(f"artifact path cannot traverse a symlink: {locator}")
    path = project_root.joinpath(*pure.parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise HandoffError(f"artifact does not exist: {locator}") from exc
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise HandoffError(f"artifact escapes project root: {locator}") from exc
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise HandoffError(f"cannot stat artifact: {locator}") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise HandoffError(f"artifact must be a regular non-symlink file: {locator}")
    return path


def _validate_candidate_artifact(project_root: Path, envelope: Mapping[str, Any]) -> None:
    artifact = envelope["artifact"]
    path = _trusted_artifact(project_root, artifact["locator"])
    declared = _require_hex64(artifact["sha256"], "artifact.sha256")
    actual = sha256_file(path)
    if actual != declared:
        raise HandoffError(
            f"artifact SHA-256 mismatch for {artifact['locator']}: expected {declared}, got {actual}"
        )


def validate_handoff(project_root: Path | str, envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached HandoffEnvelope snapshot.

    This function reads only the supplied project snapshot.  It never creates
    directories, writes JSONL, appends events, or mutates the input object.
    """
    root = _repository_root(project_root)
    normalized = normalize_handoff(
        envelope,
        schema_path=_schema_path(root, _HANDOFF_SCHEMA),
    )
    context = _validate_identity(root, normalized)
    obligation = context["obligation"]
    if normalized["outcome"] == "candidate":
        if normalized["candidate"]["kind"] not in obligation.get("acceptance", {}).get(
            "allowed_candidate_kinds", []
        ):
            raise HandoffError(
                f"candidate kind is not allowed by Obligation: {normalized['candidate']['kind']}"
            )
        _validate_candidate_artifact(root, normalized)
    return normalized


def candidate_proposal(project_root: Path | str, envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return an immutable CandidateArtifact proposal for a candidate outcome.

    A proposal is only an in-memory, schema-validated object.  Blocked and
    transport_failure envelopes are explicitly refused and cannot be upgraded.
    """
    root = _repository_root(project_root)
    normalized = normalize_handoff(
        envelope,
        schema_path=_schema_path(root, _HANDOFF_SCHEMA),
    )
    if normalized["outcome"] != "candidate":
        raise HandoffUpgradeError(
            f"only outcome=candidate can produce a Candidate proposal; got {normalized['outcome']}"
        )
    normalized = validate_handoff(root, normalized)
    proposal = {
        "schema_version": "1.0.0",
        "candidate_id": normalized["candidate"]["candidate_id"],
        "graph_id": normalized["graph_id"],
        "obligation_id": normalized["obligation_id"],
        "problem_id": normalized["problem_id"],
        "attempt_id": normalized["attempt_id"],
        "statement_sha256": normalized["candidate"]["statement_sha256"],
        "kind": normalized["candidate"]["kind"],
        "generator": normalized["candidate"]["generator"],
        "artifact": copy.deepcopy(normalized["artifact"]),
        "source_refs": list(normalized.get("source_refs", [])),
        "created_at": normalized["created_at"],
    }
    errors = _schema_errors(
        proposal,
        _schema_path(root, _CANDIDATE_SCHEMA),
    )
    if errors:
        raise HandoffError("Candidate proposal schema invalid: " + "; ".join(errors))
    return proposal


__all__ = [
    "HandoffError",
    "HandoffIdentityError",
    "HandoffSchemaError",
    "HandoffUpgradeError",
    "candidate_proposal",
    "canonical_json_sha256",
    "normalize_handoff",
    "sha256_file",
    "validate_handoff",
]
