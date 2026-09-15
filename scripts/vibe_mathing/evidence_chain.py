"""Candidate lineage replay and fail-closed Evidence admission projection.

This module deliberately keeps the four research truth layers separate:

    CandidateArtifact -> EvidenceLink/receipt -> admission decision

Lineage events are append-only relations over already-created immutable
objects.  Replaying them changes only a derived view; it never rewrites a
Candidate, an EvidenceLink, a receipt, a Result, or a Solution View.

The canonical event shape is::

    {
        "event_type": "supersedes|retracts|invalidates",
        "source": {"kind": "candidate|evidence_link", "id": "..."},
        "target": {"kind": "candidate|evidence_link", "id": "..."},
        ...
    }

``supersedes`` is candidate -> candidate and makes the target stale;
``retracts`` can target either kind; ``invalidates`` is candidate -> candidate
or evidence-link -> evidence-link.  The module also accepts a small set of
legacy flat field spellings and normalizes them before schema validation, but
all returned and appended events use the nested canonical shape.

No function in this module creates a Result or a Solution View.  The only
positive decision it emits is ``admit_evidence``.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .evidence import (
    ADMITTED_CAPABILITIES,
    EvidenceError,
    load_verifier_registry,
    read_obligation_receipt_capability,
    reject_legacy_capability,
    sha256_file,
    verify_obligation_evidence_receipt,
)

SCHEMA_VERSION = "1.0.0"
MAX_RECORD_BYTES = 2 * 1024 * 1024

CANDIDATE_RECORDS = Path("research/records/candidate-artifacts.jsonl")
EVIDENCE_LINK_RECORDS = Path("research/records/evidence-links.jsonl")
LINEAGE_EVENT_RECORDS = Path("research/records/candidate-lineage-events.jsonl")
LINEAGE_RECORDS = LINEAGE_EVENT_RECORDS
CANDIDATE_LINEAGE_RECORDS = LINEAGE_EVENT_RECORDS
# A short-lived spelling used by a few early local fixtures.  If both files
# exist, replay refuses to guess which is authoritative.
LEGACY_LINEAGE_EVENT_RECORDS = Path("research/records/candidate-lineage.jsonl")
GRAPH_RECORDS = Path("research/records/obligation-graphs.jsonl")


class EvidenceChainError(RuntimeError):
    """A malformed or unsafe Candidate/Evidence lineage input."""


class LineageCorruption(EvidenceChainError):
    """The append-only log is truncated, malformed, or has unsafe bytes."""


class LineageConflict(EvidenceChainError):
    """Two immutable records or lineage relations have incompatible content."""


class EvidenceAdmissionError(EvidenceChainError):
    """An admission projection could not be safely derived."""


# Friendly aliases used by callers that name the aggregate rather than the
# particular failure class.
EvidenceChainConflict = LineageConflict
AdmissionConflict = LineageConflict
LineageError = EvidenceChainError


def canonical_json_sha256(value: Any) -> str:
    """Hash finite canonical JSON, independent of object key order."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceChainError("lineage value 必须是有限 JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _root(project_root: Path | str | None) -> Path:
    if project_root is None:
        # scripts/vibe_mathing/evidence_chain.py -> repository root
        return Path(__file__).resolve().parents[2]
    result = Path(project_root).expanduser().resolve()
    if not result.is_dir():
        raise EvidenceChainError(f"project root 不是目录：{result}")
    return result


def _schema_path(project_root: Path, name: str) -> Path:
    preferred = project_root / "research" / "schema" / name
    if preferred.exists() or preferred.is_symlink():
        if preferred.is_symlink() or not preferred.is_file():
            raise EvidenceChainError(f"schema 必须是 regular file：{preferred}")
        return preferred
    fallback = Path(__file__).resolve().parents[2] / "research" / "schema" / name
    if fallback.is_symlink() or not fallback.is_file():
        raise EvidenceChainError(f"schema 缺失：{name}")
    return fallback


def _validate_schema(
    project_root: Path,
    name: str,
    value: Mapping[str, Any],
    label: str,
) -> None:
    path = _schema_path(project_root, name)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceChainError(f"无法读取 {label} schema：{path}") from exc
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:  # jsonschema exposes several schema error classes
        raise EvidenceChainError(f"{label} schema 本身无效：{path}") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: [str(item) for item in error.path],
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].path) or "<root>"
        raise EvidenceChainError(f"{label} schema 无效 ({location})：{errors[0].message}")


def _ensure_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LineageCorruption(f"{label} 必须是 JSON object")
    return dict(value)


def _record_id(record: Mapping[str, Any], id_field: str, label: str) -> str:
    identity = record.get(id_field)
    if not isinstance(identity, str) or not identity:
        raise LineageCorruption(f"{label} 缺少 {id_field}")
    return identity


def _dedupe_records(
    records: Iterable[Mapping[str, Any]],
    *,
    id_field: str,
    label: str,
    project_root: Path,
    schema_name: str,
) -> list[dict[str, Any]]:
    """Validate records and collapse only byte/content-equivalent duplicate IDs."""

    result: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for number, raw in enumerate(records, 1):
        value = _ensure_object(raw, f"{label} 第 {number} 条")
        _validate_schema(project_root, schema_name, value, label)
        identity = _record_id(value, id_field, label)
        digest = canonical_json_sha256(value)
        previous = seen.get(identity)
        if previous is not None:
            if previous != digest:
                raise LineageConflict(f"{label} {id_field} 重复且内容不同：{identity}")
            # Same immutable record may have been replayed by an idempotent
            # writer.  It contributes no second semantic event/object.
            continue
        seen[identity] = digest
        result.append(value)
    return result


def _strict_jsonl(
    path: Path,
    *,
    label: str,
    project_root: Path,
    schema_name: str,
    id_field: str,
    normalizer: Any | None = None,
) -> list[dict[str, Any]]:
    """Read a JSONL ledger without accepting a partial final record."""

    if path.is_symlink():
        raise LineageCorruption(f"{label} 不能是符号链接：{path}")
    if not path.exists():
        return []
    if not path.is_file():
        raise LineageCorruption(f"{label} 必须是 regular file：{path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LineageCorruption(f"无法读取 {label}：{path}") from exc
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise LineageCorruption(f"{label} 末行截断，拒绝继续：{path}")

    values: list[dict[str, Any]] = []
    # The final empty item is the required post-record newline, not a blank
    # record.  Any other empty line is rejected rather than silently skipped.
    for number, line in enumerate(raw.split(b"\n")[:-1], 1):
        if not line.strip():
            raise LineageCorruption(f"{label} 第 {number} 行为空")
        if len(line) > MAX_RECORD_BYTES:
            raise LineageCorruption(f"{label} 第 {number} 行超过 2 MiB")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LineageCorruption(f"{label} 第 {number} 行 JSON 无效") from exc
        if not isinstance(value, Mapping):
            raise LineageCorruption(f"{label} 第 {number} 行不是 object")
        values.append(normalizer(value) if normalizer is not None else dict(value))
    return _dedupe_records(
        values,
        id_field=id_field,
        label=label,
        project_root=project_root,
        schema_name=schema_name,
    )


def _confined_path(project_root: Path, value: Path | str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = project_root / path
    try:
        path.resolve(strict=False).relative_to(project_root)
    except ValueError as exc:
        raise EvidenceChainError(f"ledger path 逃逸 project root：{path}") from exc
    return path


def _records_from_input(
    values: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None,
    *,
    path: Path,
    label: str,
    project_root: Path,
    schema_name: str,
    id_field: str,
    normalizer: Any | None = None,
) -> list[dict[str, Any]]:
    path = _confined_path(project_root, path)
    if values is None:
        return _strict_jsonl(
            path,
            label=label,
            project_root=project_root,
            schema_name=schema_name,
            id_field=id_field,
            normalizer=normalizer,
        )
    if isinstance(values, Mapping):
        # A record has its ID field; otherwise accept an ID -> record mapping
        # as a convenient read-only projection input.
        values = [values] if id_field in values else list(values.values())
    if normalizer is not None:
        values = [normalizer(value) for value in values]
    return _dedupe_records(
        values,
        id_field=id_field,
        label=label,
        project_root=project_root,
        schema_name=schema_name,
    )


def _coalesce(raw: Mapping[str, Any], names: Sequence[str], label: str) -> Any:
    present = [raw[name] for name in names if name in raw and raw[name] is not None]
    if not present:
        return None
    first = present[0]
    if any(value != first for value in present[1:]):
        raise LineageConflict(f"lineage {label} aliases 内容冲突")
    return first


def _infer_kind(identity: Any) -> str | None:
    if not isinstance(identity, str):
        return None
    if identity.startswith("candidate:"):
        return "candidate"
    if identity.startswith("evidence-link:"):
        return "evidence_link"
    return None


def _node(value: Any, *, fallback_kind: str | None = None, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        unknown = set(value) - {
            "id",
            "identity",
            "candidate_id",
            "evidence_link_id",
            "kind",
            "type",
        }
        if unknown:
            raise LineageCorruption(f"lineage {label} 含未知字段：{min(unknown)}")
        identity_values = [
            value[name]
            for name in ("id", "identity", "candidate_id", "evidence_link_id")
            if name in value and value[name] is not None
        ]
        if not identity_values:
            identity = None
        else:
            identity = identity_values[0]
            if any(item != identity for item in identity_values[1:]):
                raise LineageConflict(f"lineage {label} id aliases 内容冲突")
        kind = value.get("kind", value.get("type"))
    else:
        identity = value
        kind = fallback_kind
    if kind == "evidence-link":
        kind = "evidence_link"
    if kind is None:
        kind = _infer_kind(identity)
    if kind not in {"candidate", "evidence_link"}:
        raise LineageCorruption(f"lineage {label} kind 无效")
    if not isinstance(identity, str):
        raise LineageCorruption(f"lineage {label} id 无效")
    expected = "candidate:" if kind == "candidate" else "evidence-link:"
    if not identity.startswith(expected) or len(identity) == len(expected):
        raise LineageCorruption(f"lineage {label} id 与 kind 不一致")
    return {"kind": kind, "id": identity}


def normalize_lineage_event(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical nested event shape.

    Canonical events are returned untouched (schema validation rejects unknown
    fields).  The flat aliases are intentionally conservative: conflicting
    aliases are rejected instead of choosing one silently.
    """

    value = _ensure_object(raw, "lineage event")
    if "source" in value or "target" in value:
        canonical = dict(value)
        if "source" in value:
            canonical["source"] = _node(
                value["source"],
                fallback_kind=_coalesce(value, ("source_kind", "source_type"), "source_kind"),
                label="source",
            )
        if "target" in value:
            canonical["target"] = _node(
                value["target"],
                fallback_kind=_coalesce(value, ("target_kind", "target_type"), "target_kind"),
                label="target",
            )
        return canonical

    event_type = _coalesce(value, ("event_type", "relation", "action", "type"), "event_type")
    if event_type == "supersession":
        event_type = "supersedes"
    if event_type == "retraction":
        event_type = "retracts"
    if event_type == "invalidation":
        event_type = "invalidates"
    if not isinstance(event_type, str):
        raise LineageCorruption("lineage event 缺少 event_type")

    event_id = _coalesce(value, ("event_id", "lineage_event_id"), "event_id")
    source_raw: Any = _coalesce(
        value,
        ("source", "subject", "source_node"),
        "source",
    )
    target_raw: Any = _coalesce(
        value,
        ("target", "target_node"),
        "target",
    )
    source_kind = _coalesce(value, ("source_kind", "source_type", "subject_kind"), "source_kind")
    target_kind = _coalesce(value, ("target_kind", "target_type"), "target_kind")

    if source_raw is None:
        if event_type == "supersedes":
            source_raw = _coalesce(
                value,
                ("successor_candidate_id", "replacement_candidate_id", "new_candidate_id", "candidate_id", "source_id"),
                "successor",
            )
            source_kind = source_kind or "candidate"
        elif event_type == "invalidates":
            source_raw = _coalesce(
                value,
                ("invalidator_id", "invalidating_id", "source_id", "evidence_link_id", "candidate_id"),
                "invalidator",
            )
            if source_kind is None:
                source_kind = _infer_kind(source_raw)
        else:
            # In the flat form candidate_id is normally the relation source;
            # a target-only retraction can instead name its actor explicitly.
            source_names = ("actor_id", "source_id", "caused_by_id", "candidate_id")
            if event_type == "retracts" and not any(
                name in value and value[name] is not None
                for name in ("retracted_id", "target_id", "retracts")
            ):
                # Here candidate_id is the target, so a relation source is
                # mandatory rather than being silently made self-referential.
                source_names = ("actor_id", "source_id", "caused_by_id")
            source_raw = _coalesce(value, source_names, "source")
            if source_kind is None:
                source_kind = _infer_kind(source_raw)

    if target_raw is None:
        if event_type == "supersedes":
            target_raw = _coalesce(
                value,
                ("predecessor_candidate_id", "previous_candidate_id", "old_candidate_id", "superseded_candidate_id", "target_id", "supersedes"),
                "predecessor",
            )
            target_kind = target_kind or "candidate"
        elif event_type == "invalidates":
            target_raw = _coalesce(
                value,
                ("invalidated_id", "invalidated_link_id", "target_id", "invalidates"),
                "invalidated",
            )
            if isinstance(target_raw, list):
                if len(target_raw) != 1:
                    raise LineageCorruption("一个 lineage event 只能指向一个 target")
                target_raw = target_raw[0]
            if target_kind is None:
                target_kind = _infer_kind(target_raw)
        else:
            target_raw = _coalesce(value, ("retracted_id", "target_id", "retracts"), "retracted")
            if target_raw is None:
                target_raw = value.get("candidate_id")
            if isinstance(target_raw, list):
                if len(target_raw) != 1:
                    raise LineageCorruption("一个 lineage event 只能指向一个 target")
                target_raw = target_raw[0]
            if target_kind is None:
                target_kind = _infer_kind(target_raw)

    result: dict[str, Any] = {
        "schema_version": value.get("schema_version", SCHEMA_VERSION),
        "event_id": event_id,
        "event_type": event_type,
        "graph_id": value.get("graph_id"),
        "problem_id": value.get("problem_id"),
        "attempt_id": value.get("attempt_id"),
        "obligation_id": value.get("obligation_id"),
        "source": _node(source_raw, fallback_kind=source_kind, label="source"),
        "target": _node(target_raw, fallback_kind=target_kind, label="target"),
        "reason": value.get("reason", value.get("rationale")),
        "created_at": value.get("created_at", value.get("recorded_at")),
    }
    if "sequence" in value:
        result["sequence"] = value["sequence"]
    if "source_refs" in value:
        result["source_refs"] = value["source_refs"]
    return result


def _load_lineage_path(project_root: Path) -> Path:
    paths = [project_root / LINEAGE_EVENT_RECORDS, project_root / LEGACY_LINEAGE_EVENT_RECORDS]
    existing = [path for path in paths if path.exists() or path.is_symlink()]
    if len(existing) > 1:
        raise LineageConflict("candidate lineage 同时存在两个 ledger，拒绝猜测真相源")
    return existing[0] if existing else paths[0]


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise LineageCorruption(f"{label} 必须是带时区 ISO 8601 时间")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LineageCorruption(f"{label} 无效") from exc
    if parsed.tzinfo is None:
        raise LineageCorruption(f"{label} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def _candidate_context(candidate: Mapping[str, Any]) -> dict[str, str]:
    return {
        key: candidate[key]
        for key in ("graph_id", "problem_id", "attempt_id", "obligation_id")
    }


def _link_context(
    link: Mapping[str, Any], candidates: Mapping[str, Mapping[str, Any]]
) -> dict[str, str]:
    candidate_id = link.get("candidate_id")
    candidate = candidates.get(candidate_id)
    if candidate is None:
        raise LineageCorruption(f"EvidenceLink 引用未知 Candidate：{candidate_id}")
    context = _candidate_context(candidate)
    if link.get("graph_id") != context["graph_id"] or link.get("obligation_id") != context["obligation_id"]:
        raise LineageCorruption(f"EvidenceLink 与 Candidate 身份不一致：{link.get('evidence_link_id')}")
    return context


def _resolve_node(
    node: Mapping[str, Any],
    candidates: Mapping[str, Mapping[str, Any]],
    links: Mapping[str, Mapping[str, Any]],
) -> tuple[Mapping[str, Any], dict[str, str], datetime]:
    kind = node["kind"]
    identity = node["id"]
    if kind == "candidate":
        value = candidates.get(identity)
        if value is None:
            raise LineageCorruption(f"lineage 引用未知 Candidate：{identity}")
        return value, _candidate_context(value), _timestamp(value["created_at"], f"Candidate {identity}.created_at")
    value = links.get(identity)
    if value is None:
        raise LineageCorruption(f"lineage 引用未知 EvidenceLink：{identity}")
    context = _link_context(value, candidates)
    return value, context, _timestamp(value["linked_at"], f"EvidenceLink {identity}.linked_at")


def _validate_link_references(
    links: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Mapping[str, Any]],
) -> None:
    """Validate EvidenceLink's own append-only invalidation list."""

    seen: dict[str, Mapping[str, Any]] = {}
    for link in links:
        identity = link["evidence_link_id"]
        _link_context(link, candidates)
        for old_id in link.get("invalidates", []):
            old = seen.get(old_id)
            if old is None:
                raise LineageCorruption(
                    f"EvidenceLink invalidates 必须引用更早 link：{identity} -> {old_id}"
                )
            if old["candidate_id"] != link["candidate_id"]:
                raise LineageCorruption("EvidenceLink invalidates 不得跨 Candidate")
        seen[identity] = link


def _project_lineage(
    *,
    project_root: Path,
    candidates: list[dict[str, Any]],
    links: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_by_id = {item["candidate_id"]: item for item in candidates}
    link_by_id = {item["evidence_link_id"]: item for item in links}
    _validate_link_references(links, candidate_by_id)

    candidate_states: dict[str, dict[str, Any]] = {
        identity: {
            "candidate_id": identity,
            **_candidate_context(candidate),
            "status": "current",
            "superseded_by": None,
            "supersedes": [],
            "retracted_by": [],
            "invalidated_by": [],
        }
        for identity, candidate in candidate_by_id.items()
    }
    link_states: dict[str, dict[str, Any]] = {
        identity: {
            "evidence_link_id": identity,
            "candidate_id": link["candidate_id"],
            "graph_id": link["graph_id"],
            "obligation_id": link["obligation_id"],
            "status": "current",
            "retracted_by": [],
            "invalidated_by": [],
        }
        for identity, link in link_by_id.items()
    }

    successor_by_predecessor: dict[str, str] = {}
    predecessor_by_successor: dict[str, str] = {}
    supersede_event_ids: dict[tuple[str, str], list[str]] = {}
    retracted_candidates: dict[str, list[str]] = {}
    invalidated_candidates: dict[str, list[str]] = {}
    retracted_links: dict[str, list[str]] = {}
    invalidated_links: dict[str, list[str]] = {}
    action_edges: dict[str, dict[tuple[str, str], set[tuple[str, str]]]] = {
        "retracts": {},
        "invalidates": {},
    }

    for event in events:
        source_node = event["source"]
        target_node = event["target"]
        _source, source_context, source_time = _resolve_node(source_node, candidate_by_id, link_by_id)
        _target, target_context, target_time = _resolve_node(target_node, candidate_by_id, link_by_id)
        event_context = {
            key: event[key]
            for key in ("graph_id", "problem_id", "attempt_id", "obligation_id")
        }
        if source_context != event_context or target_context != event_context:
            raise LineageCorruption(
                f"lineage event {event['event_id']} 跨 Problem/Attempt/Obligation 或 graph"
            )
        event_time = _timestamp(event["created_at"], f"lineage event {event['event_id']}.created_at")
        if event_time < source_time or event_time < target_time:
            raise LineageCorruption(
                f"lineage event {event['event_id']} 引用了尚未创建的对象"
            )
        if source_node == target_node:
            raise LineageConflict(f"lineage event {event['event_id']} 不能引用自身")

        event_type = event["event_type"]
        event_id = event["event_id"]
        if event_type == "supersedes":
            if source_node["kind"] != "candidate" or target_node["kind"] != "candidate":
                raise LineageCorruption("supersedes 必须是 Candidate -> Candidate")
            successor = source_node["id"]
            predecessor = target_node["id"]
            if source_time < target_time:
                raise LineageCorruption(
                    f"supersedes 的 successor 必须不早于 predecessor：{event_id}"
                )
            old_successor = successor_by_predecessor.get(predecessor)
            if old_successor is not None and old_successor != successor:
                raise LineageConflict(
                    f"Candidate supersession 分叉：{predecessor} -> {old_successor} / {successor}"
                )
            old_predecessor = predecessor_by_successor.get(successor)
            if old_predecessor is not None and old_predecessor != predecessor:
                raise LineageConflict(
                    f"Candidate successor 有多个 predecessor：{successor}"
                )
            # successor_by_predecessor is old -> new.  If following new's
            # forward chain reaches old, this edge closes a cycle.
            cursor = successor
            visited: set[str] = set()
            while cursor in successor_by_predecessor:
                if cursor in visited:
                    raise LineageConflict("Candidate supersession graph 已含循环")
                visited.add(cursor)
                cursor = successor_by_predecessor[cursor]
                if cursor == predecessor:
                    raise LineageConflict(f"Candidate supersession 含循环：{event_id}")
            successor_by_predecessor[predecessor] = successor
            predecessor_by_successor[successor] = predecessor
            supersede_event_ids.setdefault((predecessor, successor), []).append(event_id)
            candidate_states[predecessor]["superseded_by"] = successor
            candidate_states[successor]["supersedes"].append(predecessor)
        elif event_type == "retracts":
            source_key = (source_node["kind"], source_node["id"])
            target_key = (target_node["kind"], target_node["id"])
            edges = action_edges["retracts"]
            # Retraction is an action relation too: reciprocal actions form a
            # cycle rather than a second source of truth.
            stack = [target_key]
            reached: set[tuple[str, str]] = set()
            while stack:
                cursor = stack.pop()
                if cursor == source_key:
                    raise LineageConflict(f"retracts lineage 含循环：{event_id}")
                if cursor in reached:
                    continue
                reached.add(cursor)
                stack.extend(edges.get(cursor, set()))
            edges.setdefault(source_key, set()).add(target_key)
            if target_node["kind"] == "candidate":
                retracted_candidates.setdefault(target_node["id"], []).append(event_id)
                candidate_states[target_node["id"]]["retracted_by"].append(event_id)
            else:
                retracted_links.setdefault(target_node["id"], []).append(event_id)
                link_states[target_node["id"]]["retracted_by"].append(event_id)
        elif event_type == "invalidates":
            if source_node["kind"] != target_node["kind"]:
                raise LineageCorruption(
                    "invalidates 必须保持 Candidate 或 EvidenceLink 类型一致"
                )
            source_key = (source_node["kind"], source_node["id"])
            target_key = (target_node["kind"], target_node["id"])
            edges = action_edges["invalidates"]
            stack = [target_key]
            reached: set[tuple[str, str]] = set()
            while stack:
                cursor = stack.pop()
                if cursor == source_key:
                    raise LineageConflict(f"invalidates lineage 含循环：{event_id}")
                if cursor in reached:
                    continue
                reached.add(cursor)
                stack.extend(edges.get(cursor, set()))
            edges.setdefault(source_key, set()).add(target_key)
            if target_node["kind"] == "candidate":
                invalidated_candidates.setdefault(target_node["id"], []).append(event_id)
                candidate_states[target_node["id"]]["invalidated_by"].append(event_id)
            else:
                invalidated_links.setdefault(target_node["id"], []).append(event_id)
                link_states[target_node["id"]]["invalidated_by"].append(event_id)
        else:  # schema normally catches this; retain fail-closed defense.
            raise LineageCorruption(f"未知 lineage event_type：{event_type}")

    for state in candidate_states.values():
        if state["invalidated_by"]:
            state["status"] = "invalidated"
        elif state["retracted_by"]:
            state["status"] = "retracted"
        elif state["superseded_by"] is not None:
            state["status"] = "stale"
        state["supersedes"] = sorted(state["supersedes"])
        state["retracted_by"] = sorted(state["retracted_by"])
        state["invalidated_by"] = sorted(state["invalidated_by"])

    for state in link_states.values():
        candidate_status = candidate_states[state["candidate_id"]]["status"]
        if state["invalidated_by"] or candidate_status == "invalidated":
            state["status"] = "invalidated"
        elif state["retracted_by"] or candidate_status == "retracted":
            state["status"] = "retracted"
        elif candidate_status == "stale":
            state["status"] = "stale"
        state["retracted_by"] = sorted(state["retracted_by"])
        state["invalidated_by"] = sorted(state["invalidated_by"])

    candidate_states_ordered = {
        identity: candidate_states[identity] for identity in sorted(candidate_states)
    }
    link_states_ordered = {identity: link_states[identity] for identity in sorted(link_states)}
    projection: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "events": events,
        # ``candidate_states``/``evidence_link_states`` are the canonical
        # names.  The shorter aliases make the derived object convenient for
        # callers that already use the ledger collection names.
        "candidate_states": candidate_states_ordered,
        "evidence_link_states": link_states_ordered,
        "candidates": candidate_states_ordered,
        "evidence_links": link_states_ordered,
        "current_candidate_ids": sorted(
            identity for identity, state in candidate_states.items() if state["status"] == "current"
        ),
        "stale_candidate_ids": sorted(
            identity for identity, state in candidate_states.items() if state["status"] == "stale"
        ),
        "retracted_candidate_ids": sorted(
            identity for identity, state in candidate_states.items() if state["status"] == "retracted"
        ),
        "invalidated_candidate_ids": sorted(
            identity for identity, state in candidate_states.items() if state["status"] == "invalidated"
        ),
        "current_evidence_link_ids": sorted(
            identity for identity, state in link_states.items() if state["status"] == "current"
        ),
        "stale_evidence_link_ids": sorted(
            identity for identity, state in link_states.items() if state["status"] == "stale"
        ),
        "retracted_evidence_link_ids": sorted(
            identity for identity, state in link_states.items() if state["status"] == "retracted"
        ),
        "invalidated_evidence_link_ids": sorted(
            identity for identity, state in link_states.items() if state["status"] == "invalidated"
        ),
        "supersession_edges": [
            {
                "predecessor_candidate_id": predecessor,
                "successor_candidate_id": successor,
                "event_ids": sorted(supersede_event_ids[(predecessor, successor)]),
            }
            for predecessor, successor in sorted(successor_by_predecessor.items())
        ],
        "retraction_event_ids": sorted(
            event_id
            for values in [*retracted_candidates.values(), *retracted_links.values()]
            for event_id in values
        ),
        "invalidation_event_ids": sorted(
            event_id
            for values in [*invalidated_candidates.values(), *invalidated_links.values()]
            for event_id in values
        ),
    }
    projection["lineage_sha256"] = canonical_json_sha256(projection)
    return projection


def replay_lineage(
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | Path | str | None = None,
    evidence_links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage_events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    *,
    events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
    candidate_records_path: Path | str | None = None,
    evidence_link_records_path: Path | str | None = None,
    lineage_records_path: Path | str | None = None,
) -> dict[str, Any]:
    """Validate and deterministically replay Candidate lineage.

    All three collections may be supplied directly for isolated tests.  If a
    collection is omitted, its JSONL ledger is read strictly.  A duplicate ID
    with canonical-equivalent content is idempotent; a duplicate ID with any
    content difference is a hard conflict.
    """

    # ``replay_lineage(root, events=...)`` is also accepted.  A path cannot
    # be a valid Candidate collection, so treating it as the project root is
    # unambiguous here.
    if isinstance(candidates, (Path, str)) and project_root is None:
        project_root = candidates
        candidates = None

    root = _root(project_root)
    if links is not None:
        if evidence_links is not None:
            raise LineageConflict("evidence_links 与 links 同时提供")
        evidence_links = links
    if lineage is not None:
        if lineage_events is not None or events is not None:
            raise LineageConflict("lineage_events/events 与 lineage 同时提供")
        lineage_events = lineage
    if events is not None:
        if lineage_events is not None:
            raise LineageConflict("lineage_events 与 events 同时提供")
        lineage_events = events

    candidate_path = (
        root / CANDIDATE_RECORDS
        if candidate_records_path is None
        else Path(candidate_records_path)
    )
    link_path = (
        root / EVIDENCE_LINK_RECORDS
        if evidence_link_records_path is None
        else Path(evidence_link_records_path)
    )
    if lineage_records_path is None:
        lineage_path = _load_lineage_path(root)
    else:
        lineage_path = _confined_path(root, lineage_records_path)

    candidate_records = _records_from_input(
        candidates,
        path=candidate_path,
        label="Candidate ledger",
        project_root=root,
        schema_name="candidate-artifact.schema.json",
        id_field="candidate_id",
    )
    link_records = _records_from_input(
        evidence_links,
        path=link_path,
        label="EvidenceLink ledger",
        project_root=root,
        schema_name="evidence-link.schema.json",
        id_field="evidence_link_id",
    )
    event_records = _records_from_input(
        lineage_events,
        path=lineage_path,
        label="Candidate lineage ledger",
        project_root=root,
        schema_name="candidate-lineage-event.schema.json",
        id_field="event_id",
        normalizer=normalize_lineage_event,
    )
    return _project_lineage(
        project_root=root,
        candidates=candidate_records,
        links=link_records,
        events=event_records,
    )


# Explicit names make the projection contract discoverable to callers.
derive_lineage_projection = replay_lineage
project_candidate_lineage = replay_lineage
load_lineage_state = replay_lineage


def strict_artifact_path(project_root: Path, locator: Any) -> Path:
    """Resolve a Candidate artifact while rejecting symlinks in every component."""
    if not isinstance(locator, str) or not locator:
        raise EvidenceAdmissionError("Candidate artifact locator 为空")
    pure = PurePosixPath(locator)
    if pure.is_absolute() or ".." in pure.parts or "\\" in locator:
        raise EvidenceAdmissionError("Candidate artifact locator 非法")
    if pure.parts[:2] != ("research", "artifacts"):
        raise EvidenceAdmissionError("Candidate artifact 不在 research/artifacts")
    lexical = project_root
    for part in pure.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise EvidenceAdmissionError("Candidate artifact 路径禁止 symlink")
    path = project_root.joinpath(*pure.parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceAdmissionError("Candidate artifact 不存在") from exc
    trusted = (project_root / "research" / "artifacts").resolve()
    try:
        resolved.relative_to(trusted)
    except ValueError as exc:
        raise EvidenceAdmissionError("Candidate artifact 逃逸可信根") from exc
    if not path.is_file() or path.is_symlink():
        raise EvidenceAdmissionError("Candidate artifact 必须是 regular file")
    return path


# Keep the private spelling for older callers while making the shared policy
# explicit to the ObligationGraph loader.
_safe_artifact = strict_artifact_path


def _candidate_integrity(
    project_root: Path,
    candidate: Mapping[str, Any],
    registry: Mapping[str, Mapping[str, Any]],
    registry_error: str | None,
) -> tuple[str, str | None]:
    """Return (hard-status, reason); hard-status is accept/reject/undetermined."""

    if registry_error is not None:
        return "undetermined", registry_error
    generator = candidate.get("generator")
    entry = registry.get(generator)
    if not isinstance(entry, Mapping) or entry.get("role") != "generator":
        return "reject", "generator_not_registered"
    try:
        artifact = _safe_artifact(project_root, candidate.get("artifact", {}).get("locator"))
        if sha256_file(artifact) != candidate.get("artifact", {}).get("sha256"):
            return "reject", "candidate_artifact_digest_mismatch"
    except (EvidenceAdmissionError, OSError):
        return "reject", "candidate_artifact_unavailable"
    return "accept", None


def _load_graph_records(
    project_root: Path,
    graphs: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if graphs is None:
        path = project_root / GRAPH_RECORDS
        if path.is_symlink():
            raise EvidenceAdmissionError("ObligationGraph ledger 不能是符号链接")
        if not path.exists():
            return {}
        values = _strict_jsonl(
            path,
            label="ObligationGraph ledger",
            project_root=project_root,
            schema_name="obligation-graph.schema.json",
            id_field="graph_id",
        )
    else:
        if isinstance(graphs, Mapping):
            if "graph_id" in graphs:
                values = [dict(graphs)]
            else:
                values = list(graphs.values())
        else:
            values = list(graphs)
        values = _dedupe_records(
            values,
            id_field="graph_id",
            label="ObligationGraph",
            project_root=project_root,
            schema_name="obligation-graph.schema.json",
        )
    result = {item["graph_id"]: item for item in values}
    for graph in result.values():
        obligations = graph.get("obligations")
        if not isinstance(obligations, list):
            raise EvidenceAdmissionError("ObligationGraph obligations 不是 list")
        by_id = {item.get("obligation_id"): item for item in obligations if isinstance(item, Mapping)}
        if len(by_id) != len(obligations):
            raise EvidenceAdmissionError("ObligationGraph obligation_id 重复或无效")
        for obligation in by_id.values():
            if canonical_json_sha256(obligation.get("statement")) != obligation.get("statement_sha256"):
                raise EvidenceAdmissionError(
                    f"Obligation statement_sha256 不匹配：{obligation.get('obligation_id')}"
                )
        root_id = graph.get("root_obligation_id")
        if root_id not in by_id:
            raise EvidenceAdmissionError("ObligationGraph root obligation 不存在")
        colors: dict[str, int] = {}

        def visit(identity: str, *, _colors: dict[str, int] = colors, _by_id: dict[str, Mapping[str, Any]] = by_id) -> None:
            state = _colors.get(identity, 0)
            if state == 1:
                raise EvidenceAdmissionError(f"ObligationGraph 含循环：{identity}")
            if state == 2:
                return
            _colors[identity] = 1
            deps = _by_id[identity].get("dependencies", [])
            for dependency in deps:
                if dependency not in _by_id:
                    raise EvidenceAdmissionError(f"ObligationGraph 含未知 dependency：{dependency}")
                visit(dependency)
            _colors[identity] = 2

        visit(root_id)
        if len(colors) != len(by_id):
            raise EvidenceAdmissionError("ObligationGraph 存在 root 不可达 obligation")
    return result


def _read_binding_ledger(
    project_root: Path,
    relative_path: Path,
    *,
    label: str,
) -> list[dict[str, Any]]:
    """Read a small identity ledger without consulting any verifier registry."""
    path = project_root / relative_path
    lexical = project_root
    for part in relative_path.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise EvidenceAdmissionError(f"{label} ledger 路径禁止符号链接")
    if not path.exists():
        return []
    if not path.is_file():
        raise EvidenceAdmissionError(f"{label} ledger 必须是 regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceAdmissionError(f"无法读取 {label} ledger") from exc
    if len(raw) > 64 * 1024 * 1024:
        raise EvidenceAdmissionError(f"{label} ledger 超过 64 MiB")
    if raw and not raw.endswith(b"\n"):
        raise EvidenceAdmissionError(f"{label} ledger 末行截断")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceAdmissionError(f"{label} ledger 第 {number} 行无效") from exc
        if not isinstance(value, Mapping):
            raise EvidenceAdmissionError(f"{label} ledger 第 {number} 行必须是 object")
        records.append(dict(value))
    return records


def _unique_binding_index(
    records: Iterable[Mapping[str, Any]],
    *,
    id_field: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for record in records:
        identity = record.get(id_field)
        if not isinstance(identity, str) or not identity:
            raise EvidenceAdmissionError(f"{label} 缺少 {id_field}")
        if identity in index:
            raise EvidenceAdmissionError(f"{label} {id_field} 重复：{identity}")
        index[identity] = dict(record)
    return index


def _binding_records(
    project_root: Path,
    values: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None,
    *,
    relative_path: Path,
    id_field: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    if values is None:
        records = _read_binding_ledger(project_root, relative_path, label=label)
    elif isinstance(values, Mapping):
        records = [dict(values)] if id_field in values else [dict(item) for item in values.values()]
    else:
        records = [dict(item) for item in values]
    return _unique_binding_index(records, id_field=id_field, label=label)


def validate_candidate_contract_bindings(
    project_root: Path | str,
    *,
    graphs: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None,
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None,
) -> dict[str, str]:
    """Validate the Problem -> Attempt -> Graph -> Candidate digest chain.

    This is deliberately a registry-free preflight.  A candidate with a
    missing, forged, or cross-Problem contract digest raises before receipt or
    verifier lookup, even when an old local registry would otherwise authorize
    the next step.
    """
    root = _root(project_root)
    graph_index = _unique_binding_index(
        [] if graphs is None else (
            [graphs] if isinstance(graphs, Mapping) and "graph_id" in graphs
            else graphs.values() if isinstance(graphs, Mapping)
            else graphs
        ),
        id_field="graph_id",
        label="ObligationGraph",
    )
    candidate_index = _unique_binding_index(
        [] if candidates is None else (
            [candidates] if isinstance(candidates, Mapping) and "candidate_id" in candidates
            else candidates.values() if isinstance(candidates, Mapping)
            else candidates
        ),
        id_field="candidate_id",
        label="Candidate",
    )
    if not graph_index and not candidate_index:
        return {}

    problem_index = _binding_records(
        root,
        None,
        relative_path=Path("problem-library/records/canonical-problems.jsonl"),
        id_field="problem_id",
        label="ProblemContract",
    )
    attempt_index = _binding_records(
        root,
        None,
        relative_path=Path("research/records/attempts.jsonl"),
        id_field="attempt_id",
        label="Attempt",
    )
    expected_by_graph: dict[str, str] = {}
    for graph_id, graph in graph_index.items():
        problem_id = graph.get("problem_id")
        problem = problem_index.get(problem_id)
        if problem is None:
            raise EvidenceAdmissionError(
                f"ObligationGraph 引用未知 ProblemContract：{graph_id}"
            )
        expected_digest = canonical_json_sha256(problem)
        expected_by_graph[graph_id] = expected_digest
        if graph.get("problem_contract_sha256") != expected_digest:
            raise EvidenceAdmissionError(
                f"ObligationGraph ProblemContract digest 漂移：{graph_id}"
            )
        attempt = attempt_index.get(graph.get("attempt_id"))
        if attempt is None:
            raise EvidenceAdmissionError(
                f"ObligationGraph 引用未知 Attempt：{graph_id}"
            )
        if (
            attempt.get("problem_id") != problem_id
            or attempt.get("route_id") != graph.get("route_id")
            or attempt.get("obligation_graph_id") != graph_id
            or attempt.get("problem_contract_sha256") != expected_digest
        ):
            raise EvidenceAdmissionError(
                f"Attempt 与 ProblemContract/ObligationGraph 绑定漂移：{graph_id}"
            )

    for candidate_id, candidate in candidate_index.items():
        graph_id = candidate.get("graph_id")
        graph = graph_index.get(graph_id)
        if graph is None:
            raise EvidenceAdmissionError(
                f"Candidate 引用未知 ObligationGraph：{candidate_id}"
            )
        expected_digest = expected_by_graph[graph_id]
        if any(
            candidate.get(field) != graph.get(field)
            for field in ("problem_id", "attempt_id", "graph_id")
        ):
            raise EvidenceAdmissionError(
                f"Candidate 与 Problem/Attempt/Graph 身份不一致：{candidate_id}"
            )
        if candidate.get("problem_contract_sha256") != expected_digest:
            raise EvidenceAdmissionError(
                f"Candidate ProblemContract digest 缺失或漂移：{candidate_id}"
            )
    return expected_by_graph


def _graph_obligation(
    candidate: Mapping[str, Any],
    graph: Mapping[str, Any] | None,
    explicit_obligation: Mapping[str, Any] | None,
    explicit_required: Iterable[str] | None,
) -> tuple[dict[str, Any] | None, set[str], set[str], str | None]:
    if explicit_obligation is not None:
        obligation = dict(explicit_obligation)
    elif graph is not None:
        obligation = next(
            (
                dict(item)
                for item in graph.get("obligations", [])
                if isinstance(item, Mapping) and item.get("obligation_id") == candidate.get("obligation_id")
            ),
            None,
        )
    else:
        obligation = None
    if obligation is None:
        if explicit_required is None:
            return None, set(), set(), "obligation_requirements_unavailable"
        return None, {str(item) for item in explicit_required}, set(), None
    acceptance = obligation.get("acceptance", {})
    required = acceptance.get("required_capabilities", [])
    allowed = acceptance.get("allowed_candidate_kinds", [])
    if explicit_required is not None:
        required = list(explicit_required)
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        return obligation, set(), set(), "obligation_capabilities_invalid"
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        return obligation, set(required), set(), "obligation_candidate_kinds_invalid"
    return obligation, set(required), set(allowed), None


def _minimal_graph(candidate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "graph_id": candidate["graph_id"],
        "problem_id": candidate["problem_id"],
        "attempt_id": candidate["attempt_id"],
    }




def _reject_legacy_admission_capability(capability: Any, label: str) -> None:
    """Reject legacy/unknown capabilities before admission consults any registry.

    Merge decision 2026-09-12: ``statement_identity`` (trusted typed probe) and
    ``statement_faithfulness`` are both current; anything outside the admitted
    capability set is rejected pre-registry.
    """
    try:
        reject_legacy_capability(capability)
    except EvidenceError as exc:
        raise EvidenceAdmissionError(f"{label}: {exc}") from exc
    if capability not in ADMITTED_CAPABILITIES:
        raise EvidenceAdmissionError(
            f"{label}: admission capability 未准入：{capability}"
        )


def _reject_legacy_admission_requirements(
    values: Any,
    *,
    label: str,
) -> None:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable):
        return
    for capability in values:
        _reject_legacy_admission_capability(capability, label)


def _reject_legacy_graph_requirements(
    values: Any,
    *,
    label: str,
) -> None:
    if values is None:
        return
    if isinstance(values, Mapping):
        graph_values = [values] if "graph_id" in values else values.values()
    else:
        graph_values = values
    for graph in graph_values:
        if not isinstance(graph, Mapping):
            continue
        obligations = graph.get("obligations", [])
        if not isinstance(obligations, Iterable) or isinstance(obligations, (str, bytes)):
            continue
        for obligation in obligations:
            if not isinstance(obligation, Mapping):
                continue
            acceptance = obligation.get("acceptance", {})
            if not isinstance(acceptance, Mapping):
                continue
            _reject_legacy_admission_requirements(
                acceptance.get("required_capabilities", []),
                label=f"{label} {obligation.get('obligation_id', '<unknown>')}",
            )


def _reject_legacy_receipt_links(
    project_root: Path,
    links: Iterable[Mapping[str, Any]],
) -> None:
    """Reject legacy receipt capabilities before admission loads the registry."""
    for link in links:
        try:
            capability = read_obligation_receipt_capability(
                project_root=project_root,
                link=dict(link),
            )
        except (EvidenceError, OSError, TypeError, ValueError):
            # Invalid/missing receipts are handled by the normal assessment;
            # this preflight only needs to catch an observable legacy name.
            continue
        _reject_legacy_admission_capability(
            capability,
            f"EvidenceLink {link.get('evidence_link_id', '<unknown>')}",
        )


def _assess_link_receipts(
    *,
    project_root: Path,
    candidates: Mapping[str, Mapping[str, Any]],
    links: Sequence[Mapping[str, Any]],
    link_states: Mapping[str, Mapping[str, Any]],
    candidate_states: Mapping[str, Mapping[str, Any]],
    graphs: Mapping[str, Mapping[str, Any]],
    registry_error: str | None,
) -> dict[str, dict[str, Any]]:
    assessments: dict[str, dict[str, Any]] = {}
    for link in links:
        link_id = link["evidence_link_id"]
        candidate = candidates[link["candidate_id"]]
        graph = graphs.get(candidate["graph_id"], _minimal_graph(candidate))
        record: dict[str, Any] = {
            "evidence_link_id": link_id,
            "status": "undetermined",
            "verdict": None,
            "capability": None,
            "independent": False,
            "reason": None,
        }
        if registry_error is not None:
            record["reason"] = registry_error
            assessments[link_id] = record
            continue
        try:
            info = verify_obligation_evidence_receipt(
                project_root=project_root,
                graph=graph,
                candidate=candidate,
                link=dict(link),
            )
            record["verdict"] = info["verdict"]
            record["capability"] = info["capability"]
            record["independent"] = bool(info["independent"])
            if link.get("invalidates") and (
                info["verdict"] != "reject" or not info["independent"]
            ):
                record["status"] = "reject"
                record["reason"] = "invalidation_requires_independent_reject"
            elif info["verdict"] == "accept" and info["independent"]:
                record["status"] = "accept"
            elif info["verdict"] == "reject":
                record["status"] = "reject"
                record["reason"] = "receipt_rejected"
            else:
                record["status"] = "undetermined"
                record["reason"] = "receipt_undetermined_or_not_independent"
        except (EvidenceError, OSError, KeyError, TypeError, ValueError):
            record["status"] = "reject"
            record["reason"] = "receipt_invalid"
        # A lineage-retracted/stale object cannot be used even if its old
        # receipt is still cryptographically valid.
        if link_states[link_id]["status"] != "current":
            record["status"] = "reject"
            record["reason"] = "evidence_link_not_current"
        elif candidate_states[link["candidate_id"]]["status"] != "current":
            record["status"] = "reject"
            record["reason"] = "candidate_not_current"
        assessments[link_id] = record
    return assessments


def _receipt_invalidation_set(
    links: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    link_states: Mapping[str, Mapping[str, Any]],
) -> set[str]:
    """Replay EvidenceLink.invalidates without allowing an invalidator to act."""

    invalidated = {
        identity
        for identity, state in link_states.items()
        if state["status"] == "invalidated"
    }
    changed = True
    while changed:
        changed = False
        for link in links:
            link_id = link["evidence_link_id"]
            assessment = assessments[link_id]
            if link_id in invalidated or link_id in {
                identity
                for identity, state in link_states.items()
                if state["status"] != "current"
            }:
                continue
            if assessment.get("verdict") != "reject" or assessment.get("independent") is not True:
                continue
            capability = assessment.get("capability")
            for old_id in link.get("invalidates", []):
                old_assessment = assessments[old_id]
                if capability is None or old_assessment.get("capability") != capability:
                    continue
                if old_id not in invalidated:
                    invalidated.add(old_id)
                    changed = True
    return invalidated


def _candidate_statement_is_current(
    candidate: Mapping[str, Any], obligation: Mapping[str, Any] | None
) -> bool:
    if obligation is None or "statement_sha256" not in obligation:
        # A small explicit obligation fixture may intentionally provide only
        # acceptance requirements.  It cannot assert statement freshness, but
        # it also must not turn a missing comparison value into false evidence.
        return True
    return candidate.get("statement_sha256") == obligation.get("statement_sha256")


def _closure_for_graph(
    graph: Mapping[str, Any],
    candidate_assessments: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    obligations = {
        item["obligation_id"]: item
        for item in graph.get("obligations", [])
        if isinstance(item, Mapping) and isinstance(item.get("obligation_id"), str)
    }
    by_obligation: dict[str, list[Mapping[str, Any]]] = {}
    for assessment in candidate_assessments.values():
        if assessment.get("graph_id") == graph.get("graph_id"):
            by_obligation.setdefault(assessment["obligation_id"], []).append(assessment)

    memo: dict[str, dict[str, Any]] = {}

    def evaluate(obligation_id: str) -> dict[str, Any]:
        if obligation_id in memo:
            return memo[obligation_id]
        obligation = obligations.get(obligation_id)
        if obligation is None:
            raise EvidenceAdmissionError(f"未知 obligation：{obligation_id}")
        dependencies = [evaluate(item) for item in obligation.get("dependencies", [])]
        direct_proofs = sorted(
            assessment["candidate_id"]
            for assessment in by_obligation.get(obligation_id, [])
            if assessment.get("direct") and assessment.get("candidate_kind") != "counterexample"
        )
        direct_counterexamples = sorted(
            assessment["candidate_id"]
            for assessment in by_obligation.get(obligation_id, [])
            if assessment.get("direct") and assessment.get("candidate_kind") == "counterexample"
        )
        proof_closed = bool(direct_proofs) and all(
            item["proof_closed"] for item in dependencies
        )
        counterexample_closed = bool(direct_counterexamples)
        conflict = proof_closed and counterexample_closed
        if conflict:
            status = "conflict"
        elif counterexample_closed:
            status = "refuted"
        elif proof_closed:
            status = "closed"
        elif any(item["status"] in {"refuted", "conflict", "blocked_by_dependency"} for item in dependencies):
            status = "blocked_by_dependency"
        else:
            status = "open"
        value = {
            "obligation_id": obligation_id,
            "status": status,
            "proof_closed": proof_closed,
            "counterexample_closed": counterexample_closed,
            "proof_candidate_ids": direct_proofs,
            "counterexample_candidate_ids": direct_counterexamples,
            "dependencies": list(obligation.get("dependencies", [])),
        }
        memo[obligation_id] = value
        return value

    for obligation_id in sorted(obligations):
        evaluate(obligation_id)
    conflicting: set[str] = set()
    for item in memo.values():
        if item["status"] == "conflict":
            conflicting.update(item["proof_candidate_ids"])
            conflicting.update(item["counterexample_candidate_ids"])
    return {
        "nodes": {identity: memo[identity] for identity in sorted(memo)},
        "conflicting_candidate_ids": sorted(conflicting),
        "root": memo[graph["root_obligation_id"]],
    }


def _unknown_context(
    candidate_id: str,
    *,
    graph_id: str | None,
    problem_id: str | None,
    attempt_id: str | None,
    obligation_id: str | None,
) -> dict[str, str]:
    # The placeholders are only used for a negative decision about a missing
    # object.  They are explicit ``unknown`` identities, never a fabricated
    # candidate/result and therefore remain schema-valid without guessing a
    # real research identity.
    return {
        "graph_id": graph_id or "graph:unknown",
        "problem_id": problem_id or "problem:unknown",
        "attempt_id": attempt_id or "attempt:unknown",
        "obligation_id": obligation_id or "obligation:unknown",
        "candidate_id": candidate_id,
    }


def _validate_decision(project_root: Path, decision: dict[str, Any]) -> None:
    _validate_schema(
        project_root,
        "evidence-admission-decision.schema.json",
        decision,
        "Evidence admission decision",
    )


def _decision(
    *,
    project_root: Path,
    context: Mapping[str, Any],
    candidate_kind: str | None,
    candidate_status: str,
    decision: str,
    required: Iterable[str],
    accepted: Iterable[str],
    evidence_ids: Iterable[str],
    accepted_link_ids: Iterable[str],
    rejected_link_ids: Iterable[str],
    undetermined_link_ids: Iterable[str],
    conflicting_candidate_ids: Iterable[str],
    reasons: Iterable[str],
) -> dict[str, Any]:
    required_list = sorted(set(required))
    accepted_list = sorted(set(accepted))
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "graph_id": context["graph_id"],
        "problem_id": context["problem_id"],
        "attempt_id": context["attempt_id"],
        "obligation_id": context["obligation_id"],
        "candidate_id": context["candidate_id"],
        "candidate_kind": candidate_kind,
        "candidate_status": candidate_status,
        "required_capabilities": required_list,
        "accepted_capabilities": accepted_list,
        "missing_capabilities": sorted(set(required_list) - set(accepted_list)),
        "evidence_link_ids": sorted(set(evidence_ids)),
        "accepted_evidence_link_ids": sorted(set(accepted_link_ids)),
        "rejected_evidence_link_ids": sorted(set(rejected_link_ids)),
        "undetermined_evidence_link_ids": sorted(set(undetermined_link_ids)),
        "conflicting_candidate_ids": sorted(set(conflicting_candidate_ids)),
        "reasons": sorted({reason for reason in reasons if reason}),
    }
    base["projection_sha256"] = canonical_json_sha256(base)
    _validate_decision(project_root, base)
    return base


def admit_evidence(
    project_root: Path | str,
    candidate_id: str | Mapping[str, Any],
    *,
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    evidence_links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage_events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    graphs: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
    obligation: Mapping[str, Any] | None = None,
    required_capabilities: Iterable[str] | None = None,
    evidence_link_ids: Iterable[str] | None = None,
    candidate_records_path: Path | str | None = None,
    evidence_link_records_path: Path | str | None = None,
    lineage_records_path: Path | str | None = None,
) -> dict[str, Any]:
    """Derive one deterministic Evidence admission decision.

    A current candidate with matching, independent, registry-authorized
    receipts for every obligation capability returns ``admit_evidence``.
    Missing/undetermined evidence remains ``undetermined``; stale or
    cryptographically invalid objects are ``reject``.  If a proof and a
    counterexample both close the same obligation, the decision is
    ``conflict`` and never positive.
    """

    root = _root(project_root)
    if required_capabilities is not None:
        required_capabilities = list(required_capabilities)
        _reject_legacy_admission_requirements(
            required_capabilities,
            label="admission required_capabilities",
        )
    if obligation is not None and isinstance(obligation, Mapping):
        acceptance = obligation.get("acceptance", {})
        if isinstance(acceptance, Mapping):
            _reject_legacy_admission_requirements(
                acceptance.get("required_capabilities", []),
                label="admission obligation requirements",
            )
    if graph is not None:
        _reject_legacy_graph_requirements(graph, label="admission graph requirements")
    if graphs is not None:
        if not isinstance(graphs, Mapping):
            graphs = list(graphs)
        _reject_legacy_graph_requirements(graphs, label="admission graph requirements")
    if links is not None:
        if evidence_links is not None:
            raise LineageConflict("evidence_links 与 links 同时提供")
        evidence_links = links
    if lineage is not None:
        if lineage_events is not None or events is not None:
            raise LineageConflict("lineage_events/events 与 lineage 同时提供")
        lineage_events = lineage
    if events is not None:
        if lineage_events is not None:
            raise LineageConflict("lineage_events 与 events 同时提供")
        lineage_events = events
    # Materialize iterators once.  Admission needs the same immutable input
    # for replay, candidate lookup, and per-candidate closure; consuming a
    # generator a second time would silently turn evidence into "missing".
    if candidates is not None and not isinstance(candidates, Mapping):
        candidates = list(candidates)
    if evidence_links is not None and not isinstance(evidence_links, Mapping):
        evidence_links = list(evidence_links)
    if lineage_events is not None and not isinstance(lineage_events, Mapping):
        lineage_events = list(lineage_events)
    if events is not None and not isinstance(events, Mapping):
        events = list(events)
    candidate_value: Mapping[str, Any] | None
    if isinstance(candidate_id, Mapping):
        candidate_value = candidate_id
        candidate_identity = candidate_id.get("candidate_id")
        if not isinstance(candidate_identity, str):
            raise EvidenceAdmissionError("candidate 缺少 candidate_id")
        if candidates is None:
            candidates = [candidate_id]
        elif isinstance(candidates, Mapping):
            existing_candidates = [candidates] if "candidate_id" in candidates else list(candidates.values())
            candidates = [*existing_candidates, candidate_value]
        else:
            candidates = [*candidates, candidate_value]
    else:
        candidate_identity = candidate_id
        candidate_value = None
    if not isinstance(candidate_identity, str) or not candidate_identity.startswith("candidate:"):
        raise EvidenceAdmissionError("candidate_id 无效")

    # Replay once; this is the only state used below, so old receipts cannot
    # be copied to a successor merely because they share an obligation.
    projection = replay_lineage(
        candidates=candidates,
        evidence_links=evidence_links,
        lineage_events=lineage_events,
        events=events,
        project_root=root,
        candidate_records_path=candidate_records_path,
        evidence_link_records_path=evidence_link_records_path,
        lineage_records_path=lineage_records_path,
    )
    candidate_records = {
        item["candidate_id"]: item
        for item in _records_from_input(
            candidates,
            path=(root / CANDIDATE_RECORDS if candidate_records_path is None else _confined_path(root, candidate_records_path)),
            label="Candidate ledger",
            project_root=root,
            schema_name="candidate-artifact.schema.json",
            id_field="candidate_id",
        )
    }
    link_records = _records_from_input(
        evidence_links,
        path=(root / EVIDENCE_LINK_RECORDS if evidence_link_records_path is None else _confined_path(root, evidence_link_records_path)),
        label="EvidenceLink ledger",
        project_root=root,
        schema_name="evidence-link.schema.json",
        id_field="evidence_link_id",
    )
    # The supplied candidate may be a single record and may have been omitted
    # from ``candidates`` only when the direct argument is a mapping.
    if candidate_value is not None and candidate_identity not in candidate_records:
        candidate_records[candidate_identity] = dict(candidate_value)
    candidate = candidate_records.get(candidate_identity)

    supplied_graph = graph
    graph_records = _load_graph_records(root, graphs)
    if supplied_graph is not None:
        supplied_graphs = _load_graph_records(root, [supplied_graph])
        for graph_id, supplied in supplied_graphs.items():
            existing = graph_records.get(graph_id)
            if existing is not None and canonical_json_sha256(existing) != canonical_json_sha256(supplied):
                raise LineageConflict(f"ObligationGraph ID 已存在且内容不同：{graph_id}")
            graph_records[graph_id] = supplied

    # This must precede both receipt inspection and verifier-registry lookup.
    # The graph/attempt/problem chain, not a packet or a historical registry,
    # supplies the only accepted Candidate ProblemContract digest.
    validate_candidate_contract_bindings(
        root,
        graphs=graph_records,
        candidates=candidate_records,
    )
    # Graphs loaded from the ledger are just as untrusted as caller-supplied
    # graphs.  Check their requirements before the admission registry lookup.
    _reject_legacy_graph_requirements(
        graph_records,
        label="admission graph requirements",
    )
    _reject_legacy_receipt_links(root, link_records)
    context_fallback = _unknown_context(
        candidate_identity,
        graph_id=(candidate or {}).get("graph_id"),
        problem_id=(candidate or {}).get("problem_id"),
        attempt_id=(candidate or {}).get("attempt_id"),
        obligation_id=(candidate or {}).get("obligation_id"),
    )
    if candidate is None:
        return _decision(
            project_root=root,
            context=context_fallback,
            candidate_kind=None,
            candidate_status="unknown",
            decision="reject",
            required=required_capabilities or [],
            accepted=[],
            evidence_ids=evidence_link_ids or [],
            accepted_link_ids=[],
            rejected_link_ids=[],
            undetermined_link_ids=[],
            conflicting_candidate_ids=[],
            reasons=["candidate_not_found"],
        )

    context = _candidate_context(candidate) | {"candidate_id": candidate_identity}
    candidate_state = projection["candidate_states"].get(candidate_identity)
    candidate_status = candidate_state["status"] if candidate_state else "unknown"
    graph_value = graph_records.get(candidate["graph_id"])
    requirements_override = False
    if graph_value is not None:
        # The frozen ObligationGraph is authoritative.  Caller-supplied
        # requirements may explain a fixture, but may never weaken the graph
        # and thereby admit a Candidate without its required receipts.
        obligation_value, target_required, target_allowed, obligation_error = _graph_obligation(
            candidate,
            graph_value,
            None,
            None,
        )
        canonical_acceptance = obligation_value.get("acceptance", {}) if obligation_value else {}
        if required_capabilities is not None and set(required_capabilities) != set(target_required):
            requirements_override = True
        if obligation is not None:
            supplied_acceptance = obligation.get("acceptance", {})
            if (
                set(supplied_acceptance.get("required_capabilities", [])) != set(canonical_acceptance.get("required_capabilities", []))
                or set(supplied_acceptance.get("allowed_candidate_kinds", [])) != set(canonical_acceptance.get("allowed_candidate_kinds", []))
            ):
                requirements_override = True
    else:
        obligation_value, target_required, target_allowed, obligation_error = _graph_obligation(
            candidate,
            graph_value,
            obligation,
            required_capabilities,
        )
    reasons: list[str] = []
    if requirements_override:
        reasons.append("obligation_requirements_override")
    if obligation_error:
        reasons.append(obligation_error)
    if graph_value is not None:
        if graph_value.get("problem_id") != candidate.get("problem_id") or graph_value.get("attempt_id") != candidate.get("attempt_id"):
            reasons.append("candidate_graph_identity_mismatch")
        if not _candidate_statement_is_current(candidate, obligation_value):
            reasons.append("candidate_statement_stale")
        if obligation_value is not None and candidate.get("kind") not in target_allowed:
            reasons.append("candidate_kind_not_allowed")

    try:
        registry = load_verifier_registry(root)
        registry_error = None
    except (EvidenceError, OSError, ValueError):
        registry = {}
        registry_error = "verifier_registry_unavailable"

    candidate_status_check, candidate_integrity_reason = _candidate_integrity(
        root, candidate, registry, registry_error
    )
    if candidate_integrity_reason:
        reasons.append(candidate_integrity_reason)

    all_link_states = projection["evidence_link_states"]
    all_candidate_states = projection["candidate_states"]
    assessments = _assess_link_receipts(
        project_root=root,
        candidates=candidate_records,
        links=link_records,
        link_states=all_link_states,
        candidate_states=all_candidate_states,
        graphs=graph_records,
        registry_error=registry_error,
    )
    receipt_invalidated = _receipt_invalidation_set(link_records, assessments, all_link_states)
    for link_id in receipt_invalidated:
        if assessments[link_id].get("status") == "accept":
            assessments[link_id]["status"] = "reject"
            assessments[link_id]["reason"] = "evidence_link_invalidated"

    linked_ids = sorted(
        link["evidence_link_id"]
        for link in link_records
        if link["candidate_id"] == candidate_identity
    )
    if evidence_link_ids is None:
        selected_ids = linked_ids
    else:
        selected_ids = sorted(set(evidence_link_ids))
    unknown_selected = sorted(set(selected_ids) - set(assessments))
    if unknown_selected:
        reasons.append("evidence_link_not_found")
    selected_links = [link_id for link_id in selected_ids if link_id in assessments]
    wrong_candidate = [
        link_id
        for link_id in selected_links
        if next(item for item in link_records if item["evidence_link_id"] == link_id)["candidate_id"] != candidate_identity
    ]
    if wrong_candidate:
        reasons.append("evidence_link_candidate_mismatch")
    selected_links = [link_id for link_id in selected_links if link_id not in wrong_candidate]

    accepted_link_ids = sorted(
        link_id
        for link_id in selected_links
        if assessments[link_id].get("status") == "accept"
        and assessments[link_id].get("independent") is True
        and link_id not in receipt_invalidated
    )
    rejected_link_ids = sorted(
        link_id
        for link_id in selected_links
        if assessments[link_id].get("status") == "reject"
        or link_id in receipt_invalidated
    )
    undetermined_link_ids = sorted(
        link_id
        for link_id in selected_links
        if assessments[link_id].get("status") == "undetermined"
    )
    accepted_capabilities = sorted(
        {
            assessments[link_id]["capability"]
            for link_id in accepted_link_ids
            if assessments[link_id].get("capability")
        }
    )

    # Build per-candidate direct closure data.  Every candidate gets only its
    # own links; there is intentionally no supersession inheritance.
    target_requirements_available = obligation_error is None and (
        obligation_value is not None or required_capabilities is not None
    )
    candidate_assessments: dict[str, dict[str, Any]] = {}
    for identity, value in candidate_records.items():
        value_graph = graph_records.get(value["graph_id"])
        value_obligation, value_required, value_allowed, value_obligation_error = _graph_obligation(
            value,
            value_graph,
            None,
            target_required
            if target_requirements_available
            and value_graph is None
            and graph_value is None
            and value.get("problem_id") == candidate.get("problem_id")
            and value.get("attempt_id") == candidate.get("attempt_id")
            and value.get("obligation_id") == candidate.get("obligation_id")
            else None,
        )
        value_state = all_candidate_states.get(identity, {"status": "unknown"})
        value_link_ids = [
            link["evidence_link_id"]
            for link in link_records
            if link["candidate_id"] == identity
        ]
        value_accepted_link_ids = [
            link_id
            for link_id in value_link_ids
            if assessments[link_id].get("status") == "accept"
            and assessments[link_id].get("independent") is True
            and link_id not in receipt_invalidated
        ]
        value_capabilities = {
            assessments[link_id].get("capability")
            for link_id in value_accepted_link_ids
            if assessments[link_id].get("capability")
        }
        value_integrity, _ = _candidate_integrity(root, value, registry, registry_error)
        value_graph_identity_ok = value_graph is None or (
            value_graph.get("problem_id") == value.get("problem_id")
            and value_graph.get("attempt_id") == value.get("attempt_id")
        )
        value_direct = (
            value_state.get("status") == "current"
            and value_graph_identity_ok
            and value_integrity == "accept"
            and value_obligation_error is None
            and _candidate_statement_is_current(value, value_obligation)
            and (not value_allowed or value.get("kind") in value_allowed)
            and value_required.issubset(value_capabilities)
        )
        candidate_assessments[identity] = {
            "candidate_id": identity,
            "graph_id": value["graph_id"],
            "problem_id": value["problem_id"],
            "attempt_id": value["attempt_id"],
            "obligation_id": value["obligation_id"],
            "candidate_kind": value.get("kind"),
            "required_capabilities": sorted(value_required),
            "accepted_capabilities": sorted(value_capabilities),
            "direct": value_direct,
        }

    closure_by_graph: dict[str, dict[str, Any]] = {}
    for graph_id, graph_value in graph_records.items():
        graph_candidates = {
            identity: item
            for identity, item in candidate_assessments.items()
            if item["graph_id"] == graph_id
        }
        if not graph_candidates:
            continue
        closure = _closure_for_graph(graph_value, graph_candidates)
        closure_by_graph[graph_id] = closure

    target_node = None
    target_closure = closure_by_graph.get(candidate["graph_id"])
    target_conflicting: set[str] = set()
    if target_closure is not None:
        target_node = target_closure["nodes"].get(candidate["obligation_id"])
        target_conflicting = set(target_closure["conflicting_candidate_ids"])
    if target_node is not None and target_node["status"] == "conflict":
        reasons.append("proof_counterexample_conflict")
    elif target_conflicting:
        # A conflicting descendant is still a fail-closed graph projection;
        # do not let a sibling be promoted while the graph is contradictory.
        reasons.append("proof_counterexample_conflict")

    target_required = set(target_required)
    missing = target_required - set(accepted_capabilities)
    if missing:
        reasons.append("required_capability_missing")

    target_hard_reject = bool(
        candidate_status != "current"
        or candidate_status_check == "reject"
        or any(
            reason in {
                "candidate_graph_identity_mismatch",
                "candidate_statement_stale",
                "candidate_kind_not_allowed",
                "obligation_requirements_override",
                "candidate_artifact_digest_mismatch",
                "candidate_artifact_unavailable",
                "generator_not_registered",
            }
            for reason in reasons
        )
        or unknown_selected
        or wrong_candidate
    )
    if "proof_counterexample_conflict" in reasons or target_conflicting:
        final_decision = "conflict"
    elif target_hard_reject or (rejected_link_ids and not accepted_link_ids):
        final_decision = "reject"
    elif (
        target_requirements_available
        and not missing
        and candidate_status == "current"
        and candidate_status_check == "accept"
    ):
        final_decision = "admit_evidence"
    else:
        final_decision = "undetermined"

    # Add stable reasons for lineage status after final state is known.
    if candidate_status != "current":
        reasons.append(f"candidate_{candidate_status}")
    for link_id in rejected_link_ids:
        reason = assessments[link_id].get("reason")
        if reason:
            reasons.append(f"{link_id}:{reason}")
    for link_id in undetermined_link_ids:
        reason = assessments[link_id].get("reason")
        if reason:
            reasons.append(f"{link_id}:{reason}")

    return _decision(
        project_root=root,
        context=context,
        candidate_kind=candidate.get("kind"),
        candidate_status=candidate_status,
        decision=final_decision,
        required=target_required,
        accepted=accepted_capabilities,
        evidence_ids=selected_links,
        accepted_link_ids=accepted_link_ids,
        rejected_link_ids=rejected_link_ids,
        undetermined_link_ids=undetermined_link_ids,
        conflicting_candidate_ids=target_conflicting,
        reasons=reasons,
    )


# Public aliases keep the operation name readable in callers and tests.
evidence_admission_decision = admit_evidence
decide_evidence_admission = admit_evidence
derive_evidence_admission_decision = admit_evidence
derive_admission_decision = admit_evidence
evaluate_evidence_admission = admit_evidence
replay_candidate_lineage = replay_lineage


def project_evidence_admission(
    project_root: Path | str,
    *,
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    evidence_links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage_events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    graphs: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    candidate_records_path: Path | str | None = None,
    evidence_link_records_path: Path | str | None = None,
    lineage_records_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Project all Candidate decisions, sorted by immutable candidate ID."""

    root = _root(project_root)
    if links is not None:
        if evidence_links is not None:
            raise LineageConflict("evidence_links 与 links 同时提供")
        evidence_links = links
    if lineage is not None:
        if lineage_events is not None or events is not None:
            raise LineageConflict("lineage_events/events 与 lineage 同时提供")
        lineage_events = lineage
    if events is not None:
        if lineage_events is not None:
            raise LineageConflict("lineage_events 与 events 同时提供")
        lineage_events = events
    # The projection calls the single-candidate operation repeatedly; do not
    # consume caller-provided generators on the first replay.
    if candidates is not None and not isinstance(candidates, Mapping):
        candidates = list(candidates)
    if evidence_links is not None and not isinstance(evidence_links, Mapping):
        evidence_links = list(evidence_links)
    if lineage_events is not None and not isinstance(lineage_events, Mapping):
        lineage_events = list(lineage_events)
    if events is not None and not isinstance(events, Mapping):
        events = list(events)
    if graphs is not None and not isinstance(graphs, Mapping):
        graphs = list(graphs)
    replay_lineage(
        candidates=candidates,
        evidence_links=evidence_links,
        lineage_events=lineage_events,
        events=events,
        project_root=root,
        candidate_records_path=candidate_records_path,
        evidence_link_records_path=evidence_link_records_path,
        lineage_records_path=lineage_records_path,
    )
    candidate_records = _records_from_input(
        candidates,
        path=(root / CANDIDATE_RECORDS if candidate_records_path is None else _confined_path(root, candidate_records_path)),
        label="Candidate ledger",
        project_root=root,
        schema_name="candidate-artifact.schema.json",
        id_field="candidate_id",
    )
    return [
        admit_evidence(
            root,
            candidate["candidate_id"],
            candidates=candidate_records,
            evidence_links=evidence_links,
            lineage_events=lineage_events,
            events=events,
            graphs=graphs,
            candidate_records_path=candidate_records_path,
            evidence_link_records_path=evidence_link_records_path,
            lineage_records_path=lineage_records_path,
        )
        for candidate in sorted(candidate_records, key=lambda item: item["candidate_id"])
    ]


admit_all_evidence = project_evidence_admission
derive_evidence_admission_projection = project_evidence_admission
admission_projection = project_evidence_admission


def append_lineage_event(
    project_root: Path | str,
    event: Mapping[str, Any],
    *,
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    evidence_links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage_records_path: Path | str | None = None,
) -> bool:
    """Append one validated event without replacing history.

    Returns ``False`` for a canonical-equivalent duplicate event ID and
    ``True`` when a new line is durably appended.  The complete proposed log
    is replayed before the append, so a cycle, branch, future reference, or
    cross-identity relation cannot partially enter the ledger.
    """

    root = _root(project_root)
    path = (
        _load_lineage_path(root)
        if lineage_records_path is None
        else _confined_path(root, lineage_records_path)
    )
    if path.is_symlink():
        raise LineageCorruption("lineage ledger 不能是符号链接")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    if lock_path.is_symlink():
        raise LineageCorruption("lineage lock 不能是符号链接")
    descriptor: int | None = None
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(lock_path, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        existing = _strict_jsonl(
            path,
            label="Candidate lineage ledger",
            project_root=root,
            schema_name="candidate-lineage-event.schema.json",
            id_field="event_id",
            normalizer=normalize_lineage_event,
        )
        normalized = normalize_lineage_event(event)
        _validate_schema(root, "candidate-lineage-event.schema.json", normalized, "Candidate lineage event")
        event_id = normalized["event_id"]
        digest = canonical_json_sha256(normalized)
        for old in existing:
            if old["event_id"] != event_id:
                continue
            if canonical_json_sha256(old) == digest:
                return False
            raise LineageConflict(f"lineage event_id 已存在且内容不同：{event_id}")
        proposed = [*existing, normalized]
        # replay validates object existence and all relation invariants before
        # touching the file.  The caller may provide direct records for a
        # temporary test project; otherwise the normal ledgers are read.
        replay_lineage(
            candidates=candidates,
            evidence_links=evidence_links,
            lineage_events=proposed,
            project_root=root,
        )
        encoded = (json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if path.exists() and not path.is_file():
            raise LineageCorruption("lineage ledger 必须是 regular file")
        with path.open("ab") as handle:
            written = handle.write(encoded)
            if written != len(encoded):
                raise LineageCorruption("lineage event 未完整写入")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise LineageCorruption("lineage ledger 目录 fsync 失败") from exc
        return True
    except OSError as exc:
        raise LineageCorruption("lineage event append 失败") from exc
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


# A validation-oriented spelling for CLI/test callers.
def validate_lineage_records(
    project_root: Path | str,
    *,
    candidates: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    evidence_links: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    lineage_events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    events: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None = None,
) -> list[str]:
    try:
        replay_lineage(
            candidates=candidates,
            evidence_links=evidence_links,
            lineage_events=lineage_events,
            events=events,
            project_root=project_root,
        )
    except EvidenceChainError as exc:
        return [str(exc)]
    return []


validate_lineage = validate_lineage_records


__all__ = [
    "CANDIDATE_LINEAGE_RECORDS",
    "CANDIDATE_RECORDS",
    "EVIDENCE_LINK_RECORDS",
    "LINEAGE_EVENT_RECORDS",
    "LINEAGE_RECORDS",
    "AdmissionConflict",
    "EvidenceAdmissionError",
    "EvidenceChainConflict",
    "EvidenceChainError",
    "LineageConflict",
    "LineageCorruption",
    "LineageError",
    "admission_projection",
    "admit_all_evidence",
    "admit_evidence",
    "append_lineage_event",
    "canonical_json_sha256",
    "decide_evidence_admission",
    "derive_admission_decision",
    "derive_evidence_admission_decision",
    "derive_evidence_admission_projection",
    "derive_lineage_projection",
    "evaluate_evidence_admission",
    "evidence_admission_decision",
    "load_lineage_state",
    "normalize_lineage_event",
    "project_candidate_lineage",
    "project_evidence_admission",
    "replay_candidate_lineage",
    "replay_lineage",
    "strict_artifact_path",
    "validate_candidate_contract_bindings",
    "validate_lineage",
    "validate_lineage_records",
]
