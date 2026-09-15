"""单机 Coordinator 的最小身份、事件账本和 Job 投影实现。

本模块只负责控制平面：Job 合同、append-only Event Store、lease 和从事件
重建当前 Job 状态。它不会写入 Problem/Attempt/Result，也不会调用执行器。

事件日志是内部操作真相源；Job 当前状态是可删除、可重建的投影。事件中的
payload 只承载控制面元数据，绝不因此成为数学 Evidence。
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .obligations import canonical_json_sha256


SCHEMA_VERSION = "1.0.0"
EVENT_TYPES = frozenset(
    {
        "created",
        "ready",
        "claimed",
        "started",
        "checkpointed",
        "candidate_created",
        "verifier_requested",
        "verifier_completed",
        "blocked",
        "failed",
        "completed",
        "cancelled",
    }
)

EVENT_TO_STATUS = {
    "created": "new",
    "ready": "ready",
    "claimed": "claimed",
    "started": "started",
    "checkpointed": "checkpointed",
    "candidate_created": "candidate_ready",
    "verifier_requested": "verifying",
    "verifier_completed": "verifier_completed",
    "blocked": "blocked",
    "failed": "failed",
    "completed": "completed",
    "cancelled": "cancelled",
}

# These are control-plane actors. A worker actor still has to match the active
# lease holder; administrative actors may record a cancellation/failure or a
# coordinator-mediated transition without pretending to be the worker.
ADMIN_ACTORS = frozenset({"coordinator", "root", "system"})

ALLOWED_TRANSITIONS = {
    "new": {"ready", "blocked", "failed", "cancelled"},
    "ready": {"claimed", "blocked", "failed", "cancelled"},
    "claimed": {"ready", "started", "blocked", "failed", "cancelled"},
    "started": {
        "checkpointed",
        "candidate_created",
        "verifier_requested",
        "blocked",
        "failed",
        "completed",
        "cancelled",
    },
    "checkpointed": {
        "started",
        "checkpointed",
        "candidate_created",
        "verifier_requested",
        "blocked",
        "failed",
        "completed",
        "cancelled",
    },
    "candidate_ready": {
        "verifier_requested",
        "completed",
        "blocked",
        "failed",
        "cancelled",
    },
    "verifying": {"verifier_completed", "blocked", "failed", "cancelled"},
    "verifier_completed": {"completed", "blocked", "failed", "cancelled"},
    # blocked/failed are terminal for this bounded Job. A retry or route change
    # must create a new Job and retain this event history.
    "blocked": set(),
    "failed": set(),
    "completed": set(),
    "cancelled": set(),
}

DEFAULT_BUDGETS: dict[str, int] = {
    "timeout_seconds": 30,
    "max_output_bytes": 1_048_576,
    "max_retries": 2,
    "max_transitions": 16,
}


class CoordinatorError(RuntimeError):
    """Coordinator 合同、事件或投影失败。"""


class EventStoreError(CoordinatorError):
    """事件日志无法安全读取或追加。"""


class DuplicateEventError(EventStoreError):
    """同 event_id 的内容与既有事件不同。"""


class ReplayError(EventStoreError):
    """事件不能按合法生命周期重放。"""


class JobError(CoordinatorError):
    """Job 合同或状态操作失败。"""


class LeaseError(JobError):
    """lease 不存在、已过期或归属不符。"""


class JobAlreadyExists(JobError):
    """job_id 或 dedupe_key 已绑定到不同 Job。"""


class SchemaContractError(CoordinatorError):
    """JSON schema 校验失败。"""


class CanonicalAdmissionError(JobError):
    """Job 未能绑定到当前 canonical Problem/Attempt/ObligationGraph 快照。"""


def now() -> str:
    """返回带时区的 UTC 时间戳。"""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, *, label: str = "时间戳") -> datetime:
    if not isinstance(value, str):
        raise CoordinatorError(f"{label} 必须是 ISO 8601 字符串")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoordinatorError(f"{label} 无效") from exc
    if parsed.tzinfo is None:
        raise CoordinatorError(f"{label} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def canonical_json_bytes(value: Any) -> bytes:
    """以稳定 JSON 编码一个可持久化值。"""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CoordinatorError("值不能编码为有限 JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _new_identifier(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4().hex}"


def _schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "research" / "schema"


def _read_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaContractError(f"无法读取 schema：{path}") from exc
    if not isinstance(value, dict):
        raise SchemaContractError(f"schema 不是 JSON object：{path}")
    return value


def _schema_error(validator: Draft202012Validator, value: Any, label: str) -> None:
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        path = ".".join(str(part) for part in errors[0].path)
        suffix = f" at {path}" if path else ""
        raise SchemaContractError(f"{label} schema 无效{suffix}: {errors[0].message}")


_CANONICAL_LEDGER_SPECS = (
    (
        "problem-library/records/canonical-problems.jsonl",
        "problem-library/schema/canonical-problem.schema.json",
        "problem_id",
        "ProblemContract",
    ),
    (
        "research/records/attempts.jsonl",
        "research/schema/attempt.schema.json",
        "attempt_id",
        "Attempt",
    ),
    (
        "research/records/obligation-graphs.jsonl",
        "research/schema/obligation-graph.schema.json",
        "graph_id",
        "ObligationGraph",
    ),
)
_MAX_LEDGER_LINE_BYTES = 2 * 1024 * 1024


def _read_strict_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    """Read an admitted ledger without silently accepting truncation or gaps."""
    if path.is_symlink() or not path.is_file():
        raise CanonicalAdmissionError(f"{label} 必须是 regular file：{path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CanonicalAdmissionError(f"无法读取 {label}：{path}") from exc
    if not raw:
        raise CanonicalAdmissionError(f"{label} 不能为空：{path}")
    if not raw.endswith(b"\n"):
        raise CanonicalAdmissionError(f"{label} 末行缺少换行，疑似截断：{path}")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.split(b"\n")[:-1], 1):
        if len(line) > _MAX_LEDGER_LINE_BYTES:
            raise CanonicalAdmissionError(f"{label}:{line_number} 超过 2 MiB")
        if not line.strip():
            raise CanonicalAdmissionError(f"{label}:{line_number} 为空行")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CanonicalAdmissionError(f"{label}:{line_number} JSON 无效") from exc
        if not isinstance(value, dict):
            raise CanonicalAdmissionError(f"{label}:{line_number} 必须是 JSON object")
        records.append(value)
    if not records:
        raise CanonicalAdmissionError(f"{label} 没有记录：{path}")
    return records


def _contract_schema_path(project_root: Path, relative_path: str) -> Path:
    """Use a project schema when present, otherwise the trusted package schema."""
    project_path = project_root / relative_path
    if project_path.is_symlink():
        raise CanonicalAdmissionError(f"contract schema 不能是符号链接：{project_path}")
    if project_path.is_file():
        return project_path
    fallback = _schema_root() / Path(relative_path).name
    if fallback.is_file() and not fallback.is_symlink():
        return fallback
    raise CanonicalAdmissionError(f"contract schema 不存在：{project_path}")


def _read_admitted_ledgers(project_root: Path) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    """Load and schema-check all three canonical identity ledgers."""
    indexes: list[dict[str, dict[str, Any]]] = []
    for relative_path, schema_relative_path, id_field, label in _CANONICAL_LEDGER_SPECS:
        path = project_root / relative_path
        records = _read_strict_jsonl(path, label)
        schema_path = _contract_schema_path(project_root, schema_relative_path)
        try:
            schema = _read_schema(schema_path)
        except SchemaContractError as exc:
            raise CanonicalAdmissionError(
                f"{label} schema 不可用：{schema_path}"
            ) from exc
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        index: dict[str, dict[str, Any]] = {}
        for line_number, record in enumerate(records, 1):
            try:
                _schema_error(validator, record, label)
            except SchemaContractError as exc:
                raise CanonicalAdmissionError(
                    f"{label}:{line_number} schema 无效：{exc}"
                ) from exc
            identity = record.get(id_field)
            if not isinstance(identity, str) or not identity:
                raise CanonicalAdmissionError(
                    f"{label}:{line_number} 缺少 {id_field}"
                )
            if identity in index:
                raise CanonicalAdmissionError(f"{label} {id_field} 重复：{identity}")
            index[identity] = record
        indexes.append(index)
    return indexes[0], indexes[1], indexes[2]


def _validate_obligation_nodes(graph: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Validate statement digests, dependencies, DAG reachability and node IDs."""
    obligations = graph.get("obligations")
    if not isinstance(obligations, list):
        raise CanonicalAdmissionError("ObligationGraph obligations 必须是 array")
    indexed: dict[str, dict[str, Any]] = {}
    for obligation in obligations:
        if not isinstance(obligation, dict):
            raise CanonicalAdmissionError("ObligationGraph 节点必须是 object")
        obligation_id = obligation.get("obligation_id")
        if not isinstance(obligation_id, str) or obligation_id in indexed:
            raise CanonicalAdmissionError(f"Obligation 节点 ID 重复或无效：{obligation_id}")
        if canonical_json_sha256(obligation["statement"]) != obligation["statement_sha256"]:
            raise CanonicalAdmissionError(
                f"obligation statement digest 不匹配：{obligation_id}"
            )
        indexed[obligation_id] = obligation
    root_id = graph.get("root_obligation_id")
    if root_id not in indexed:
        raise CanonicalAdmissionError(f"root obligation 不存在：{root_id}")
    color: dict[str, int] = {}

    def visit(obligation_id: str) -> None:
        state = color.get(obligation_id, 0)
        if state == 1:
            raise CanonicalAdmissionError(f"ObligationGraph 含循环：{obligation_id}")
        if state == 2:
            return
        color[obligation_id] = 1
        dependencies = indexed[obligation_id].get("dependencies")
        if not isinstance(dependencies, list):
            raise CanonicalAdmissionError(f"obligation dependencies 无效：{obligation_id}")
        for dependency in dependencies:
            if dependency not in indexed:
                raise CanonicalAdmissionError(
                    f"未知 obligation dependency：{obligation_id} -> {dependency}"
                )
            visit(dependency)
        color[obligation_id] = 2

    visit(root_id)
    unreachable = sorted(set(indexed) - color.keys())
    if unreachable:
        raise CanonicalAdmissionError(f"ObligationGraph 含 root 不可达节点：{unreachable[0]}")
    return indexed


def _validate_canonical_job_binding(job: Mapping[str, Any], project_root: Path) -> None:
    """Recompute and verify the complete Problem→Attempt→Graph→node chain."""
    problems, attempts, graphs = _read_admitted_ledgers(project_root)
    graph_nodes: dict[str, dict[str, dict[str, Any]]] = {}
    seen_graph_ids: set[str] = set()
    child_by_predecessor: dict[str, str] = {}
    for graph_id, graph in graphs.items():
        predecessor_id = graph.get("supersedes")
        if predecessor_id is not None:
            if predecessor_id not in seen_graph_ids:
                raise CanonicalAdmissionError(
                    f"Graph supersedes 必须引用更早记录：{graph_id} -> {predecessor_id}"
                )
            if predecessor_id in child_by_predecessor:
                raise CanonicalAdmissionError(
                    f"ObligationGraph revision 分叉：{predecessor_id}"
                )
            child_by_predecessor[predecessor_id] = graph_id
        seen_graph_ids.add(graph_id)
        graph_nodes[graph_id] = _validate_obligation_nodes(graph)
        problem = problems.get(graph.get("problem_id"))
        if problem is None:
            raise CanonicalAdmissionError(
                f"ObligationGraph 引用未知 Problem：{graph.get('problem_id')}"
            )
        expected_contract = canonical_json_sha256(problem)
        if graph.get("problem_contract_sha256") != expected_contract:
            raise CanonicalAdmissionError(
                f"ProblemContract digest 与 Graph 不一致：{graph_id}"
            )
        attempt = attempts.get(graph.get("attempt_id"))
        if attempt is None:
            raise CanonicalAdmissionError(
                f"ObligationGraph 引用未知 Attempt：{graph.get('attempt_id')}"
            )
        if attempt.get("problem_id") != graph.get("problem_id"):
            raise CanonicalAdmissionError(f"Attempt/Problem 跨绑定：{graph_id}")
        if attempt.get("route_id") != graph.get("route_id"):
            raise CanonicalAdmissionError(f"Attempt/Graph route 不一致：{graph_id}")
        if attempt.get("obligation_graph_id") != graph_id:
            if graph.get("supersedes") is None:
                raise CanonicalAdmissionError(f"Attempt 未绑定 current Graph：{graph_id}")
        if attempt.get("problem_contract_sha256") != graph.get("problem_contract_sha256"):
            raise CanonicalAdmissionError(f"Attempt/Graph contract digest 不一致：{graph_id}")
        predecessor_id = graph.get("supersedes")
        if predecessor_id is not None:
            predecessor = graphs.get(predecessor_id)
            if predecessor is None:
                raise CanonicalAdmissionError(
                    f"Graph supersedes 未知 predecessor：{predecessor_id}"
                )
            if (predecessor.get("problem_id"), predecessor.get("attempt_id")) != (
                graph.get("problem_id"),
                graph.get("attempt_id"),
            ):
                raise CanonicalAdmissionError(f"Graph revision 跨 Problem/Attempt：{graph_id}")
    superseded = {
        graph.get("supersedes") for graph in graphs.values() if graph.get("supersedes")
    }

    problem_id = job.get("problem_id")
    problem = problems.get(problem_id)
    if problem is None:
        raise CanonicalAdmissionError(f"Job 引用未知 canonical Problem：{problem_id}")
    if problem.get("lifecycle") != "active":
        raise CanonicalAdmissionError(f"ProblemContract 不是 active：{problem_id}")
    contract_digest = job.get("problem_contract_sha256")
    if canonical_json_sha256(problem) != contract_digest:
        raise CanonicalAdmissionError(f"Job ProblemContract digest 不匹配：{problem_id}")

    attempt_id = job.get("attempt_id")
    attempt = attempts.get(attempt_id)
    if attempt is None:
        raise CanonicalAdmissionError(f"Job 引用未知 Attempt：{attempt_id}")
    for field in ("problem_id", "route_id", "obligation_graph_id", "problem_contract_sha256"):
        if attempt.get(field) != job.get(field):
            raise CanonicalAdmissionError(f"Job/Attempt {field} 不一致：{attempt_id}")

    graph_id = job.get("obligation_graph_id")
    graph = graphs.get(graph_id)
    if graph is None:
        raise CanonicalAdmissionError(f"Job 引用未知 ObligationGraph：{graph_id}")
    if graph_id in superseded:
        raise CanonicalAdmissionError(f"Job 只能绑定 current ObligationGraph：{graph_id}")
    for field in ("problem_id", "attempt_id", "route_id", "problem_contract_sha256"):
        if graph.get(field) != job.get(field):
            raise CanonicalAdmissionError(f"Job/Graph {field} 不一致：{graph_id}")
    if graph.get("root_obligation_id") not in graph_nodes[graph_id]:
        raise CanonicalAdmissionError(f"Graph root obligation 无效：{graph_id}")
    obligation_id = job.get("obligation_id")
    if obligation_id not in graph_nodes[graph_id]:
        raise CanonicalAdmissionError(
            f"Job obligation 不属于 Graph：{obligation_id} -> {graph_id}"
        )


def validate_job(job: Mapping[str, Any], *, schema_path: Path | None = None) -> None:
    """验证一个 Job 合同，不触碰任何研究事实表。"""
    if not isinstance(job, Mapping):
        raise SchemaContractError("Job 必须是 object")
    path = schema_path or (_schema_root() / "coordinator-job.schema.json")
    schema = _read_schema(path)
    _schema_error(
        Draft202012Validator(schema, format_checker=FormatChecker()),
        dict(job),
        "Job",
    )
    if "problem_contract_digest" in job and job["problem_contract_digest"] != job.get(
        "problem_contract_sha256"
    ):
        raise SchemaContractError("problem_contract_digest 与 problem_contract_sha256 不一致")
    if job.get("lease", {}).get("holder") is None and job.get("lease", {}).get("lease_id") is not None:
        raise SchemaContractError("没有 lease holder 时不能有 lease_id")
    if job.get("lease", {}).get("holder") is not None and job.get("lease", {}).get("lease_id") is None:
        raise SchemaContractError("有 lease holder 时必须有 lease_id")


def _payload_for_digest(event: Mapping[str, Any]) -> Any:
    return event.get("payload", {})


def validate_event(event: Mapping[str, Any], *, schema_path: Path | None = None) -> None:
    """验证单个事件及其 payload digest。"""
    if not isinstance(event, Mapping):
        raise SchemaContractError("Event 必须是 object")
    path = schema_path or (_schema_root() / "coordinator-event.schema.json")
    schema = _read_schema(path)
    _schema_error(
        Draft202012Validator(schema, format_checker=FormatChecker()),
        dict(event),
        "Event",
    )
    expected = sha256_json(_payload_for_digest(event))
    if event.get("payload_digest") != expected:
        raise SchemaContractError(
            f"Event payload_digest 不匹配：声明 {event.get('payload_digest')}，实际 {expected}"
        )
    if event.get("event_type") not in EVENT_TYPES:
        raise SchemaContractError(f"未知 event_type：{event.get('event_type')}")


def make_event(
    *,
    job_id: str,
    run_instance_id: str,
    attempt_id: str,
    session_id: str,
    actor: str,
    event_type: str,
    correlation_id: str,
    causation_id: str | None = None,
    payload: Any = None,
    event_id: str | None = None,
    created_at: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    """构造一个待追加 Event。

    sequence 可留空，由 EventStore 在持锁状态下分配，避免并发调用方预取同一
    序号。其余身份和摘要均在这里明确写入。
    """
    if event_type not in EVENT_TYPES:
        raise EventStoreError(f"未知 event_type：{event_type}")
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id or _new_identifier("event"),
        "job_id": job_id,
        "run_instance_id": run_instance_id,
        "attempt_id": attempt_id,
        "session_id": session_id,
        "actor": actor,
        "event_type": event_type,
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "payload_digest": sha256_json({} if payload is None else payload),
        "created_at": created_at or now(),
    }
    if payload is not None:
        value["payload"] = copy.deepcopy(payload)
    if sequence is not None:
        value["sequence"] = sequence
    return value


# fcntl locks protect processes; a separate in-process guard also protects threads,
# because flock semantics are process-oriented on some Unix implementations.
_LOCK_REGISTRY_GUARD = threading.Lock()
_LOCK_REGISTRY: dict[str, threading.RLock] = {}


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path)
    with _LOCK_REGISTRY_GUARD:
        return _LOCK_REGISTRY.setdefault(key, threading.RLock())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class EventStore:
    """单机、只追加、可重放的 JSONL Event Store。"""

    def __init__(self, project_root_or_path: Path | str, event_path: Path | str | None = None) -> None:
        supplied = Path(project_root_or_path).expanduser()
        if event_path is None and supplied.suffix == ".jsonl":
            self.project_root = supplied.parent.parent.parent
            self.event_path = supplied
        else:
            self.project_root = supplied
            requested_event_path = Path(event_path).expanduser() if event_path else (
                supplied / "research" / "events" / "coordinator-events.jsonl"
            )
            self.event_path = (
                supplied / requested_event_path
                if event_path is not None and not requested_event_path.is_absolute()
                else requested_event_path
            )
        self.event_path = self.event_path.absolute()
        self.project_root = self.project_root.absolute()
        self.lock_path = self.event_path.with_name(f".{self.event_path.name}.lock")
        project_event_schema = self.project_root / "research" / "schema" / "coordinator-event.schema.json"
        project_job_schema = self.project_root / "research" / "schema" / "coordinator-job.schema.json"
        self.event_schema_path = project_event_schema if project_event_schema.is_file() else (
            _schema_root() / "coordinator-event.schema.json"
        )
        self.job_schema_path = project_job_schema if project_job_schema.is_file() else (
            _schema_root() / "coordinator-job.schema.json"
        )

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.event_path.parent.mkdir(parents=True, exist_ok=True)
        guard = _thread_lock(self.lock_path)
        guard.acquire()
        handle = self.lock_path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
                guard.release()

    def locked(self) -> Iterator[None]:
        """为 Coordinator 提供一个可重入的持锁上下文。"""
        return self._locked()

    def _read_events_unlocked(self) -> list[dict[str, Any]]:
        if not self.event_path.exists():
            return []
        if self.event_path.is_symlink():
            raise EventStoreError("事件日志不能是符号链接")
        try:
            raw = self.event_path.read_bytes()
        except OSError as exc:
            raise EventStoreError(f"无法读取事件日志：{self.event_path}") from exc
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise EventStoreError("事件日志末行缺少换行，疑似截断；拒绝继续")
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        prior_ids: set[str] = set()
        for sequence, line in enumerate(raw.split(b"\n")[:-1], 1):
            if not line:
                raise EventStoreError(f"事件日志第 {sequence} 行为空，拒绝静默跳过")
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EventStoreError(f"事件日志第 {sequence} 行 JSON 无效") from exc
            if not isinstance(value, dict):
                raise EventStoreError(f"事件日志第 {sequence} 行不是 object")
            validate_event(value, schema_path=self.event_schema_path)
            if value["sequence"] != sequence:
                raise EventStoreError(
                    f"事件序列断裂：第 {sequence} 行声明 {value['sequence']}"
                )
            event_id = value["event_id"]
            if event_id in seen_ids:
                raise EventStoreError(f"事件日志包含重复 event_id：{event_id}")
            causation_id = value["causation_id"]
            if causation_id is not None and causation_id not in prior_ids:
                raise EventStoreError(
                    f"事件 {event_id} 的 causation_id 未指向较早事件：{causation_id}"
                )
            seen_ids.add(event_id)
            prior_ids.add(event_id)
            events.append(value)
        return events

    def read_events(self) -> list[dict[str, Any]]:
        with self._locked():
            return self._read_events_unlocked()

    read = read_events

    def next_sequence(self) -> int:
        with self._locked():
            return len(self._read_events_unlocked()) + 1

    def _normalise_for_append(
        self,
        event: Mapping[str, Any],
        *,
        next_sequence: int,
        existing: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise EventStoreError("Event 必须是 object")
        value = copy.deepcopy(dict(event))
        if "sequence" not in value:
            value["sequence"] = existing["sequence"] if existing is not None else next_sequence
        if "payload_digest" not in value:
            value["payload_digest"] = sha256_json(_payload_for_digest(value))
        validate_event(value, schema_path=self.event_schema_path)
        if existing is None and value["sequence"] != next_sequence:
            raise EventStoreError(
                f"新事件 sequence 必须为 {next_sequence}，实际为 {value['sequence']}"
            )
        return value

    def _append_unlocked(
        self,
        event: Mapping[str, Any],
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        existing = next((item for item in events if item["event_id"] == event.get("event_id")), None)
        normalised = self._normalise_for_append(
            event,
            next_sequence=len(events) + 1,
            existing=existing,
        )
        if existing is not None:
            if existing == normalised:
                return copy.deepcopy(existing)
            raise DuplicateEventError(
                f"event_id 已存在但内容不同：{event.get('event_id')}"
            )
        causation_id = normalised["causation_id"]
        if causation_id is not None and not any(
            item["event_id"] == causation_id for item in events
        ):
            raise EventStoreError(f"causation_id 不存在：{causation_id}")
        encoded = canonical_json_bytes(normalised) + b"\n"
        self.event_path.parent.mkdir(parents=True, exist_ok=True)
        if self.event_path.exists() and self.event_path.is_symlink():
            raise EventStoreError("事件日志不能是符号链接")
        try:
            with self.event_path.open("ab") as handle:
                written = handle.write(encoded)
                if written != len(encoded):
                    raise EventStoreError("事件日志未完整写入")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(self.event_path, 0o600)
            _fsync_directory(self.event_path.parent)
        except OSError as exc:
            raise EventStoreError(f"事件追加失败：{self.event_path}") from exc
        return copy.deepcopy(normalised)

    def append(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """持锁读取、验证并追加一个事件；同 ID 同内容只返回既有事件。"""
        with self._locked():
            events = self._read_events_unlocked()
            stored = self._append_unlocked(event, events)
            return stored

    append_event = append

    def append_many(self, events_to_append: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """在一个锁和多个连续序号内追加事件。"""
        with self._locked():
            events = self._read_events_unlocked()
            stored: list[dict[str, Any]] = []
            for event in events_to_append:
                item = self._append_unlocked(event, events)
                if not any(existing["event_id"] == item["event_id"] for existing in events):
                    events.append(item)
                stored.append(item)
            return stored

    def replay(self) -> dict[str, dict[str, Any]]:
        """严格读取事件并从头派生当前 Job 状态。"""
        with self._locked():
            events = self._read_events_unlocked()
            return _project_events(events, job_schema_path=self.job_schema_path)

    project = replay

    def events_for_job(self, job_id: str) -> list[dict[str, Any]]:
        return [event for event in self.read_events() if event.get("job_id") == job_id]


def _job_immutable_fingerprint(job: Mapping[str, Any]) -> str:
    ignored = {
        "job_id",
        "run_instance_id",
        "attempt_id",
        "session_id",
        "created_at",
        "updated_at",
        "status",
        "lease",
        "last_event_id",
    }
    value = {key: copy.deepcopy(item) for key, item in job.items() if key not in ignored}
    metadata = value.get("metadata")
    if isinstance(metadata, dict):
        metadata = {key: item for key, item in metadata.items() if key != "_correlation_id"}
        if metadata:
            value["metadata"] = metadata
        else:
            value.pop("metadata", None)
    return sha256_json(value)


def _event_lineage_matches_job(event: Mapping[str, Any], job: Mapping[str, Any]) -> None:
    for field in ("job_id", "run_instance_id", "attempt_id", "session_id"):
        if event.get(field) != job.get(field):
            raise ReplayError(
                f"事件 {event.get('event_id')} 的 {field} 与 Job 不一致"
            )


def _check_actor_and_lease(event: Mapping[str, Any], job: Mapping[str, Any]) -> None:
    event_type = event["event_type"]
    actor = event["actor"]
    lease = job.get("lease", {})
    holder = lease.get("holder")
    if event_type == "claimed":
        payload = event.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("lease"), dict):
            raise ReplayError("claimed 事件必须携带 lease")
        claimed_lease = payload["lease"]
        if claimed_lease.get("holder") != actor:
            raise ReplayError("claimed 事件 actor 必须等于 lease holder")
        if not claimed_lease.get("lease_id"):
            raise ReplayError("claimed 事件缺少 lease_id")
        expires_at = claimed_lease.get("expires_at")
        if expires_at is None or _parse_time(expires_at, label="lease expires_at") <= _parse_time(
            event["created_at"], label="event created_at"
        ):
            raise ReplayError("claimed 事件的 lease 必须在事件时刻之后过期")
        return
    payload = event.get("payload")
    if isinstance(payload, dict):
        payload_holder = payload.get("holder")
        if payload_holder is not None and payload_holder != holder:
            raise ReplayError("事件 payload holder 与当前 lease 不一致")
    if actor in ADMIN_ACTORS:
        return
    if holder is None or actor != holder:
        raise ReplayError(
            f"事件 {event['event_id']} 的 actor={actor} 不拥有当前 lease={holder}"
        )
    expires_at = lease.get("expires_at")
    if expires_at is not None and _parse_time(
        event["created_at"], label="event created_at"
    ) > _parse_time(expires_at, label="lease expires_at"):
        raise ReplayError("非管理事件发生在 lease 过期之后")


def _apply_event(
    job: dict[str, Any],
    event: Mapping[str, Any],
    *,
    job_schema_path: Path | None = None,
) -> None:
    current = job["status"]
    event_type = event["event_type"]
    target = EVENT_TO_STATUS[event_type]
    if event_type not in ALLOWED_TRANSITIONS.get(current, set()):
        raise ReplayError(f"非法 Job 状态转换：{current} --{event_type}--> {target}")
    _event_lineage_matches_job(event, job)
    _check_actor_and_lease(event, job)
    if event["correlation_id"] != job["metadata"].get("_correlation_id"):
        raise ReplayError("同一 Job 的 correlation_id 不得漂移")
    payload = event.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise ReplayError("Coordinator Job 事件 payload 必须是 object")
    payload = payload or {}
    declared_status = payload.get("status")
    if declared_status is not None and declared_status != target:
        raise ReplayError("事件 payload status 与生命周期转换不一致")

    if event_type == "claimed":
        lease = payload.get("lease")
        if not isinstance(lease, dict):
            raise ReplayError("claimed 事件缺少 lease object")
        job["lease"] = copy.deepcopy(lease)
    elif event_type == "ready":
        job["lease"] = {"holder": None, "lease_id": None, "expires_at": None}
    else:
        if "checkpoint_digest" in payload:
            checkpoint_digest = payload["checkpoint_digest"]
            if not isinstance(checkpoint_digest, str) or len(checkpoint_digest) != 64:
                raise ReplayError("checkpoint_digest 无效")
            job["checkpoint_digest"] = checkpoint_digest
        if "output_digest" in payload:
            output_digest = payload["output_digest"]
            if not isinstance(output_digest, str) or len(output_digest) != 64:
                raise ReplayError("output_digest 无效")
            job["output_digest"] = output_digest
        if "retry_count" in payload:
            retry_count = payload["retry_count"]
            if not isinstance(retry_count, int) or retry_count < 0:
                raise ReplayError("retry_count 无效")
            job["retry_count"] = retry_count

    job["status"] = target
    job["last_event_id"] = event["event_id"]
    job["updated_at"] = event["created_at"]
    validate_job(job, schema_path=job_schema_path)


def _project_events(
    events: list[Mapping[str, Any]],
    *,
    job_schema_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """纯函数式地从事件序列派生 Job；任何损坏或不合法转换都失败。"""
    jobs: dict[str, dict[str, Any]] = {}
    prior_events: dict[str, Mapping[str, Any]] = {}
    expected_sequence = 1
    for raw_event in events:
        if not isinstance(raw_event, Mapping):
            raise ReplayError("重放输入包含非 object 事件")
        event = dict(raw_event)
        validate_event(event)
        if event["sequence"] != expected_sequence:
            raise ReplayError(
                f"重放 sequence 断裂：期望 {expected_sequence}，实际 {event['sequence']}"
            )
        expected_sequence += 1
        causation_id = event["causation_id"]
        if causation_id is not None and causation_id not in prior_events:
            raise ReplayError(f"causation_id 未指向更早事件：{causation_id}")

        job_id = event["job_id"]
        if event["event_type"] == "created":
            if job_id in jobs:
                raise ReplayError(f"Job 重复 created：{job_id}")
            payload = event.get("payload")
            if not isinstance(payload, dict) or not isinstance(payload.get("job"), dict):
                raise ReplayError("created 事件必须携带 payload.job")
            job = copy.deepcopy(payload["job"])
            validate_job(job, schema_path=job_schema_path)
            if job["status"] != "new":
                raise ReplayError("created 事件的 Job 初始 status 必须为 new")
            if job["job_id"] != job_id:
                raise ReplayError("created 事件的 job_id 身份不一致")
            _event_lineage_matches_job(event, job)
            if job["lease"]["holder"] is not None:
                raise ReplayError("created Job 不能携带活动 lease")
            metadata = job.get("metadata") or {}
            metadata = copy.deepcopy(metadata)
            metadata["_correlation_id"] = event["correlation_id"]
            job["metadata"] = metadata
            job["last_event_id"] = event["event_id"]
            job["updated_at"] = event["created_at"]
            validate_job(job, schema_path=job_schema_path)
            jobs[job_id] = job
        else:
            job = jobs.get(job_id)
            if job is None:
                raise ReplayError(f"Job {job_id} 在 created 前收到 {event['event_type']}")
            _apply_event(job, event, job_schema_path=job_schema_path)
        prior_events[event["event_id"]] = event
    return jobs


def replay_events(
    events: list[Mapping[str, Any]],
    *,
    job_schema_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """公开的纯重放入口，便于删除投影后从事件重建。"""
    return _project_events(events, job_schema_path=job_schema_path)


project_events = replay_events


CoordinatorEventStore = EventStore


class Coordinator:
    """只使用 EventStore 的最小本地 Coordinator。"""

    def __init__(self, project_root_or_store: Path | str | EventStore) -> None:
        if isinstance(project_root_or_store, EventStore):
            self.events = project_root_or_store
        else:
            self.events = EventStore(project_root_or_store)
        self.event_store = self.events

    def _replay_unlocked(self, events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return _project_events(events, job_schema_path=self.events.job_schema_path)

    def _event_for(
        self,
        job: Mapping[str, Any],
        event_type: str,
        *,
        actor: str,
        payload: dict[str, Any] | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        return make_event(
            job_id=job["job_id"],
            run_instance_id=job["run_instance_id"],
            attempt_id=job["attempt_id"],
            session_id=job["session_id"],
            actor=actor,
            event_type=event_type,
            correlation_id=str(job["metadata"].get("_correlation_id", job["job_id"])),
            causation_id=causation_id if causation_id is not None else job.get("last_event_id"),
            payload=payload,
        )

    def _append_transition(
        self,
        job_id: str,
        event_type: str,
        *,
        actor: str,
        payload: dict[str, Any] | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES or event_type == "created":
            raise JobError(f"不是可变更的 Job event_type：{event_type}")
        with self.events._locked():
            events = self.events._read_events_unlocked()
            jobs = self._replay_unlocked(events)
            job = jobs.get(job_id)
            if job is None:
                raise JobError(f"Job 不存在：{job_id}")
            event = self._event_for(
                job,
                event_type,
                actor=actor,
                payload=payload,
                causation_id=causation_id,
            )
            normalised = self.events._normalise_for_append(
                event,
                next_sequence=len(events) + 1,
            )
            # 先在内存中完整重放，避免把非法转换写进 append-only 日志。
            projected = self._replay_unlocked([*events, normalised])
            self.events._append_unlocked(normalised, events)
            return copy.deepcopy(projected[job_id])

    def create_job(
        self,
        job: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        """创建 Job；相同 dedupe_key 的同一合同幂等返回，不写数学真相表。"""
        if job is not None and fields:
            raise JobError("create_job 不能同时传 job object 与散列字段")
        candidate = copy.deepcopy(dict(job)) if job is not None else copy.deepcopy(fields)
        created_at = candidate.get("created_at", now())
        identity_defaults = {
            "schema_version": SCHEMA_VERSION,
            "project_id": candidate.get("project_id", "project:local"),
            "workflow_id": candidate.get("workflow_id", "workflow:default"),
            "task_id": candidate.get("task_id", "task:default"),
            "step_id": candidate.get("step_id", "step:default"),
            "job_id": candidate.get("job_id", _new_identifier("job")),
            "run_instance_id": candidate.get("run_instance_id", _new_identifier("run")),
            "attempt_id": candidate.get("attempt_id", _new_identifier("attempt")),
            "session_id": candidate.get("session_id", _new_identifier("session")),
            "problem_id": candidate.get("problem_id"),
            "problem_contract_sha256": candidate.get("problem_contract_sha256", candidate.get("problem_contract_digest")),
            "adapter": candidate.get("adapter"),
            "input_digest": candidate.get("input_digest"),
            "status": "new",
            "created_at": created_at,
            "updated_at": candidate.get("updated_at", created_at),
            "budgets": {**DEFAULT_BUDGETS, **candidate.get("budgets", {})},
            "write_scopes": list(candidate.get("write_scopes", [])),
            "lease": {"holder": None, "lease_id": None, "expires_at": None},
        }
        for key, value in identity_defaults.items():
            if value is not None and key not in candidate:
                candidate[key] = value
        candidate.setdefault("schema_version", SCHEMA_VERSION)
        candidate.setdefault("status", "new")
        candidate.setdefault("created_at", created_at)
        candidate.setdefault("updated_at", created_at)
        candidate.setdefault("budgets", {**DEFAULT_BUDGETS})
        candidate.setdefault("write_scopes", [])
        candidate.setdefault("lease", {"holder": None, "lease_id": None, "expires_at": None})
        if "problem_contract_digest" in candidate and "problem_contract_sha256" not in candidate:
            candidate["problem_contract_sha256"] = candidate["problem_contract_digest"]
        if "problem_contract_digest" in candidate:
            if candidate["problem_contract_digest"] != candidate.get("problem_contract_sha256"):
                raise JobError("ProblemContract digest 别名不一致")
        if not isinstance(candidate.get("problem_contract_sha256"), str):
            raise JobError("create_job 必须绑定 problem_contract_sha256")
        if not isinstance(candidate.get("input_digest"), str):
            raise JobError("create_job 必须绑定 input_digest")
        if not isinstance(candidate.get("adapter"), str):
            raise JobError("create_job 必须绑定 adapter")
        if not isinstance(candidate.get("dedupe_key"), str):
            immutable = {
                key: candidate.get(key)
                for key in (
                    "project_id",
                    "workflow_id",
                    "task_id",
                    "step_id",
                    "problem_id",
                    "problem_contract_sha256",
                    "adapter",
                    "input_digest",
                    "write_scopes",
                    "budgets",
                )
            }
            candidate["dedupe_key"] = f"dedupe:{sha256_json(immutable)}"
        # Do not persist the alias as a second, competing digest field.
        candidate.pop("problem_contract_digest", None)
        validate_job(candidate, schema_path=self.events.job_schema_path)
        if candidate["status"] != "new":
            raise JobError("新 Job 的 status 必须为 new")
        if candidate.get("last_event_id") is not None:
            raise JobError("新 Job 不能预设 last_event_id")
        # A created event is a production control-plane admission point.  It
        # must be bound to the current canonical Problem/Attempt/Graph snapshot
        # before any append is attempted; missing, stale, malformed, or
        # cross-bound ledgers therefore cannot be bypassed by a synthetic Job.
        _validate_canonical_job_binding(candidate, self.events.project_root)
        correlation_id = candidate.get("metadata", {}).get("correlation_id") if isinstance(candidate.get("metadata"), dict) else None
        correlation_id = correlation_id or candidate["job_id"]

        with self.events._locked():
            events = self.events._read_events_unlocked()
            jobs = self._replay_unlocked(events)
            existing_by_id = jobs.get(candidate["job_id"])
            if existing_by_id is not None:
                if _job_immutable_fingerprint(existing_by_id) == _job_immutable_fingerprint(candidate):
                    return copy.deepcopy(existing_by_id)
                raise JobAlreadyExists(f"job_id 已绑定不同 Job：{candidate['job_id']}")
            for existing in jobs.values():
                if existing["dedupe_key"] != candidate["dedupe_key"]:
                    continue
                if _job_immutable_fingerprint(existing) != _job_immutable_fingerprint(candidate):
                    raise JobAlreadyExists(
                        f"dedupe_key 已绑定不同 Job：{candidate['dedupe_key']}"
                    )
                return copy.deepcopy(existing)
            event = make_event(
                job_id=candidate["job_id"],
                run_instance_id=candidate["run_instance_id"],
                attempt_id=candidate["attempt_id"],
                session_id=candidate["session_id"],
                actor="coordinator",
                event_type="created",
                correlation_id=correlation_id,
                payload={"job": candidate},
            )
            normalised = self.events._normalise_for_append(event, next_sequence=len(events) + 1)
            projected = self._replay_unlocked([*events, normalised])
            self.events._append_unlocked(normalised, events)
            return copy.deepcopy(projected[candidate["job_id"]])

    create = create_job

    def get_job(self, job_id: str) -> dict[str, Any]:
        jobs = self.events.replay()
        try:
            return copy.deepcopy(jobs[job_id])
        except KeyError as exc:
            raise JobError(f"Job 不存在：{job_id}") from exc

    def list_jobs(self) -> list[dict[str, Any]]:
        return [copy.deepcopy(item) for item in self.events.replay().values()]

    def replay(self) -> dict[str, dict[str, Any]]:
        return self.events.replay()

    project = replay

    def ready_job(self, job_id: str, *, actor: str = "coordinator", reason: str | None = None) -> dict[str, Any]:
        payload = {"reason": reason} if reason is not None else None
        return self._append_transition(job_id, "ready", actor=actor, payload=payload)

    mark_ready = ready_job

    def claim_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 300,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(worker_id, str) or not worker_id:
            raise LeaseError("worker_id 必须非空")
        if not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise LeaseError("lease_seconds 必须为正整数")
        with self.events._locked():
            events = self.events._read_events_unlocked()
            jobs = self._replay_unlocked(events)
            job = jobs.get(job_id)
            if job is None:
                raise JobError(f"Job 不存在：{job_id}")
            if session_id is not None and session_id != job["session_id"]:
                raise LeaseError("claim session_id 与 Job session_id 不一致")
            if job["status"] == "claimed":
                expires_at = job["lease"].get("expires_at")
                expired = expires_at is None or _parse_time(expires_at) <= datetime.now(timezone.utc)
                if not expired:
                    if job["lease"].get("holder") == worker_id:
                        # A retry after a lost response is idempotent at the
                        # Coordinator boundary: return the live lease without
                        # appending a second claimed event.  session_id was
                        # checked above when supplied by the caller.
                        return copy.deepcopy(job)
                    raise LeaseError("Job 已被未过期 lease 认领")
                release = self._event_for(
                    job,
                    "ready",
                    actor="coordinator",
                    payload={"reason": "expired_lease_recovery"},
                )
                release = self.events._normalise_for_append(release, next_sequence=len(events) + 1)
                self._replay_unlocked([*events, release])
                self.events._append_unlocked(release, events)
                events.append(release)
                jobs = self._replay_unlocked(events)
                job = jobs[job_id]
            if job["status"] != "ready":
                raise JobError(f"Job 只有 ready 才能 claim，当前为 {job['status']}")
            claimed_at = datetime.now(timezone.utc)
            lease = {
                "holder": worker_id,
                "lease_id": _new_identifier("lease"),
                "expires_at": (claimed_at + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z"),
                "claimed_at": claimed_at.isoformat().replace("+00:00", "Z"),
            }
            event = self._event_for(
                job,
                "claimed",
                actor=worker_id,
                payload={"lease": lease},
            )
            normalised = self.events._normalise_for_append(event, next_sequence=len(events) + 1)
            projected = self._replay_unlocked([*events, normalised])
            self.events._append_unlocked(normalised, events)
            return copy.deepcopy(projected[job_id])

    claim = claim_job

    def start_job(self, job_id: str, *, actor: str = "coordinator") -> dict[str, Any]:
        return self._append_transition(job_id, "started", actor=actor)

    start = start_job

    def checkpoint_job(
        self,
        job_id: str,
        checkpoint_digest: str,
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        if not isinstance(checkpoint_digest, str) or len(checkpoint_digest) != 64 or any(
            character not in "0123456789abcdef" for character in checkpoint_digest
        ):
            raise JobError("checkpoint_digest 必须是 64 位小写 SHA-256")
        return self._append_transition(
            job_id,
            "checkpointed",
            actor=actor,
            payload={"checkpoint_digest": checkpoint_digest, **metadata},
        )

    checkpoint = checkpoint_job

    def candidate_created(
        self,
        job_id: str,
        *,
        actor: str = "coordinator",
        output_digest: str | None = None,
        **metadata: Any,
    ) -> dict[str, Any]:
        payload = dict(metadata)
        if output_digest is not None:
            payload["output_digest"] = output_digest
        return self._append_transition(job_id, "candidate_created", actor=actor, payload=payload or None)

    def verifier_requested(
        self,
        job_id: str,
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        return self._append_transition(job_id, "verifier_requested", actor=actor, payload=metadata or None)

    def verifier_completed(
        self,
        job_id: str,
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        return self._append_transition(job_id, "verifier_completed", actor=actor, payload=metadata or None)

    def block_job(
        self,
        job_id: str,
        reason: str,
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        return self._append_transition(
            job_id,
            "blocked",
            actor=actor,
            payload={"reason": reason, **metadata},
        )

    block = block_job

    def fail_job(
        self,
        job_id: str,
        error: str,
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        return self._append_transition(
            job_id,
            "failed",
            actor=actor,
            payload={"error": error, **metadata},
        )

    fail = fail_job

    def complete_job(
        self,
        job_id: str,
        *,
        actor: str = "coordinator",
        output_digest: str | None = None,
        **metadata: Any,
    ) -> dict[str, Any]:
        payload = dict(metadata)
        if output_digest is not None:
            payload["output_digest"] = output_digest
        return self._append_transition(job_id, "completed", actor=actor, payload=payload or None)

    complete = complete_job

    def cancel_job(
        self,
        job_id: str,
        reason: str = "cancelled by coordinator",
        *,
        actor: str = "coordinator",
        **metadata: Any,
    ) -> dict[str, Any]:
        return self._append_transition(
            job_id,
            "cancelled",
            actor=actor,
            payload={"reason": reason, **metadata},
        )

    cancel = cancel_job

    def append_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """低层追加入口；合法 Job 生命周期仍由 replay 负责检查。"""
        return self.events.append(event)


__all__ = [
    "ADMIN_ACTORS",
    "ALLOWED_TRANSITIONS",
    "Coordinator",
    "CoordinatorEventStore",
    "CoordinatorError",
    "CanonicalAdmissionError",
    "DEFAULT_BUDGETS",
    "DuplicateEventError",
    "EVENT_TO_STATUS",
    "EVENT_TYPES",
    "EventStore",
    "EventStoreError",
    "JobAlreadyExists",
    "JobError",
    "LeaseError",
    "ReplayError",
    "SCHEMA_VERSION",
    "SchemaContractError",
    "canonical_json_bytes",
    "make_event",
    "now",
    "project_events",
    "replay_events",
    "sha256_bytes",
    "sha256_json",
    "validate_event",
    "validate_job",
]
