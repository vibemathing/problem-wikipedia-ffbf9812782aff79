"""Durable, candidate-only intake for Coordinator HandoffEnvelopes.

The intake bridge is deliberately narrower than the mathematical truth plane:

    HandoffEnvelope -> CandidateArtifact -> Coordinator events

It never creates Attempt, EvidenceLink, Result, or Solution records.  The
Candidate JSONL ledger is locked before the Coordinator EventStore lock is
entered.  A small 0600 pending receipt makes the non-atomic boundary
recoverable without ever treating an existing Candidate as idempotent unless
that pending receipt (or a final receipt) proves its identity.
"""

from __future__ import annotations

import copy
import fcntl
import json
import os
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .coordinator import Coordinator, CoordinatorError
from .evidence import EvidenceError, load_verifier_registry
from .handoff import (
    HandoffError,
    HandoffIdentityError,
    canonical_json_sha256,
    candidate_proposal,
    validate_handoff,
)


SCHEMA_VERSION = "1.0.0"
CANDIDATE_LEDGER = Path("research/records/candidate-artifacts.jsonl")
RECEIPT_DIRECTORY = Path("research/artifacts/receipts/handoff-intake")
RECEIPT_SCHEMA = "handoff-intake-receipt.schema.json"
CANDIDATE_SCHEMA = "candidate-artifact.schema.json"
PENDING_SUFFIX = ".pending"

EVENT_DIGEST_KEYS = ("candidate_created", "verifier_requested", "blocked", "failed")
EVENT_ID_KEYS = EVENT_DIGEST_KEYS


class HandoffIntakeError(RuntimeError):
    """The handoff cannot be safely admitted to the candidate-only bridge."""


class HandoffIntakeConflict(HandoffIntakeError):
    """An existing Candidate, pending receipt, or event has conflicting content."""


class StalePendingError(HandoffIntakeError):
    """An unrelated or malformed pending receipt blocks safe reconciliation."""


class InjectedCrash(HandoffIntakeError):
    """Test-only crash point; the pending receipt is intentionally retained."""


# The local lock is supplemental to fcntl: flock is process-scoped on some
# Unix implementations, while multiple threads in one process still need a
# mutual exclusion point.
_LOCK_REGISTRY_GUARD = threading.Lock()
_LOCK_REGISTRY: dict[str, threading.RLock] = {}


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path)
    with _LOCK_REGISTRY_GUARD:
        return _LOCK_REGISTRY.setdefault(key, threading.RLock())


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise HandoffIntakeError(f"{label} 必须是带时区的 ISO 8601 时间")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HandoffIntakeError(f"{label} 无效") from exc
    if parsed.tzinfo is None:
        raise HandoffIntakeError(f"{label} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HandoffIntakeError("intake payload 必须是有限 JSON") from exc


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise HandoffIntakeError(f"无法打开目录进行 fsync：{path}") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "research" / "schema"


def _schema_path(project_root: Path, filename: str) -> Path:
    candidate = project_root / "research" / "schema" / filename
    if candidate.is_file() and not candidate.is_symlink():
        return candidate
    fallback = _schema_root() / filename
    if not fallback.is_file() or fallback.is_symlink():
        raise HandoffIntakeError(f"schema 缺失或不安全：{filename}")
    return fallback


def _schema_error(value: Any, path: Path, label: str) -> None:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffIntakeError(f"无法读取 {label} schema：{path}") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "<root>"
        raise HandoffIntakeError(f"{label} schema 无效 ({location})：{errors[0].message}")


def _ensure_regular(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise HandoffIntakeError(f"无法检查 {label}：{path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise HandoffIntakeError(f"{label} 必须是 regular file：{path}")


def _read_strict_json(path: Path, label: str) -> dict[str, Any]:
    _ensure_regular(path, label)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HandoffIntakeError(f"无法读取 {label}：{path}") from exc
    if not raw or not raw.endswith(b"\n"):
        raise HandoffIntakeError(f"{label} 缺少完整末行换行：{path}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffIntakeError(f"{label} 不是有效 JSON：{path}") from exc
    if not isinstance(value, dict):
        raise HandoffIntakeError(f"{label} 必须是 JSON object：{path}")
    return value


def _read_candidate_ledger(project_root: Path) -> list[dict[str, Any]]:
    path = project_root / CANDIDATE_LEDGER
    if path.is_symlink():
        raise HandoffIntakeError("Candidate ledger 不能是符号链接")
    if not path.exists():
        return []
    _ensure_regular(path, "Candidate ledger")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HandoffIntakeError(f"无法读取 Candidate ledger：{path}") from exc
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise HandoffIntakeError("Candidate ledger 末行截断，拒绝继续")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    schema_path = _schema_path(project_root, CANDIDATE_SCHEMA)
    for number, line in enumerate(raw.split(b"\n")[:-1], 1):
        if not line:
            raise HandoffIntakeError(f"Candidate ledger 第 {number} 行为空")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HandoffIntakeError(f"Candidate ledger 第 {number} 行 JSON 无效") from exc
        if not isinstance(value, dict):
            raise HandoffIntakeError(f"Candidate ledger 第 {number} 行不是 object")
        _schema_error(value, schema_path, "Candidate")
        candidate_id = value["candidate_id"]
        if candidate_id in seen:
            raise HandoffIntakeError(f"Candidate ledger 重复 candidate_id：{candidate_id}")
        seen.add(candidate_id)
        records.append(value)
    return records


def _append_candidate(project_root: Path, proposal: Mapping[str, Any]) -> None:
    path = project_root / CANDIDATE_LEDGER
    _ensure_regular(path, "Candidate ledger")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = _canonical_bytes(dict(proposal)) + b"\n"
    try:
        with path.open("ab") as handle:
            written = handle.write(encoded)
            if written != len(encoded):
                raise HandoffIntakeError("Candidate ledger 未完整写入")
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except OSError as exc:
        raise HandoffIntakeError(f"Candidate ledger 追加失败：{path}") from exc


@contextmanager
def _candidate_ledger_lock(project_root: Path) -> Iterator[None]:
    ledger_path = project_root / CANDIDATE_LEDGER
    lock_path = ledger_path.with_name(f".{ledger_path.name}.lock")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if lock_path.is_symlink():
        raise HandoffIntakeError("Candidate ledger lock 不能是符号链接")
    guard = _thread_lock(lock_path)
    guard.acquire()
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            os.chmod(lock_path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            raise HandoffIntakeError(f"无法取得 Candidate ledger lock：{lock_path}") from exc
        yield
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        guard.release()


class HandoffIntake:
    """Coordinator-bound durable HandoffEnvelope receiver."""

    def __init__(
        self,
        project_root: Path | str,
        coordinator: Coordinator | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        if not self.project_root.is_dir():
            raise HandoffIntakeError(f"project root 不是目录：{self.project_root}")
        self.coordinator = coordinator or Coordinator(self.project_root)
        if self.coordinator.events.project_root != self.project_root:
            try:
                self.coordinator.events.event_path.absolute().resolve().relative_to(self.project_root)
            except ValueError as exc:
                raise HandoffIntakeError("Coordinator EventStore project root 与 intake root 不一致") from exc
        self.receipt_dir = self.project_root / RECEIPT_DIRECTORY

    def _ensure_receipt_dir(self) -> None:
        if self.receipt_dir.is_symlink():
            raise HandoffIntakeError("handoff intake receipt directory 不能是符号链接")
        self.receipt_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.receipt_dir.is_dir() or self.receipt_dir.is_symlink():
            raise HandoffIntakeError("handoff intake receipt directory 必须是目录")
        try:
            os.chmod(self.receipt_dir, 0o700)
        except OSError as exc:
            raise HandoffIntakeError("无法保护 handoff receipt directory") from exc

    def _paths(self, envelope_sha256: str) -> tuple[Path, Path]:
        if len(envelope_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in envelope_sha256
        ):
            raise HandoffIntakeError("envelope digest 无效")
        return (
            self.receipt_dir / f"{envelope_sha256}.json",
            self.receipt_dir / f".{envelope_sha256}{PENDING_SUFFIX}",
        )

    def _scan_pending(self, pending_path: Path) -> dict[str, Any] | None:
        pending_files: list[Path] = []
        try:
            children = list(self.receipt_dir.iterdir())
        except OSError as exc:
            raise HandoffIntakeError("无法扫描 handoff pending receipts") from exc
        for child in children:
            if child.name.startswith(".") and child.name.endswith(".tmp"):
                raise StalePendingError(f"发现未清理的 receipt 临时文件：{child.name}")
            if child.name.endswith(".pending") or ".pending." in child.name:
                pending_files.append(child)
        for child in pending_files:
            if child != pending_path:
                raise StalePendingError(
                    f"发现不属于当前 envelope 的 pending receipt：{child.name}"
                )
        if not pending_files:
            return None
        try:
            mode = pending_path.stat().st_mode
        except OSError as exc:
            raise StalePendingError(f"无法检查 pending receipt：{pending_path}") from exc
        if stat.S_IMODE(mode) != 0o600:
            raise StalePendingError("pending receipt 必须严格为 0600")
        pending = _read_strict_json(pending_path, "pending receipt")
        try:
            _schema_error(pending, self._receipt_schema_path(), "Handoff intake pending receipt")
        except HandoffIntakeError as exc:
            raise StalePendingError(str(exc)) from exc
        return pending

    def _receipt_schema_path(self) -> Path:
        return _schema_path(self.project_root, RECEIPT_SCHEMA)

    def _read_final(self, receipt_path: Path) -> dict[str, Any] | None:
        if not receipt_path.exists():
            return None
        try:
            mode = receipt_path.stat().st_mode
        except OSError as exc:
            raise HandoffIntakeError(f"无法检查 final receipt：{receipt_path}") from exc
        if stat.S_IMODE(mode) != 0o600:
            raise HandoffIntakeError("final receipt 必须严格为 0600")
        value = _read_strict_json(receipt_path, "final receipt")
        _schema_error(value, self._receipt_schema_path(), "Handoff intake receipt")
        return value

    def _write_exclusive_json(self, path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
        if path.exists() or path.is_symlink():
            raise HandoffIntakeConflict(f"目标 JSON 已存在：{path}")
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags, mode)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, mode)
            _fsync_directory(path.parent)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise HandoffIntakeError(f"JSON durable write failed：{path}") from exc

    def _write_final_atomic(self, path: Path, value: Mapping[str, Any]) -> None:
        if path.exists() or path.is_symlink():
            raise HandoffIntakeConflict(f"final receipt 已存在：{path}")
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise StalePendingError(f"发现未清理的 final receipt 临时文件：{temporary.name}")
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            _fsync_directory(path.parent)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise HandoffIntakeError(f"final receipt durable write failed：{path}") from exc

    def _update_pending(self, pending_path: Path, value: Mapping[str, Any]) -> None:
        try:
            _schema_error(dict(value), self._receipt_schema_path(), "Handoff intake pending receipt")
        except HandoffIntakeError as exc:
            raise StalePendingError(str(exc)) from exc
        if not pending_path.exists() or pending_path.is_symlink():
            raise StalePendingError("pending receipt 在更新前消失或变为符号链接")
        _ensure_regular(pending_path, "pending receipt")
        temporary = pending_path.with_name(f".{pending_path.name}.{os.getpid()}.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise StalePendingError(f"发现未清理的 pending 临时文件：{temporary.name}")
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, pending_path)
            os.chmod(pending_path, 0o600)
            _fsync_directory(pending_path.parent)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise HandoffIntakeError(f"pending receipt update failed：{pending_path}") from exc

    def _job_identity(self, job: Mapping[str, Any], envelope: Mapping[str, Any]) -> dict[str, Any]:
        graph_id = job.get("obligation_graph_id")
        if job.get("graph_id") is not None:
            if graph_id is not None and graph_id != job.get("graph_id"):
                raise HandoffIdentityError("Coordinator Job graph identity has conflicting aliases")
            graph_id = job.get("graph_id")
        contract_digest = job.get("problem_contract_sha256", job.get("problem_contract_digest"))
        pairs = (
            ("job_id", job.get("job_id"), envelope.get("job_id")),
            ("run_instance_id", job.get("run_instance_id"), envelope.get("run_instance_id")),
            ("attempt_id", job.get("attempt_id"), envelope.get("attempt_id")),
            ("session_id", job.get("session_id"), envelope.get("session_id")),
            ("dedupe_key", job.get("dedupe_key"), envelope.get("dedupe_key")),
            ("problem_id", job.get("problem_id"), envelope.get("problem_id")),
            (
                "problem_contract_sha256",
                contract_digest,
                envelope.get("problem_contract_sha256"),
            ),
            ("route_id", job.get("route_id"), envelope.get("route_id")),
            ("graph_id", graph_id, envelope.get("graph_id")),
            ("obligation_id", job.get("obligation_id"), envelope.get("obligation_id")),
        )
        for label, actual, expected in pairs:
            if actual is None or actual != expected:
                raise HandoffIdentityError(
                    f"Coordinator Job {label} drift: expected {expected}, got {actual}"
                )
        metadata = job.get("metadata")
        if isinstance(metadata, dict) and metadata.get("correlation_id") is not None:
            if metadata["correlation_id"] != envelope["correlation_id"]:
                raise HandoffIdentityError("Coordinator Job correlation_id drift")
        project_id = job.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            raise HandoffIdentityError("Coordinator Job 缺少 project_id")
        return {
            "project_id": project_id,
            "job_id": job["job_id"],
            "run_instance_id": job["run_instance_id"],
            "attempt_id": job["attempt_id"],
            "session_id": job["session_id"],
            "dedupe_key": job["dedupe_key"],
            "problem_id": job["problem_id"],
            "problem_contract_sha256": contract_digest,
            "route_id": job["route_id"],
            "graph_id": graph_id,
            "obligation_id": job["obligation_id"],
        }

    def _bind_job(
        self,
        job: Mapping[str, Any],
        envelope: Mapping[str, Any],
        *,
        recovery: bool,
        require_active_lease: bool = True,
    ) -> dict[str, Any]:
        identity = self._job_identity(job, envelope)
        outcome = envelope["outcome"]
        status = job.get("status")
        # A fresh candidate may only enter from started/checkpointed.  The
        # later states are recovery-only: they are admissible only when the
        # same pending/final receipt proves that this bridge already crossed
        # the corresponding event boundary.
        if outcome == "candidate":
            initial = {"started", "checkpointed"}
            recovery_states = {"candidate_ready", "verifying", "verifier_completed", "completed"}
        elif outcome == "blocked":
            initial = {"started", "checkpointed"}
            recovery_states = {"blocked"}
        else:
            initial = {"started", "checkpointed"}
            recovery_states = {"failed"}
        if status not in initial and not (recovery and status in recovery_states):
            raise HandoffIdentityError(
                f"Job {identity['job_id']} status={status} 不允许接收 outcome={outcome}"
            )
        producer = envelope.get("producer")
        principal = producer.get("principal") if isinstance(producer, dict) else None
        lease = job.get("lease")
        if not isinstance(lease, dict):
            raise HandoffIdentityError("Coordinator Job 缺少 lease")
        holder = lease.get("holder")
        if not isinstance(principal, str) or holder != principal:
            raise HandoffIdentityError(
                f"Envelope actor={principal} 不是当前 lease holder={holder}"
            )
        expires_at = lease.get("expires_at")
        if require_active_lease:
            if not isinstance(expires_at, str) or _parse_time(expires_at, "lease expires_at") <= datetime.now(timezone.utc):
                raise HandoffIdentityError("Coordinator Job lease 已过期或无有效 expires_at")
        return {"identity": identity, "principal": principal, "status": status}

    def _registered_generator(self, envelope: Mapping[str, Any]) -> None:
        generator = envelope["candidate"]["generator"]
        try:
            registry = load_verifier_registry(self.project_root)
        except EvidenceError as exc:
            raise HandoffIntakeError(f"无法验证 verifier registry：{exc}") from exc
        entry = registry.get(generator)
        if entry is None or entry.get("role") != "generator":
            raise HandoffIntakeError(f"Candidate generator 未注册为 generator：{generator}")

    def _pending_identity_check(
        self,
        pending: Mapping[str, Any],
        *,
        receipt_id: str,
        envelope_sha256: str,
        outcome: str,
        identity: Mapping[str, Any],
        proposal: Mapping[str, Any] | None,
    ) -> None:
        try:
            _schema_error(
                dict(pending),
                self._receipt_schema_path(),
                "Handoff intake pending receipt",
            )
        except HandoffIntakeError as exc:
            raise StalePendingError(str(exc)) from exc
        expected_decision = {
            "candidate": "candidate_only",
            "blocked": "blocked",
            "transport_failure": "transport_failure",
        }[outcome]
        if pending.get("decision") != expected_decision or pending.get("idempotent") is not False:
            raise StalePendingError("pending decision/idempotent 不匹配")
        if pending.get("completed_at") is not None:
            raise StalePendingError("pending receipt 不应有 completed_at")
        if pending.get("receipt_id") != receipt_id:
            raise StalePendingError("pending receipt_id 不匹配")
        if pending.get("envelope_sha256") != envelope_sha256:
            raise StalePendingError("pending envelope digest 不匹配")
        if pending.get("outcome") != outcome:
            raise StalePendingError("pending outcome 不匹配")
        if pending.get("job_identity") != dict(identity):
            raise StalePendingError("pending Job identity 不匹配")
        expected_hash = canonical_json_sha256(proposal) if proposal is not None else None
        expected_candidate_id = proposal.get("candidate_id") if proposal is not None else None
        expected_artifact_hash = (
            proposal.get("artifact", {}).get("sha256") if proposal is not None else None
        )
        if pending.get("candidate_id") != expected_candidate_id:
            raise StalePendingError("pending candidate_id 不匹配")
        if pending.get("candidate_record_sha256") != expected_hash:
            raise StalePendingError("pending Candidate digest 不匹配")
        if pending.get("candidate_artifact_sha256") != expected_artifact_hash:
            raise StalePendingError("pending artifact digest 不匹配")
        event_ids = pending.get("event_ids")
        event_digests = pending.get("event_digests")
        if not isinstance(event_ids, dict) or set(event_ids) != set(EVENT_ID_KEYS):
            raise StalePendingError("pending event_ids 结构不匹配")
        if not isinstance(event_digests, dict) or set(event_digests) != set(EVENT_DIGEST_KEYS):
            raise StalePendingError("pending event_digests 结构不匹配")
        for key in EVENT_ID_KEYS:
            event_id = event_ids[key]
            event_digest = event_digests[key]
            if event_id is not None and not isinstance(event_id, str):
                raise StalePendingError(f"pending event_id 无效：{key}")
            if event_digest is not None:
                if not isinstance(event_digest, str) or len(event_digest) != 64 or any(
                    character not in "0123456789abcdef" for character in event_digest
                ):
                    raise StalePendingError(f"pending event digest 无效：{key}")
            if (event_id is None) != (event_digest is None):
                raise StalePendingError(f"pending event_id/digest 必须成对出现：{key}")
        if outcome == "candidate":
            forbidden = ("blocked", "failed")
        elif outcome == "blocked":
            forbidden = ("candidate_created", "verifier_requested", "failed")
        else:
            forbidden = ("candidate_created", "verifier_requested", "blocked")
        if any(event_ids[key] is not None for key in forbidden):
            raise StalePendingError("pending event 类型与 outcome 冲突")

    def _base_pending(
        self,
        *,
        receipt_id: str,
        envelope_sha256: str,
        envelope: Mapping[str, Any],
        identity: Mapping[str, Any],
        proposal: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        candidate_id = proposal.get("candidate_id") if proposal is not None else None
        candidate_record_sha256 = canonical_json_sha256(proposal) if proposal is not None else None
        candidate_artifact_sha256 = (
            proposal.get("artifact", {}).get("sha256") if proposal is not None else None
        )
        at = now()
        return {
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "envelope_sha256": envelope_sha256,
            "outcome": envelope["outcome"],
            "decision": {
                "candidate": "candidate_only",
                "blocked": "blocked",
                "transport_failure": "transport_failure",
            }[envelope["outcome"]],
            "idempotent": False,
            "job_identity": copy.deepcopy(dict(identity)),
            "candidate_id": candidate_id,
            "candidate_record_sha256": candidate_record_sha256,
            "candidate_artifact_sha256": candidate_artifact_sha256,
            "event_ids": {key: None for key in EVENT_ID_KEYS},
            "event_digests": {key: None for key in EVENT_DIGEST_KEYS},
            "stages": {
                "validated": {"status": "completed", "at": at},
                "candidate_persisted": {
                    "status": "pending" if proposal is not None else "skipped",
                    "at": at,
                },
                "candidate_created_event": {
                    "status": "pending" if proposal is not None else "skipped",
                    "at": at,
                },
                "verifier_requested_event": {
                    "status": "pending" if proposal is not None else "skipped",
                    "at": at,
                },
                "finalized": {"status": "pending", "at": at},
            },
            "created_at": at,
            "completed_at": None,
        }

    def _set_stage(self, pending: dict[str, Any], name: str, status: str) -> None:
        pending["stages"][name] = {"status": status, "at": now()}

    def _event_payload_matches(
        self,
        event: Mapping[str, Any],
        expected: Mapping[str, Any],
    ) -> bool:
        payload = event.get("payload")
        if not isinstance(payload, dict):
            return False
        return all(payload.get(key) == value for key, value in expected.items())

    def _event_by_id(
        self,
        events: list[dict[str, Any]],
        event_id: str,
        event_type: str,
        expected_payload: Mapping[str, Any],
        identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        matches = [event for event in events if event.get("event_id") == event_id]
        if len(matches) != 1:
            raise HandoffIntakeConflict(f"receipt event_id 不存在或不唯一：{event_id}")
        event = matches[0]
        if event.get("event_type") != event_type:
            raise HandoffIntakeConflict(f"receipt event type drift：{event_id}")
        for field in ("job_id", "run_instance_id", "attempt_id", "session_id"):
            if event.get(field) != identity[field]:
                raise HandoffIntakeConflict(f"receipt event {field} identity drift：{event_id}")
        if not self._event_payload_matches(event, expected_payload):
            raise HandoffIntakeConflict(f"receipt event metadata drift：{event_id}")
        return event

    def _find_event(
        self,
        events: list[dict[str, Any]],
        *,
        job_id: str,
        event_type: str,
        expected_payload: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        candidates = [
            event
            for event in events
            if event.get("job_id") == job_id and event.get("event_type") == event_type
        ]
        matching = [event for event in candidates if self._event_payload_matches(event, expected_payload)]
        if len(matching) > 1:
            raise HandoffIntakeConflict(f"同一 Job 存在多个相同 {event_type} 事件")
        if matching:
            if len(candidates) != 1:
                raise HandoffIntakeConflict(f"同一 Job 存在冲突 {event_type} 事件")
            return matching[0]
        if candidates:
            raise HandoffIntakeConflict(f"同一 Job 存在 metadata 不匹配的 {event_type} 事件")
        return None

    def _event_metadata(
        self,
        envelope: Mapping[str, Any],
        *,
        candidate_record_sha256: str | None,
        candidate_id: str | None,
    ) -> dict[str, Any]:
        return {
            "envelope_sha256": canonical_json_sha256(envelope),
            "envelope_correlation_id": envelope["correlation_id"],
            "envelope_causation_id": envelope["causation_id"],
            "candidate_id": candidate_id,
            "candidate_record_sha256": candidate_record_sha256,
        }

    def _reconcile_candidate_event(
        self,
        pending: dict[str, Any],
        envelope: Mapping[str, Any],
        identity: Mapping[str, Any],
        principal: str,
    ) -> None:
        expected = {
            **self._event_metadata(
                envelope,
                candidate_record_sha256=pending["candidate_record_sha256"],
                candidate_id=pending["candidate_id"],
            ),
            "output_digest": pending["candidate_artifact_sha256"],
        }
        events = self.coordinator.events.read_events()
        event_id = pending["event_ids"].get("candidate_created")
        if event_id is not None:
            event = self._event_by_id(
                events,
                event_id,
                "candidate_created",
                expected,
                identity,
            )
            if pending["event_digests"]["candidate_created"] != canonical_json_sha256(event):
                raise HandoffIntakeConflict("pending candidate_created event digest drift")
            status = "recovered"
        else:
            event = self._find_event(
                events,
                job_id=identity["job_id"],
                event_type="candidate_created",
                expected_payload=expected,
            )
            if event is None:
                self.coordinator.candidate_created(
                    identity["job_id"],
                    actor=principal,
                    **expected,
                )
                events = self.coordinator.events.read_events()
                event = self._find_event(
                    events,
                    job_id=identity["job_id"],
                    event_type="candidate_created",
                    expected_payload=expected,
                )
                if event is None:
                    raise HandoffIntakeError("candidate_created event append 后无法回读")
                status = "completed"
            else:
                status = "recovered"
        pending["event_ids"]["candidate_created"] = event["event_id"]
        pending["event_digests"]["candidate_created"] = canonical_json_sha256(event)
        self._set_stage(pending, "candidate_created_event", status)

    def _reconcile_verifier_event(
        self,
        pending: dict[str, Any],
        envelope: Mapping[str, Any],
        identity: Mapping[str, Any],
        principal: str,
    ) -> None:
        candidate_expected = {
            **self._event_metadata(
                envelope,
                candidate_record_sha256=pending["candidate_record_sha256"],
                candidate_id=pending["candidate_id"],
            ),
            "output_digest": pending["candidate_artifact_sha256"],
        }
        expected = {
            **self._event_metadata(
                envelope,
                candidate_record_sha256=pending["candidate_record_sha256"],
                candidate_id=pending["candidate_id"],
            ),
            "requested_verification": list(envelope["requested_verification"]),
        }
        events = self.coordinator.events.read_events()
        candidate_event_id = pending["event_ids"].get("candidate_created")
        if candidate_event_id is None:
            raise HandoffIntakeError("verifier request 前缺少 candidate_created event")
        candidate_event = self._event_by_id(
            events,
            candidate_event_id,
            "candidate_created",
            candidate_expected,
            identity,
        )
        event_id = pending["event_ids"].get("verifier_requested")
        if event_id is not None:
            event = self._event_by_id(
                events,
                event_id,
                "verifier_requested",
                expected,
                identity,
            )
            if pending["event_digests"]["verifier_requested"] != canonical_json_sha256(event):
                raise HandoffIntakeConflict("pending verifier_requested event digest drift")
            status = "recovered"
        else:
            event = self._find_event(
                events,
                job_id=identity["job_id"],
                event_type="verifier_requested",
                expected_payload=expected,
            )
            if event is None:
                self.coordinator.verifier_requested(
                    identity["job_id"],
                    actor=principal,
                    **expected,
                )
                events = self.coordinator.events.read_events()
                event = self._find_event(
                    events,
                    job_id=identity["job_id"],
                    event_type="verifier_requested",
                    expected_payload=expected,
                )
                if event is None:
                    raise HandoffIntakeError("verifier_requested event append 后无法回读")
                status = "completed"
            else:
                status = "recovered"
        if event["sequence"] <= candidate_event["sequence"]:
            raise HandoffIntakeConflict("verifier_requested 必须发生在 candidate_created 之后")
        pending["event_ids"]["verifier_requested"] = event["event_id"]
        pending["event_digests"]["verifier_requested"] = canonical_json_sha256(event)
        self._set_stage(pending, "verifier_requested_event", status)

    def _reconcile_terminal_event(
        self,
        pending: dict[str, Any],
        envelope: Mapping[str, Any],
        identity: Mapping[str, Any],
        principal: str,
    ) -> None:
        outcome = envelope["outcome"]
        if outcome == "blocked":
            blocker = envelope["blocker"]
            expected = {
                **self._event_metadata(
                    envelope,
                    candidate_record_sha256=None,
                    candidate_id=None,
                ),
                "outcome": "blocked",
                "reason": blocker,
                "blocker": blocker,
                "next_obligation": envelope["next_obligation"],
            }
            event_type = "blocked"
            event_key = "blocked"
        else:
            transport = envelope["transport"]
            expected = {
                **self._event_metadata(
                    envelope,
                    candidate_record_sha256=None,
                    candidate_id=None,
                ),
                "outcome": "transport_failure",
                "error": transport["error"],
                "transport_failure": True,
                "retryability": transport["retryability"],
                "stage": transport.get("stage", "unknown"),
            }
            event_type = "failed"
            event_key = "failed"
        events = self.coordinator.events.read_events()
        event_id = pending["event_ids"].get(event_key)
        if event_id is not None:
            event = self._event_by_id(events, event_id, event_type, expected, identity)
            if pending["event_digests"][event_key] != canonical_json_sha256(event):
                raise HandoffIntakeConflict(f"pending {event_type} event digest drift")
            status = "recovered"
        else:
            event = self._find_event(
                events,
                job_id=identity["job_id"],
                event_type=event_type,
                expected_payload=expected,
            )
            if event is None:
                if outcome == "blocked":
                    self.coordinator.block_job(
                        identity["job_id"],
                        actor=principal,
                        **expected,
                    )
                else:
                    self.coordinator.fail_job(
                        identity["job_id"],
                        actor=principal,
                        **expected,
                    )
                events = self.coordinator.events.read_events()
                event = self._find_event(
                    events,
                    job_id=identity["job_id"],
                    event_type=event_type,
                    expected_payload=expected,
                )
                if event is None:
                    raise HandoffIntakeError(f"{event_type} event append 后无法回读")
                status = "completed"
            else:
                status = "recovered"
        pending["event_ids"][event_key] = event["event_id"]
        pending["event_digests"][event_key] = canonical_json_sha256(event)
        # Non-applicable phases remain explicitly skipped in the final receipt.
        self._set_stage(
            pending,
            "finalized",
            "recovered" if status == "recovered" else "pending",
        )
        self._set_stage(pending, "verifier_requested_event", "skipped")
        self._set_stage(pending, "candidate_created_event", "skipped")

    def _receipt_from_pending(self, pending: Mapping[str, Any], *, idempotent: bool) -> dict[str, Any]:
        stages = copy.deepcopy(dict(pending["stages"]))
        stages["finalized"] = {"status": "completed", "at": now()}
        outcome = pending["outcome"]
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "receipt_id": pending["receipt_id"],
            "envelope_sha256": pending["envelope_sha256"],
            "outcome": outcome,
            "decision": {
                "candidate": "candidate_only",
                "blocked": "blocked",
                "transport_failure": "transport_failure",
            }[outcome],
            "idempotent": idempotent,
            "job_identity": copy.deepcopy(pending["job_identity"]),
            "candidate_id": pending["candidate_id"],
            "candidate_record_sha256": pending["candidate_record_sha256"],
            "candidate_artifact_sha256": pending["candidate_artifact_sha256"],
            "event_ids": copy.deepcopy(pending["event_ids"]),
            "event_digests": copy.deepcopy(pending["event_digests"]),
            "stages": stages,
            "created_at": pending["created_at"],
            "completed_at": now(),
        }
        _schema_error(receipt, self._receipt_schema_path(), "Handoff intake receipt")
        return receipt

    def _write_final_and_remove_pending(
        self,
        receipt_path: Path,
        pending_path: Path,
        receipt: Mapping[str, Any],
    ) -> None:
        if receipt_path.exists():
            existing = self._read_final(receipt_path)
            if existing != dict(receipt):
                raise HandoffIntakeConflict("final receipt 已存在且内容不同")
        else:
            self._write_final_atomic(receipt_path, receipt)
        if pending_path.exists():
            _ensure_regular(pending_path, "pending receipt")
            try:
                pending_path.unlink()
                _fsync_directory(pending_path.parent)
            except OSError as exc:
                raise HandoffIntakeError("无法清理已完成的 pending receipt") from exc

    def _result(self, receipt: Mapping[str, Any], *, idempotent: bool) -> dict[str, Any]:
        candidate_id = receipt.get("candidate_id")
        return {
            "decision": receipt["decision"],
            "outcome": receipt["outcome"],
            "idempotent": idempotent,
            "receipt": (self.receipt_dir / f"{receipt['envelope_sha256']}.json").relative_to(self.project_root).as_posix(),
            "candidate_id": candidate_id,
            "event_ids": copy.deepcopy(receipt["event_ids"]),
            "event_digests": copy.deepcopy(receipt["event_digests"]),
            "stages": copy.deepcopy(receipt["stages"]),
        }

    def _verify_final(
        self,
        receipt: Mapping[str, Any],
        *,
        normalized: Mapping[str, Any],
        envelope_sha256: str,
        proposal: Mapping[str, Any] | None,
        identity: Mapping[str, Any],
    ) -> None:
        if receipt["receipt_id"] != f"handoff-intake:{envelope_sha256}":
            raise HandoffIntakeConflict("final receipt identity mismatch")
        if receipt.get("completed_at") is None:
            raise HandoffIntakeConflict("final receipt 缺少 completed_at")
        expected_decision = {
            "candidate": "candidate_only",
            "blocked": "blocked",
            "transport_failure": "transport_failure",
        }[normalized["outcome"]]
        if receipt["decision"] != expected_decision:
            raise HandoffIntakeConflict("final receipt decision mismatch")
        stages = receipt.get("stages", {})
        if stages.get("validated", {}).get("status") != "completed":
            raise HandoffIntakeConflict("final receipt validated stage mismatch")
        if stages.get("finalized", {}).get("status") != "completed":
            raise HandoffIntakeConflict("final receipt finalized stage mismatch")
        if normalized["outcome"] == "candidate":
            for name in (
                "candidate_persisted",
                "candidate_created_event",
                "verifier_requested_event",
            ):
                if stages.get(name, {}).get("status") not in {"completed", "recovered"}:
                    raise HandoffIntakeConflict(f"final receipt {name} stage mismatch")
        else:
            for name in (
                "candidate_persisted",
                "candidate_created_event",
                "verifier_requested_event",
            ):
                if stages.get(name, {}).get("status") != "skipped":
                    raise HandoffIntakeConflict(f"final receipt {name} stage mismatch")
        if receipt["envelope_sha256"] != envelope_sha256:
            raise HandoffIntakeConflict("final receipt envelope digest mismatch")
        if receipt["outcome"] != normalized["outcome"]:
            raise HandoffIntakeConflict("final receipt outcome mismatch")
        if receipt["job_identity"] != dict(identity):
            raise HandoffIntakeConflict("final receipt Job identity mismatch")
        expected_candidate_id = proposal.get("candidate_id") if proposal is not None else None
        expected_candidate_digest = canonical_json_sha256(proposal) if proposal is not None else None
        expected_artifact_digest = proposal.get("artifact", {}).get("sha256") if proposal is not None else None
        if receipt["candidate_id"] != expected_candidate_id:
            raise HandoffIntakeConflict("final receipt candidate_id mismatch")
        if receipt["candidate_record_sha256"] != expected_candidate_digest:
            raise HandoffIntakeConflict("final receipt Candidate digest mismatch")
        if receipt["candidate_artifact_sha256"] != expected_artifact_digest:
            raise HandoffIntakeConflict("final receipt artifact digest mismatch")
        records = _read_candidate_ledger(self.project_root)
        by_id = {record["candidate_id"]: record for record in records}
        if proposal is not None:
            if by_id.get(proposal["candidate_id"]) != dict(proposal):
                raise HandoffIntakeConflict("final receipt Candidate ledger mismatch")
        events = self.coordinator.events.read_events()
        if normalized["outcome"] == "candidate":
            base = {
                **self._event_metadata(
                    normalized,
                    candidate_record_sha256=expected_candidate_digest,
                    candidate_id=expected_candidate_id,
                ),
                "output_digest": expected_artifact_digest,
            }
            candidate_event = self._event_by_id(
                events,
                receipt["event_ids"]["candidate_created"],
                "candidate_created",
                base,
                identity,
            )
            verifier_expected = {
                **self._event_metadata(
                    normalized,
                    candidate_record_sha256=expected_candidate_digest,
                    candidate_id=expected_candidate_id,
                ),
                "requested_verification": list(normalized["requested_verification"]),
            }
            verifier_event = self._event_by_id(
                events,
                receipt["event_ids"]["verifier_requested"],
                "verifier_requested",
                verifier_expected,
                identity,
            )
            if verifier_event["sequence"] <= candidate_event["sequence"]:
                raise HandoffIntakeConflict("final receipt event order invalid")
            if receipt["event_ids"]["blocked"] is not None or receipt["event_ids"]["failed"] is not None:
                raise HandoffIntakeConflict("candidate receipt carries terminal failure event")
        elif normalized["outcome"] == "blocked":
            expected = {
                **self._event_metadata(
                    normalized,
                    candidate_record_sha256=None,
                    candidate_id=None,
                ),
                "outcome": "blocked",
                "reason": normalized["blocker"],
                "blocker": normalized["blocker"],
                "next_obligation": normalized["next_obligation"],
            }
            self._event_by_id(events, receipt["event_ids"]["blocked"], "blocked", expected, identity)
            if any(receipt["event_ids"][key] is not None for key in ("candidate_created", "verifier_requested", "failed")):
                raise HandoffIntakeConflict("blocked receipt carries Candidate/verifier/transport event")
        else:
            transport = normalized["transport"]
            expected = {
                **self._event_metadata(
                    normalized,
                    candidate_record_sha256=None,
                    candidate_id=None,
                ),
                "outcome": "transport_failure",
                "error": transport["error"],
                "transport_failure": True,
                "retryability": transport["retryability"],
                "stage": transport.get("stage", "unknown"),
            }
            self._event_by_id(events, receipt["event_ids"]["failed"], "failed", expected, identity)
            if any(receipt["event_ids"][key] is not None for key in ("candidate_created", "verifier_requested", "blocked")):
                raise HandoffIntakeConflict("transport receipt carries Candidate/verifier/blocked event")
        for key in EVENT_ID_KEYS:
            event_id = receipt["event_ids"][key]
            digest = receipt["event_digests"][key]
            if event_id is None:
                if digest is not None:
                    raise HandoffIntakeConflict(f"null event_id has digest：{key}")
                continue
            matches = [event for event in events if event["event_id"] == event_id]
            if len(matches) != 1 or canonical_json_sha256(matches[0]) != digest:
                raise HandoffIntakeConflict(f"final receipt event digest mismatch：{key}")

    def intake(
        self,
        envelope: Mapping[str, Any],
        *,
        crash_after: str | None = None,
    ) -> dict[str, Any]:
        """Validate, persist/reconcile, and return a Candidate-only receipt.

        ``crash_after`` is a test-only fault injection hook.  It leaves the
        pending receipt in place so a subsequent identical call exercises the
        normal recovery path.
        """
        try:
            normalized = validate_handoff(self.project_root, envelope)
        except (HandoffError, OSError, ValueError) as exc:
            raise HandoffIntakeError(f"HandoffEnvelope validation failed：{exc}") from exc
        envelope_sha256 = canonical_json_sha256(normalized)
        receipt_path, pending_path = self._paths(envelope_sha256)
        proposal: dict[str, Any] | None = None
        if normalized["outcome"] == "candidate":
            self._registered_generator(normalized)
            try:
                proposal = candidate_proposal(self.project_root, normalized)
            except HandoffError as exc:
                raise HandoffIntakeError(f"Candidate proposal invalid：{exc}") from exc
        with _candidate_ledger_lock(self.project_root):
            self._ensure_receipt_dir()
            pending = self._scan_pending(pending_path)
            # Read the event projector only after the Candidate lock is held.
            try:
                jobs = self.coordinator.replay()
            except CoordinatorError as exc:
                raise HandoffIntakeError(f"Coordinator replay failed：{exc}") from exc
            job_id = normalized["job_id"]
            job = jobs.get(job_id)
            if job is None:
                raise HandoffIntakeError(f"Coordinator Job 不存在：{job_id}")
            receipt_id = f"handoff-intake:{envelope_sha256}"
            final = self._read_final(receipt_path)
            try:
                binding = self._bind_job(
                    job,
                    normalized,
                    recovery=pending is not None or final is not None,
                )
            except HandoffError as exc:
                raise HandoffIntakeError(f"Coordinator Job binding failed：{exc}") from exc
            identity = binding["identity"]
            if final is not None:
                self._verify_final(
                    final,
                    normalized=normalized,
                    envelope_sha256=envelope_sha256,
                    proposal=proposal,
                    identity=identity,
                )
                if pending is not None:
                    self._pending_identity_check(
                        pending,
                        receipt_id=receipt_id,
                        envelope_sha256=envelope_sha256,
                        outcome=normalized["outcome"],
                        identity=identity,
                        proposal=proposal,
                    )
                    pending_path.unlink()
                    _fsync_directory(pending_path.parent)
                return self._result(final, idempotent=True)

            records = _read_candidate_ledger(self.project_root)
            existing = None
            if proposal is not None:
                existing = next(
                    (record for record in records if record["candidate_id"] == proposal["candidate_id"]),
                    None,
                )
                if existing is not None and existing != proposal and pending is not None:
                    raise HandoffIntakeConflict("pending Candidate ID 内容冲突")
                if existing is not None and existing != proposal:
                    raise HandoffIntakeConflict("Candidate ID 已存在但内容不同")
                if existing is not None and pending is None:
                    raise HandoffIntakeConflict(
                        "未知既有 Candidate 不得视为幂等；缺少 matching pending/final receipt"
                    )
            if pending is not None:
                self._pending_identity_check(
                    pending,
                    receipt_id=receipt_id,
                    envelope_sha256=envelope_sha256,
                    outcome=normalized["outcome"],
                    identity=identity,
                    proposal=proposal,
                )
                pending = copy.deepcopy(dict(pending))
            else:
                pending = self._base_pending(
                    receipt_id=receipt_id,
                    envelope_sha256=envelope_sha256,
                    envelope=normalized,
                    identity=identity,
                    proposal=proposal,
                )
                _schema_error(
                    pending,
                    self._receipt_schema_path(),
                    "Handoff intake pending receipt",
                )
                self._write_exclusive_json(pending_path, pending, 0o600)

            if normalized["outcome"] == "candidate":
                if existing is None:
                    _append_candidate(self.project_root, proposal or {})
                    self._set_stage(pending, "candidate_persisted", "completed")
                else:
                    self._set_stage(pending, "candidate_persisted", "recovered")
                self._update_pending(pending_path, pending)
                if crash_after in {"candidate", "candidate_persisted", "after_candidate"}:
                    raise InjectedCrash("injected crash after Candidate persistence")

                self._reconcile_candidate_event(pending, normalized, identity, binding["principal"])
                self._update_pending(pending_path, pending)
                if crash_after in {"candidate_created", "after_candidate_created"}:
                    raise InjectedCrash("injected crash after candidate_created event")

                self._reconcile_verifier_event(pending, normalized, identity, binding["principal"])
                self._update_pending(pending_path, pending)
                if crash_after in {"verifier_requested", "after_verifier_requested"}:
                    raise InjectedCrash("injected crash after verifier_requested event")
            else:
                self._reconcile_terminal_event(
                    pending,
                    normalized,
                    identity,
                    binding["principal"],
                )
                self._update_pending(pending_path, pending)

            receipt = self._receipt_from_pending(pending, idempotent=any(
                stage.get("status") == "recovered"
                for stage in pending["stages"].values()
                if isinstance(stage, dict)
            ))
            self._write_final_and_remove_pending(receipt_path, pending_path, receipt)
            return self._result(receipt, idempotent=receipt["idempotent"])

    ingest = intake
    receive = intake
    accept = intake
    process = intake

    def recover(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Explicit alias for replaying the normal same-envelope intake path."""
        return self.intake(envelope)


def intake_handoff(
    project_root: Path | str,
    envelope: Mapping[str, Any],
    coordinator: Coordinator | None = None,
    *,
    crash_after: str | None = None,
) -> dict[str, Any]:
    return HandoffIntake(project_root, coordinator).intake(envelope, crash_after=crash_after)


receive_handoff = intake_handoff
ingest_handoff = intake_handoff


__all__ = [
    "CANDIDATE_LEDGER",
    "HandoffIntake",
    "HandoffIntakeConflict",
    "HandoffIntakeError",
    "InjectedCrash",
    "RECEIPT_DIRECTORY",
    "StalePendingError",
    "ingest_handoff",
    "intake_handoff",
    "receive_handoff",
]
