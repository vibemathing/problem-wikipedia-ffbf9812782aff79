"""Durable, projection-only scheduling over the Coordinator Event Store.

The scheduler deliberately has no queue or reservation ledger of its own.  Job
state, lease state, dependency completion, fairness counters, and capacity
usage are all derived from the append-only Coordinator events.  The only
mutation this module performs is an atomic ``ready``/``claimed`` event append
inside the Event Store lock.

This is an engineering control-plane scheduler.  It does not create Attempts,
Evidence, Results, or any other mathematical truth-plane record.
"""

from __future__ import annotations

import copy
import json
import os
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .coordinator import (
    Coordinator,
    CoordinatorError,
    EventStore,
    JobError,
    LeaseError,
    make_event,
    replay_events,
    sha256_json,
)

CONTRACT_VERSION = "1.0.0"
SNAPSHOT_VERSION = "1.0.0"

# Coordinator's terminal states are intentionally kept narrower than its
# intermediate verifier states.  A dependency must not be satisfied merely
# because a verifier request was emitted.
TERMINAL_STATUSES = frozenset({"completed", "blocked", "failed", "cancelled"})
ACTIVE_STATUSES = frozenset(
    {
        "claimed",
        "started",
        "checkpointed",
        "candidate_ready",
        "verifying",
        "verifier_completed",
    }
)

DEFAULT_TERMINAL_POLICY: dict[str, Any] = {
    "success_statuses": ["completed"],
    "failure_statuses": ["blocked", "failed", "cancelled"],
    "failure_action": "block",
}

# Metadata is persisted inside the created Job event.  It is not a second
# source of truth: replaying the created event recovers it exactly.
SCHEDULER_METADATA_KEY = "scheduler"
DEPENDENCY_METADATA_KEY = "dependencies"
CAPACITY_METADATA_KEY = "capacity"


class SchedulerError(CoordinatorError):
    """Base error for scheduler contracts and projections."""


class DependencyError(SchedulerError):
    """A dependency contract is malformed or cannot be resolved safely."""


class DependencyContractError(DependencyError):
    """A single dependency contract is invalid."""


class DependencyCycleError(DependencyError):
    """The execution dependency graph contains a cycle."""


class CapacityError(SchedulerError):
    """A capacity contract or claim accounting operation is invalid."""


class CapacityContractError(CapacityError):
    """A capacity contract is invalid."""


class ScopeConflictError(CapacityError):
    """A candidate's write scope overlaps an active reservation."""


class ClaimError(SchedulerError):
    """A requested claim cannot be admitted."""


class ClaimConflictError(ClaimError, LeaseError):
    """The requested Job is already owned or changed during a claim."""


class SnapshotError(SchedulerError):
    """A derived scheduler snapshot is corrupt, stale, or inconsistent."""


class SnapshotExpiredError(SnapshotError):
    """A scheduler snapshot is past its explicit freshness deadline."""


class NoClaimAvailable(ClaimError):
    """No runnable Job is available for the requested worker."""


# Public aliases used by callers that prefer a more explicit name.
SchedulerSnapshotError = SnapshotError
ExpiredSnapshotError = SnapshotExpiredError


_IDENTIFIER_MAX = 256


def _schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "research" / "schema"


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerError(f"无法读取调度器 schema：{path}") from exc
    if not isinstance(value, dict):
        raise SchedulerError(f"调度器 schema 不是 object：{path}")
    return value


def _validate_schema(value: Mapping[str, Any], path: Path, label: str) -> None:
    errors = sorted(
        Draft202012Validator(
            _load_schema(path),
            format_checker=FormatChecker(),
        ).iter_errors(dict(value)),
        key=lambda item: list(item.path),
    )
    if errors:
        location = "/".join(str(part) for part in errors[0].path) or "<root>"
        raise SchedulerError(f"{label} schema 无效 ({location})：{errors[0].message}")


def _parse_time(value: Any, *, label: str = "时间戳") -> datetime:
    if not isinstance(value, str):
        raise SchedulerError(f"{label} 必须是 ISO 8601 字符串")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchedulerError(f"{label} 无效") from exc
    if parsed.tzinfo is None:
        raise SchedulerError(f"{label} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SchedulerError("时间必须包含时区")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _clock_value(clock: Callable[[], Any] | None) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            raise SchedulerError("clock 返回的 datetime 必须包含时区")
        return parsed.astimezone(timezone.utc)
    return _parse_time(value, label="clock 时间")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _IDENTIFIER_MAX:
        raise DependencyContractError(f"{label} 必须是非空短字符串")
    return value


def _copy_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SchedulerError(f"{label} 必须是 object")
    return copy.deepcopy(dict(value))


def _dependency_ref(value: Any) -> str | dict[str, str]:
    if isinstance(value, str):
        return _identifier(value, "dependency job_id")
    if isinstance(value, Mapping):
        unknown = set(value) - {"job_id", "id", "workflow_id"}
        if unknown:
            raise DependencyContractError(
                f"dependency reference 含未知字段：{min(unknown)}"
            )
        if "job_id" in value and "id" in value and value["job_id"] != value["id"]:
            raise DependencyContractError("dependency reference 的 job_id/id 冲突")
        job_id = value.get("job_id", value.get("id"))
        result: dict[str, str] = {"job_id": _identifier(job_id, "dependency job_id")}
        workflow_id = value.get("workflow_id")
        if workflow_id is not None:
            result["workflow_id"] = _identifier(workflow_id, "dependency workflow_id")
        return result
    raise DependencyContractError("dependency reference 必须是 job_id 或 object")


def _ref_job_id(value: str | Mapping[str, Any]) -> str:
    return value if isinstance(value, str) else str(value["job_id"])


def _ref_workflow_id(value: str | Mapping[str, Any]) -> str | None:
    if isinstance(value, Mapping):
        result = value.get("workflow_id")
        return str(result) if result is not None else None
    return None


def _list_of_refs(value: Any, label: str) -> list[str | dict[str, str]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise DependencyContractError(f"{label} 必须是 array")
    result = [_dependency_ref(item) for item in value]
    keys = [sha256_json(item) for item in result]
    if len(set(keys)) != len(keys):
        raise DependencyContractError(f"{label} 不能包含重复 dependency")
    return result


def _first_present(mapping: Mapping[str, Any], names: Sequence[str]) -> tuple[bool, Any]:
    present = [(name, mapping[name]) for name in names if name in mapping]
    if not present:
        return False, None
    first = present[0][1]
    for name, value in present[1:]:
        if value != first:
            raise DependencyContractError(f"dependency 字段别名冲突：{present[0][0]} 与 {name}")
    return True, first


def _normalize_terminal_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DependencyContractError("terminal_policy 必须是 object")
    unknown = set(value) - {
        "success_statuses",
        "satisfied_statuses",
        "success",
        "failure_statuses",
        "blocked_statuses",
        "failure",
        "failure_action",
        "on_failure",
        "failed_action",
    }
    if unknown:
        raise DependencyContractError(
            f"terminal_policy 含未知字段：{min(unknown)}"
        )
    success_present, success_value = _first_present(
        value, ("success_statuses", "satisfied_statuses", "success")
    )
    failure_present, failure_value = _first_present(
        value, ("failure_statuses", "blocked_statuses", "failure")
    )
    action_present, action_value = _first_present(
        value, ("failure_action", "on_failure", "failed_action")
    )
    if not success_present or not failure_present or not action_present:
        raise DependencyContractError(
            "terminal_policy 必须显式声明 success_statuses、failure_statuses 和 failure_action"
        )
    if not isinstance(success_value, Sequence) or isinstance(success_value, (str, bytes, bytearray)):
        raise DependencyContractError("success_statuses 必须是 array")
    if not isinstance(failure_value, Sequence) or isinstance(failure_value, (str, bytes, bytearray)):
        raise DependencyContractError("failure_statuses 必须是 array")
    success = list(success_value)
    failure = list(failure_value)
    allowed = set(TERMINAL_STATUSES)
    if not success or not failure:
        raise DependencyContractError("terminal_policy 的两类 status 都不能为空")
    if any(item not in allowed for item in [*success, *failure]):
        raise DependencyContractError("terminal_policy 只能引用 Coordinator terminal status")
    if len(set(success)) != len(success) or len(set(failure)) != len(failure):
        raise DependencyContractError("terminal_policy status 不能重复")
    if set(success) & set(failure):
        raise DependencyContractError("terminal_policy success/failure status 不能重叠")
    if action_value not in {"block", "wait"}:
        raise DependencyContractError("terminal_policy.failure_action 必须为 block 或 wait")
    return {
        "success_statuses": success,
        "failure_statuses": failure,
        "failure_action": action_value,
    }


def _normalize_dependency_contract(
    value: Mapping[str, Any],
    *,
    workflow_id: str | None = None,
    job_id: str | None = None,
    require_identity: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DependencyContractError("dependency contract 必须是 object")
    raw = dict(value)
    unknown = set(raw) - {
        "schema_version",
        "workflow_id",
        "job_id",
        "all_of",
        "all",
        "any_of",
        "any",
        "terminal_policy",
        "terminal",
    }
    if unknown:
        raise DependencyContractError(
            f"dependency contract 含未知字段：{min(unknown)}"
        )
    version = raw.get("schema_version", CONTRACT_VERSION)
    if version != CONTRACT_VERSION:
        raise DependencyContractError(f"不支持的 dependency schema_version：{version}")
    contract_workflow = raw.get("workflow_id", workflow_id)
    contract_job = raw.get("job_id", job_id)
    if require_identity and contract_workflow is None:
        raise DependencyContractError("dependency contract 缺少 workflow_id")
    if require_identity and contract_job is None:
        raise DependencyContractError("dependency contract 缺少 job_id")
    if contract_workflow is not None:
        contract_workflow = _identifier(contract_workflow, "dependency workflow_id")
    if contract_job is not None:
        contract_job = _identifier(contract_job, "dependency job_id")
    if workflow_id is not None and contract_workflow != workflow_id:
        raise DependencyContractError("dependency contract 跨 workflow")
    if job_id is not None and contract_job != job_id:
        raise DependencyContractError("dependency contract job_id 与 Job 不一致")

    all_present, all_value = _first_present(raw, ("all_of", "all"))
    any_present, any_value = _first_present(raw, ("any_of", "any"))
    policy_present, policy_value = _first_present(raw, ("terminal_policy", "terminal"))
    # An explicit contract must make terminal handling visible.  A missing
    # contract is handled separately by _default_dependency_contract.
    if not policy_present:
        raise DependencyContractError("dependency contract 缺少显式 terminal_policy")
    all_of = _list_of_refs(all_value if all_present else [], "all_of")
    any_of = _list_of_refs(any_value if any_present else [], "any_of")
    ref_keys = [_ref_job_id(item) for item in [*all_of, *any_of]]
    if len(set(ref_keys)) != len(ref_keys):
        raise DependencyContractError("同一 dependency 不能同时出现在 all_of 和 any_of")
    result: dict[str, Any] = {
        "schema_version": CONTRACT_VERSION,
        "all_of": all_of,
        "any_of": any_of,
        "terminal_policy": _normalize_terminal_policy(policy_value),
    }
    if contract_workflow is not None:
        result["workflow_id"] = contract_workflow
    if contract_job is not None:
        result["job_id"] = contract_job
    if require_identity:
        _validate_schema(
            result,
            _schema_root() / "coordinator-dependency.schema.json",
            "dependency contract",
        )
    return result


def _default_dependency_contract(job_id: str, workflow_id: str) -> dict[str, Any]:
    return {
        "schema_version": CONTRACT_VERSION,
        "workflow_id": workflow_id,
        "job_id": job_id,
        "all_of": [],
        "any_of": [],
        "terminal_policy": copy.deepcopy(DEFAULT_TERMINAL_POLICY),
    }


def normalize_dependency_contract(
    contract: Mapping[str, Any],
    *,
    workflow_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Normalize and schema-validate one dependency contract."""
    try:
        return _normalize_dependency_contract(
            contract,
            workflow_id=workflow_id,
            job_id=job_id,
            require_identity=True,
        )
    except SchedulerError:
        raise
    except Exception as exc:  # fail closed at the public contract boundary
        raise DependencyContractError("dependency contract 无效") from exc


def validate_dependency_contract(
    contract: Mapping[str, Any],
    *,
    workflow_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Validate a dependency contract and return its canonical form."""
    return normalize_dependency_contract(contract, workflow_id=workflow_id, job_id=job_id)


def _metadata_mapping(job: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = job.get("metadata")
    return metadata if isinstance(metadata, Mapping) else {}


def _scheduler_metadata(job: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = _metadata_mapping(job)
    scheduler = metadata.get(SCHEDULER_METADATA_KEY)
    if isinstance(scheduler, Mapping):
        return scheduler
    return {}


def _extract_dependency_contract(job: Mapping[str, Any]) -> Mapping[str, Any] | None:
    scheduler = _scheduler_metadata(job)
    for key in (DEPENDENCY_METADATA_KEY, "dependency", "dependency_contract"):
        if key in scheduler:
            value = scheduler[key]
            if not isinstance(value, Mapping):
                raise DependencyContractError(f"Job {job.get('job_id')} 的 scheduler.{key} 必须是 object")
            return value
    metadata = _metadata_mapping(job)
    for key in (DEPENDENCY_METADATA_KEY, "dependency", "dependency_contract"):
        if key in metadata:
            value = metadata[key]
            if not isinstance(value, Mapping):
                raise DependencyContractError(f"Job {job.get('job_id')} 的 metadata.{key} 必须是 object")
            return value
    # A low-level fixture may carry this field before the Coordinator schema is
    # applied.  It is accepted here but never written outside Job metadata.
    if DEPENDENCY_METADATA_KEY in job:
        value = job[DEPENDENCY_METADATA_KEY]
        if not isinstance(value, Mapping):
            raise DependencyContractError(f"Job {job.get('job_id')} 的 dependencies 必须是 object")
        return value
    return None


def _job_index(jobs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    if isinstance(jobs, Mapping):
        values = list(jobs.values())
    else:
        values = list(jobs)
    result: dict[str, Mapping[str, Any]] = {}
    for item in values:
        if not isinstance(item, Mapping):
            raise DependencyError("Job projection 必须是 object")
        job_id = item.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise DependencyError("Job 缺少 job_id")
        if job_id in result:
            raise DependencyError(f"重复 job_id：{job_id}")
        result[job_id] = item
    return result


def validate_dependency_graph(
    jobs: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Validate unknown references, workflow boundaries, and cycles.

    ``jobs`` is a replay projection.  The returned mapping is a normalized
    projection of the contracts; it is never persisted as a second ledger.
    """
    index = _job_index(jobs)
    if contracts is not None and not isinstance(contracts, Mapping):
        raise DependencyError("dependency_contracts 必须是 object")
    if contracts is not None:
        unknown_contracts = sorted(set(contracts) - set(index))
        if unknown_contracts:
            raise DependencyError(
                f"dependency_contracts 引用未知 Job：{unknown_contracts[0]}"
            )
    normalized: dict[str, dict[str, Any]] = {}
    for job_id, job in index.items():
        workflow_id = job.get("workflow_id")
        if not isinstance(workflow_id, str) or not workflow_id:
            raise DependencyError(f"Job {job_id} 缺少 workflow_id")
        persisted = _extract_dependency_contract(job)
        supplied = contracts.get(job_id) if contracts is not None and job_id in contracts else None
        if persisted is not None and supplied is not None:
            persisted_normalized = _normalize_dependency_contract(
                persisted,
                workflow_id=workflow_id,
                job_id=job_id,
                require_identity=True,
            )
            supplied_normalized = _normalize_dependency_contract(
                supplied,
                workflow_id=workflow_id,
                job_id=job_id,
                require_identity=True,
            )
            if persisted_normalized != supplied_normalized:
                raise DependencyError(
                    f"Job {job_id} 的事件 contract 与外部 contract 漂移"
                )
            normalized[job_id] = persisted_normalized
        else:
            raw = supplied if supplied is not None else persisted
            if raw is None:
                normalized[job_id] = _default_dependency_contract(job_id, workflow_id)
            else:
                normalized[job_id] = _normalize_dependency_contract(
                    raw,
                    workflow_id=workflow_id,
                    job_id=job_id,
                    require_identity=True,
                )
        contract = normalized[job_id]
        for ref in [*contract["all_of"], *contract["any_of"]]:
            dependency_id = _ref_job_id(ref)
            dependency = index.get(dependency_id)
            if dependency is None:
                raise DependencyError(f"Job {job_id} 引用未知 dependency：{dependency_id}")
            dependency_workflow = dependency.get("workflow_id")
            if dependency_workflow != workflow_id:
                raise DependencyError(
                    f"Job {job_id} 引用跨 workflow dependency：{dependency_id}"
                )
            ref_workflow = _ref_workflow_id(ref)
            if ref_workflow is not None and ref_workflow != workflow_id:
                raise DependencyError(
                    f"Job {job_id} dependency reference 声明跨 workflow：{dependency_id}"
                )

    graph: dict[str, list[str]] = {
        job_id: [_ref_job_id(item) for item in [*contract["all_of"], *contract["any_of"]]]
        for job_id, contract in normalized.items()
    }
    colors: dict[str, int] = {}

    def visit(job_id: str, stack: list[str]) -> None:
        color = colors.get(job_id, 0)
        if color == 1:
            cycle_start = stack.index(job_id) if job_id in stack else 0
            cycle = " -> ".join([*stack[cycle_start:], job_id])
            raise DependencyCycleError(f"执行 dependency 含循环：{cycle}")
        if color == 2:
            return
        colors[job_id] = 1
        stack.append(job_id)
        for dependency_id in graph[job_id]:
            visit(dependency_id, stack)
        stack.pop()
        colors[job_id] = 2

    for job_id in sorted(graph):
        visit(job_id, [])
    return normalized


def _status_of(value: Any) -> str | None:
    if isinstance(value, Mapping):
        status = value.get("status")
    else:
        status = value
    return status if isinstance(status, str) else None


def evaluate_dependency_contract(
    contract: Mapping[str, Any],
    dependency_statuses: Mapping[str, Any],
    *,
    job_status: str = "ready",
) -> dict[str, Any]:
    """Evaluate all_of/any_of against a replay-derived status mapping."""
    normalized = _normalize_dependency_contract(contract, require_identity=False)
    if job_status != "ready":
        return {
            "ready": False,
            "state": "not_ready",
            "reasons": [f"lifecycle status is {job_status}"],
            "dependency_states": {},
        }
    success = set(normalized["terminal_policy"]["success_statuses"])
    failure = set(normalized["terminal_policy"]["failure_statuses"])
    states: dict[str, dict[str, Any]] = {}
    for ref in [*normalized["all_of"], *normalized["any_of"]]:
        dependency_id = _ref_job_id(ref)
        status = _status_of(dependency_statuses.get(dependency_id))
        if status in success:
            state = "satisfied"
        elif status in failure:
            state = "failed"
        elif status is None:
            state = "unknown"
        else:
            state = "pending"
        states[dependency_id] = {"status": status, "state": state}

    all_ids = [_ref_job_id(item) for item in normalized["all_of"]]
    any_ids = [_ref_job_id(item) for item in normalized["any_of"]]
    all_failed = [item for item in all_ids if states[item]["state"] in {"failed", "unknown"}]
    all_pending = [item for item in all_ids if states[item]["state"] == "pending"]
    all_satisfied = all(item not in all_failed and item not in all_pending for item in all_ids)
    any_satisfied = not any_ids or any(states[item]["state"] == "satisfied" for item in any_ids)
    any_pending = [item for item in any_ids if states[item]["state"] in {"pending", "unknown"}]
    any_failed = bool(any_ids) and not any_satisfied and not any_pending
    reasons: list[str] = []
    policy_action = normalized["terminal_policy"]["failure_action"]
    if all_failed:
        reasons.append(f"all_of dependency failed: {','.join(all_failed)}")
    if any_failed:
        reasons.append("any_of dependencies all reached failure terminal states")
    if (all_failed or any_failed) and policy_action == "block":
        return {
            "ready": False,
            "state": "blocked",
            "reasons": reasons,
            "dependency_states": states,
        }
    if all_pending or any_pending or all_failed or any_failed:
        if all_pending:
            reasons.append(f"all_of dependency pending: {','.join(all_pending)}")
        if any_pending:
            reasons.append(f"any_of dependency pending: {','.join(any_pending)}")
        if all_failed or any_failed:
            reasons.append("terminal failure policy is wait")
        return {
            "ready": False,
            "state": "waiting",
            "reasons": reasons,
            "dependency_states": states,
        }
    if all_satisfied and any_satisfied:
        return {
            "ready": True,
            "state": "ready",
            "reasons": [],
            "dependency_states": states,
        }
    return {
        "ready": False,
        "state": "waiting",
        "reasons": ["dependency conditions are not satisfied"],
        "dependency_states": states,
    }


def dependency_ready(
    job: Mapping[str, Any],
    jobs: Mapping[str, Mapping[str, Any]],
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return dependency readiness for one replay-projected Job."""
    job_id = job.get("job_id")
    workflow_id = job.get("workflow_id")
    if not isinstance(job_id, str) or not isinstance(workflow_id, str):
        raise DependencyError("Job identity 不完整")
    index = _job_index(jobs)
    normalized = validate_dependency_graph(index, {job_id: contract} if contract is not None else None)
    statuses = {identity: item.get("status") for identity, item in index.items()}
    result = evaluate_dependency_contract(
        normalized[job_id], statuses, job_status=str(job.get("status"))
    )
    result["job_id"] = job_id
    result["workflow_id"] = workflow_id
    return result


# Friendly aliases for integrations and tests.
evaluate_dependencies = evaluate_dependency_contract
is_dependency_ready = dependency_ready
validate_dependencies = validate_dependency_graph


def _normalize_limit(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise CapacityContractError(f"{label} 必须是正整数")
    if isinstance(value, int):
        if value <= 0:
            raise CapacityContractError(f"{label} 必须是正整数")
        return value
    if isinstance(value, Mapping):
        unknown = set(value) - {
            "max_active",
            "limit",
            "max",
            "slots",
            "max_jobs",
            "max_concurrent",
            "concurrency",
        }
        if unknown:
            raise CapacityContractError(
                f"{label} 含未知字段：{min(unknown)}"
            )
        candidates = [
            key
            for key in (
                "max_active",
                "limit",
                "max",
                "slots",
                "max_jobs",
                "max_concurrent",
                "concurrency",
            )
            if key in value
        ]
        if not candidates:
            raise CapacityContractError(f"{label} 缺少 max_active/limit")
        first = value[candidates[0]]
        if any(value[key] != first for key in candidates[1:]):
            raise CapacityContractError(f"{label} 的 limit 别名冲突")
        return _normalize_limit(first, label)
    raise CapacityContractError(f"{label} 必须是正整数")


def _normalize_limit_map(value: Any, label: str) -> dict[str, int]:
    if value is None:
        return {}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        result: dict[str, int] = {}
        for item in value:
            if not isinstance(item, Mapping):
                raise CapacityContractError(f"{label} list item 必须是 object")
            key = item.get("scope", item.get("key", item.get("name")))
            if not isinstance(key, str) or not key:
                raise CapacityContractError(f"{label} list item 缺少 key/scope")
            limit = item.get(
                "max_active",
                item.get(
                    "limit",
                    item.get("max", item.get("max_jobs", item.get("max_concurrent", item.get("concurrency")))),
                ),
            )
            if key in result and result[key] != _normalize_limit(limit, f"{label}.{key}"):
                raise CapacityContractError(f"{label} 包含重复 key：{key}")
            result[key] = _normalize_limit(limit, f"{label}.{key}")
        return result
    if not isinstance(value, Mapping):
        raise CapacityContractError(f"{label} 必须是 object")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise CapacityContractError(f"{label} key 必须是非空字符串")
        result[key] = _normalize_limit(item, f"{label}.{key}")
    return result


def _combine_limit_aliases(raw: Mapping[str, Any], names: Sequence[str], label: str) -> dict[str, int]:
    present = [(name, raw[name]) for name in names if name in raw]
    if not present:
        return {}
    first = _normalize_limit_map(present[0][1], label)
    for name, value in present[1:]:
        other = _normalize_limit_map(value, label)
        if other != first:
            raise CapacityContractError(f"capacity 字段别名冲突：{present[0][0]} 与 {name}")
    return first


def normalize_capacity_contract(contract: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize aliases and validate the four scheduler capacity dimensions."""
    if contract is None:
        raw: dict[str, Any] = {}
    elif isinstance(contract, Mapping):
        raw = dict(contract)
    else:
        raise CapacityContractError("capacity contract 必须是 object")
    unknown = set(raw) - {
        "schema_version",
        "default_limit",
        "default_max_active",
        "default",
        "adapter_limits",
        "project_limits",
        "worker_limits",
        "write_scope_limits",
        "adapters",
        "projects",
        "workers",
        "write_scopes",
        "adapter",
        "project",
        "worker",
        "write_scope",
        "limits",
    }
    if unknown:
        raise CapacityContractError(
            f"capacity contract 含未知字段：{min(unknown)}"
        )
    version = raw.get("schema_version", CONTRACT_VERSION)
    if version != CONTRACT_VERSION:
        raise CapacityContractError(f"不支持的 capacity schema_version：{version}")
    grouped_limits = raw.get("limits")
    if grouped_limits is not None:
        if not isinstance(grouped_limits, Mapping):
            raise CapacityContractError("capacity.limits 必须是 object")
        allowed_grouped = {
            "adapter_limits", "adapters", "adapter",
            "project_limits", "projects", "project",
            "worker_limits", "workers", "worker",
            "write_scope_limits", "write_scopes", "write_scope",
        }
        unknown_grouped = set(grouped_limits) - allowed_grouped
        if unknown_grouped:
            raise CapacityContractError(
                f"capacity.limits 含未知字段：{min(unknown_grouped)}"
            )
        for canonical, names in (
            ("adapter_limits", ("adapter_limits", "adapters", "adapter")),
            ("project_limits", ("project_limits", "projects", "project")),
            ("worker_limits", ("worker_limits", "workers", "worker")),
            ("write_scope_limits", ("write_scope_limits", "write_scopes", "write_scope")),
        ):
            grouped_present = [(name, grouped_limits[name]) for name in names if name in grouped_limits]
            if not grouped_present:
                continue
            grouped_normalized = _normalize_limit_map(grouped_present[0][1], f"limits.{canonical}")
            for name, value in grouped_present[1:]:
                if _normalize_limit_map(value, f"limits.{canonical}") != grouped_normalized:
                    raise CapacityContractError(f"capacity.limits 字段别名冲突：{grouped_present[0][0]} 与 {name}")
            top_present = any(name in raw for name in names)
            top_normalized = _combine_limit_aliases(raw, names, canonical)
            if top_present and top_normalized != grouped_normalized:
                raise CapacityContractError(f"capacity.limits 与顶层 {canonical} 冲突")
            if not top_present:
                raw[canonical] = grouped_present[0][1]
    default_values = [
        (name, raw[name])
        for name in ("default_limit", "default_max_active", "default")
        if name in raw
    ]
    if default_values:
        default_value = default_values[0][1]
        if any(value != default_value for _, value in default_values[1:]):
            raise CapacityContractError(
                f"capacity default 字段别名冲突：{default_values[0][0]} 与 {default_values[1][0]}"
            )
        default_limit = None if default_value is None else _normalize_limit(default_value, "default_limit")
    else:
        default_limit = None
    write_scope_limits = _combine_limit_aliases(
        raw, ("write_scope_limits", "write_scopes", "write_scope"), "write_scope_limits"
    )
    normalized_scope_limits: dict[str, int] = {}
    for scope, limit in write_scope_limits.items():
        normalized_scope = _normalize_scope(scope)
        if normalized_scope in normalized_scope_limits and normalized_scope_limits[normalized_scope] != limit:
            raise CapacityContractError(f"write scope limit 规范化后冲突：{scope}")
        normalized_scope_limits[normalized_scope] = limit
    result = {
        "schema_version": CONTRACT_VERSION,
        "default_limit": default_limit,
        "adapter_limits": _combine_limit_aliases(
            raw, ("adapter_limits", "adapters", "adapter"), "adapter_limits"
        ),
        "project_limits": _combine_limit_aliases(
            raw, ("project_limits", "projects", "project"), "project_limits"
        ),
        "worker_limits": _combine_limit_aliases(
            raw, ("worker_limits", "workers", "worker"), "worker_limits"
        ),
        "write_scope_limits": normalized_scope_limits,
    }
    _validate_schema(
        result,
        _schema_root() / "coordinator-capacity.schema.json",
        "capacity contract",
    )
    return result


def validate_capacity_contract(contract: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate a capacity contract and return its canonical form."""
    return normalize_capacity_contract(contract)


validate_capacity = validate_capacity_contract


def _job_capacity(job: Mapping[str, Any]) -> dict[str, int]:
    scheduler = _scheduler_metadata(job)
    value: Any = scheduler.get(CAPACITY_METADATA_KEY)
    if value is None:
        value = _metadata_mapping(job).get(CAPACITY_METADATA_KEY)
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise CapacityError(f"Job {job.get('job_id')} 的 capacity 必须是 object")
    unknown = set(value) - {
        "units",
        "weight",
        "slots",
        "cost",
        "adapter_units",
        "adapter",
        "project_units",
        "project",
        "worker_units",
        "worker",
        "write_scope_units",
        "write_scope",
        "scope",
    }
    if unknown:
        raise CapacityError(
            f"Job {job.get('job_id')} capacity 含未知字段：{min(unknown)}"
        )
    base_present = [
        (name, value[name]) for name in ("units", "weight", "slots", "cost") if name in value
    ]
    if base_present:
        base = _normalize_limit(base_present[0][1], f"Job {job.get('job_id')} capacity.units")
        if any(item != base for _, item in base_present[1:]):
            raise CapacityError(f"Job {job.get('job_id')} capacity.units 别名冲突")
    else:
        base = 1
    result: dict[str, int] = {"units": base}
    for target, names in {
        "adapter_units": ("adapter_units", "adapter"),
        "project_units": ("project_units", "project"),
        "worker_units": ("worker_units", "worker"),
        "write_scope_units": ("write_scope_units", "write_scope", "scope"),
    }.items():
        present = [(name, value[name]) for name in names if name in value]
        if not present:
            result[target] = base
            continue
        first = _normalize_limit(present[0][1], f"Job {job.get('job_id')} capacity.{target}")
        if any(item != first for _, item in present[1:]):
            raise CapacityError(f"Job {job.get('job_id')} capacity.{target} 别名冲突")
        result[target] = first
    return result


def _normalize_scope(scope: Any) -> str:
    if not isinstance(scope, str) or not scope:
        raise CapacityError("write scope 必须是非空字符串")
    if "\\" in scope:
        raise CapacityError(f"write scope 不能使用反斜杠：{scope}")
    path = PurePosixPath(scope)
    if path.is_absolute() or ".." in path.parts:
        raise CapacityError(f"write scope 必须位于相对路径：{scope}")
    if not path.parts or path.parts == (".",):
        raise CapacityError("write scope 不能是当前目录")
    normalized = "/".join(part for part in path.parts if part not in {"", "."})
    if not normalized:
        raise CapacityError("write scope 不能为空")
    return normalized


def normalize_write_scopes(scopes: Any) -> list[str]:
    if not isinstance(scopes, Sequence) or isinstance(scopes, (str, bytes, bytearray)):
        raise CapacityError("write_scopes 必须是 array")
    result = [_normalize_scope(item) for item in scopes]
    if len(set(result)) != len(result):
        raise CapacityError("write_scopes 不能重复")
    for index, left in enumerate(result):
        for right in result[index + 1 :]:
            if scopes_overlap(left, right):
                raise CapacityError(f"同一 Job 的 write scopes 互相重叠：{left} 与 {right}")
    return result


def scopes_overlap(left: str, right: str) -> bool:
    """Return whether two relative path-prefix scopes can write the same file."""
    left_parts = tuple(_normalize_scope(left).split("/"))
    right_parts = tuple(_normalize_scope(right).split("/"))
    return (
        left_parts == right_parts
        or left_parts[: len(right_parts)] == right_parts
        or right_parts[: len(left_parts)] == left_parts
    )


def write_scopes_overlap(left: str, right: str) -> bool:
    return scopes_overlap(left, right)


def _scope_matches(configured: str, actual: str) -> bool:
    if configured in {"*", "default"}:
        return True
    return scopes_overlap(configured, actual)


def _lookup_limit(limits: Mapping[str, int], key: str, default: int | None) -> tuple[int | None, str | None]:
    if key in limits:
        return limits[key], key
    if "*" in limits:
        return limits["*"], "*"
    if "default" in limits:
        return limits["default"], "default"
    return default, None


def _human_value(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {
            "human",
            "human_control",
            "human-takeover",
            "human_takeover",
        }
    if isinstance(value, Mapping):
        for key in ("holder", "owner", "controller", "control_holder"):
            if key in value and _human_value(value[key]):
                return True
    return False


def has_human_control(job: Mapping[str, Any]) -> bool:
    """Detect a visible HUMAN control lease without treating normal workers as human."""
    lease = job.get("lease")
    metadata = _metadata_mapping(job)
    scheduler = _scheduler_metadata(job)
    sources: list[Mapping[str, Any]] = [job, metadata, scheduler]
    if isinstance(lease, Mapping):
        sources.append(lease)
    for source in sources:
        for key in (
            "holder",
            "owner",
            "controller",
            "control_holder",
            "control",
            "mode",
            "control_lease",
            "write_control",
            "write_lease",
            "human_control",
        ):
            if key in source and _human_value(source[key]):
                return True
    return False


def _lease_expiry(job: Mapping[str, Any]) -> datetime | None:
    lease = job.get("lease")
    if not isinstance(lease, Mapping):
        return None
    expiry = lease.get("expires_at")
    if expiry is None:
        return None
    return _parse_time(expiry, label="lease expires_at")


def _lease_is_active(job: Mapping[str, Any], as_of: datetime) -> bool:
    if job.get("status") not in ACTIVE_STATUSES:
        return False
    expiry = _lease_expiry(job)
    if expiry is None:
        # An in-flight status without a bounded lease is unsafe to overlap.
        return True
    return expiry > as_of


def _active_reservations(jobs: Mapping[str, Mapping[str, Any]], as_of: datetime) -> list[dict[str, Any]]:
    reservations: list[dict[str, Any]] = []
    for job_id in sorted(jobs):
        job = jobs[job_id]
        if not _lease_is_active(job, as_of):
            continue
        scopes = normalize_write_scopes(job.get("write_scopes", []))
        lease = job.get("lease") if isinstance(job.get("lease"), Mapping) else {}
        reservations.append(
            {
                "job_id": job_id,
                "job": job,
                "adapter": job.get("adapter"),
                "project_id": job.get("project_id"),
                "worker_id": lease.get("holder"),
                "scopes": scopes,
                "capacity": _job_capacity(job),
                "human_control": has_human_control(job),
            }
        )
    return reservations


def capacity_decision(
    job: Mapping[str, Any],
    active_reservations: Sequence[Mapping[str, Any]] | Mapping[str, Mapping[str, Any]],
    capacity_contract: Mapping[str, Any] | None = None,
    *,
    worker_id: str | None = None,
    as_of: datetime | str | None = None,
) -> dict[str, Any]:
    """Check dimensions and write-scope conflicts for one candidate.

    The public function accepts either the reservation view emitted by this
    module or a plain ``job_id -> replayed Job`` mapping for callers that do
    not need to retain an intermediate projection.
    """
    capacity = normalize_capacity_contract(capacity_contract)
    job_id = str(job.get("job_id", "<unknown>"))
    reasons: list[str] = []
    adapter_value = job.get("adapter")
    project_value = job.get("project_id")
    if not isinstance(adapter_value, str) or not adapter_value:
        raise CapacityError(f"Job {job_id} adapter 无效")
    if not isinstance(project_value, str) or not project_value:
        raise CapacityError(f"Job {job_id} project_id 无效")
    scopes = normalize_write_scopes(job.get("write_scopes", []))
    units = _job_capacity(job)
    when = _parse_time(as_of, label="as_of") if isinstance(as_of, str) else (as_of or datetime.now(timezone.utc))
    if when.tzinfo is None:
        raise CapacityError("as_of 必须包含时区")
    if isinstance(active_reservations, Mapping):
        active = _active_reservations(active_reservations, when.astimezone(timezone.utc))
    else:
        supplied_active = list(active_reservations)
        if supplied_active and any(
            not isinstance(item, Mapping)
            or "capacity" not in item
            or "scopes" not in item
            for item in supplied_active
        ):
            plain_jobs = {
                str(item["job_id"]): item
                for item in supplied_active
                if isinstance(item, Mapping) and isinstance(item.get("job_id"), str)
            }
            if len(plain_jobs) != len(supplied_active):
                raise CapacityError("active_reservations item 不是有效 reservation/Job")
            active = _active_reservations(plain_jobs, when.astimezone(timezone.utc))
        else:
            active = supplied_active

    if has_human_control(job):
        reasons.append("Job is under HUMAN control")

    scope_conflicts: list[str] = []
    for reservation in active:
        for candidate_scope in scopes:
            for active_scope in reservation.get("scopes", []):
                if scopes_overlap(candidate_scope, str(active_scope)):
                    scope_conflicts.append(str(reservation.get("job_id")))
                    break
            if scope_conflicts and scope_conflicts[-1] == str(reservation.get("job_id")):
                break
    scope_conflicts = sorted(set(scope_conflicts))
    if scope_conflicts:
        reasons.append(f"write scope overlaps active Job(s): {','.join(scope_conflicts)}")

    adapter = adapter_value
    project_id = project_value
    dimensions: dict[str, dict[str, Any]] = {}
    for dimension, key, amount_key, reservation_key in (
        ("adapter", adapter, "adapter_units", "adapter"),
        ("project", project_id, "project_units", "project_id"),
    ):
        limits = capacity[f"{dimension}_limits"]
        limit, matched = _lookup_limit(limits, key, capacity.get("default_limit"))
        used = sum(
            int(item["capacity"][amount_key])
            for item in active
            if item.get(reservation_key) == key
        )
        required = units[amount_key]
        dimensions[dimension] = {
            "key": key,
            "used": used,
            "required": required,
            "limit": limit,
            "matched_limit": matched,
            "available": limit is None or used + required <= limit,
        }
        if limit is not None and used + required > limit:
            reasons.append(f"{dimension} capacity insufficient: {used}+{required}>{limit}")

    worker_dimensions: dict[str, Any] = {"key": worker_id, "used": 0, "required": units["worker_units"], "limit": None, "matched_limit": None, "available": True}
    if worker_id is not None:
        limit, matched = _lookup_limit(
            capacity["worker_limits"], worker_id, capacity.get("default_limit")
        )
        used = sum(
            int(item["capacity"]["worker_units"])
            for item in active
            if item.get("worker_id") == worker_id
        )
        worker_dimensions = {
            "key": worker_id,
            "used": used,
            "required": units["worker_units"],
            "limit": limit,
            "matched_limit": matched,
            "available": limit is None or used + units["worker_units"] <= limit,
        }
        if limit is not None and used + units["worker_units"] > limit:
            reasons.append(f"worker capacity insufficient: {used}+{units['worker_units']}>{limit}")
    dimensions["worker"] = worker_dimensions

    scope_dimensions: list[dict[str, Any]] = []
    for candidate_scope in scopes:
        matching_limits: list[tuple[str, int]] = []
        for configured_scope, limit in capacity["write_scope_limits"].items():
            if _scope_matches(configured_scope, candidate_scope):
                matching_limits.append((configured_scope, limit))
        if not matching_limits and capacity.get("default_limit") is not None:
            matching_limits.append(("default", int(capacity["default_limit"])))
        if matching_limits:
            configured_scope, limit = max(matching_limits, key=lambda item: len(item[0].split("/")))
            used = sum(
                int(item["capacity"]["write_scope_units"])
                for item in active
                if any(
                    _scope_matches(configured_scope, str(active_scope))
                    for active_scope in item.get("scopes", [])
                )
            )
            available = used + units["write_scope_units"] <= limit
            scope_dimensions.append(
                {
                    "scope": candidate_scope,
                    "used": used,
                    "required": units["write_scope_units"],
                    "limit": limit,
                    "matched_limit": configured_scope,
                    "available": available,
                }
            )
            if not available:
                reasons.append(f"write scope capacity insufficient: {candidate_scope} {used}+{units['write_scope_units']}>{limit}")
        else:
            scope_dimensions.append(
                {
                    "scope": candidate_scope,
                    "used": 0,
                    "required": units["write_scope_units"],
                    "limit": None,
                    "matched_limit": None,
                    "available": True,
                }
            )
    dimensions["write_scope"] = scope_dimensions  # type: ignore[assignment]
    return {
        "allowed": not reasons,
        "reasons": reasons,
        "job_id": job_id,
        "dimensions": dimensions,
        "active_job_ids": sorted(str(item.get("job_id")) for item in active),
    }


def account_capacity(
    jobs: Mapping[str, Mapping[str, Any]],
    capacity_contract: Mapping[str, Any] | None = None,
    *,
    as_of: datetime | str | None = None,
) -> dict[str, Any]:
    """Return deterministic usage counts from active replay-projected leases."""
    when = _parse_time(as_of, label="as_of") if isinstance(as_of, str) else (as_of or datetime.now(timezone.utc))
    if when.tzinfo is None:
        raise CapacityError("as_of 必须包含时区")
    active = _active_reservations(jobs, when.astimezone(timezone.utc))
    adapter = Counter()
    project = Counter()
    worker = Counter()
    scopes = Counter()
    for reservation in active:
        capacity = reservation["capacity"]
        adapter[str(reservation["adapter"])] += capacity["adapter_units"]
        project[str(reservation["project_id"])] += capacity["project_units"]
        if reservation["worker_id"] is not None:
            worker[str(reservation["worker_id"])] += capacity["worker_units"]
        for scope in reservation["scopes"]:
            scopes[scope] += capacity["write_scope_units"]
    return {
        "as_of": _timestamp(when.astimezone(timezone.utc)),
        "active_job_ids": [item["job_id"] for item in active],
        "adapter": dict(sorted(adapter.items())),
        "project": dict(sorted(project.items())),
        "worker": dict(sorted(worker.items())),
        "write_scope": dict(sorted(scopes.items())),
        "capacity_contract": normalize_capacity_contract(capacity_contract),
    }


capacity_usage = account_capacity


# Fairness helpers ---------------------------------------------------------


def _priority(job: Mapping[str, Any]) -> int:
    scheduler = _scheduler_metadata(job)
    metadata = _metadata_mapping(job)
    value = scheduler.get("priority", metadata.get("priority", 0))
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchedulerError(f"Job {job.get('job_id')} priority 必须是整数")
    return value


def _fairness_group(job: Mapping[str, Any]) -> str:
    scheduler = _scheduler_metadata(job)
    metadata = _metadata_mapping(job)
    fairness = scheduler.get("fairness")
    if isinstance(fairness, Mapping):
        value = fairness.get(
            "group",
            fairness.get("fairness_group", metadata.get("fairness_group", job.get("project_id"))),
        )
    else:
        value = scheduler.get("fairness_group", metadata.get("fairness_group", job.get("project_id")))
    if not isinstance(value, str) or not value:
        raise SchedulerError(f"Job {job.get('job_id')} fairness_group 无效")
    return value


def _created_sequences(events: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for event in events:
        if event.get("event_type") == "created":
            job_id = event.get("job_id")
            if isinstance(job_id, str):
                result[job_id] = int(event["sequence"])
    return result


def _fairness_counts(events: Sequence[Mapping[str, Any]], jobs: Mapping[str, Mapping[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for event in events:
        if event.get("event_type") != "claimed":
            continue
        job = jobs.get(str(event.get("job_id")))
        if job is not None:
            counts[_fairness_group(job)] += 1
    return counts


def _selection_info(
    job: Mapping[str, Any],
    *,
    created_sequence: int,
    fairness_counts: Mapping[str, int],
    source_sequence: int,
) -> dict[str, Any]:
    group = _fairness_group(job)
    return {
        "priority": _priority(job),
        "fairness_group": group,
        "fairness_claim_count": int(fairness_counts.get(group, 0)),
        "wait_sequences": max(0, source_sequence - created_sequence),
        "created_sequence": created_sequence,
    }


def _selection_key(info: Mapping[str, Any], job_id: str) -> tuple[Any, ...]:
    # Priority is primary.  Among equal priority, the least-served fairness
    # group wins; creation sequence and job_id make the outcome total and
    # reproducible.  wait_sequences is exposed in the projection and is folded
    # into the age tie break through created_sequence.
    return (
        -int(info["priority"]),
        int(info["fairness_claim_count"]),
        int(info["created_sequence"]),
        job_id,
    )


# Projection ---------------------------------------------------------------


def event_source_digest(events: Sequence[Mapping[str, Any]]) -> str:
    """Digest the exact canonical Event Store sequence used by a projection."""
    return sha256_json([dict(event) for event in events])


def _configuration_digest(
    capacity: Mapping[str, Any],
    external_dependencies: Mapping[str, Mapping[str, Any]],
) -> str:
    return sha256_json(
        {
            "capacity": capacity,
            "external_dependencies": {
                key: external_dependencies[key] for key in sorted(external_dependencies)
            },
        }
    )


def _raw_replay(
    events: Sequence[Mapping[str, Any]],
    *,
    job_schema_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    try:
        return replay_events(list(events), job_schema_path=job_schema_path)
    except (CoordinatorError, KeyError, TypeError) as exc:
        raise SchedulerError(f"Coordinator Event replay 失败：{exc}") from exc


def _derive_body(
    events: Sequence[Mapping[str, Any]],
    *,
    capacity_contract: Mapping[str, Any],
    external_dependencies: Mapping[str, Mapping[str, Any]],
    as_of: datetime,
    job_schema_path: Path | None = None,
) -> dict[str, Any]:
    jobs = _raw_replay(events, job_schema_path=job_schema_path)
    contracts = validate_dependency_graph(jobs, external_dependencies or None)
    statuses = {job_id: job.get("status") for job_id, job in jobs.items()}
    created = _created_sequences(events)
    source_sequence = int(events[-1]["sequence"]) if events else 0
    fairness_counts = _fairness_counts(events, jobs)
    active = _active_reservations(jobs, as_of)
    projected_jobs: dict[str, Any] = {}
    for job_id in sorted(jobs):
        job = copy.deepcopy(jobs[job_id])
        dependency = evaluate_dependency_contract(
            contracts[job_id], statuses, job_status=str(job.get("status"))
        )
        # ``readiness`` is a pure derived field.  It is intentionally not
        # written back to the Coordinator Job or represented by a ledger row.
        job["dependencies"] = contracts[job_id]
        job["created_sequence"] = created[job_id]
        job["readiness"] = dependency
        job["fairness"] = _selection_info(
            job,
            created_sequence=created[job_id],
            fairness_counts=fairness_counts,
            source_sequence=source_sequence,
        )
        job["capacity"] = capacity_decision(
            job, active, capacity_contract, worker_id=None
        )
        projected_jobs[job_id] = job

    runnable: list[str] = []
    for job_id in sorted(projected_jobs):
        job = projected_jobs[job_id]
        if not job["readiness"]["ready"]:
            continue
        if job["capacity"]["allowed"]:
            runnable.append(job_id)
    runnable.sort(
        key=lambda identity: _selection_key(projected_jobs[identity]["fairness"], identity)
    )
    body = {
        "schema_version": SNAPSHOT_VERSION,
        "source_sequence": source_sequence,
        "source_digest": event_source_digest(events),
        "configuration_digest": _configuration_digest(capacity_contract, external_dependencies),
        "as_of": _timestamp(as_of),
        "jobs": projected_jobs,
        "fairness_counts": dict(sorted(fairness_counts.items())),
        "active_job_ids": [item["job_id"] for item in active],
        "ready_job_ids": sorted(
            identity
            for identity, item in projected_jobs.items()
            if item["readiness"]["ready"]
        ),
        "runnable_job_ids": runnable,
        "ttl_seconds": None,
        "expires_at": None,
    }
    return body


def _snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    body = {key: copy.deepcopy(value) for key, value in snapshot.items() if key != "snapshot_digest"}
    return sha256_json(body)


def _validate_snapshot_shape(snapshot: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "source_sequence",
        "source_digest",
        "configuration_digest",
        "as_of",
        "jobs",
        "fairness_counts",
        "active_job_ids",
        "ready_job_ids",
        "runnable_job_ids",
        "ttl_seconds",
        "expires_at",
        "snapshot_digest",
    }
    if not isinstance(snapshot, Mapping) or not required.issubset(snapshot):
        missing = sorted(required - set(snapshot)) if isinstance(snapshot, Mapping) else sorted(required)
        raise SnapshotError(f"scheduler snapshot 缺少字段：{missing}")
    unknown = set(snapshot) - required
    if unknown:
        raise SnapshotError(f"scheduler snapshot 含未知字段：{min(unknown)}")
    if snapshot.get("schema_version") != SNAPSHOT_VERSION:
        raise SnapshotError("scheduler snapshot schema_version 不支持")
    for field in ("source_digest", "configuration_digest", "snapshot_digest"):
        value = snapshot.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise SnapshotError(f"scheduler snapshot {field} 无效")
    source_sequence = snapshot.get("source_sequence")
    if isinstance(source_sequence, bool) or not isinstance(source_sequence, int) or source_sequence < 0:
        raise SnapshotError("scheduler snapshot source_sequence 无效")
    _parse_time(snapshot.get("as_of"), label="snapshot as_of")
    expires_at = snapshot.get("expires_at")
    if expires_at is not None:
        expiry_time = _parse_time(expires_at, label="snapshot expires_at")
    else:
        expiry_time = None
    ttl_seconds = snapshot.get("ttl_seconds")
    if ttl_seconds is not None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise SnapshotError("scheduler snapshot ttl_seconds 无效")
        if expiry_time is None or expiry_time != _parse_time(snapshot["as_of"], label="snapshot as_of") + timedelta(seconds=ttl_seconds):
            raise SnapshotError("scheduler snapshot expires_at 与 ttl_seconds 不一致")
    elif expiry_time is not None:
        raise SnapshotError("无 ttl_seconds 时不能声明 expires_at")
    jobs = snapshot.get("jobs")
    if not isinstance(jobs, Mapping):
        raise SnapshotError("scheduler snapshot jobs 必须是 object")
    if any(not isinstance(job_id, str) or not isinstance(job, Mapping) for job_id, job in jobs.items()):
        raise SnapshotError("scheduler snapshot jobs identity/value 无效")
    for job_id, job in jobs.items():
        if job.get("job_id") != job_id:
            raise SnapshotError(f"scheduler snapshot jobs key 与 job_id 不一致：{job_id}")
    fairness_counts = snapshot.get("fairness_counts")
    if not isinstance(fairness_counts, Mapping):
        raise SnapshotError("scheduler snapshot fairness_counts 必须是 object")
    if any(
        not isinstance(group, str)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for group, count in fairness_counts.items()
    ):
        raise SnapshotError("scheduler snapshot fairness_counts value 无效")
    for field in ("active_job_ids", "ready_job_ids", "runnable_job_ids"):
        value = snapshot.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise SnapshotError(f"scheduler snapshot {field} 必须是 string array")
        if len(set(value)) != len(value):
            raise SnapshotError(f"scheduler snapshot {field} 不能重复")
    if not set(snapshot["active_job_ids"]).issubset(jobs):
        raise SnapshotError("scheduler snapshot active_job_ids 引用未知 Job")
    if not set(snapshot["ready_job_ids"]).issubset(jobs):
        raise SnapshotError("scheduler snapshot ready_job_ids 引用未知 Job")
    if not set(snapshot["runnable_job_ids"]).issubset(snapshot["ready_job_ids"]):
        raise SnapshotError("scheduler snapshot runnable_job_ids 不是 ready 子集")
    if snapshot.get("snapshot_digest") != _snapshot_digest(snapshot):
        raise SnapshotError("scheduler snapshot digest 不匹配")


def validate_snapshot(snapshot: Mapping[str, Any], *, now: datetime | str | None = None) -> dict[str, Any]:
    """Validate intrinsic snapshot integrity and explicit expiry."""
    _validate_snapshot_shape(snapshot)
    current = _parse_time(now, label="now") if isinstance(now, str) else (now or datetime.now(timezone.utc))
    if current.tzinfo is None:
        raise SnapshotError("now 必须包含时区")
    expires_at = snapshot.get("expires_at")
    if expires_at is not None:
        expiry_time = _parse_time(expires_at, label="snapshot expires_at")
        as_of = _parse_time(snapshot["as_of"], label="snapshot as_of")
        if expiry_time <= as_of:
            raise SnapshotError("scheduler snapshot expires_at 不晚于 as_of")
        if expiry_time <= current.astimezone(timezone.utc):
            raise SnapshotExpiredError("scheduler snapshot 已过期")
    return copy.deepcopy(dict(snapshot))


def project_scheduler_events(
    events: Sequence[Mapping[str, Any]],
    *,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
    as_of: datetime | str | None = None,
    job_schema_path: Path | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Purely project an Event sequence into a scheduler snapshot."""
    copied_events = [copy.deepcopy(dict(event)) for event in events]
    if capacity_contract is not None and capacity is not None and capacity_contract != capacity:
        raise CapacityContractError("capacity_contract 与 capacity 冲突")
    if dependency_contracts is not None and dependencies is not None and dependency_contracts != dependencies:
        raise DependencyError("dependency_contracts 与 dependencies 冲突")
    effective_capacity = capacity_contract if capacity_contract is not None else capacity
    normalized_capacity = normalize_capacity_contract(effective_capacity)
    effective_dependencies = dependency_contracts if dependency_contracts is not None else dependencies
    external: dict[str, dict[str, Any]] = {}
    for key, value in (effective_dependencies or {}).items():
        if not isinstance(value, Mapping):
            raise DependencyError(f"dependency_contracts[{key}] 必须是 object")
        external[str(key)] = copy.deepcopy(dict(value))
    when = _parse_time(as_of, label="as_of") if isinstance(as_of, str) else (as_of or datetime.now(timezone.utc))
    if when.tzinfo is None:
        raise SnapshotError("as_of 必须包含时区")
    when = when.astimezone(timezone.utc)
    body = _derive_body(
        copied_events,
        capacity_contract=normalized_capacity,
        external_dependencies=external,
        as_of=when,
        job_schema_path=job_schema_path,
    )
    if ttl_seconds is not None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise SnapshotError("ttl_seconds 必须是正整数")
        body["ttl_seconds"] = ttl_seconds
        body["expires_at"] = _timestamp(when + timedelta(seconds=ttl_seconds))
    body["snapshot_digest"] = _snapshot_digest(body)
    return body


project_events = project_scheduler_events
project_snapshot = project_scheduler_events


# Scheduler object ---------------------------------------------------------


class Scheduler:
    """A deterministic scheduler backed by one Coordinator Event Store."""

    def __init__(
        self,
        project_root_or_store: Path | str | EventStore | Coordinator,
        *,
        capacity_contract: Mapping[str, Any] | None = None,
        capacity: Mapping[str, Any] | None = None,
        dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
        dependencies: Mapping[str, Mapping[str, Any]] | None = None,
        clock: Callable[[], Any] | None = None,
    ) -> None:
        if isinstance(project_root_or_store, Coordinator):
            self.coordinator = project_root_or_store
        elif isinstance(project_root_or_store, EventStore):
            self.coordinator = Coordinator(project_root_or_store)
        else:
            self.coordinator = Coordinator(project_root_or_store)
        if capacity_contract is not None and capacity is not None and capacity_contract != capacity:
            raise CapacityContractError("capacity_contract 与 capacity 冲突")
        if dependency_contracts is not None and dependencies is not None and dependency_contracts != dependencies:
            raise DependencyError("dependency_contracts 与 dependencies 冲突")
        self.capacity_contract = normalize_capacity_contract(
            capacity_contract if capacity_contract is not None else capacity
        )
        supplied_dependencies = (
            dependency_contracts if dependency_contracts is not None else dependencies
        ) or {}
        if not isinstance(supplied_dependencies, Mapping):
            raise DependencyError("dependency_contracts 必须是 object")
        self.dependency_contracts = {}
        for key, value in supplied_dependencies.items():
            if not isinstance(value, Mapping):
                raise DependencyError(f"dependency_contracts[{key}] 必须是 object")
            self.dependency_contracts[str(key)] = copy.deepcopy(dict(value))
        self.clock = clock

    @property
    def events(self) -> EventStore:
        return self.coordinator.events

    @property
    def event_store(self) -> EventStore:
        return self.coordinator.events

    def _now(self) -> datetime:
        return _clock_value(self.clock)

    def _event_for_at(
        self,
        job: Mapping[str, Any],
        event_type: str,
        *,
        actor: str,
        payload: dict[str, Any] | None = None,
        created_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Build a Coordinator event using the scheduler clock.

        Keeping the lease timestamp and event timestamp on the same clock is
        important for deterministic tests and for fail-closed replay when a
        caller supplies a controlled clock.
        """
        return make_event(
            job_id=str(job["job_id"]),
            run_instance_id=str(job["run_instance_id"]),
            attempt_id=str(job["attempt_id"]),
            session_id=str(job["session_id"]),
            actor=actor,
            event_type=event_type,
            correlation_id=str(job.get("metadata", {}).get("_correlation_id", job["job_id"])),
            causation_id=job.get("last_event_id"),
            payload=payload,
            created_at=_timestamp(created_at or self._now()),
        )

    def _project_events_locked(
        self,
        events: Sequence[Mapping[str, Any]],
        *,
        as_of: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        return project_scheduler_events(
            events,
            capacity_contract=self.capacity_contract,
            dependency_contracts=self.dependency_contracts,
            as_of=as_of or self._now(),
            job_schema_path=self.events.job_schema_path,
            ttl_seconds=ttl_seconds,
        )

    def project(self, *, as_of: datetime | str | None = None, ttl_seconds: int | None = None) -> dict[str, Any]:
        """Read and project a consistent Event Store snapshot."""
        when = _parse_time(as_of, label="as_of") if isinstance(as_of, str) else as_of
        with self.events.locked():
            events = self.events._read_events_unlocked()
            return self._project_events_locked(events, as_of=when, ttl_seconds=ttl_seconds)

    snapshot = project
    project_snapshot = project
    projector = project

    def _read_projected_locked(self, *, as_of: datetime | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        events = self.events._read_events_unlocked()
        return events, self._project_events_locked(events, as_of=as_of or self._now())

    def refresh_readiness(self) -> list[dict[str, Any]]:
        """Append ready events for satisfiable ``new`` Jobs, then reproject.

        Readiness itself remains derived from replay; this method only emits
        the Coordinator lifecycle event that admits a Job to the queue.
        """
        changed: list[str] = []
        with self.events.locked():
            events = self.events._read_events_unlocked()
            # Validate the complete graph before any event is appended.
            self._project_events_locked(events)
            while True:
                jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
                statuses = {identity: value.get("status") for identity, value in jobs.items()}
                contracts = validate_dependency_graph(jobs, self.dependency_contracts or None)
                appendable = []
                for job_id in sorted(jobs):
                    job = jobs[job_id]
                    if job.get("status") != "new":
                        continue
                    readiness = evaluate_dependency_contract(
                        contracts[job_id], statuses, job_status="ready"
                    )
                    if readiness["ready"]:
                        appendable.append((job_id, job))
                if not appendable:
                    break
                for job_id, job in appendable:
                    event = self._event_for_at(
                        job,
                        "ready",
                        actor="coordinator",
                        payload={"reason": "scheduler_dependency_ready"},
                    )
                    normalized = self.events._normalise_for_append(
                        event, next_sequence=len(events) + 1
                    )
                    self.coordinator._replay_unlocked([*events, normalized])
                    stored = self.events._append_unlocked(normalized, events)
                    events.append(stored)
                    changed.append(job_id)
            final = self._project_events_locked(events)
            return [copy.deepcopy(final["jobs"][job_id]) for job_id in changed]

    reconcile_readiness = refresh_readiness
    admit_ready = refresh_readiness

    def ensure_ready(self, job_id: str) -> dict[str, Any]:
        """Admit one new Job only when its derived dependency state is ready."""
        if not isinstance(job_id, str) or not job_id:
            raise DependencyError("job_id 必须非空")
        with self.events.locked():
            events = self.events._read_events_unlocked()
            jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
            job = jobs.get(job_id)
            if job is None:
                raise JobError(f"Job 不存在：{job_id}")
            if job.get("status") == "ready":
                return copy.deepcopy(job)
            if job.get("status") != "new":
                raise ClaimError(f"Job 只有 new 才能由 scheduler admit，当前为 {job.get('status')}")
            contracts = validate_dependency_graph(jobs, self.dependency_contracts or None)
            statuses = {identity: value.get("status") for identity, value in jobs.items()}
            readiness = evaluate_dependency_contract(contracts[job_id], statuses, job_status="ready")
            if not readiness["ready"]:
                raise ClaimError(f"Job 尚未 ready：{'; '.join(readiness['reasons']) or readiness['state']}")
            event = self._event_for_at(
                job,
                "ready",
                actor="coordinator",
                payload={"reason": "scheduler_dependency_ready"},
            )
            normalized = self.events._normalise_for_append(event, next_sequence=len(events) + 1)
            projected = self.coordinator._replay_unlocked([*events, normalized])
            self.events._append_unlocked(normalized, events)
            return copy.deepcopy(projected[job_id])

    mark_ready = ensure_ready

    def create_job(
        self,
        job: Mapping[str, Any] | None = None,
        *,
        dependencies: Mapping[str, Any] | None = None,
        dependency_contract: Mapping[str, Any] | None = None,
        capacity: Mapping[str, Any] | None = None,
        priority: int | None = None,
        fairness_group: str | None = None,
        control_holder: str | None = None,
        ready: bool = False,
        **fields: Any,
    ) -> dict[str, Any]:
        """Create a Job with scheduler metadata, optionally admitting it."""
        if job is not None and fields:
            raise SchedulerError("create_job 不能同时传 job object 与 fields")
        candidate = copy.deepcopy(dict(job)) if job is not None else copy.deepcopy(fields)
        # Accept scheduler-only convenience fields on an input mapping, then
        # move them into Coordinator-safe metadata before the created event.
        for dependency_field in (DEPENDENCY_METADATA_KEY, "dependency_contract"):
            if dependency_field not in candidate:
                continue
            top_level_dependencies = candidate.pop(dependency_field)
            if dependencies is not None and dependencies != top_level_dependencies:
                raise DependencyError("Job dependencies 与 dependencies 参数冲突")
            dependencies = top_level_dependencies
        if CAPACITY_METADATA_KEY in candidate:
            top_level_capacity = candidate.pop(CAPACITY_METADATA_KEY)
            if capacity is not None and capacity != top_level_capacity:
                raise CapacityError("Job capacity 与 capacity 参数冲突")
            capacity = top_level_capacity
        for field_name, parameter_name in (
            ("priority", "priority"),
            ("fairness_group", "fairness_group"),
            ("control_holder", "control_holder"),
        ):
            if field_name not in candidate:
                continue
            top_level_value = candidate.pop(field_name)
            current_value = locals()[parameter_name]
            if current_value is not None and current_value != top_level_value:
                raise SchedulerError(f"Job {field_name} 与参数冲突")
            if parameter_name == "priority":
                priority = top_level_value
            elif parameter_name == "fairness_group":
                fairness_group = top_level_value
            else:
                control_holder = top_level_value
        if dependencies is not None and dependency_contract is not None and dependencies != dependency_contract:
            raise DependencyError("dependencies 与 dependency_contract 冲突")
        raw_dependency = dependency_contract if dependency_contract is not None else dependencies
        workflow_id = str(candidate.get("workflow_id", "workflow:default"))
        # Generate identity here so the persisted contract can bind to it
        # before Coordinator.create_job emits the created event.
        candidate.setdefault("job_id", f"job:{uuid.uuid4().hex}")
        candidate.setdefault("project_id", "project:local")
        candidate.setdefault("workflow_id", workflow_id)
        job_id = str(candidate["job_id"])
        metadata = copy.deepcopy(candidate.get("metadata", {}))
        if not isinstance(metadata, Mapping):
            raise SchedulerError("Job metadata 必须是 object")
        metadata = dict(metadata)
        scheduler_value = metadata.get(SCHEDULER_METADATA_KEY)
        if scheduler_value is not None and not isinstance(scheduler_value, Mapping):
            raise SchedulerError("Job metadata.scheduler 必须是 object")
        scheduler_metadata = dict(scheduler_value or {})
        existing_dependency = _extract_dependency_contract(candidate)
        if raw_dependency is not None and existing_dependency is not None:
            supplied_normalized = _normalize_dependency_contract(
                raw_dependency,
                workflow_id=workflow_id,
                job_id=job_id,
                require_identity=True,
            )
            existing_normalized = _normalize_dependency_contract(
                existing_dependency,
                workflow_id=workflow_id,
                job_id=job_id,
                require_identity=True,
            )
            if supplied_normalized != existing_normalized:
                raise DependencyError("Job dependency contract 与 metadata contract 冲突")
        if raw_dependency is None:
            raw_dependency = existing_dependency
        if raw_dependency is None:
            normalized_dependency = None
        else:
            normalized_dependency = _normalize_dependency_contract(
                raw_dependency,
                workflow_id=workflow_id,
                job_id=job_id,
                require_identity=True,
            )
            scheduler_metadata[DEPENDENCY_METADATA_KEY] = normalized_dependency
        if capacity is not None:
            scheduler_metadata[CAPACITY_METADATA_KEY] = _job_capacity({"job_id": job_id, "metadata": {SCHEDULER_METADATA_KEY: {CAPACITY_METADATA_KEY: capacity}}})
        elif CAPACITY_METADATA_KEY in scheduler_metadata:
            scheduler_metadata[CAPACITY_METADATA_KEY] = _job_capacity({"job_id": job_id, "metadata": {SCHEDULER_METADATA_KEY: scheduler_metadata[CAPACITY_METADATA_KEY]}})
        if priority is not None:
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise SchedulerError("priority 必须是整数")
            scheduler_metadata["priority"] = priority
        if fairness_group is not None:
            if not isinstance(fairness_group, str) or not fairness_group:
                raise SchedulerError("fairness_group 必须是非空字符串")
            scheduler_metadata["fairness_group"] = fairness_group
        if control_holder is not None:
            scheduler_metadata["control_holder"] = control_holder
        if scheduler_metadata:
            metadata[SCHEDULER_METADATA_KEY] = scheduler_metadata
        else:
            metadata.pop(SCHEDULER_METADATA_KEY, None)
        if metadata:
            candidate["metadata"] = metadata
        else:
            candidate.pop("metadata", None)
        normalize_write_scopes(candidate.get("write_scopes", []))
        _priority(candidate)
        _fairness_group(candidate)

        # Validate references against the existing replay plus this candidate
        # before Coordinator writes anything.  Forward references are rejected
        # until their target Job is durably present.
        with self.events.locked():
            existing_events = self.events._read_events_unlocked()
            existing_jobs = _raw_replay(existing_events, job_schema_path=self.events.job_schema_path)
            synthetic = copy.deepcopy(candidate)
            # Let Coordinator fill defaults; the fields relevant to the graph
            # are already explicit here.
            synthetic.setdefault("project_id", candidate.get("project_id", "project:local"))
            synthetic.setdefault("workflow_id", workflow_id)
            synthetic.setdefault("status", "new")
            combined = {**existing_jobs, job_id: synthetic}
            validate_dependency_graph(combined, self.dependency_contracts or None)
        created = self.coordinator.create_job(candidate)
        if ready:
            if created["status"] == "ready":
                return created
            return self.ensure_ready(job_id)
        return created

    create = create_job

    def enqueue_job(
        self,
        job: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create a Job and admit it when its dependency projection is ready.

        Waiting on a declared dependency is a normal queue state, not an
        error.  Unknown, cyclic, or cross-workflow references still raise
        before the ``created`` event is written.
        """
        kwargs["ready"] = False
        created = self.create_job(job, **kwargs)
        if created.get("status") != "new":
            return created
        try:
            return self.ensure_ready(str(created["job_id"]))
        except ClaimError:
            return created

    submit_job = enqueue_job
    add_job = enqueue_job
    enqueue = enqueue_job

    def _claim_event_locked(
        self,
        events: list[dict[str, Any]],
        job: Mapping[str, Any],
        worker_id: str,
        lease_seconds: int,
    ) -> dict[str, Any]:
        claimed_at = self._now()
        lease = {
            "holder": worker_id,
            "lease_id": f"lease:{uuid.uuid4().hex}",
            "expires_at": _timestamp(claimed_at + timedelta(seconds=lease_seconds)),
            "claimed_at": _timestamp(claimed_at),
        }
        event = self._event_for_at(
            job,
            "claimed",
            actor=worker_id,
            payload={"lease": lease},
            created_at=claimed_at,
        )
        normalized = self.events._normalise_for_append(
            event, next_sequence=len(events) + 1
        )
        projected = self.coordinator._replay_unlocked([*events, normalized])
        self.events._append_unlocked(normalized, events)
        return copy.deepcopy(projected[job["job_id"]])

    def _recover_expired_claim_locked(
        self,
        events: list[dict[str, Any]],
        job: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if job.get("status") != "claimed":
            return events, copy.deepcopy(dict(job))
        expiry = _lease_expiry(job)
        if expiry is None or expiry > self._now():
            return events, copy.deepcopy(dict(job))
        event = self._event_for_at(
            job,
            "ready",
            actor="coordinator",
            payload={"reason": "expired_lease_recovery"},
        )
        normalized = self.events._normalise_for_append(
            event, next_sequence=len(events) + 1
        )
        projected = self.coordinator._replay_unlocked([*events, normalized])
        self.events._append_unlocked(normalized, events)
        events.append(normalized)
        return events, copy.deepcopy(projected[job["job_id"]])

    def recover_expired_leases(self) -> list[dict[str, Any]]:
        """Durably release expired pre-start claims and return recovered Jobs."""
        recovered: list[str] = []
        with self.events.locked():
            events = self.events._read_events_unlocked()
            self._project_events_locked(events)
            jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
            for job_id in sorted(jobs):
                job = jobs[job_id]
                if job.get("status") != "claimed":
                    continue
                expiry = _lease_expiry(job)
                if expiry is not None and expiry <= self._now():
                    events, _ = self._recover_expired_claim_locked(events, job)
                    recovered.append(job_id)
            current = _raw_replay(events, job_schema_path=self.events.job_schema_path)
            return [copy.deepcopy(current[job_id]) for job_id in recovered]

    recover_expired_claims = recover_expired_leases

    def _claimable_decision_locked(
        self,
        snapshot: Mapping[str, Any],
        job_id: str,
        worker_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        jobs = snapshot["jobs"]
        job = jobs.get(job_id)
        if not isinstance(job, Mapping):
            raise JobError(f"Job 不存在：{job_id}")
        if job.get("status") != "ready":
            raise ClaimConflictError(f"Job 只有 ready 才能 claim，当前为 {job.get('status')}")
        if not job.get("readiness", {}).get("ready", False):
            readiness = job.get("readiness", {})
            raise ClaimError(
                f"Job dependency 未 ready：{'; '.join(readiness.get('reasons', [])) or readiness.get('state')}"
            )
        active = _active_reservations(jobs, _parse_time(snapshot["as_of"], label="snapshot as_of"))
        decision = capacity_decision(
            job,
            active,
            self.capacity_contract,
            worker_id=worker_id,
        )
        if not decision["allowed"]:
            if any("write scope overlaps" in reason for reason in decision["reasons"]):
                raise ScopeConflictError("; ".join(decision["reasons"]))
            raise CapacityError("; ".join(decision["reasons"]))
        return dict(job), decision

    def runnable_jobs(
        self,
        worker_id: str | None = None,
        *,
        snapshot: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Return deterministically ranked runnable Jobs for a worker."""
        value = dict(snapshot) if snapshot is not None else self.project()
        validate_snapshot(value)
        jobs = value["jobs"]
        active = _active_reservations(jobs, _parse_time(value["as_of"], label="snapshot as_of"))
        candidates: list[dict[str, Any]] = []
        for job_id in sorted(jobs):
            job = jobs[job_id]
            if job.get("status") != "ready" or not job.get("readiness", {}).get("ready"):
                continue
            decision = capacity_decision(
                job, active, self.capacity_contract, worker_id=worker_id
            )
            if not decision["allowed"]:
                continue
            value_copy = copy.deepcopy(dict(job))
            value_copy["claim_decision"] = decision
            candidates.append(value_copy)
        candidates.sort(key=lambda item: _selection_key(item["fairness"], str(item["job_id"])))
        return candidates

    ready_jobs = runnable_jobs
    select_jobs = runnable_jobs
    runnable = runnable_jobs

    def select_next_job(
        self,
        worker_id: str | None = None,
        *,
        snapshot: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        candidates = self.runnable_jobs(worker_id, snapshot=snapshot)
        return candidates[0] if candidates else None

    select_next = select_next_job
    select = select_next_job
    next_job = select_next_job

    def claim_next(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 300,
    ) -> dict[str, Any] | None:
        """Select and claim under one lock/reload/validate/append transaction."""
        if not isinstance(worker_id, str) or not worker_id:
            raise ClaimError("worker_id 必须非空")
        if worker_id.strip().lower() in {"human", "human_control", "human-takeover", "human_takeover"}:
            raise ClaimError("HUMAN control 不能通过 scheduler claim")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ClaimError("lease_seconds 必须为正整数")
        with self.events.locked():
            events = self.events._read_events_unlocked()
            # Validate the complete replay/dependency projection before any
            # recovery event can be appended.
            self._project_events_locked(events)
            # Recovery is itself an Event Store transition.  Recover every
            # expired pre-start claim while holding the same lock, so a worker
            # can use claim_next after a crashed claimant without a side
            # ledger or a second polling transaction.
            jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
            for job_id in sorted(jobs):
                job = jobs[job_id]
                if job.get("status") != "claimed":
                    continue
                expiry = _lease_expiry(job)
                if expiry is not None and expiry <= self._now():
                    events, _ = self._recover_expired_claim_locked(events, job)
            snapshot = self._project_events_locked(events)
            candidate = self.select_next_job(worker_id, snapshot=snapshot)
            if candidate is None:
                return None
            return self._claim_event_locked(
                events,
                snapshot["jobs"][candidate["job_id"]],
                worker_id,
                lease_seconds,
            )

    claim_one = claim_next

    def claim_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 300,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly claim one Job with idempotent same-worker semantics."""
        if not isinstance(job_id, str) or not job_id:
            raise ClaimError("job_id 必须非空")
        if not isinstance(worker_id, str) or not worker_id:
            raise ClaimError("worker_id 必须非空")
        if worker_id.strip().lower() in {"human", "human_control", "human-takeover", "human_takeover"}:
            raise ClaimError("HUMAN control 不能通过 scheduler claim")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ClaimError("lease_seconds 必须为正整数")
        with self.events.locked():
            events = self.events._read_events_unlocked()
            # Validate all scheduler metadata before a stale lease can be
            # released and before the claim event is constructed.
            self._project_events_locked(events)
            jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
            job = jobs.get(job_id)
            if job is None:
                raise JobError(f"Job 不存在：{job_id}")
            if session_id is not None and session_id != job.get("session_id"):
                raise ClaimError("claim session_id 与 Job session_id 不一致")
            status = job.get("status")
            if status in ACTIVE_STATUSES:
                holder = (job.get("lease") or {}).get("holder") if isinstance(job.get("lease"), Mapping) else None
                expiry = _lease_expiry(job)
                if holder == worker_id and expiry is not None and expiry > self._now():
                    # A retry after a lost response returns the existing claim
                    # without creating a second event.
                    return copy.deepcopy(job)
                if expiry is not None and expiry <= self._now() and status == "claimed":
                    events, job = self._recover_expired_claim_locked(events, job)
                    jobs = _raw_replay(events, job_schema_path=self.events.job_schema_path)
                else:
                    raise ClaimConflictError(f"Job 已由未过期 lease 持有或正在执行：{job_id}")
            snapshot = self._project_events_locked(events)
            current, _ = self._claimable_decision_locked(snapshot, job_id, worker_id)
            return self._claim_event_locked(events, current, worker_id, lease_seconds)

    claim = claim_job
    claim_ready = claim_job

    def build_snapshot(self, *, ttl_seconds: int | None = 300, as_of: datetime | str | None = None) -> dict[str, Any]:
        return self.project(as_of=as_of, ttl_seconds=ttl_seconds)

    def write_snapshot(
        self,
        path: Path | str,
        *,
        ttl_seconds: int | None = 300,
        as_of: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Write only a derived, digest-bound snapshot atomically."""
        target = Path(path).expanduser()
        if target.exists() and target.is_symlink():
            raise SnapshotError("snapshot path 不能是符号链接")
        snapshot = self.build_snapshot(ttl_seconds=ttl_seconds, as_of=as_of)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        encoded = (json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        try:
            with temporary.open("wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            try:
                directory_fd = os.open(target.parent, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return copy.deepcopy(snapshot)

    save_snapshot = write_snapshot

    def load_snapshot(
        self,
        path: Path | str,
        *,
        now: datetime | str | None = None,
        max_age_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Load a snapshot only if it matches the live Event Store projection."""
        target = Path(path).expanduser()
        if target.is_symlink() or not target.is_file():
            raise SnapshotError("snapshot 必须是 regular file")
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise SnapshotError(f"无法读取 snapshot：{target}") from exc
        if not raw or not raw.endswith(b"\n"):
            raise SnapshotError("snapshot 末尾缺少换行，疑似截断")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotError("snapshot JSON 无效") from exc
        if not isinstance(value, Mapping):
            raise SnapshotError("snapshot 必须是 object")
        snapshot = validate_snapshot(value, now=now)
        current = _parse_time(now, label="now") if isinstance(now, str) else (now or datetime.now(timezone.utc))
        if current.tzinfo is None:
            raise SnapshotError("now 必须包含时区")
        if max_age_seconds is not None:
            if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
                raise SnapshotError("max_age_seconds 必须是正整数")
            if current.astimezone(timezone.utc) - _parse_time(snapshot["as_of"], label="snapshot as_of") > timedelta(seconds=max_age_seconds):
                raise SnapshotExpiredError("scheduler snapshot 超过 max_age_seconds")
        with self.events.locked():
            events = self.events._read_events_unlocked()
            source_sequence = int(events[-1]["sequence"]) if events else 0
            source_digest = event_source_digest(events)
            if snapshot["source_sequence"] != source_sequence:
                raise SnapshotError("snapshot source sequence 已漂移")
            if snapshot["source_digest"] != source_digest:
                raise SnapshotError("snapshot source digest 已漂移")
            expected = self._project_events_locked(
                events,
                as_of=_parse_time(snapshot["as_of"], label="snapshot as_of"),
            )
            # Expiry belongs to the stored snapshot envelope.  The derived
            # body is recomputed at the original as_of for deterministic
            # comparison, then the stored expiry is restored for digest check.
            expected["ttl_seconds"] = snapshot.get("ttl_seconds")
            expected["expires_at"] = snapshot.get("expires_at")
            expected["snapshot_digest"] = _snapshot_digest(expected)
            if expected != dict(snapshot):
                raise SnapshotError("snapshot projection 与当前 Event Store/configuration 漂移")
        return snapshot

    read_snapshot = load_snapshot


def project_scheduler(
    project_root_or_store: Path | str | EventStore | Coordinator,
    *,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
    as_of: datetime | str | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Convenience wrapper around :class:`Scheduler.project`."""
    scheduler = Scheduler(
        project_root_or_store,
        capacity_contract=capacity_contract,
        capacity=capacity,
        dependency_contracts=dependency_contracts,
        dependencies=dependencies,
    )
    return scheduler.project(as_of=as_of, ttl_seconds=ttl_seconds)


def build_snapshot(
    project_root_or_store: Path | str | EventStore | Coordinator,
    *,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
    as_of: datetime | str | None = None,
    ttl_seconds: int | None = 300,
) -> dict[str, Any]:
    return Scheduler(
        project_root_or_store,
        capacity_contract=capacity_contract,
        capacity=capacity,
        dependency_contracts=dependency_contracts,
        dependencies=dependencies,
    ).build_snapshot(as_of=as_of, ttl_seconds=ttl_seconds)


def load_snapshot(
    project_root_or_store: Path | str | EventStore | Coordinator,
    path: Path | str,
    *,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
    now: datetime | str | None = None,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    return Scheduler(
        project_root_or_store,
        capacity_contract=capacity_contract,
        capacity=capacity,
        dependency_contracts=dependency_contracts,
        dependencies=dependencies,
    ).load_snapshot(path, now=now, max_age_seconds=max_age_seconds)


def select_next_job(
    project_root_or_store: Path | str | EventStore | Coordinator,
    worker_id: str | None = None,
    *,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any] | None:
    return Scheduler(
        project_root_or_store,
        capacity_contract=capacity_contract,
        capacity=capacity,
        dependency_contracts=dependency_contracts,
        dependencies=dependencies,
    ).select_next_job(worker_id)


select_next = select_next_job


def claim_next(
    project_root_or_store: Path | str | EventStore | Coordinator,
    worker_id: str,
    *,
    lease_seconds: int = 300,
    capacity_contract: Mapping[str, Any] | None = None,
    capacity: Mapping[str, Any] | None = None,
    dependency_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    dependencies: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any] | None:
    return Scheduler(
        project_root_or_store,
        capacity_contract=capacity_contract,
        capacity=capacity,
        dependency_contracts=dependency_contracts,
        dependencies=dependencies,
    ).claim_next(worker_id, lease_seconds=lease_seconds)


__all__ = [
    "ACTIVE_STATUSES",
    "DEFAULT_TERMINAL_POLICY",
    "SNAPSHOT_VERSION",
    "TERMINAL_STATUSES",
    "CapacityContractError",
    "CapacityError",
    "ClaimConflictError",
    "ClaimError",
    "DependencyContractError",
    "DependencyCycleError",
    "DependencyError",
    "ExpiredSnapshotError",
    "NoClaimAvailable",
    "Scheduler",
    "SchedulerError",
    "SchedulerSnapshotError",
    "ScopeConflictError",
    "SnapshotError",
    "SnapshotExpiredError",
    "account_capacity",
    "build_snapshot",
    "capacity_decision",
    "capacity_usage",
    "claim_next",
    "dependency_ready",
    "evaluate_dependencies",
    "evaluate_dependency_contract",
    "event_source_digest",
    "has_human_control",
    "is_dependency_ready",
    "load_snapshot",
    "normalize_capacity_contract",
    "normalize_dependency_contract",
    "normalize_write_scopes",
    "project_events",
    "project_scheduler",
    "project_scheduler_events",
    "project_snapshot",
    "scopes_overlap",
    "select_next",
    "select_next_job",
    "validate_capacity",
    "validate_capacity_contract",
    "validate_dependencies",
    "validate_dependency_contract",
    "validate_dependency_graph",
    "validate_snapshot",
    "write_scopes_overlap",
]
