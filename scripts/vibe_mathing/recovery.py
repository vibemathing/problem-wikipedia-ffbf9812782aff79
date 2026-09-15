"""Pure, finite recovery policy and integrity-bound checkpoint primitives.

This module is deliberately independent from the runtime executor and from any
network client.  It classifies an observation, returns one bounded decision, and
lets a caller persist the resulting checkpoint.  In particular, asking for a
recovery decision never sleeps, reconnects, sends a goal, or writes a failed
mathematical route.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
CHECKPOINT_SCHEMA = ROOT / "research/schema/recovery-checkpoint.schema.json"
POLICY_SCHEMA = ROOT / "research/schema/recovery-policy.schema.json"
CHECKPOINT_COMMIT_MARKER = "VIBE-MATHING-RECOVERY-CHECKPOINT-COMMIT-V1"

ERROR_KINDS = (
    "rate_limit",
    "network_disconnect",
    "delivery_timeout",
    "execution_timeout",
    "tool_error",
    "resource_limit",
    "hard_stop",
    "session_lost",
    "invalid_checkpoint",
    "unknown",
)
DECISION_KINDS = (
    "retry_same",
    "resume_verified",
    "switch_route",
    "park",
    "block_human",
    "terminal_execution_failure",
)
TRANSPORT_FAILURE_KINDS = frozenset(
    {"rate_limit", "network_disconnect", "delivery_timeout", "session_lost"}
)
# Only these categories describe a bounded mathematical route execution.  A
# user stop, unknown error, or corrupt checkpoint is control-plane evidence and
# must not be promoted into a mathematical failed-route record.
MATHEMATICAL_ROUTE_FAILURE_KINDS = frozenset(
    {"execution_timeout", "tool_error", "resource_limit"}
)


class RecoveryError(RuntimeError):
    """Base class for fail-closed recovery errors."""


class PolicyValidationError(RecoveryError):
    """The recovery policy is malformed or incomplete."""


class CheckpointValidationError(RecoveryError):
    """A checkpoint is malformed, expired, truncated, or mis-bound."""


class CheckpointExpired(CheckpointValidationError):
    """The checkpoint's explicit expiry has passed."""


class ResumeReceiptError(RecoveryError):
    """A proposed session migration lacks a valid receipt."""


class EffectConflict(RecoveryError):
    """An idempotency key was reused with different effect content."""


class InjectedCrash(RecoveryError):
    """Test-only crash point; no real process or network is started."""


# All six decisions have a contract.  The rules below select a contract and
# add the error-specific finite retry/recovery budget.
DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": "1.0.0",
    "policy_id": "recovery-policy-v1",
    "max_total_attempts": 8,
    "max_same_route_attempts": 2,
    "max_route_switches": 3,
    "max_resume_attempts": 1,
    "max_delivery_retries": 1,
    "backoff": {
        "strategy": "exponential_no_jitter",
        "base_seconds": 1,
        "max_seconds": 60,
    },
    "decision_contracts": {
        "retry_same": {
            "budget": {
                "max_total_attempts": 8,
                "max_same_route_attempts": 2,
                "max_route_switches": 0,
                "max_resume_attempts": 0,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 1,
                "max_seconds": 60,
            },
            "idempotency": "replay_safe_with_dedupe_key",
            "stop_proof": "finite retry budget and an idempotency key are required",
        },
        "resume_verified": {
            "budget": {
                "max_total_attempts": 0,
                "max_same_route_attempts": 0,
                "max_route_switches": 0,
                "max_resume_attempts": 1,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 0,
                "max_seconds": 0.001,
            },
            "idempotency": "resume_receipt_required",
            "stop_proof": "only one unexpired receipt bound to the exact checkpoint may resume",
        },
        "switch_route": {
            "budget": {
                "max_total_attempts": 8,
                "max_same_route_attempts": 0,
                "max_route_switches": 3,
                "max_resume_attempts": 0,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 0,
                "max_seconds": 0.001,
            },
            "idempotency": "new_route_from_verified_checkpoint",
            "stop_proof": "a new route starts only from a sealed checkpoint and a finite switch budget",
        },
        "park": {
            "budget": {
                "max_total_attempts": 0,
                "max_same_route_attempts": 0,
                "max_route_switches": 0,
                "max_resume_attempts": 0,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 0,
                "max_seconds": 0.001,
            },
            "idempotency": "no_external_write",
            "stop_proof": "no automatic action is permitted while the run is parked",
        },
        "block_human": {
            "budget": {
                "max_total_attempts": 0,
                "max_same_route_attempts": 0,
                "max_route_switches": 0,
                "max_resume_attempts": 0,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 0,
                "max_seconds": 0.001,
            },
            "idempotency": "no_external_write",
            "stop_proof": "ambiguity or identity failure requires a human and forbids blind replay",
        },
        "terminal_execution_failure": {
            "budget": {
                "max_total_attempts": 0,
                "max_same_route_attempts": 0,
                "max_route_switches": 0,
                "max_resume_attempts": 0,
            },
            "backoff": {
                "strategy": "exponential_no_jitter",
                "base_seconds": 0,
                "max_seconds": 0.001,
            },
            "idempotency": "terminal_no_retry",
            "stop_proof": "the bounded execution has no safe remaining retry or route",
        },
    },
    "rules": {
        "rate_limit": {
            "decision": "retry_same",
            "max_attempts": 3,
            "backoff_multiplier": 2,
            "idempotency": "replay_safe_with_dedupe_key",
            "stop_proof": "rate-limit retries stop at the finite rate-limit budget",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "network_disconnect": {
            "decision": "retry_same",
            "max_attempts": 2,
            "backoff_multiplier": 2,
            "idempotency": "replay_safe_with_dedupe_key",
            "stop_proof": "network retries stop at the finite transport budget",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "delivery_timeout": {
            "decision": "park",
            "max_attempts": 0,
            "backoff_multiplier": 1,
            "idempotency": "no_external_write",
            "stop_proof": "delivery ambiguity is parked until the same destination is externally probed",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": True,
        },
        "execution_timeout": {
            "decision": "retry_same",
            "max_attempts": 1,
            "backoff_multiplier": 2,
            "idempotency": "replay_safe_with_dedupe_key",
            "stop_proof": "one bounded execution retry is followed by route change or terminal stop",
            "records_failed_route": True,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "tool_error": {
            "decision": "retry_same",
            "max_attempts": 1,
            "backoff_multiplier": 2,
            "idempotency": "replay_safe_with_dedupe_key",
            "stop_proof": "one bounded tool retry is followed by route change or terminal stop",
            "records_failed_route": True,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "resource_limit": {
            "decision": "switch_route",
            "max_attempts": 0,
            "backoff_multiplier": 1,
            "idempotency": "new_route_from_verified_checkpoint",
            "stop_proof": "resource exhaustion cannot reconnect the same unbounded execution",
            "records_failed_route": True,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "hard_stop": {
            "decision": "block_human",
            "max_attempts": 0,
            "backoff_multiplier": 1,
            "idempotency": "no_external_write",
            "stop_proof": "an explicit hard stop is never overridden by recovery automation",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "session_lost": {
            "decision": "resume_verified",
            "max_attempts": 1,
            "backoff_multiplier": 1,
            "idempotency": "resume_receipt_required",
            "stop_proof": "session recovery requires one exact, unexpired resume receipt",
            "records_failed_route": False,
            "requires_resume_receipt": True,
            "requires_delivery_probe": False,
        },
        "invalid_checkpoint": {
            "decision": "block_human",
            "max_attempts": 0,
            "backoff_multiplier": 1,
            "idempotency": "no_external_write",
            "stop_proof": "invalid checkpoint identity or integrity forbids replay",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
        "unknown": {
            "decision": "block_human",
            "max_attempts": 0,
            "backoff_multiplier": 1,
            "idempotency": "no_external_write",
            "stop_proof": "an unclassified error is fail-closed and needs human classification",
            "records_failed_route": False,
            "requires_resume_receipt": False,
            "requires_delivery_probe": False,
        },
    },
}


@dataclass(frozen=True)
class RecoveryPolicy:
    """Validated immutable view of a policy mapping."""

    value: dict[str, Any]

    @classmethod
    def default(cls) -> "RecoveryPolicy":
        return cls.from_mapping(DEFAULT_POLICY)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RecoveryPolicy":
        candidate = _json_clone(value)
        validate_policy(candidate)
        return cls(candidate)

    def as_dict(self) -> dict[str, Any]:
        return _json_clone(self.value)

    def rule(self, error_kind: str) -> dict[str, Any]:
        return copy.deepcopy(self.value["rules"][error_kind])

    def contract(self, decision: str) -> dict[str, Any]:
        return copy.deepcopy(self.value["decision_contracts"][decision])


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _pretty_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_value(value: Any) -> str:
    """Hash a JSON value using the same canonical encoding as checkpoint seals."""

    return sha256_bytes(_canonical_bytes(value))


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def _normalise_digest(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise CheckpointValidationError(f"{label} must be a SHA-256 string")
    candidate = value.lower()
    if candidate.startswith("sha256:"):
        candidate = candidate.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", candidate):
        raise CheckpointValidationError(f"{label} is not a lowercase SHA-256 digest")
    return "sha256:" + candidate


def _normalise_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CheckpointValidationError(f"{label} must be a non-empty identifier")
    if len(value) > 256 or any(char in value for char in "\x00\r\n"):
        raise CheckpointValidationError(f"{label} contains an invalid control character or is too long")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise CheckpointValidationError(f"{label} must be an ISO date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckpointValidationError(f"{label} is not an ISO date-time") from exc
    if parsed.tzinfo is None:
        raise CheckpointValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _now(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CheckpointValidationError("now must include a timezone")
        return value.astimezone(timezone.utc)
    return _parse_time(value, "now")


def _schema_errors(schema_path: Path, value: Mapping[str, Any]) -> list[str]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"cannot read recovery schema: {schema_path}") from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    ]


def validate_policy(value: Mapping[str, Any]) -> None:
    """Validate all policy categories and all six decision contracts."""

    if not isinstance(value, Mapping):
        raise PolicyValidationError("recovery policy must be an object")
    errors = _schema_errors(POLICY_SCHEMA, value)
    if errors:
        raise PolicyValidationError(errors[0])
    for error_kind in ERROR_KINDS:
        rule = value["rules"][error_kind]
        if rule["decision"] not in DECISION_KINDS:
            raise PolicyValidationError(f"unsupported decision for {error_kind}")
        if rule["max_attempts"] > value["max_total_attempts"]:
            raise PolicyValidationError(f"{error_kind} retry budget exceeds total budget")
        if rule["requires_resume_receipt"] and rule["decision"] != "resume_verified":
            raise PolicyValidationError(f"{error_kind} receipt flag does not select resume_verified")
    if value["backoff"]["max_seconds"] < value["backoff"]["base_seconds"]:
        raise PolicyValidationError("policy backoff max_seconds is below base_seconds")


def load_policy(path: Path) -> RecoveryPolicy:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyValidationError(f"cannot read recovery policy: {path}") from exc
    return RecoveryPolicy.from_mapping(value)


def _checkpoint_base(value: Mapping[str, Any]) -> dict[str, Any]:
    base = _json_clone(value)
    base.pop("checkpoint_digest", None)
    base.pop("integrity", None)
    return base


def _checkpoint_payload_digest(value: Mapping[str, Any]) -> str:
    return sha256_value(_checkpoint_base(value))


def _seal_checkpoint(value: Mapping[str, Any]) -> dict[str, Any]:
    result = _json_clone(value)
    result["checkpoint_digest"] = _checkpoint_payload_digest(result)
    result["integrity"] = {
        "payload_sha256": result["checkpoint_digest"],
        "byte_length": 1,
        "commit_marker": CHECKPOINT_COMMIT_MARKER,
    }
    # byte_length is outside the hashed payload.  Iterate because a change from
    # e.g. 99 to 100 bytes changes the pretty JSON length itself.
    for _ in range(8):
        encoded = _pretty_bytes(result)
        length = len(encoded)
        if result["integrity"]["byte_length"] == length:
            break
        result["integrity"]["byte_length"] = length
    else:  # pragma: no cover - only reachable with an exotic JSON encoder
        raise CheckpointValidationError("could not stabilize checkpoint byte length")
    errors = _schema_errors(CHECKPOINT_SCHEMA, result)
    if errors:
        raise CheckpointValidationError(errors[0])
    return result


def _validate_effect_uniqueness(value: Mapping[str, Any]) -> None:
    ids = [item["effect_id"] for item in value["effect_ledger"]]
    if len(ids) != len(set(ids)):
        raise CheckpointValidationError("effect_ledger contains duplicate effect_id")
    sequences = [item["sequence"] for item in value["effect_ledger"]]
    if len(sequences) != len(set(sequences)):
        raise CheckpointValidationError("effect_ledger contains duplicate sequence")


def validate_checkpoint(
    value: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None = None,
    now: datetime | str | None = None,
    raw_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate schema, seal digest, expiry and exact identity binding.

    ``raw_bytes`` is used by :func:`load_checkpoint`; its length and parsed
    payload must match the integrity seal, so a syntactically valid truncation
    cannot silently become a new checkpoint.
    """

    if not isinstance(value, Mapping):
        raise CheckpointValidationError("checkpoint must be an object")
    candidate = _json_clone(value)
    errors = _schema_errors(CHECKPOINT_SCHEMA, candidate)
    if errors:
        raise CheckpointValidationError(errors[0])
    expected_digest = _checkpoint_payload_digest(candidate)
    if candidate["checkpoint_digest"] != expected_digest:
        raise CheckpointValidationError("checkpoint_digest does not match checkpoint payload")
    if candidate["integrity"]["payload_sha256"] != expected_digest:
        raise CheckpointValidationError("checkpoint integrity payload_sha256 does not match")
    if candidate["integrity"]["commit_marker"] != CHECKPOINT_COMMIT_MARKER:
        raise CheckpointValidationError("checkpoint commit marker is invalid")
    encoded = _pretty_bytes(candidate)
    if candidate["integrity"]["byte_length"] != len(encoded):
        raise CheckpointValidationError("checkpoint byte_length does not match canonical encoding")
    if raw_bytes is not None:
        if len(raw_bytes) != candidate["integrity"]["byte_length"]:
            raise CheckpointValidationError("checkpoint file is truncated or has trailing bytes")
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckpointValidationError("checkpoint file is not valid UTF-8 JSON") from exc
        if parsed != candidate:
            raise CheckpointValidationError("checkpoint file bytes do not match parsed checkpoint")
    _validate_effect_uniqueness(candidate)
    if candidate["status"] == "stalled" and candidate["completion_status"] == "completed":
        raise CheckpointValidationError("stalled checkpoint cannot be completed")
    if candidate["status"] == "completed" and candidate["completion_status"] != "completed":
        raise CheckpointValidationError("completed checkpoint must have completed completion_status")
    current = _now(now)
    if current >= _parse_time(candidate["expires_at"], "expires_at"):
        raise CheckpointExpired("checkpoint has expired")
    if _parse_time(candidate["updated_at"], "updated_at") < _parse_time(
        candidate["created_at"], "created_at"
    ):
        raise CheckpointValidationError("updated_at precedes created_at")
    for key, expected_value in _flatten_expected(expected or {}).items():
        if key not in candidate:
            continue
        comparable = expected_value
        if key.endswith("_fingerprint") or key.endswith("_digest"):
            comparable = _normalise_digest(expected_value, key)
        if candidate[key] != comparable:
            raise CheckpointValidationError(f"checkpoint identity mismatch: {key}")
    return candidate


def _flatten_expected(expected: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in expected.items():
        if key in {"identity", "fingerprints", "digests"} and isinstance(value, Mapping):
            result.update(value)
        else:
            result[key] = value
    return result


def _required_map(
    direct: Mapping[str, Any] | None,
    fields: Mapping[str, Any],
    required: Sequence[str],
    aliases: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    result = dict(direct or {})
    alias_map = aliases or {}
    for name in required:
        if name in result:
            continue
        for alias in alias_map.get(name, (name,)):
            if alias in fields:
                result[name] = fields[alias]
                break
    missing = [name for name in required if name not in result]
    if missing:
        raise CheckpointValidationError("missing checkpoint binding: " + ", ".join(missing))
    return result


def create_checkpoint(
    *,
    identity: Mapping[str, Any] | None = None,
    fingerprints: Mapping[str, Any] | None = None,
    digests: Mapping[str, Any] | None = None,
    next_obligation: str | Mapping[str, Any] = "resume the next bounded obligation",
    best_verified_result: Mapping[str, Any] | None = None,
    failed_route_refs: Sequence[str] = (),
    effect_ledger: Sequence[Mapping[str, Any]] = (),
    budget: Mapping[str, int] | None = None,
    budget_usage: Mapping[str, int] | None = None,
    checkpoint_id: str | None = None,
    sequence: int = 1,
    parent_checkpoint_digest: str | None = None,
    status: str = "active",
    completion_status: str = "open",
    migration_count: int = 0,
    last_error_kind: str | None = None,
    resume_receipt_digest: str | None = None,
    created_at: str | None = None,
    updated_at: str | None = None,
    expires_at: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Create and seal a checkpoint from explicit identity/fingerprint/digest maps.

    The ``fields`` fallback keeps the function convenient for callers that pass
    ``task_id=...`` or ``provider_fingerprint=...`` directly, while still
    requiring every identity binding rather than inventing one.
    """

    identity_required = (
        "project_id",
        "workflow_id",
        "task_id",
        "step_id",
        "job_id",
        "run_id",
        "attempt_id",
        "problem_id",
        "session_id",
        "route_id",
    )
    fingerprint_required = (
        "provider_fingerprint",
        "wire_api_fingerprint",
        "model_fingerprint",
        "tool_fingerprint",
        "runtime_fingerprint",
        "session_fingerprint",
    )
    digest_required = (
        "input_digest",
        "problem_contract_digest",
        "goal_digest",
        "entrypoint_digest",
    )
    identity_map = _required_map(identity, fields, identity_required)
    fingerprint_map = _required_map(fingerprints, fields, fingerprint_required, {
        "provider_fingerprint": ("provider_fingerprint", "provider"),
        "wire_api_fingerprint": ("wire_api_fingerprint", "wire_api", "wire"),
        "model_fingerprint": ("model_fingerprint", "model"),
        "tool_fingerprint": ("tool_fingerprint", "tool"),
        "runtime_fingerprint": ("runtime_fingerprint", "runtime"),
        "session_fingerprint": ("session_fingerprint", "session"),
    })
    digest_map = _required_map(digests, fields, digest_required, {
        "input_digest": ("input_digest", "input"),
        "problem_contract_digest": ("problem_contract_digest", "problem_digest", "problem_contract", "problem"),
        "goal_digest": ("goal_digest", "goal"),
        "entrypoint_digest": ("entrypoint_digest", "entry_digest", "entrypoint", "entry"),
    })
    identity_map = {
        key: _normalise_identifier(value, key) for key, value in identity_map.items()
    }
    if not re.fullmatch(r"^problem:[a-z0-9][a-z0-9.-]*$", identity_map["problem_id"]):
        raise CheckpointValidationError("problem_id is not a canonical problem identifier")
    if not re.fullmatch(r"^route:[A-Za-z0-9][A-Za-z0-9_.:-]*$", identity_map["route_id"]):
        raise CheckpointValidationError("route_id is not a canonical route identifier")
    fingerprint_map = {
        key: _normalise_digest(value, key) for key, value in fingerprint_map.items()
    }
    digest_map = {key: _normalise_digest(value, key) for key, value in digest_map.items()}
    if sequence < 1:
        raise CheckpointValidationError("checkpoint sequence must be positive")
    if parent_checkpoint_digest is not None:
        parent_checkpoint_digest = _normalise_digest(parent_checkpoint_digest, "parent_checkpoint_digest")
    now_value = created_at or utc_now()
    _parse_time(now_value, "created_at")
    updated_value = updated_at or now_value
    _parse_time(updated_value, "updated_at")
    expiry_value = expires_at or (
        _parse_time(now_value, "created_at") + timedelta(hours=1)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    _parse_time(expiry_value, "expires_at")
    raw_budget = {
        "max_total_attempts": 8,
        "max_same_route_attempts": 2,
        "max_route_switches": 3,
        "max_resume_attempts": 1,
        "max_delivery_retries": 1,
        **dict(budget or {}),
    }
    raw_usage = {
        "total_attempts": 0,
        "same_route_attempts": 0,
        "route_switches": 0,
        "resume_attempts": 0,
        "delivery_retries": 0,
        **dict(budget_usage or {}),
    }
    for key, value in {**raw_budget, **raw_usage}.items():
        if not isinstance(value, int) or value < 0:
            raise CheckpointValidationError(f"checkpoint budget values must be non-negative integers: {key}")
    if raw_usage["total_attempts"] > raw_budget["max_total_attempts"]:
        raise CheckpointValidationError("total_attempts exceeds max_total_attempts")
    if raw_usage["same_route_attempts"] > raw_budget["max_same_route_attempts"]:
        raise CheckpointValidationError("same_route_attempts exceeds max_same_route_attempts")
    if raw_usage["route_switches"] > raw_budget["max_route_switches"]:
        raise CheckpointValidationError("route_switches exceeds max_route_switches")
    if raw_usage["resume_attempts"] > raw_budget["max_resume_attempts"]:
        raise CheckpointValidationError("resume_attempts exceeds max_resume_attempts")
    if raw_usage["delivery_retries"] > raw_budget["max_delivery_retries"]:
        raise CheckpointValidationError("delivery_retries exceeds max_delivery_retries")
    if status not in {"active", "checkpointed", "stalled", "parked", "blocked", "failed", "completed"}:
        raise CheckpointValidationError("invalid checkpoint status")
    if completion_status not in {"open", "candidate", "refuted", "completed"}:
        raise CheckpointValidationError("invalid checkpoint completion_status")
    if status == "completed" and completion_status != "completed":
        raise CheckpointValidationError("completed checkpoint must have completed completion_status")
    if status == "stalled" and completion_status == "completed":
        raise CheckpointValidationError("stalled checkpoint cannot be completed")
    if last_error_kind is not None and last_error_kind not in ERROR_KINDS:
        raise CheckpointValidationError("invalid last_error_kind")
    if migration_count < 0:
        raise CheckpointValidationError("migration_count must be non-negative")
    if resume_receipt_digest is not None:
        resume_receipt_digest = _normalise_digest(resume_receipt_digest, "resume_receipt_digest")

    normalized_effects: list[dict[str, Any]] = []
    for index, item in enumerate(effect_ledger, 1):
        effect = _json_clone(item)
        effect.setdefault("sequence", index)
        effect.setdefault("status", "committed")
        effect.setdefault("committed_at", updated_value)
        effect["effect_id"] = _normalise_identifier(effect.get("effect_id"), "effect_id")
        if effect.get("effect_type") not in {"candidate", "event"}:
            raise CheckpointValidationError("effect_type must be candidate or event")
        effect["payload_digest"] = _normalise_digest(effect.get("payload_digest"), "payload_digest")
        normalized_effects.append(effect)
    if len({item["effect_id"] for item in normalized_effects}) != len(normalized_effects):
        raise CheckpointValidationError("effect_ledger contains duplicate effect_id")
    normalized_routes = list(failed_route_refs)
    if len(set(normalized_routes)) != len(normalized_routes):
        raise CheckpointValidationError("failed_route_refs contains duplicates")
    for route in normalized_routes:
        if not isinstance(route, str) or not re.fullmatch(r"^route:[A-Za-z0-9][A-Za-z0-9_.:-]*$", route):
            raise CheckpointValidationError("failed_route_refs contains an invalid route")
    if best_verified_result is not None and len(_canonical_bytes(best_verified_result)) > 65_536:
        raise CheckpointValidationError("best_verified_result is too large")
    seed = {
        **identity_map,
        **fingerprint_map,
        **digest_map,
        "sequence": sequence,
        "parent_checkpoint_digest": parent_checkpoint_digest,
    }
    generated_id = "checkpoint:" + hashlib.sha256(_canonical_bytes(seed)).hexdigest()[:24]
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "checkpoint_id": checkpoint_id or generated_id,
        "sequence": sequence,
        "parent_checkpoint_digest": parent_checkpoint_digest,
        **identity_map,
        **fingerprint_map,
        **digest_map,
        "status": status,
        "completion_status": completion_status,
        "budget": raw_budget,
        "budget_usage": raw_usage,
        "best_verified_result": _json_clone(best_verified_result),
        "next_obligation": _json_clone(next_obligation),
        "failed_route_refs": normalized_routes,
        "effect_ledger": normalized_effects,
        "migration_count": migration_count,
        "last_error_kind": last_error_kind,
        "created_at": now_value,
        "updated_at": updated_value,
        "expires_at": expiry_value,
    }
    if resume_receipt_digest is not None:
        result["resume_receipt_digest"] = resume_receipt_digest
    return _seal_checkpoint(result)


# Descriptive aliases used by small callers and tests.
build_checkpoint = create_checkpoint
seal_checkpoint = _seal_checkpoint


def load_checkpoint(
    path: Path,
    *,
    expected: Mapping[str, Any] | None = None,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CheckpointValidationError(f"cannot read checkpoint: {path}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointValidationError(f"checkpoint is truncated or invalid JSON: {path}") from exc
    return validate_checkpoint(value, expected=expected, now=now, raw_bytes=raw)


def write_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Atomically replace the current checkpoint without changing its content."""

    validated = validate_checkpoint(checkpoint)
    encoded = _pretty_bytes(validated)
    if len(encoded) != validated["integrity"]["byte_length"]:
        raise CheckpointValidationError("checkpoint is not sealed for its canonical byte length")
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return validated


class CheckpointStore:
    """Small atomic store enforcing a contiguous checkpoint lineage."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self, *, expected: Mapping[str, Any] | None = None, now: datetime | str | None = None) -> dict[str, Any]:
        return load_checkpoint(self.path, expected=expected, now=now)

    def commit(self, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        candidate = validate_checkpoint(checkpoint)
        if self.path.exists():
            current = load_checkpoint(self.path)
            if candidate["sequence"] != current["sequence"] + 1:
                raise CheckpointValidationError("checkpoint sequence is not the next lineage sequence")
            if candidate["parent_checkpoint_digest"] != current["checkpoint_digest"]:
                raise CheckpointValidationError("checkpoint parent digest does not match current checkpoint")
            immutable = (
                "project_id",
                "workflow_id",
                "task_id",
                "step_id",
                "job_id",
                "run_id",
                "attempt_id",
                "problem_id",
                "provider_fingerprint",
                "wire_api_fingerprint",
                "model_fingerprint",
                "tool_fingerprint",
                "runtime_fingerprint",
                "input_digest",
                "problem_contract_digest",
                "goal_digest",
                "entrypoint_digest",
                "budget",
                "created_at",
                "expires_at",
            )
            for key in immutable:
                if candidate[key] != current[key]:
                    raise CheckpointValidationError(f"checkpoint lineage drift: {key}")
            if current["status"] == "completed" and candidate["status"] != "completed":
                raise CheckpointValidationError("completed checkpoint cannot be reopened")
            if current["completion_status"] == "completed" and candidate["completion_status"] != "completed":
                raise CheckpointValidationError("completed checkpoint cannot lose completion status")
            session_changed = (
                candidate["session_id"] != current["session_id"]
                or candidate["session_fingerprint"] != current["session_fingerprint"]
            )
            if session_changed:
                if candidate.get("resume_receipt_digest") is None:
                    raise CheckpointValidationError("session drift requires a verified resume receipt")
                if candidate["migration_count"] != current["migration_count"] + 1:
                    raise CheckpointValidationError("session migration count is not contiguous")
                if candidate["budget_usage"]["resume_attempts"] != current["budget_usage"]["resume_attempts"] + 1:
                    raise CheckpointValidationError("session migration budget usage is not contiguous")
            elif candidate["migration_count"] != current["migration_count"]:
                raise CheckpointValidationError("migration_count changed without session migration")
            if not set(current["failed_route_refs"]).issubset(candidate["failed_route_refs"]):
                raise CheckpointValidationError("checkpoint lineage dropped a failed-route reference")
            old_effects = {item["effect_id"]: item for item in current["effect_ledger"]}
            new_effects = {item["effect_id"]: item for item in candidate["effect_ledger"]}
            for effect_id, old_effect in old_effects.items():
                if new_effects.get(effect_id) != old_effect:
                    raise CheckpointValidationError("checkpoint lineage changed an effect ledger entry")
        elif candidate["sequence"] != 1 or candidate["parent_checkpoint_digest"] is not None:
            raise CheckpointValidationError("first checkpoint must have sequence 1 and no parent")
        return write_checkpoint(self.path, candidate)


def _next_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    status: str | None = None,
    completion_status: str | None = None,
    route_id: str | None = None,
    session_id: str | None = None,
    session_fingerprint: str | None = None,
    budget_usage: Mapping[str, int] | None = None,
    next_obligation: str | Mapping[str, Any] | None = None,
    failed_route_refs: Sequence[str] | None = None,
    effect_ledger: Sequence[Mapping[str, Any]] | None = None,
    last_error_kind: str | None = None,
    resume_receipt_digest: str | None = None,
    migration_count: int | None = None,
) -> dict[str, Any]:
    old = validate_checkpoint(checkpoint)
    result = _json_clone(old)
    result["sequence"] = old["sequence"] + 1
    result["parent_checkpoint_digest"] = old["checkpoint_digest"]
    result["updated_at"] = utc_now()
    if status is not None:
        result["status"] = status
    if completion_status is not None:
        result["completion_status"] = completion_status
    if route_id is not None:
        result["route_id"] = route_id
    if session_id is not None:
        result["session_id"] = session_id
    if session_fingerprint is not None:
        result["session_fingerprint"] = _normalise_digest(session_fingerprint, "session_fingerprint")
    if budget_usage is not None:
        result["budget_usage"] = _json_clone(budget_usage)
    if next_obligation is not None:
        result["next_obligation"] = _json_clone(next_obligation)
    if failed_route_refs is not None:
        result["failed_route_refs"] = list(failed_route_refs)
    if effect_ledger is not None:
        result["effect_ledger"] = _json_clone(effect_ledger)
    result["last_error_kind"] = last_error_kind
    if resume_receipt_digest is not None:
        result["resume_receipt_digest"] = _normalise_digest(
            resume_receipt_digest, "resume_receipt_digest"
        )
    if migration_count is not None:
        result["migration_count"] = migration_count
    return _seal_checkpoint(result)


def advance_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    status: str | None = None,
    completion_status: str | None = None,
    route_id: str | None = None,
    budget_usage: Mapping[str, int] | None = None,
    next_obligation: str | Mapping[str, Any] | None = None,
    failed_route_refs: Sequence[str] | None = None,
    effect_ledger: Sequence[Mapping[str, Any]] | None = None,
    last_error_kind: str | None = None,
) -> dict[str, Any]:
    """Create the next sealed checkpoint without publishing any external effect."""

    old = validate_checkpoint(checkpoint)
    if old["status"] == "completed" and status != "completed":
        raise CheckpointValidationError("completed checkpoint cannot be reopened")
    return _next_checkpoint(
        old,
        status=status,
        completion_status=completion_status,
        route_id=route_id,
        budget_usage=budget_usage,
        next_obligation=next_obligation,
        failed_route_refs=failed_route_refs,
        effect_ledger=effect_ledger,
        last_error_kind=last_error_kind,
    )


def _receipt_time(value: Any, label: str) -> datetime:
    try:
        return _parse_time(value, label)
    except CheckpointValidationError as exc:
        raise ResumeReceiptError(str(exc)) from exc


def create_resume_receipt(
    checkpoint: Mapping[str, Any],
    *,
    new_session_id: str,
    new_session_fingerprint: str,
    verified_at: str,
    expires_at: str,
    source_ref: str = "operator_resume_map",
) -> dict[str, Any]:
    """Build a receipt suitable for a same-provider session migration."""

    current = validate_checkpoint(checkpoint, now=verified_at)
    if not new_session_id or new_session_id == current["session_id"]:
        raise ResumeReceiptError("a migrated session must have a distinct session_id")
    receipt = {
        "schema_version": "1.0.0",
        "receipt_id": "resume-receipt:" + hashlib.sha256(
            _canonical_bytes({"checkpoint": current["checkpoint_digest"], "session": new_session_id})
        ).hexdigest()[:24],
        "previous_session_id": current["session_id"],
        "new_session_id": _normalise_identifier(new_session_id, "new_session_id"),
        "new_session_fingerprint": _normalise_digest(new_session_fingerprint, "new_session_fingerprint"),
        "project_id": current["project_id"],
        "workflow_id": current["workflow_id"],
        "task_id": current["task_id"],
        "step_id": current["step_id"],
        "job_id": current["job_id"],
        "run_id": current["run_id"],
        "attempt_id": current["attempt_id"],
        "problem_id": current["problem_id"],
        "checkpoint_digest": current["checkpoint_digest"],
        "provider_fingerprint": current["provider_fingerprint"],
        "wire_api_fingerprint": current["wire_api_fingerprint"],
        "model_fingerprint": current["model_fingerprint"],
        "tool_fingerprint": current["tool_fingerprint"],
        "input_digest": current["input_digest"],
        "problem_contract_digest": current["problem_contract_digest"],
        "goal_digest": current["goal_digest"],
        "verification_method": "operator_resume_map",
        "verified_at": verified_at,
        "expires_at": expires_at,
        "source_ref": _normalise_identifier(source_ref, "source_ref"),
    }
    validate_resume_receipt(receipt, current, now=verified_at)
    return receipt


def validate_resume_receipt(
    receipt: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Verify exact task/problem/job/run and same provider/model/tool binding."""

    try:
        current = validate_checkpoint(checkpoint, now=now)
    except CheckpointValidationError as exc:
        raise ResumeReceiptError(str(exc)) from exc
    if not isinstance(receipt, Mapping):
        raise ResumeReceiptError("resume receipt must be an object")
    value = _json_clone(receipt)
    required = (
        "receipt_id",
        "previous_session_id",
        "new_session_id",
        "new_session_fingerprint",
        "project_id",
        "workflow_id",
        "task_id",
        "step_id",
        "job_id",
        "run_id",
        "attempt_id",
        "problem_id",
        "checkpoint_digest",
        "provider_fingerprint",
        "wire_api_fingerprint",
        "model_fingerprint",
        "tool_fingerprint",
        "input_digest",
        "problem_contract_digest",
        "goal_digest",
        "verification_method",
        "verified_at",
        "expires_at",
    )
    missing = [key for key in required if key not in value]
    if missing:
        raise ResumeReceiptError("resume receipt missing: " + ", ".join(missing))
    if value["verification_method"] != "operator_resume_map":
        raise ResumeReceiptError("resume receipt verification method is not operator_resume_map")
    if value["previous_session_id"] != current["session_id"]:
        raise ResumeReceiptError("resume receipt previous session does not match checkpoint")
    if value["new_session_id"] == current["session_id"]:
        raise ResumeReceiptError("resume receipt does not identify a new session")
    for key in (
        "project_id",
        "workflow_id",
        "task_id",
        "step_id",
        "job_id",
        "run_id",
        "attempt_id",
        "problem_id",
        "checkpoint_digest",
        "provider_fingerprint",
        "wire_api_fingerprint",
        "model_fingerprint",
        "tool_fingerprint",
        "input_digest",
        "problem_contract_digest",
        "goal_digest",
    ):
        expected = current[key] if key != "checkpoint_digest" else current["checkpoint_digest"]
        actual = value[key]
        if key.endswith("fingerprint") or key.endswith("digest"):
            try:
                actual = _normalise_digest(actual, key)
            except CheckpointValidationError as exc:
                raise ResumeReceiptError(str(exc)) from exc
        if actual != expected:
            raise ResumeReceiptError(f"resume receipt mismatch: {key}")
    try:
        _normalise_identifier(value["new_session_id"], "new_session_id")
        new_fingerprint = _normalise_digest(value["new_session_fingerprint"], "new_session_fingerprint")
    except CheckpointValidationError as exc:
        raise ResumeReceiptError(str(exc)) from exc
    value["new_session_fingerprint"] = new_fingerprint
    verified = _receipt_time(value["verified_at"], "verified_at")
    expiry = _receipt_time(value["expires_at"], "expires_at")
    current_time = _now(now)
    if verified > current_time:
        raise ResumeReceiptError("resume receipt is from the future")
    if expiry <= current_time or expiry <= verified:
        raise ResumeReceiptError("resume receipt is expired or has no positive lifetime")
    return value


def migrate_session(
    checkpoint: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Return a new checkpoint after an exact same-provider session migration."""

    current = validate_checkpoint(checkpoint, now=now)
    verified = validate_resume_receipt(receipt, current, now=now)
    usage = dict(current["budget_usage"])
    if usage["resume_attempts"] >= current["budget"]["max_resume_attempts"]:
        raise ResumeReceiptError("resume attempt budget exhausted")
    usage["resume_attempts"] += 1
    # Session migration changes only the session identity.  Provider, model,
    # tool, input and problem digests remain byte-for-byte bound to the parent.
    return _next_checkpoint(
        current,
        status="active",
        budget_usage=usage,
        session_id=verified["new_session_id"],
        session_fingerprint=verified["new_session_fingerprint"],
        last_error_kind="session_lost",
        resume_receipt_digest=sha256_value(verified),
        migration_count=current["migration_count"] + 1,
    )


@dataclass(frozen=True)
class RecoveryDecision:
    """A serialisable decision; construction has no side effects."""

    decision: str
    error_kind: str
    budget: dict[str, int]
    backoff: dict[str, Any]
    idempotency: str
    stop_proof: str
    reason: str
    records_failed_route: bool
    requires_resume_receipt: bool
    resume_receipt_valid: bool = False

    @property
    def kind(self) -> str:
        return self.decision

    @property
    def action(self) -> str:
        return self.decision

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "error_kind": self.error_kind,
            "budget": copy.deepcopy(self.budget),
            "backoff": copy.deepcopy(self.backoff),
            "idempotency": self.idempotency,
            "stop_proof": self.stop_proof,
            "reason": self.reason,
            "records_failed_route": self.records_failed_route,
            "requires_resume_receipt": self.requires_resume_receipt,
            "resume_receipt_valid": self.resume_receipt_valid,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]


def _error_text(error: Any) -> str:
    if isinstance(error, Mapping):
        for key in ("error_kind", "category", "kind", "type", "code", "message"):
            value = error.get(key)
            if isinstance(value, str):
                return value
        return " ".join(str(item) for item in error.values())
    if isinstance(error, BaseException):
        return f"{type(error).__name__}: {error}"
    return str(error)


def classify_error(error: Any) -> str:
    """Map an exception/observation to one of the ten closed categories."""

    if isinstance(error, str) and error in ERROR_KINDS:
        return error
    if isinstance(error, Mapping):
        for key in ("error_kind", "category", "kind"):
            candidate = error.get(key)
            if isinstance(candidate, str) and candidate in ERROR_KINDS:
                return candidate
    text = _error_text(error).lower()
    if any(token in text for token in ("invalid_checkpoint", "invalid checkpoint", "checkpoint digest", "checkpoint expired", "checkpoint truncated")):
        return "invalid_checkpoint"
    if any(token in text for token in ("delivery_timeout", "delivery timeout", "message send timeout", "消息发送超时", "delivery ambiguous")):
        return "delivery_timeout"
    if any(token in text for token in ("session_lost", "session lost", "session disconnected", "resume session")):
        return "session_lost"
    if any(token in text for token in ("hard_stop", "hard stop", "user stop", "cancelled", "canceled")):
        return "hard_stop"
    if any(token in text for token in ("resource_limit", "resource limit", "out of memory", "quota", "high-watermark", "high watermark", "max output")):
        return "resource_limit"
    if any(token in text for token in ("rate_limit", "rate limit", "too many requests", "http 429", "429")):
        return "rate_limit"
    if any(token in text for token in ("network_disconnect", "network disconnect", "connection reset", "connection refused", "broken pipe", "eof", "dns")):
        return "network_disconnect"
    if any(token in text for token in ("execution_timeout", "execution timeout", "process timeout", "subprocess timeout")):
        return "execution_timeout"
    if any(token in text for token in ("tool_error", "tool error", "tool failed", "command failed")):
        return "tool_error"
    if "timeout" in text:
        return "execution_timeout"
    return "unknown"


def is_transport_failure(error: Any) -> bool:
    return classify_error(error) in TRANSPORT_FAILURE_KINDS


def _usage(checkpoint: Mapping[str, Any]) -> dict[str, int]:
    raw = checkpoint["budget_usage"]
    return {key: int(value) for key, value in raw.items()}


def _budget_summary(checkpoint: Mapping[str, Any], policy: RecoveryPolicy) -> dict[str, int]:
    usage = _usage(checkpoint)
    configured = checkpoint["budget"]
    # A caller may narrow policy budgets, never widen the checkpoint's frozen
    # budget.  This makes a changed policy unable to resurrect an old run.
    limits = {
        "max_total_attempts": min(configured["max_total_attempts"], policy.value["max_total_attempts"]),
        "max_same_route_attempts": min(configured["max_same_route_attempts"], policy.value["max_same_route_attempts"]),
        "max_route_switches": min(configured["max_route_switches"], policy.value["max_route_switches"]),
        "max_resume_attempts": min(configured["max_resume_attempts"], policy.value["max_resume_attempts"]),
        "max_delivery_retries": min(configured["max_delivery_retries"], policy.value["max_delivery_retries"]),
    }
    return {
        **limits,
        "used_total_attempts": usage["total_attempts"],
        "used_same_route_attempts": usage["same_route_attempts"],
        "used_route_switches": usage["route_switches"],
        "used_resume_attempts": usage["resume_attempts"],
        "used_delivery_retries": usage["delivery_retries"],
        "remaining_total_attempts": max(0, limits["max_total_attempts"] - usage["total_attempts"]),
        "remaining_same_route_attempts": max(0, limits["max_same_route_attempts"] - usage["same_route_attempts"]),
        "remaining_route_switches": max(0, limits["max_route_switches"] - usage["route_switches"]),
        "remaining_resume_attempts": max(0, limits["max_resume_attempts"] - usage["resume_attempts"]),
        "remaining_delivery_retries": max(0, limits["max_delivery_retries"] - usage["delivery_retries"]),
    }


def _decision(
    policy: RecoveryPolicy,
    checkpoint: Mapping[str, Any],
    *,
    decision: str,
    error_kind: str,
    reason: str,
    attempt_index: int = 0,
    records_failed_route: bool = False,
    requires_resume_receipt: bool = False,
    resume_receipt_valid: bool = False,
    backoff_multiplier: float = 1,
) -> RecoveryDecision:
    if decision not in DECISION_KINDS:
        raise RecoveryError(f"unsupported recovery decision: {decision}")
    contract = policy.contract(decision)
    base = float(policy.value["backoff"]["base_seconds"])
    maximum = float(policy.value["backoff"]["max_seconds"])
    seconds = 0.0 if decision != "retry_same" else min(
        maximum, base * (backoff_multiplier ** max(0, attempt_index))
    )
    backoff = {
        "strategy": policy.value["backoff"]["strategy"],
        "seconds": seconds,
        "attempt_index": max(0, attempt_index),
    }
    stop_proof = contract["stop_proof"]
    if not stop_proof:
        raise RecoveryError(f"decision {decision} has no stop proof")
    return RecoveryDecision(
        decision=decision,
        error_kind=error_kind,
        budget=_budget_summary(checkpoint, policy),
        backoff=backoff,
        idempotency=contract["idempotency"],
        stop_proof=stop_proof,
        reason=reason,
        records_failed_route=records_failed_route,
        requires_resume_receipt=requires_resume_receipt,
        resume_receipt_valid=resume_receipt_valid,
    )


def decide_recovery(
    error: Any,
    checkpoint: Mapping[str, Any],
    *,
    policy: RecoveryPolicy | Mapping[str, Any] | None = None,
    resume_receipt: Mapping[str, Any] | None = None,
    now: datetime | str | None = None,
    alternate_route_available: bool = False,
    delivery_state: str = "unknown",
    delivery_probe_complete: bool = False,
    safe_to_retry: bool = True,
) -> RecoveryDecision:
    """Return exactly one finite recovery action without mutating anything."""

    selected_policy = policy if isinstance(policy, RecoveryPolicy) else RecoveryPolicy.from_mapping(
        DEFAULT_POLICY if policy is None else policy
    )
    error_kind = classify_error(error)
    try:
        current = validate_checkpoint(checkpoint, now=now)
    except CheckpointValidationError as exc:
        # A corrupt/expired checkpoint is itself an invalid-checkpoint event;
        # never attempt to recover from the object that failed validation.
        synthetic = {"budget": {"max_total_attempts": 0, "max_same_route_attempts": 0, "max_route_switches": 0, "max_resume_attempts": 0, "max_delivery_retries": 0}, "budget_usage": {"total_attempts": 0, "same_route_attempts": 0, "route_switches": 0, "resume_attempts": 0, "delivery_retries": 0}}
        return _decision(
            selected_policy,
            synthetic,
            decision="block_human",
            error_kind="invalid_checkpoint",
            reason=f"checkpoint validation failed: {type(exc).__name__}",
        )
    if current["status"] == "completed" or current["completion_status"] == "completed":
        return _decision(
            selected_policy,
            current,
            decision="terminal_execution_failure",
            error_kind=error_kind,
            reason="completed checkpoint is terminal; replay is forbidden",
        )
    if error_kind == "invalid_checkpoint":
        return _decision(
            selected_policy,
            current,
            decision="block_human",
            error_kind=error_kind,
            reason="caller reported an invalid checkpoint; no automatic repair is safe",
        )
    if error_kind == "hard_stop":
        return _decision(
            selected_policy,
            current,
            decision="block_human",
            error_kind=error_kind,
            reason="explicit hard stop is authoritative",
        )
    if error_kind == "unknown":
        return _decision(
            selected_policy,
            current,
            decision="block_human",
            error_kind=error_kind,
            reason="unclassified failure is fail-closed",
        )

    budget = _budget_summary(current, selected_policy)
    rule = selected_policy.rule(error_kind)
    if error_kind == "session_lost":
        receipt_valid = False
        if resume_receipt is not None:
            try:
                validate_resume_receipt(resume_receipt, current, now=now)
            except ResumeReceiptError:
                receipt_valid = False
            else:
                receipt_valid = True
        if receipt_valid and budget["remaining_resume_attempts"] > 0:
            return _decision(
                selected_policy,
                current,
                decision="resume_verified",
                error_kind=error_kind,
                reason="exact same-provider resume receipt is valid",
                requires_resume_receipt=True,
                resume_receipt_valid=True,
            )
        return _decision(
            selected_policy,
            current,
            decision="block_human",
            error_kind=error_kind,
            reason="session loss has no valid unexpired receipt within budget",
            requires_resume_receipt=True,
        )

    if error_kind == "delivery_timeout":
        # A timeout after submit is ambiguous.  The caller must refresh/probe the
        # same destination before any retry; no candidate/event is resent here.
        if delivery_state in {"observed", "delivered", "committed"}:
            return _decision(
                selected_policy,
                current,
                decision="terminal_execution_failure",
                error_kind=error_kind,
                reason="delivery was observed; duplicate resend is forbidden",
            )
        if not delivery_probe_complete or delivery_state in {"unknown", "ambiguous"}:
            return _decision(
                selected_policy,
                current,
                decision="park",
                error_kind=error_kind,
                reason="delivery timeout requires a same-destination probe before retry",
            )
        if safe_to_retry and budget["remaining_delivery_retries"] > 0 and budget["remaining_total_attempts"] > 0:
            return _decision(
                selected_policy,
                current,
                decision="retry_same",
                error_kind=error_kind,
                reason="probe found no delivery and the bounded delivery retry remains",
                attempt_index=budget["used_delivery_retries"],
                backoff_multiplier=rule["backoff_multiplier"],
            )
        return _decision(
            selected_policy,
            current,
            decision="block_human",
            error_kind=error_kind,
            reason="delivery retry budget is exhausted or retry safety is false",
        )

    if rule["decision"] == "retry_same" and safe_to_retry:
        allowed = (
            budget["remaining_total_attempts"] > 0
            and budget["remaining_same_route_attempts"] > 0
            and budget["used_same_route_attempts"] < rule["max_attempts"]
        )
        if allowed:
            return _decision(
                selected_policy,
                current,
                decision="retry_same",
                error_kind=error_kind,
                reason="same-route retry remains inside the finite policy budget",
                attempt_index=budget["used_same_route_attempts"],
                records_failed_route=False,
                backoff_multiplier=rule["backoff_multiplier"],
            )
        if alternate_route_available and budget["remaining_route_switches"] > 0 and budget["remaining_total_attempts"] > 0:
            return _decision(
                selected_policy,
                current,
                decision="switch_route",
                error_kind=error_kind,
                reason="same-route budget is exhausted; switch from the sealed checkpoint",
                records_failed_route=bool(rule["records_failed_route"]),
            )
        return _decision(
            selected_policy,
            current,
            decision=("terminal_execution_failure" if error_kind in {"execution_timeout", "tool_error"} else "park"),
            error_kind=error_kind,
            reason="finite same-route budget is exhausted and no safe alternate route is available",
            records_failed_route=False,
        )

    if rule["decision"] == "retry_same" and not safe_to_retry:
        if alternate_route_available and budget["remaining_route_switches"] > 0 and budget["remaining_total_attempts"] > 0:
            return _decision(
                selected_policy,
                current,
                decision="switch_route",
                error_kind=error_kind,
                reason="same-route replay is unsafe; switch only from the sealed checkpoint",
                records_failed_route=False,
            )
        return _decision(
            selected_policy,
            current,
            decision=("terminal_execution_failure" if error_kind in {"execution_timeout", "tool_error"} else "park"),
            error_kind=error_kind,
            reason="retry safety is false and no bounded alternate action is available",
            records_failed_route=False,
        )

    if rule["decision"] == "switch_route":
        if alternate_route_available and budget["remaining_route_switches"] > 0 and budget["remaining_total_attempts"] > 0:
            return _decision(
                selected_policy,
                current,
                decision="switch_route",
                error_kind=error_kind,
                reason="resource or execution boundary requires a different bounded route",
                records_failed_route=bool(rule["records_failed_route"]),
            )
        return _decision(
            selected_policy,
            current,
            decision=("terminal_execution_failure" if error_kind in {"execution_timeout", "tool_error"} else "park"),
            error_kind=error_kind,
            reason="no finite route switch remains",
            records_failed_route=False,
        )

    return _decision(
        selected_policy,
        current,
        decision=rule["decision"],
        error_kind=error_kind,
        reason="policy rule selected a bounded non-retry action",
        requires_resume_receipt=bool(rule["requires_resume_receipt"]),
    )


# Short alias for callers that describe the operation as policy evaluation.
recover = decide_recovery


def apply_recovery_decision(
    checkpoint: Mapping[str, Any],
    decision: RecoveryDecision | Mapping[str, Any],
    *,
    new_route_id: str | None = None,
    resume_receipt: Mapping[str, Any] | None = None,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Apply only control-plane counters/status; external effects stay separate."""

    current = validate_checkpoint(checkpoint, now=now)
    decision_value = decision.as_dict() if isinstance(decision, RecoveryDecision) else dict(decision)
    action = decision_value.get("decision")
    error_kind = decision_value.get("error_kind")
    if action not in DECISION_KINDS:
        raise RecoveryError("invalid decision")
    if error_kind not in ERROR_KINDS:
        raise RecoveryError("invalid decision error_kind")
    usage = dict(current["budget_usage"])
    if action == "retry_same":
        if usage["total_attempts"] >= current["budget"]["max_total_attempts"]:
            raise RecoveryError("total retry budget exhausted")
        if usage["same_route_attempts"] >= current["budget"]["max_same_route_attempts"]:
            raise RecoveryError("same-route retry budget exhausted")
        usage["total_attempts"] += 1
        usage["same_route_attempts"] += 1
        if error_kind == "delivery_timeout":
            if usage["delivery_retries"] >= current["budget"]["max_delivery_retries"]:
                raise RecoveryError("delivery retry budget exhausted")
            usage["delivery_retries"] += 1
        return _next_checkpoint(
            current,
            status="checkpointed",
            budget_usage=usage,
            last_error_kind=error_kind,
        )
    if action == "switch_route":
        if not new_route_id:
            raise RecoveryError("switch_route requires an explicit new_route_id")
        _normalise_identifier(new_route_id, "new_route_id")
        if not re.fullmatch(r"^route:[A-Za-z0-9][A-Za-z0-9_.:-]*$", new_route_id):
            raise RecoveryError("new_route_id is not a route identifier")
        if usage["route_switches"] >= current["budget"]["max_route_switches"]:
            raise RecoveryError("route switch budget exhausted")
        if usage["total_attempts"] >= current["budget"]["max_total_attempts"]:
            raise RecoveryError("total attempt budget exhausted")
        usage["route_switches"] += 1
        usage["total_attempts"] += 1
        return _next_checkpoint(
            current,
            status="active",
            route_id=new_route_id,
            budget_usage=usage,
            last_error_kind=error_kind,
        )
    if action == "resume_verified":
        if resume_receipt is None:
            raise ResumeReceiptError("resume_verified requires a receipt")
        return migrate_session(current, resume_receipt, now=now)
    if action == "park":
        return _next_checkpoint(current, status="parked", last_error_kind=error_kind)
    if action == "block_human":
        return _next_checkpoint(current, status="blocked", last_error_kind=error_kind)
    # terminal_execution_failure is an execution lifecycle state, not a Result.
    return _next_checkpoint(current, status="failed", last_error_kind=error_kind)


def failed_route_record(
    error: Any,
    *,
    route_id: str,
    problem_id: str,
    blocker: str,
    evidence: Sequence[str],
) -> dict[str, Any] | None:
    """Build a mathematical failed-route record only for non-transport failures.

    Returning ``None`` for transport/session/delivery errors is intentional: a
    provider outage is not evidence that a mathematical route is false.
    """

    kind = classify_error(error)
    if kind not in MATHEMATICAL_ROUTE_FAILURE_KINDS:
        return None
    if not isinstance(problem_id, str) or not re.fullmatch(r"^problem:[a-z0-9][a-z0-9.-]*$", problem_id):
        raise RecoveryError("failed route problem_id is invalid")
    if not isinstance(route_id, str) or not re.fullmatch(r"^route:[A-Za-z0-9][A-Za-z0-9_.:-]*$", route_id):
        raise RecoveryError("failed route route_id is invalid")
    if not blocker or not evidence:
        raise RecoveryError("failed route requires a blocker and evidence")
    return {
        "route_id": route_id,
        "problem_id": problem_id,
        "error_kind": kind,
        "blocker": blocker,
        "evidence": list(evidence),
    }


class IdempotentEffectLedger:
    """In-memory Candidate/Event effect journal used by the recovery boundary.

    It models the commit boundary without starting a worker or making a network
    call.  Replaying an already committed effect returns ``already_committed``;
    reusing its id with a different digest is a hard conflict.
    """

    def __init__(self, entries: Sequence[Mapping[str, Any]] = ()):
        self._records: dict[str, dict[str, Any]] = {}
        for entry in entries:
            value = _json_clone(entry)
            effect_id = _normalise_identifier(value.get("effect_id"), "effect_id")
            effect_type = value.get("effect_type")
            if effect_type not in {"candidate", "event"}:
                raise EffectConflict("effect_type must be candidate or event")
            payload_digest = _normalise_digest(value.get("payload_digest"), "payload_digest")
            old = self._records.get(effect_id)
            if old is not None and old["payload_digest"] != payload_digest:
                raise EffectConflict("effect id is already bound to a different payload")
            value["effect_id"] = effect_id
            value["effect_type"] = effect_type
            value["payload_digest"] = payload_digest
            value["status"] = "committed"
            value.setdefault("sequence", len(self._records) + 1)
            value.setdefault("committed_at", utc_now())
            self._records[effect_id] = value

    def _payload_digest(self, payload: Any) -> str:
        if isinstance(payload, str):
            try:
                return _normalise_digest(payload, "payload_digest")
            except CheckpointValidationError:
                pass
        return sha256_value(payload)

    def commit(
        self,
        effect_type: str,
        effect_id: str,
        payload: Any,
        *,
        crash_point: str | None = None,
    ) -> dict[str, Any]:
        if effect_type not in {"candidate", "event"}:
            raise EffectConflict("effect_type must be candidate or event")
        effect_id = _normalise_identifier(effect_id, "effect_id")
        payload_digest = self._payload_digest(payload)
        existing = self._records.get(effect_id)
        if existing is not None:
            if existing["effect_type"] != effect_type or existing["payload_digest"] != payload_digest:
                raise EffectConflict("effect id replay has a different type or payload")
            return {**_json_clone(existing), "result": "already_committed"}
        if crash_point == "before_commit":
            raise InjectedCrash("injected crash before effect commit")
        if crash_point not in {None, "after_commit"}:
            raise RecoveryError("unknown effect crash point")
        record = {
            "effect_id": effect_id,
            "effect_type": effect_type,
            "payload_digest": payload_digest,
            "sequence": len(self._records) + 1,
            "status": "committed",
            "committed_at": utc_now(),
        }
        self._records[effect_id] = record
        if crash_point == "after_commit":
            raise InjectedCrash("injected crash after effect commit")
        return {**_json_clone(record), "result": "committed"}

    def replay(self, effect_type: str, effect_id: str, payload: Any) -> dict[str, Any]:
        return self.commit(effect_type, effect_id, payload)

    def record_candidate(self, candidate_id: str, payload: Any, *, crash_point: str | None = None) -> dict[str, Any]:
        return self.commit("candidate", candidate_id, payload, crash_point=crash_point)

    def record_event(self, event_id: str, payload: Any, *, crash_point: str | None = None) -> dict[str, Any]:
        return self.commit("event", event_id, payload, crash_point=crash_point)

    def effect_ledger(self) -> list[dict[str, Any]]:
        return [_json_clone(value) for value in sorted(self._records.values(), key=lambda item: item["sequence"])]

    def count(self, effect_type: str | None = None) -> int:
        if effect_type is None:
            return len(self._records)
        return sum(item["effect_type"] == effect_type for item in self._records.values())

    def snapshot(self) -> dict[str, int]:
        return {"candidate": self.count("candidate"), "event": self.count("event"), "total": self.count()}


ReplayLedger = IdempotentEffectLedger


__all__ = [
    "CHECKPOINT_COMMIT_MARKER",
    "CHECKPOINT_SCHEMA",
    "DECISION_KINDS",
    "DEFAULT_POLICY",
    "ERROR_KINDS",
    "MATHEMATICAL_ROUTE_FAILURE_KINDS",
    "TRANSPORT_FAILURE_KINDS",
    "CheckpointExpired",
    "CheckpointStore",
    "CheckpointValidationError",
    "EffectConflict",
    "IdempotentEffectLedger",
    "InjectedCrash",
    "PolicyValidationError",
    "RecoveryDecision",
    "RecoveryError",
    "RecoveryPolicy",
    "ReplayLedger",
    "ResumeReceiptError",
    "advance_checkpoint",
    "apply_recovery_decision",
    "build_checkpoint",
    "classify_error",
    "create_checkpoint",
    "create_resume_receipt",
    "decide_recovery",
    "failed_route_record",
    "is_transport_failure",
    "load_checkpoint",
    "load_policy",
    "migrate_session",
    "recover",
    "seal_checkpoint",
    "sha256_bytes",
    "sha256_text",
    "sha256_value",
    "utc_now",
    "validate_checkpoint",
    "validate_policy",
    "validate_resume_receipt",
    "write_checkpoint",
]
