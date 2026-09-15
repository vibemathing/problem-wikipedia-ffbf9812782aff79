"""Pure runtime-adapter contracts for the four research channels.

The module is deliberately a protocol boundary rather than an executor.  A
:class:`ReferenceAdapter` validates and normalizes an already available
channel output; it never opens a network connection, starts a process,
controls a browser/tmux session, or writes a file.  :class:`SyntheticAdapter`
uses the same path with an in-memory fixture output so that end-to-end tests
can exercise the contract without an external service.

There are three distinct layers in the returned data:

* ``transport`` says whether the adapter request was delivered;
* ``execution`` says whether the adapter had usable work/output;
* ``handoff.outcome`` is the candidate-only mathematical handoff.

In particular, ``delivered`` is not ``candidate`` and neither is a Result or
Evidence verdict.  A Prove2me or Web label is never promoted by this module.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

from .handoff import (
    HandoffError,
    canonical_json_sha256 as handoff_json_sha256,
    normalize_handoff,
    validate_handoff,
    sha256_file,
)


SCHEMA_VERSION = "1.0.0"
MATURITY_STATES: tuple[str, ...] = (
    "surveyed",
    "source_locked",
    "installed",
    "smoke_checked",
    "evidence_capable",
    "verifier_admitted",
)
CHANNELS: tuple[str, ...] = (
    "local_pi",
    "web_chatgpt",
    "github_candidate",
    "prove2me",
)
RECEIPT_STATUSES: tuple[str, ...] = (
    "delivered",
    "execution_failed",
    "transport_failure",
    "candidate",
)

_RUNTIME_SCHEMA = "runtime-adapter.schema.json"
_REQUEST_SCHEMA = "adapter-request.schema.json"
_RECEIPT_SCHEMA = "adapter-receipt.schema.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ADAPTER_ID = re.compile(r"^adapter:[a-z0-9][a-z0-9.-]*$")
_PRIVATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"(?im)^\s*authorization\s*:\s*\S+"),
    re.compile(r"(?im)^\s*cookie\s*:\s*\S+"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*\S+"),
    re.compile(r"(?:^|[\s'\"`])/(?:home|root|srv|tmp)/[^\s'\"`]+"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\s'\"`]+"),
)
_PROHIBITED_KEYS = frozenset(
    {
        "result_id",
        "solution_id",
        "evidence_link_id",
        "kernel_checked",
        "independent",
        "result_admission",
    }
)
_PRIVATE_KEYS = frozenset(
    {
        "password",
        "passphrase",
        "mfa",
        "cookie",
        "cookies",
        "token",
        "access_token",
        "api_key",
        "apikey",
        "secret",
        "private_key",
        "client_secret",
    }
)
_IDENTITY_FIELDS: tuple[str, ...] = (
    "coordinator_id",
    "project_id",
    "job_id",
    "run_instance_id",
    "attempt_id",
    "graph_id",
    "obligation_id",
    "route_id",
    "session_id",
    "correlation_id",
    "causation_id",
    "dedupe_key",
    "problem_id",
    "problem_contract_sha256",
)
_REQUIRED_IDENTITY_FIELDS: tuple[str, ...] = tuple(
    field for field in _IDENTITY_FIELDS if field != "project_id"
)
_HO_IDENTITY_FIELDS: tuple[str, ...] = tuple(
    field for field in _IDENTITY_FIELDS if field != "coordinator_id" and field != "project_id"
)
_NO_SIDE_EFFECTS: dict[str, bool] = {
    "network": False,
    "filesystem": False,
    "subprocess": False,
    "browser": False,
    "github": False,
    "prove2me": False,
    "tmux": False,
}
_FORBIDDEN_EASY_STOP_PHRASES = (
    "one exact missing source field",
    "一个精确缺失来源字段",
    "找到一个缺失字段后停止",
    "完成当前阶段后停止",
    "完成本路线后停止",
    "stop after the first",
    "plan-only response is acceptable",
    "plan-only",
    "plan_only",
    "easy-stop",
    "easy_stop",
    "micro-task",
    "microtask",
)
_TERMINAL_WEB_ROOT_STATES = frozenset(
    {
        "root_closed",
        "all_routes_blocked",
        "external_dependency_cut",
        "platform_hard_limit",
        "user_stop",
    }
)
_OUTPUT_METADATA_KEYS = frozenset(
    {
        "adapter_id",
        "adapter_version",
        "maturity",
        "fingerprints",
        "claim_ceiling",
        "request_id",
        "request_sha256",
        "input_digest",
        "status",
        "done",
        "completed_phases",
        "all_phases_completed",
        "root_status",
        "program_result",
        "execution_metadata",
        "media_type",
    }
)


class AdapterError(ValueError):
    """The adapter contract cannot be safely accepted."""


class AdapterSchemaError(AdapterError):
    """A declaration, request, receipt, or handoff fails its schema."""


class AdapterIdentityError(AdapterError):
    """A request, receipt, or output has drifted from its bound identity."""


class AdapterCapabilityError(AdapterError):
    """A requested or declared capability is not admitted by the adapter."""


class AdapterRegistrationError(AdapterError):
    """An adapter cannot be added to a registry without an identity conflict."""


class AdapterExecutionError(AdapterError):
    """An adapter output was delivered but could not be normalized."""


class AdapterTransportError(AdapterError):
    """A transport failure is represented separately from execution failure."""


# Compatibility names make the boundary easy to consume without changing its
# semantics.  They are aliases, not additional protocol states.
RuntimeAdapterError = AdapterError
RuntimeAdapterSchemaError = AdapterSchemaError


def canonical_json_bytes(value: Any) -> bytes:
    """Encode finite JSON deterministically for request/receipt digests."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AdapterError("adapter value must be finite JSON") from exc


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


# The handoff module has the same canonical encoding.  Keeping this assertion
# here makes accidental protocol divergence visible during import/tests.
assert handoff_json_sha256({"adapter_protocol": 1}) == canonical_json_sha256(
    {"adapter_protocol": 1}
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _copy_json(value: Any, label: str) -> Any:
    try:
        copied = copy.deepcopy(value)
        canonical_json_bytes(copied)
        return copied
    except AdapterError:
        raise
    except Exception as exc:  # pragma: no cover - defensive boundary
        raise AdapterError(f"{label} is not safely copyable JSON") from exc


def _schema_root() -> Path:
    return Path(__file__).resolve().parents[2] / "research" / "schema"


def _schema_path(project_root: Path | str | None, filename: str) -> Path:
    if project_root is not None:
        root = Path(project_root).expanduser().resolve()
        candidate = root / "research" / "schema" / filename
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    fallback = _schema_root() / filename
    if not fallback.is_file() or fallback.is_symlink():
        raise AdapterSchemaError(f"schema is missing or unsafe: {filename}")
    return fallback


def _schema_errors(value: Any, filename: str, project_root: Path | str | None = None) -> list[str]:
    path = _schema_path(project_root, filename)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterSchemaError(f"cannot load schema: {path}") from exc
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    return [
        f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in errors
    ]


def _validate_schema(
    value: Any,
    filename: str,
    *,
    project_root: Path | str | None = None,
    label: str,
) -> dict[str, Any]:
    errors = _schema_errors(value, filename, project_root)
    if errors:
        raise AdapterSchemaError(f"{label} schema invalid: {'; '.join(errors)}")
    return _copy_json(value, label)


def _scan_prohibited_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _PROHIBITED_KEYS:
                errors.append(f"prohibited upgrade key {path}.{key}")
            errors.extend(_scan_prohibited_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_scan_prohibited_keys(child, f"{path}[{index}]"))
    return errors


def _contains_private_text(value: Any) -> bool:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return False
    return any(pattern.search(text) for pattern in _PRIVATE_PATTERNS)


def _scan_private_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.casefold() in _PRIVATE_KEYS:
                errors.append(f"private-material key is prohibited at {path}.{key}")
            errors.extend(_scan_private_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_scan_private_keys(child, f"{path}[{index}]"))
    return errors


def _require_hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise AdapterIdentityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_fingerprint(value: Mapping[str, Any], label: str) -> None:
    status = value.get("fingerprint_status")
    fingerprint = value.get("fingerprint")
    if status == "verified" and not fingerprint:
        raise AdapterIdentityError(f"verified {label} fingerprint cannot be empty")
    if status == "unavailable" and fingerprint is not None:
        raise AdapterIdentityError(f"unavailable {label} fingerprint must be null")


def _validate_no_side_effects(value: Mapping[str, Any]) -> None:
    if any(value.get(key) is not False for key in _NO_SIDE_EFFECTS):
        raise AdapterError("runtime adapter declares an external side effect")


def _adapter_mapping(adapter: RuntimeAdapter | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(adapter, RuntimeAdapter):
        return adapter.to_dict()
    if not isinstance(adapter, Mapping):
        raise AdapterSchemaError("runtime adapter must be an object")
    return _copy_json(dict(adapter), "runtime adapter")


def _validate_adapter_mapping(
    adapter: RuntimeAdapter | Mapping[str, Any],
    *,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    value = _adapter_mapping(adapter)
    validated = _validate_schema(
        value,
        _RUNTIME_SCHEMA,
        project_root=project_root,
        label="runtime adapter",
    )
    _validate_no_side_effects(validated["side_effects"])
    for name, fingerprint in validated["fingerprints"].items():
        _validate_fingerprint(fingerprint, f"{name}")
    return validated


def validate_adapter(
    adapter: RuntimeAdapter | Mapping[str, Any],
    *,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Validate and return a detached adapter declaration."""
    return _validate_adapter_mapping(adapter, project_root=project_root)


@dataclass(frozen=True)
class RuntimeAdapter:
    """Immutable declaration for one pure runtime adapter."""

    adapter_id: str
    channel: str
    capabilities: tuple[str, ...]
    maturity: str
    input_media: tuple[str, ...]
    output_media: tuple[str, ...]
    budgets: Mapping[str, int]
    fingerprints: Mapping[str, Mapping[str, Any]]
    claim_ceiling: str = "candidate_only"
    version: str = "1.0.0"
    adapter_kind: str = "reference"
    side_effects: Mapping[str, bool] = field(
        default_factory=lambda: copy.deepcopy(_NO_SIDE_EFFECTS)
    )
    notes: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        object.__setattr__(self, "input_media", tuple(self.input_media))
        object.__setattr__(self, "output_media", tuple(self.output_media))
        object.__setattr__(self, "budgets", copy.deepcopy(dict(self.budgets)))
        object.__setattr__(self, "fingerprints", copy.deepcopy(dict(self.fingerprints)))
        object.__setattr__(self, "side_effects", copy.deepcopy(dict(self.side_effects)))
        _validate_adapter_mapping(self)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "adapter_kind": self.adapter_kind,
            "channel": self.channel,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "maturity": self.maturity,
            "input_media": list(self.input_media),
            "output_media": list(self.output_media),
            "budgets": copy.deepcopy(dict(self.budgets)),
            "fingerprints": copy.deepcopy(dict(self.fingerprints)),
            "claim_ceiling": self.claim_ceiling,
            "side_effects": copy.deepcopy(dict(self.side_effects)),
        }
        if self.notes is not None:
            value["notes"] = self.notes
        return value

    declaration = to_dict

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeAdapter":
        validated = _validate_adapter_mapping(value)
        return cls(
            adapter_id=validated["adapter_id"],
            channel=validated["channel"],
            capabilities=tuple(validated["capabilities"]),
            maturity=validated["maturity"],
            input_media=tuple(validated["input_media"]),
            output_media=tuple(validated["output_media"]),
            budgets=validated["budgets"],
            fingerprints=validated["fingerprints"],
            claim_ceiling=validated["claim_ceiling"],
            version=validated["version"],
            adapter_kind=validated["adapter_kind"],
            side_effects=validated["side_effects"],
            notes=validated.get("notes"),
        )


class AdapterRegistry:
    """In-memory registry; registration has no filesystem or external effect."""

    def __init__(self, adapters: Iterable[RuntimeAdapter | Mapping[str, Any]] = ()) -> None:
        self._adapters: dict[str, RuntimeAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(
        self,
        adapter: RuntimeAdapter | Mapping[str, Any],
        *,
        replace: bool = False,
    ) -> RuntimeAdapter:
        spec = adapter if isinstance(adapter, RuntimeAdapter) else RuntimeAdapter.from_mapping(adapter)
        old = self._adapters.get(spec.adapter_id)
        if old is not None and old.to_dict() != spec.to_dict() and not replace:
            raise AdapterRegistrationError(
                f"adapter_id already registered with different declaration: {spec.adapter_id}"
            )
        self._adapters[spec.adapter_id] = spec
        return spec

    add = register
    register_adapter = register

    def get(self, adapter_id: str) -> RuntimeAdapter | None:
        direct = self._adapters.get(adapter_id)
        if direct is not None:
            return direct
        if adapter_id in CHANNELS:
            options = self.for_channel(adapter_id)
            return options[0] if options else None
        return None

    def require(self, adapter_id: str) -> RuntimeAdapter:
        adapter = self.get(adapter_id)
        if adapter is None:
            raise AdapterCapabilityError(f"unknown runtime adapter: {adapter_id}")
        return adapter

    resolve = require

    def for_channel(self, channel: str) -> list[RuntimeAdapter]:
        return sorted(
            (adapter for adapter in self._adapters.values() if adapter.channel == channel),
            key=lambda adapter: adapter.adapter_id,
        )

    def declarations(self) -> list[dict[str, Any]]:
        return [adapter.to_dict() for adapter in sorted(self._adapters.values(), key=lambda item: item.adapter_id)]

    def snapshot(self) -> list[dict[str, Any]]:
        return self.declarations()

    def validate(self) -> list[dict[str, Any]]:
        return [validate_adapter(item.to_dict()) for item in self._adapters.values()]

    def __contains__(self, adapter_id: object) -> bool:
        return adapter_id in self._adapters

    def __len__(self) -> int:
        return len(self._adapters)

    def __iter__(self):
        return iter(sorted(self._adapters.values(), key=lambda item: item.adapter_id))



def _fingerprint(
    label: str,
    fingerprint: str | None,
    status: str = "unverified",
) -> dict[str, Any]:
    return {
        "label": label,
        "fingerprint": fingerprint,
        "fingerprint_status": status,
    }


def _default_fingerprints(adapter_id: str, channel: str) -> dict[str, dict[str, Any]]:
    return {
        "adapter": _fingerprint("runtime-adapter-declaration", f"{adapter_id}@1.0.0"),
        "tool": _fingerprint(f"{channel}-reference-adapter", f"{channel}-reference-v1"),
        "model": _fingerprint("external-model-not-observed", None, "unavailable"),
        "environment": _fingerprint("pure-python-reference-runtime", None, "unavailable"),
    }


def _make_default_adapter(
    adapter_id: str,
    channel: str,
    capabilities: Sequence[str],
    maturity: str,
    input_media: Sequence[str],
    output_media: Sequence[str],
    *,
    adapter_kind: str = "reference",
) -> RuntimeAdapter:
    return RuntimeAdapter(
        adapter_id=adapter_id,
        adapter_kind=adapter_kind,
        channel=channel,
        version="1.0.0",
        capabilities=tuple(capabilities),
        maturity=maturity,
        input_media=tuple(input_media),
        output_media=tuple(output_media),
        budgets={
            "timeout_seconds": 7200 if channel == "web_chatgpt" else 3600,
            "max_output_bytes": 16_777_216,
            "max_files": 256,
            "max_retries": 2,
        },
        fingerprints=_default_fingerprints(adapter_id, channel),
        claim_ceiling="candidate_only",
        side_effects=copy.deepcopy(_NO_SIDE_EFFECTS),
        notes="Pure reference contract; live channel capability is not implied.",
    )


def default_registry() -> AdapterRegistry:
    """Return a fresh registry of the four reference channels plus a fixture."""
    return AdapterRegistry(
        [
            _make_default_adapter(
                "adapter:local-pi-reference-v1",
                "local_pi",
                ("bounded_execution", "candidate_generation", "handoff_normalization"),
                "smoke_checked",
                ("application/json", "text/plain", "text/markdown", "text/x-lean"),
                ("application/json", "text/markdown", "text/plain", "text/x-lean"),
            ),
            _make_default_adapter(
                "adapter:web-chatgpt-reference-v1",
                "web_chatgpt",
                (
                    "candidate_generation",
                    "long_horizon_program",
                    "canonical_conversation",
                    "digest_bound_task_package",
                    "handoff_normalization",
                ),
                "smoke_checked",
                ("application/json", "text/markdown"),
                ("application/json", "text/markdown", "text/plain"),
            ),
            _make_default_adapter(
                "adapter:github-candidate-reference-v1",
                "github_candidate",
                ("candidate_transport", "artifact_transport", "handoff_normalization"),
                "smoke_checked",
                ("application/json", "text/markdown"),
                ("application/json", "text/markdown", "text/x-lean", "text/plain"),
            ),
            _make_default_adapter(
                "adapter:prove2me-reference-v1",
                "prove2me",
                ("formal_candidate_transport", "statement_identity", "handoff_normalization"),
                "source_locked",
                ("application/json", "text/x-lean"),
                ("application/json", "text/x-lean", "text/markdown"),
            ),
            _make_default_adapter(
                "adapter:synthetic-fixture-v1",
                "local_pi",
                ("synthetic_fixture", "candidate_generation", "handoff_normalization"),
                "smoke_checked",
                ("application/json", "text/markdown", "text/plain"),
                ("application/json", "text/markdown", "text/plain", "text/x-lean"),
                adapter_kind="synthetic",
            ),
        ]
    )


DEFAULT_REGISTRY = default_registry()


def resolve_adapter(
    adapter: RuntimeAdapter | Mapping[str, Any] | str | ReferenceAdapter,
    *,
    registry: AdapterRegistry | None = None,
) -> RuntimeAdapter:
    if isinstance(adapter, RuntimeAdapter):
        return adapter
    # ReferenceAdapter is defined later in this module; the name is resolved
    # when this function is called, after module initialization is complete.
    if "ReferenceAdapter" in globals() and isinstance(adapter, ReferenceAdapter):
        return adapter.spec
    if isinstance(adapter, Mapping):
        return RuntimeAdapter.from_mapping(adapter)
    if not isinstance(adapter, str):
        raise AdapterCapabilityError("adapter must be an adapter id, declaration, or RuntimeAdapter")
    active = registry or DEFAULT_REGISTRY
    if adapter in CHANNELS:
        options = active.for_channel(adapter)
        if not options:
            raise AdapterCapabilityError(f"no adapter registered for channel: {adapter}")
        return options[0]
    return active.require(adapter)


def register_adapter(
    adapter: RuntimeAdapter | Mapping[str, Any],
    *,
    registry: AdapterRegistry | None = None,
    replace: bool = False,
) -> RuntimeAdapter:
    """Register one declaration in an in-memory registry."""
    target = registry or DEFAULT_REGISTRY
    return target.register(adapter, replace=replace)


def get_adapter(
    adapter_id: str,
    *,
    registry: AdapterRegistry | None = None,
) -> RuntimeAdapter:
    return (registry or DEFAULT_REGISTRY).require(adapter_id)


def list_adapters(*, registry: AdapterRegistry | None = None) -> list[RuntimeAdapter]:
    return list(registry or DEFAULT_REGISTRY)


def _as_identity(identity: Mapping[str, Any] | None, fields: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(identity or {})
    merged.update({key: value for key, value in fields.items() if value is not None})
    aliases = {
        "problem_contract_digest": "problem_contract_sha256",
        "obligation_graph_id": "graph_id",
    }
    for old, new in aliases.items():
        if old in merged:
            if new in merged and merged[new] != merged[old]:
                raise AdapterIdentityError(f"{old} and {new} drift")
            merged[new] = merged.pop(old)
    if merged.get("project_id") is None:
        merged.pop("project_id", None)
    missing = [key for key in _REQUIRED_IDENTITY_FIELDS if key not in merged or merged[key] is None]
    if missing:
        raise AdapterIdentityError(f"adapter request identity is incomplete: {', '.join(missing)}")
    return merged


def _default_principal(adapter: RuntimeAdapter) -> str:
    slug = adapter.adapter_id.removeprefix("adapter:")
    slug = re.sub(r"[^a-z0-9._-]+", "-", slug)
    return f"runtime-{slug}"[:256]


def build_web_research_program(
    *,
    root_mission: str,
    conversation_id: str,
    conversation_url: str,
    task_package_id: str,
    task_package_sha256: str,
    route_portfolio: Sequence[str],
    mandatory_phases: Sequence[str],
    stop_conditions: Sequence[str],
    prompt_characters: int = 3000,
    prompt_sha256: str | None = None,
    task_package_locator: str | None = None,
) -> dict[str, Any]:
    """Build the explicit long-horizon fields required by the Web adapter."""
    program: dict[str, Any] = {
        "mode": "long_horizon_program",
        "root_mission": root_mission,
        "canonical_conversation": {
            "conversation_id": conversation_id,
            "url": conversation_url,
            "canonical": True,
            "conversation_count": 1,
        },
        "task_package": {
            "package_id": task_package_id,
            "sha256": task_package_sha256,
        },
        "route_portfolio": list(route_portfolio),
        "mandatory_phases": list(mandatory_phases),
        "anti_early_stop": {
            "enabled": True,
            "continue_after_each_phase": True,
            "switch_route_on_blocker": True,
            "stop_conditions": list(stop_conditions),
        },
        "prompt_characters": prompt_characters,
    }
    if prompt_sha256 is not None:
        program["prompt_sha256"] = prompt_sha256
    if task_package_locator is not None:
        program["task_package"]["locator"] = task_package_locator
    return program


build_web_program = build_web_research_program


def build_adapter_request(
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    *,
    registry: AdapterRegistry | None = None,
    adapter_id: str | None = None,
    identity: Mapping[str, Any] | None = None,
    coordinator_id: str | None = None,
    project_id: str | None = None,
    job_id: str | None = None,
    run_instance_id: str | None = None,
    attempt_id: str | None = None,
    graph_id: str | None = None,
    obligation_id: str | None = None,
    route_id: str | None = None,
    session_id: str | None = None,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    dedupe_key: str | None = None,
    problem_id: str | None = None,
    problem_contract_sha256: str | None = None,
    problem_contract_digest: str | None = None,
    principal: str | None = None,
    requested_capabilities: Sequence[str] | None = None,
    capabilities: Sequence[str] | None = None,
    input_payload: Any = None,
    input_media_type: str = "application/json",
    input: Mapping[str, Any] | None = None,
    budgets: Mapping[str, int] | None = None,
    expected_claim_ceiling: str | None = None,
    research_program: Mapping[str, Any] | None = None,
    web_program: Mapping[str, Any] | None = None,
    task_package_sha256: str | None = None,
    request_id: str | None = None,
    created_at: str | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Create and validate a Coordinator-bound request.

    No identity is invented.  Only the request id is deterministically derived
    when omitted; all Problem/Attempt/Graph/Obligation fields are required.
    """
    selected = resolve_adapter(adapter_id or adapter or "adapter:local-pi-reference-v1", registry=registry)
    identity_fields = {
        "coordinator_id": coordinator_id,
        "project_id": project_id,
        "job_id": job_id,
        "run_instance_id": run_instance_id,
        "attempt_id": attempt_id,
        "graph_id": graph_id,
        "obligation_id": obligation_id,
        "route_id": route_id,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "dedupe_key": dedupe_key,
        "problem_id": problem_id,
        "problem_contract_sha256": problem_contract_sha256 or problem_contract_digest,
    }
    bound_identity = _as_identity(identity, identity_fields)

    selected_program = research_program if research_program is not None else web_program
    if research_program is not None and web_program is not None and dict(research_program) != dict(web_program):
        raise AdapterIdentityError("research_program and web_program drift")
    program = _copy_json(selected_program, "research program") if selected_program is not None else None

    if input is not None:
        if not isinstance(input, Mapping):
            raise AdapterSchemaError("input must be an object")
        input_object = _copy_json(dict(input), "adapter input")
        if input_media_type != "application/json" and input_object.get("media_type") != input_media_type:
            raise AdapterIdentityError("input media type arguments drift")
        input_object.setdefault("media_type", input_media_type)
        if "payload" not in input_object:
            raise AdapterSchemaError("input must contain payload")
    else:
        payload = _copy_json(input_payload, "input payload")
        input_object = {"media_type": input_media_type, "payload": payload}

    if selected.channel == "web_chatgpt":
        if program is None:
            raise AdapterCapabilityError("web_chatgpt requests require research_program")
        package = program.get("task_package") if isinstance(program, dict) else None
        if not isinstance(package, dict):
            raise AdapterSchemaError("web research_program must contain task_package")
        package_digest = package.get("sha256")
        if task_package_sha256 is not None and task_package_sha256 != package_digest:
            raise AdapterIdentityError("task package digest drift")
        task_package_sha256 = package_digest
        payload = input_object.get("payload")
        if not isinstance(payload, dict):
            raise AdapterCapabilityError(
                "web input payload must be an object so the task-package digest can be bound"
            )
        payload = copy.deepcopy(payload)
        prior = payload.get("task_package_sha256")
        if prior is not None and prior != task_package_sha256:
            raise AdapterIdentityError("input task-package digest drift")
        payload["task_package_sha256"] = task_package_sha256
        input_object["payload"] = payload
    elif task_package_sha256 is not None:
        raise AdapterCapabilityError("task_package_sha256 is only valid for web_chatgpt")

    requested = list(requested_capabilities or capabilities or selected.capabilities)
    effective_budgets = copy.deepcopy(dict(budgets or selected.budgets))
    request: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        **bound_identity,
        "adapter_id": selected.adapter_id,
        "channel": selected.channel,
        "principal": principal or _default_principal(selected),
        "requested_capabilities": requested,
        "input": input_object,
        "input_digest": canonical_json_sha256(input_object),
        "budgets": effective_budgets,
        "expected_claim_ceiling": expected_claim_ceiling or selected.claim_ceiling,
        "created_at": created_at or now(),
    }
    if program is not None:
        request["research_program"] = program
        request["task_package_sha256"] = task_package_sha256
    if request_id is None:
        request_basis = {
            key: request[key]
            for key in (
                "coordinator_id",
                "job_id",
                "run_instance_id",
                "attempt_id",
                "graph_id",
                "obligation_id",
                "route_id",
                "session_id",
                "correlation_id",
                "causation_id",
                "dedupe_key",
                "problem_id",
                "problem_contract_sha256",
                "adapter_id",
                "input_digest",
            )
        }
        request_id = f"adapter-request:{canonical_json_sha256(request_basis)[:32]}"
    request["request_id"] = request_id
    # Put request_id in the contract order only for human-readable output; JSON
    # canonical hashing remains order independent.
    return validate_request(request, adapter=selected, project_root=project_root, registry=registry)


create_adapter_request = build_adapter_request
make_adapter_request = build_adapter_request
build_request = build_adapter_request
create_request = build_adapter_request
make_request = build_adapter_request


def _profile_requirements(project_root: Path | str | None) -> tuple[int, int, int, tuple[str, ...]]:
    minimum_phases = 4
    minimum_routes = 3
    minimum_prompt_characters = 3000
    forbidden = list(_FORBIDDEN_EASY_STOP_PHRASES)
    root = Path(project_root).expanduser().resolve() if project_root is not None else _schema_root().parents[1]
    profile_path = root / "governance" / "control-plane" / "web-long-horizon-prompt-profile.v2.json"
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return minimum_phases, minimum_routes, minimum_prompt_characters, tuple(forbidden)
    if isinstance(profile, dict):
        try:
            minimum_phases = max(minimum_phases, int(profile.get("mandatory_phase_min", minimum_phases)))
            minimum_routes = max(minimum_routes, int(profile.get("route_portfolio_min", minimum_routes)))
            minimum_prompt_characters = max(
                minimum_prompt_characters,
                int(profile.get("minimum_prompt_characters", minimum_prompt_characters)),
            )
        except (TypeError, ValueError):
            pass
        values = profile.get("forbidden_easy_stop_phrases", [])
        if isinstance(values, list):
            forbidden.extend(item for item in values if isinstance(item, str))
    return minimum_phases, minimum_routes, minimum_prompt_characters, tuple(dict.fromkeys(forbidden))


def _validate_task_package(
    request: Mapping[str, Any],
    *,
    project_root: Path | str | None,
) -> None:
    program = request.get("research_program")
    if not isinstance(program, Mapping):
        return
    package = program.get("task_package")
    if not isinstance(package, Mapping):
        raise AdapterSchemaError("research_program.task_package must be an object")
    digest = _require_hex64(package.get("sha256"), "task package sha256")
    if request.get("task_package_sha256") != digest:
        raise AdapterIdentityError("request task_package_sha256 does not match program")
    payload = request.get("input", {}).get("payload") if isinstance(request.get("input"), Mapping) else None
    if not isinstance(payload, Mapping) or payload.get("task_package_sha256") != digest:
        raise AdapterIdentityError("input is not digest-bound to the task package")
    locator = package.get("locator")
    if locator is None or project_root is None:
        return
    if not isinstance(locator, str) or not locator:
        raise AdapterError("task package locator must be a non-empty path")
    pure = PurePosixPath(locator)
    if pure.is_absolute() or "." in pure.parts or ".." in pure.parts or "\\" in locator:
        raise AdapterError("task package locator is unsafe")
    root = Path(project_root).expanduser().resolve()
    path = root.joinpath(*pure.parts)
    lexical = root
    for part in pure.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise AdapterError("task package locator traverses a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise AdapterError("task package locator is missing or escapes project root") from exc
    if path.is_symlink() or not path.is_file():
        raise AdapterError("task package locator must be a regular file")
    if sha256_file(path) != digest:
        raise AdapterIdentityError("task package file digest mismatch")


def _read_optional_jsonl(root: Path, relative_path: str) -> list[dict[str, Any]]:
    path = root / relative_path
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise AdapterIdentityError(f"identity record source is unsafe: {relative_path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AdapterIdentityError(f"cannot read identity record source: {relative_path}") from exc
    records: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AdapterIdentityError(f"invalid identity JSON at {relative_path}:{number}") from exc
        if not isinstance(value, dict):
            raise AdapterIdentityError(f"identity record is not an object: {relative_path}:{number}")
        records.append(value)
    return records


def _unique_record(
    records: list[dict[str, Any]],
    key: str,
    value: str,
    label: str,
) -> dict[str, Any]:
    matches = [record for record in records if record.get(key) == value]
    if len(matches) != 1:
        raise AdapterIdentityError(f"{label} is not unique: {value}")
    return matches[0]


def _validate_request_identity_against_root(
    request: Mapping[str, Any],
    *,
    project_root: Path | str | None,
) -> None:
    if project_root is None:
        return
    root = Path(project_root).expanduser().resolve()
    problems = _read_optional_jsonl(root, "problem-library/records/canonical-problems.jsonl")
    if not problems:
        return
    problem = _unique_record(problems, "problem_id", request["problem_id"], "ProblemContract")
    actual_contract = canonical_json_sha256(problem)
    if actual_contract != request["problem_contract_sha256"]:
        raise AdapterIdentityError("request ProblemContract digest drift")
    attempts = _read_optional_jsonl(root, "research/records/attempts.jsonl")
    attempt = _unique_record(attempts, "attempt_id", request["attempt_id"], "Attempt")
    expected_attempt = {
        "problem_id": request["problem_id"],
        "route_id": request["route_id"],
        "obligation_graph_id": request["graph_id"],
        "problem_contract_sha256": request["problem_contract_sha256"],
    }
    for key, expected in expected_attempt.items():
        if attempt.get(key) != expected:
            raise AdapterIdentityError(f"Attempt {key} drift")
    graphs = _read_optional_jsonl(root, "research/records/obligation-graphs.jsonl")
    graph = _unique_record(graphs, "graph_id", request["graph_id"], "ObligationGraph")
    expected_graph = {
        "problem_id": request["problem_id"],
        "attempt_id": request["attempt_id"],
        "route_id": request["route_id"],
        "problem_contract_sha256": request["problem_contract_sha256"],
    }
    for key, expected in expected_graph.items():
        if graph.get(key) != expected:
            raise AdapterIdentityError(f"ObligationGraph {key} drift")
    obligations = graph.get("obligations")
    if not isinstance(obligations, list) or not any(
        isinstance(item, Mapping) and item.get("obligation_id") == request["obligation_id"]
        for item in obligations
    ):
        raise AdapterIdentityError("request obligation_id is not present in ObligationGraph")


def _validate_web_request(
    request: Mapping[str, Any],
    *,
    project_root: Path | str | None,
) -> None:
    if request["channel"] != "web_chatgpt":
        if "research_program" in request:
            raise AdapterCapabilityError("research_program is only valid for web_chatgpt")
        return
    program = request.get("research_program")
    if not isinstance(program, Mapping):
        raise AdapterCapabilityError("web_chatgpt request lacks research_program")
    minimum_phases, minimum_routes, minimum_prompt_characters, forbidden = _profile_requirements(project_root)
    conversation = program.get("canonical_conversation")
    if not isinstance(conversation, Mapping):
        raise AdapterCapabilityError("web request lacks canonical conversation")
    if conversation.get("canonical") is not True or conversation.get("conversation_count") != 1:
        raise AdapterCapabilityError("web request must bind exactly one canonical conversation")
    if not conversation.get("conversation_id") or not conversation.get("url"):
        raise AdapterCapabilityError("canonical conversation identity is incomplete")
    routes = program.get("route_portfolio")
    phases = program.get("mandatory_phases")
    if not isinstance(routes, list) or len(routes) < minimum_routes:
        raise AdapterCapabilityError(f"web route portfolio requires at least {minimum_routes} routes")
    if not isinstance(phases, list) or len(phases) < minimum_phases:
        raise AdapterCapabilityError(f"web request requires at least {minimum_phases} mandatory phases")
    anti = program.get("anti_early_stop")
    if not isinstance(anti, Mapping):
        raise AdapterCapabilityError("web request lacks anti-early-stop contract")
    if (
        anti.get("enabled") is not True
        or anti.get("continue_after_each_phase") is not True
        or anti.get("switch_route_on_blocker") is not True
        or not isinstance(anti.get("stop_conditions"), list)
        or not anti.get("stop_conditions")
    ):
        raise AdapterCapabilityError("web anti-early-stop contract is incomplete")
    declared_prompt_characters = int(program.get("prompt_characters", 0))
    if declared_prompt_characters < minimum_prompt_characters:
        raise AdapterCapabilityError(
            f"web prompt is below the {minimum_prompt_characters}-character minimum"
        )
    input_payload = request.get("input", {}).get("payload") if isinstance(request.get("input"), Mapping) else None
    if isinstance(input_payload, Mapping) and "prompt" in input_payload:
        prompt = input_payload["prompt"]
        if not isinstance(prompt, str) or len(prompt) != declared_prompt_characters:
            raise AdapterIdentityError("declared Web prompt character count does not match input prompt")
    serialized = json.dumps(
        {"program": program, "input": input_payload},
        ensure_ascii=False,
        sort_keys=True,
    ).casefold()
    for phrase in forbidden:
        if phrase.casefold() in serialized:
            raise AdapterCapabilityError(f"web request contains forbidden easy-stop shape: {phrase}")
    _validate_task_package(request, project_root=project_root)


def validate_request(
    request: Mapping[str, Any],
    *,
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    registry: AdapterRegistry | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Validate a request, its input digest, adapter capability and Web gates."""
    if not isinstance(request, Mapping):
        raise AdapterSchemaError("adapter request must be an object")
    value = _validate_schema(dict(request), _REQUEST_SCHEMA, project_root=project_root, label="adapter request")
    prohibited = _scan_prohibited_keys(value)
    private_keys = _scan_private_keys(value)
    if prohibited or private_keys:
        raise AdapterSchemaError("; ".join([*prohibited, *private_keys]))
    if _contains_private_text(value.get("input")):
        raise AdapterSchemaError("adapter request input appears to contain private material")
    actual_input_digest = canonical_json_sha256(value["input"])
    if actual_input_digest != value["input_digest"]:
        raise AdapterIdentityError(
            f"input digest mismatch: expected {actual_input_digest}, got {value['input_digest']}"
        )
    selected = resolve_adapter(adapter or value["adapter_id"], registry=registry)
    declaration = selected.to_dict()
    if value["adapter_id"] != selected.adapter_id or value["channel"] != selected.channel:
        raise AdapterIdentityError("request adapter/channel does not match declaration")
    if value.get("expected_claim_ceiling") != selected.claim_ceiling:
        raise AdapterIdentityError("request claim ceiling does not match adapter declaration")
    requested = set(value["requested_capabilities"])
    admitted = set(selected.capabilities)
    if not requested.issubset(admitted):
        raise AdapterCapabilityError(
            "request asks for unknown capabilities: " + ", ".join(sorted(requested - admitted))
        )
    media_type = value["input"]["media_type"]
    if media_type not in selected.input_media:
        raise AdapterCapabilityError(f"input media type is not admitted: {media_type}")
    for key, requested_budget in value["budgets"].items():
        if key not in selected.budgets:
            raise AdapterCapabilityError(f"request budget is not declared by adapter: {key}")
        if requested_budget > selected.budgets[key]:
            raise AdapterCapabilityError(
                f"request budget exceeds adapter budget: {key}={requested_budget}>{selected.budgets[key]}"
            )
    if value.get("principal") and _contains_private_text(value["principal"]):
        raise AdapterSchemaError("adapter principal contains private material")
    _validate_request_identity_against_root(value, project_root=project_root)
    _validate_web_request(value, project_root=project_root)
    # Keep a local declaration read so a future caller cannot mutate nested
    # adapter mappings after validation and silently change the receipt.
    _validate_adapter_mapping(declaration, project_root=project_root)
    return value


validate_adapter_request = validate_request
validate_runtime_adapter_request = validate_request


# Mapping aliases document the wire representation without introducing a
# second object model.  The protocol deliberately remains JSON-shaped.
AdapterRequest = dict[str, Any]
AdapterReceipt = dict[str, Any]


def _request_identity(request: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(request[key]) for key in _IDENTITY_FIELDS if key in request}


def _handoff_identity(request: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(request[key]) for key in _HO_IDENTITY_FIELDS if key in request}


def _expected_claim_ceiling(outcome: str) -> str:
    return {
        "candidate": "candidate_only",
        "blocked": "blocked_only",
        "transport_failure": "transport_only",
    }[outcome]


def _adapter_allows_outcome(adapter: RuntimeAdapter, outcome: str) -> bool:
    """Treat claim_ceiling as a maximum, never as a way to upgrade output."""
    if adapter.claim_ceiling == "candidate_only":
        return outcome in {"candidate", "blocked", "transport_failure"}
    if adapter.claim_ceiling == "blocked_only":
        return outcome in {"blocked", "transport_failure"}
    return outcome == "transport_failure"


def _producer_for(
    request: Mapping[str, Any],
    adapter: RuntimeAdapter,
    claim_ceiling: str,
    supplied: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    principal = request.get("principal") or _default_principal(adapter)
    expected = {
        "channel": adapter.channel,
        "principal": principal,
        "tool": copy.deepcopy(adapter.fingerprints["tool"]),
        "model": copy.deepcopy(adapter.fingerprints["model"]),
        "environment": copy.deepcopy(adapter.fingerprints["environment"]),
        "claim_ceiling": claim_ceiling,
    }
    if supplied is None:
        return expected
    if not isinstance(supplied, Mapping):
        raise AdapterIdentityError("handoff producer must be an object")
    given = _copy_json(dict(supplied), "handoff producer")
    # HandoffEnvelope's own schema is the final shape gate.  Before it runs,
    # compare every trust-bearing field instead of silently replacing claims.
    if given != expected:
        raise AdapterIdentityError("handoff producer fingerprint/channel/ceiling drift")
    return expected


def _extract_program_metadata(source: Mapping[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    nested: Any = source.get("program_result")
    if nested is None:
        nested = source.get("execution_metadata")
    if isinstance(nested, Mapping):
        source_for_fields: Mapping[str, Any] = nested
    else:
        source_for_fields = source
    for key in ("completed_phases", "all_phases_completed", "root_status", "done"):
        if key in source_for_fields:
            metadata[key] = copy.deepcopy(source_for_fields[key])
    if source.get("status") == "done":
        metadata["done"] = True
    return metadata


def _validate_web_output_metadata(
    request: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> None:
    if request["channel"] != "web_chatgpt" or not metadata:
        return
    program = request.get("research_program")
    if not isinstance(program, Mapping):
        raise AdapterCapabilityError("web output has metadata without a research program")
    phases = set(program["mandatory_phases"])
    completed = metadata.get("completed_phases")
    if completed is not None:
        if not isinstance(completed, list) or not all(isinstance(item, str) for item in completed):
            raise AdapterExecutionError("web output reports an unknown or malformed phase")
        if not set(completed).issubset(phases):
            raise AdapterExecutionError("web output reports an unknown or malformed phase")
    all_completed = metadata.get("all_phases_completed")
    if all_completed is True and set(completed or []) != phases:
        raise AdapterExecutionError("web output falsely reports all mandatory phases completed")
    if metadata.get("done") is True:
        if set(completed or []) != phases:
            raise AdapterExecutionError("Web DONE is forbidden before every mandatory phase completes")
        if metadata.get("root_status") not in _TERMINAL_WEB_ROOT_STATES:
            raise AdapterExecutionError("Web DONE lacks a permitted root stop certificate")


def _raw_output_and_metadata(output: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if "handoff" in output:
        nested = output.get("handoff")
        if not isinstance(nested, Mapping):
            raise AdapterExecutionError("handoff output must be an object")
        raw = _copy_json(dict(nested), "handoff output")
    else:
        raw = _copy_json(dict(output), "adapter output")
    metadata = _extract_program_metadata(output)
    if "handoff" not in output:
        for key in _OUTPUT_METADATA_KEYS:
            raw.pop(key, None)
    return raw, metadata


class ReferenceAdapter:
    """Pure converter/validator for one registered channel."""

    def __init__(
        self,
        declaration: RuntimeAdapter | Mapping[str, Any] | str | None = None,
        *,
        registry: AdapterRegistry | None = None,
    ) -> None:
        if declaration is None:
            selected: RuntimeAdapter | Mapping[str, Any] | str = "adapter:local-pi-reference-v1"
        else:
            selected = declaration
        self.spec = resolve_adapter(selected, registry=registry)
        _validate_adapter_mapping(self.spec)

    @property
    def adapter_id(self) -> str:
        return self.spec.adapter_id

    @property
    def channel(self) -> str:
        return self.spec.channel

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.spec.capabilities

    @property
    def maturity(self) -> str:
        return self.spec.maturity

    @property
    def declaration(self) -> dict[str, Any]:
        return self.spec.to_dict()

    def validate_request(
        self,
        request: Mapping[str, Any],
        *,
        project_root: Path | str | None = None,
    ) -> dict[str, Any]:
        return validate_request(request, adapter=self.spec, project_root=project_root)

    def normalize_output(
        self,
        request: Mapping[str, Any],
        output: Mapping[str, Any],
        *,
        project_root: Path | str | None = None,
    ) -> dict[str, Any]:
        """Bind a channel-native output to the request as a HandoffEnvelope."""
        request_value = self.validate_request(request, project_root=project_root)
        if not isinstance(output, Mapping):
            raise AdapterExecutionError("adapter output must be an object")
        private_keys = _scan_private_keys(output)
        if private_keys or _contains_private_text(output):
            raise AdapterExecutionError("adapter output appears to contain private material")
        raw, metadata = _raw_output_and_metadata(output)
        _validate_web_output_metadata(request_value, metadata)

        for key in ("adapter_id", "adapter_version", "request_id", "request_sha256", "input_digest"):
            if key not in output:
                continue
            expected = {
                "adapter_id": self.spec.adapter_id,
                "adapter_version": self.spec.version,
                "request_id": request_value["request_id"],
                "request_sha256": canonical_json_sha256(request_value),
                "input_digest": request_value["input_digest"],
            }[key]
            if output[key] != expected:
                raise AdapterIdentityError(f"adapter output {key} drift")
        if "maturity" in output and output["maturity"] != self.spec.maturity:
            raise AdapterIdentityError("adapter output maturity drift")
        if "fingerprints" in output and output["fingerprints"] != self.spec.fingerprints:
            raise AdapterIdentityError("adapter output fingerprints drift")
        if "claim_ceiling" in output and output["claim_ceiling"] != self.spec.claim_ceiling:
            raise AdapterIdentityError("adapter output claim ceiling drift")

        if "outcome" not in raw:
            if "candidate" in raw:
                raw["outcome"] = "candidate"
            elif "blocker" in raw:
                raw["outcome"] = "blocked"
            elif "transport" in raw:
                raw["outcome"] = "transport_failure"
            else:
                raise AdapterExecutionError("adapter output has no HandoffEnvelope outcome")
        outcome = raw.get("outcome")
        if outcome not in {"candidate", "blocked", "transport_failure"}:
            raise AdapterExecutionError("adapter output cannot assert a mathematical Result outcome")
        if not _adapter_allows_outcome(self.spec, outcome):
            raise AdapterCapabilityError(
                f"adapter claim ceiling {self.spec.claim_ceiling} cannot emit outcome={outcome}"
            )
        expected_ceiling = _expected_claim_ceiling(outcome)
        supplied_producer = raw.get("producer")
        raw["producer"] = _producer_for(
            request_value,
            self.spec,
            expected_ceiling,
            supplied_producer if supplied_producer is not None else None,
        )
        raw.setdefault("schema_version", SCHEMA_VERSION)
        raw.setdefault("envelope_id", "")
        # A producer output may not silently change any common identity field.
        for key, expected in _handoff_identity(request_value).items():
            if key in raw and raw[key] != expected:
                raise AdapterIdentityError(f"handoff identity drift: {key}")
            raw[key] = expected
        if not raw["envelope_id"]:
            envelope_basis = {
                "request_id": request_value["request_id"],
                "request_sha256": canonical_json_sha256(request_value),
                "output": raw,
            }
            raw["envelope_id"] = f"handoff:{canonical_json_sha256(envelope_basis)[:32]}"
        raw.setdefault("created_at", request_value["created_at"])
        try:
            normalized = normalize_handoff(raw, schema_path=_schema_path(project_root, "handoff-envelope.schema.json"))
        except HandoffError as exc:
            raise AdapterExecutionError(f"HandoffEnvelope normalization failed: {exc}") from exc
        if project_root is not None:
            try:
                validate_handoff(project_root, normalized)
            except (HandoffError, OSError, ValueError) as exc:
                raise AdapterExecutionError(f"HandoffEnvelope validation failed: {exc}") from exc
        return normalized

    normalize = normalize_output

    def make_receipt(
        self,
        request: Mapping[str, Any],
        status: str,
        *,
        handoff: Mapping[str, Any] | None = None,
        error: str | None = None,
        transport_error: str | None = None,
        stage: str | None = None,
        execution_metadata: Mapping[str, Any] | None = None,
        project_root: Path | str | None = None,
    ) -> dict[str, Any]:
        return make_adapter_receipt(
            request,
            status,
            adapter=self.spec,
            handoff=handoff,
            error=error,
            transport_error=transport_error,
            stage=stage,
            execution_metadata=execution_metadata,
            project_root=project_root,
        )

    def execute(
        self,
        request: Mapping[str, Any],
        output: Mapping[str, Any] | None = None,
        *,
        delivered: bool = True,
        transport_error: str | None = None,
        execution_error: str | None = None,
        stage: str | None = None,
        project_root: Path | str | None = None,
    ) -> dict[str, Any]:
        """Return a receipt without performing transport or execution.

        ``output=None`` intentionally produces ``status=delivered`` with a
        pending execution, not a false candidate.  Malformed delivered output
        becomes ``execution_failed``; it is not relabeled as transport failure.
        """
        request_value = self.validate_request(request, project_root=project_root)
        if transport_error is not None and delivered:
            raise AdapterTransportError("transport_error requires delivered=False")
        if not delivered:
            return self.make_receipt(
                request_value,
                "transport_failure",
                error=transport_error or "adapter transport did not deliver the request",
                transport_error=transport_error or "adapter transport did not deliver the request",
                stage=stage or "delivery",
                project_root=project_root,
            )
        if execution_error is not None:
            return self.make_receipt(
                request_value,
                "execution_failed",
                error=execution_error,
                stage=stage or "execution",
                project_root=project_root,
            )
        if output is None:
            return self.make_receipt(
                request_value,
                "delivered",
                stage=stage or "delivery",
                project_root=project_root,
            )
        try:
            handoff = self.normalize_output(request_value, output, project_root=project_root)
        except AdapterError as exc:
            return self.make_receipt(
                request_value,
                "execution_failed",
                error=str(exc),
                stage=stage or "normalization",
                project_root=project_root,
            )
        metadata = _extract_program_metadata(output)
        status = "candidate" if handoff["outcome"] == "candidate" else "delivered"
        return self.make_receipt(
            request_value,
            status,
            handoff=handoff,
            execution_metadata=metadata,
            stage=stage or "execution",
            project_root=project_root,
        )

    run = execute
    dispatch = execute
    handle = execute
    adapt = normalize_output
    to_handoff = normalize_output


def _synthetic_declaration_for_channel(
    channel: str,
    *,
    registry: AdapterRegistry | None = None,
) -> RuntimeAdapter:
    if channel not in CHANNELS:
        raise AdapterCapabilityError(f"unknown adapter channel: {channel}")
    active = registry or DEFAULT_REGISTRY
    references = [item for item in active.for_channel(channel) if item.adapter_kind == "reference"]
    if not references:
        raise AdapterCapabilityError(f"no reference adapter for channel: {channel}")
    value = references[0].to_dict()
    slug = channel.replace("_", "-")
    value["adapter_id"] = f"adapter:synthetic-{slug}-v1"
    value["adapter_kind"] = "synthetic"
    value["capabilities"] = list(dict.fromkeys(["synthetic_fixture", *value["capabilities"]]))
    value["fingerprints"]["adapter"] = _fingerprint(
        "synthetic-runtime-adapter", f"adapter:synthetic-{slug}-v1@1.0.0"
    )
    value["fingerprints"]["tool"] = _fingerprint(
        f"{channel}-synthetic-adapter", f"synthetic-{slug}-v1"
    )
    value["notes"] = "In-memory synthetic fixture; no live channel is contacted."
    return RuntimeAdapter.from_mapping(value)


class SyntheticAdapter(ReferenceAdapter):
    """Reference adapter with an optional in-memory fixture output."""

    def __init__(
        self,
        declaration: RuntimeAdapter | Mapping[str, Any] | str | None = None,
        *,
        channel: str | None = None,
        registry: AdapterRegistry | None = None,
        fixture_output: Mapping[str, Any] | None = None,
    ) -> None:
        if channel is not None and declaration is not None:
            raise AdapterIdentityError("SyntheticAdapter channel and declaration are ambiguous")
        if channel is not None:
            declaration = _synthetic_declaration_for_channel(channel, registry=registry)
        elif isinstance(declaration, str) and declaration in CHANNELS:
            declaration = _synthetic_declaration_for_channel(declaration, registry=registry)
        selected = declaration or "adapter:synthetic-fixture-v1"
        super().__init__(selected, registry=registry)
        if self.spec.adapter_kind != "synthetic":
            raise AdapterCapabilityError("SyntheticAdapter requires adapter_kind=synthetic")
        self.fixture_output = _copy_json(fixture_output, "synthetic fixture output") if fixture_output is not None else None

    def execute(
        self,
        request: Mapping[str, Any],
        output: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if output is None and self.fixture_output is not None:
            output = self.fixture_output
        if output is None:
            request_value = self.validate_request(request, project_root=kwargs.get("project_root"))
            payload = request_value.get("input", {}).get("payload")
            if isinstance(payload, Mapping):
                for key in ("fixture_output", "output", "handoff"):
                    candidate = payload.get(key)
                    if isinstance(candidate, Mapping):
                        output = candidate
                        break
        return super().execute(request, output, **kwargs)

    # Rebind aliases so SyntheticAdapter's fixture lookup is retained when a
    # caller uses the short ``run``/``dispatch`` names.
    run = execute
    dispatch = execute
    handle = execute


ReferenceRuntimeAdapter = ReferenceAdapter
SyntheticRuntimeAdapter = SyntheticAdapter
RuntimeAdapterRegistry = AdapterRegistry


def normalize_adapter_output(
    request: Mapping[str, Any],
    output: Mapping[str, Any],
    *,
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    registry: AdapterRegistry | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    selected = resolve_adapter(adapter or request.get("adapter_id", ""), registry=registry)
    return ReferenceAdapter(selected, registry=registry).normalize_output(
        request,
        output,
        project_root=project_root,
    )


normalize_output = normalize_adapter_output


def make_adapter_receipt(
    request: Mapping[str, Any],
    status: str,
    *,
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    registry: AdapterRegistry | None = None,
    handoff: Mapping[str, Any] | None = None,
    error: str | None = None,
    transport_error: str | None = None,
    stage: str | None = None,
    execution_metadata: Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Construct a schema-valid receipt with explicit transport/execution states."""
    if status not in RECEIPT_STATUSES:
        raise AdapterSchemaError(f"unknown adapter receipt status: {status}")
    selected = resolve_adapter(adapter or request.get("adapter_id", ""), registry=registry)
    request_value = validate_request(request, adapter=selected, project_root=project_root, registry=registry)
    normalized_handoff: dict[str, Any] | None = None
    if handoff is not None:
        normalized_handoff = ReferenceAdapter(selected, registry=registry).normalize_output(
            {**request_value},
            {"handoff": handoff},
            project_root=project_root,
        )
    if status == "transport_failure":
        if error is None:
            error = transport_error
        elif transport_error is None:
            transport_error = error
        elif error != transport_error:
            raise AdapterTransportError("transport failure error fields drift")
    if normalized_handoff is not None and not _adapter_allows_outcome(
        selected, normalized_handoff["outcome"]
    ):
        raise AdapterCapabilityError(
            f"adapter claim ceiling {selected.claim_ceiling} cannot carry outcome={normalized_handoff['outcome']}"
        )
    if status == "candidate" and (normalized_handoff is None or normalized_handoff["outcome"] != "candidate"):
        raise AdapterExecutionError("candidate receipt requires outcome=candidate HandoffEnvelope")
    if status == "execution_failed" and normalized_handoff is not None:
        raise AdapterExecutionError("execution_failed receipt cannot carry a handoff")
    if status == "transport_failure" and normalized_handoff is not None:
        raise AdapterTransportError("transport_failure receipt cannot carry a handoff")
    if status == "delivered" and normalized_handoff is not None and normalized_handoff["outcome"] == "candidate":
        raise AdapterExecutionError("candidate handoff must use status=candidate")
    if status in {"execution_failed", "transport_failure"} and not (error or transport_error):
        raise AdapterError(f"{status} receipt requires an error")
    if status != "transport_failure" and transport_error is not None:
        raise AdapterTransportError("transport_error is only valid for status=transport_failure")
    if status in {"delivered", "candidate"} and error is not None:
        raise AdapterError(f"{status} receipt cannot carry an execution error")
    if error is not None and _contains_private_text(error):
        raise AdapterError("receipt error appears to contain private material")
    if execution_metadata is not None and (
        _scan_private_keys(execution_metadata) or _contains_private_text(execution_metadata)
    ):
        raise AdapterError("receipt execution metadata appears to contain private material")
    if transport_error is not None and _contains_private_text(transport_error):
        raise AdapterError("transport error appears to contain private material")

    receipt_created_at = created_at or now()
    request_digest = canonical_json_sha256(request_value)
    handoff_digest = canonical_json_sha256(normalized_handoff) if normalized_handoff is not None else None
    identity = _request_identity(request_value)
    if identity.get("project_id") is None:
        identity.pop("project_id", None)
    if status == "transport_failure":
        transport = {
            "status": "failed",
            "attempted": True,
            "stage": stage or "delivery",
            "error": transport_error or error or "adapter transport failed",
        }
        execution = {"status": "not_started"}
        claim_ceiling = "transport_only"
        mathematical_outcome = "not_evaluated"
        completed = receipt_created_at
    elif status == "execution_failed":
        transport = {"status": "delivered", "attempted": True, "stage": stage or "delivery"}
        execution = {
            "status": "failed",
            "error": error or "adapter execution failed",
        }
        claim_ceiling = "transport_only"
        mathematical_outcome = "not_evaluated"
        completed = receipt_created_at
    elif normalized_handoff is None:
        transport = {"status": "delivered", "attempted": True, "stage": stage or "delivery"}
        execution = {"status": "pending"}
        claim_ceiling = "transport_only"
        mathematical_outcome = "not_evaluated"
        completed = None
    else:
        transport = {"status": "delivered", "attempted": True, "stage": stage or "execution"}
        execution = {"status": "succeeded", "output_digest": handoff_digest}
        claim_ceiling = _expected_claim_ceiling(normalized_handoff["outcome"])
        mathematical_outcome = normalized_handoff["outcome"]
        completed = receipt_created_at
    if execution_metadata:
        if not isinstance(execution_metadata, Mapping):
            raise AdapterSchemaError("execution_metadata must be an object")
        for key in ("completed_phases", "all_phases_completed", "root_status", "done"):
            if key in execution_metadata:
                execution[key] = _copy_json(execution_metadata[key], f"execution metadata {key}")
        if request_value["channel"] == "web_chatgpt" and "completed_phases" in execution:
            completed_phases = execution["completed_phases"]
            if isinstance(completed_phases, list) and all(isinstance(item, str) for item in completed_phases):
                phases = set(request_value["research_program"]["mandatory_phases"])
                execution.setdefault("all_phases_completed", set(completed_phases) == phases)
        if request_value["channel"] == "web_chatgpt":
            _validate_web_output_metadata(request_value, execution)
    receipt_basis = {
        "request_sha256": request_digest,
        "status": status,
        "handoff_sha256": handoff_digest,
        "error": error,
        "transport_error": transport_error,
    }
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": f"adapter-receipt:{canonical_json_sha256(receipt_basis)[:32]}",
        "request_id": request_value["request_id"],
        "request_sha256": request_digest,
        "adapter_id": selected.adapter_id,
        "adapter_version": selected.version,
        "channel": selected.channel,
        "status": status,
        "claim_ceiling": claim_ceiling,
        "maturity": selected.maturity,
        "capabilities": list(selected.capabilities),
        "fingerprints": copy.deepcopy(dict(selected.fingerprints)),
        "identity": identity,
        "input_digest": request_value["input_digest"],
        "transport": transport,
        "execution": execution,
        "mathematical_outcome": mathematical_outcome,
        "created_at": receipt_created_at,
        "completed_at": completed,
    }
    if normalized_handoff is not None:
        receipt["handoff"] = normalized_handoff
        receipt["handoff_sha256"] = handoff_digest
        receipt["output"] = {"media_type": "application/json", "sha256": handoff_digest}
    if error is not None:
        receipt["error"] = error
    return validate_receipt(
        receipt,
        request=request_value,
        adapter=selected,
        project_root=project_root,
        registry=registry,
    )


create_adapter_receipt = make_adapter_receipt
build_receipt = make_adapter_receipt


def _compare_identity(expected: Mapping[str, Any], actual: Mapping[str, Any], label: str) -> None:
    for key, value in expected.items():
        if key == "project_id" and value is None:
            continue
        if actual.get(key) != value:
            raise AdapterIdentityError(f"{label} identity drift: {key}")


def validate_receipt(
    receipt: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None = None,
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    registry: AdapterRegistry | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Validate a receipt and, when supplied, bind it to the exact request."""
    if not isinstance(receipt, Mapping):
        raise AdapterSchemaError("adapter receipt must be an object")
    value = _validate_schema(dict(receipt), _RECEIPT_SCHEMA, project_root=project_root, label="adapter receipt")
    prohibited = _scan_prohibited_keys(value)
    private_keys = _scan_private_keys(value)
    if prohibited or private_keys:
        raise AdapterSchemaError("; ".join([*prohibited, *private_keys]))
    selected: RuntimeAdapter | None = None
    request_value: dict[str, Any] | None = None
    if request is not None:
        selected = resolve_adapter(adapter or value["adapter_id"], registry=registry)
        request_value = validate_request(request, adapter=selected, project_root=project_root, registry=registry)
        if value["request_id"] != request_value["request_id"]:
            raise AdapterIdentityError("receipt request_id drift")
        request_digest = canonical_json_sha256(request_value)
        if value["request_sha256"] != request_digest:
            raise AdapterIdentityError("receipt request_sha256 drift")
        if value["input_digest"] != request_value["input_digest"]:
            raise AdapterIdentityError("receipt input_digest drift")
        _compare_identity(_request_identity(request_value), value["identity"], "receipt")
    elif adapter is not None:
        selected = resolve_adapter(adapter, registry=registry)
    if selected is None:
        # A receipt without its request is still checked against the registered
        # declaration. Unknown adapters therefore fail closed rather than
        # allowing an unverifiable maturity/fingerprint claim.
        selected = resolve_adapter(value["adapter_id"], registry=registry)
    if selected is not None:
        if value["adapter_id"] != selected.adapter_id or value["channel"] != selected.channel:
            raise AdapterIdentityError("receipt adapter/channel drift")
        if value["adapter_version"] != selected.version:
            raise AdapterIdentityError("receipt adapter version drift")
        if value["maturity"] != selected.maturity:
            raise AdapterIdentityError("receipt maturity drift")
        if value["capabilities"] != list(selected.capabilities):
            raise AdapterCapabilityError("receipt capabilities drift")
        if value["fingerprints"] != selected.fingerprints:
            raise AdapterIdentityError("receipt fingerprints drift")

    status = value["status"]
    transport = value["transport"]
    execution = value["execution"]
    handoff = value.get("handoff")
    if status == "transport_failure":
        if transport["status"] != "failed" or transport["attempted"] is not True:
            raise AdapterTransportError("transport_failure must record a failed attempted transport")
        if not transport.get("error") or execution["status"] != "not_started":
            raise AdapterTransportError("transport_failure must stop before execution")
        if handoff is not None or value["claim_ceiling"] != "transport_only":
            raise AdapterTransportError("transport_failure cannot carry candidate state")
        if value["mathematical_outcome"] != "not_evaluated":
            raise AdapterTransportError("transport_failure cannot assert mathematical state")
        if value.get("error") != transport.get("error"):
            raise AdapterTransportError("transport_failure error fields drift")
    elif status == "execution_failed":
        if transport["status"] != "delivered" or execution["status"] != "failed":
            raise AdapterExecutionError("execution_failed must follow delivered transport")
        if not execution.get("error") or handoff is not None:
            raise AdapterExecutionError("execution_failed cannot carry a handoff")
        if value.get("error") != execution.get("error"):
            raise AdapterExecutionError("execution_failed error fields drift")
        if value["claim_ceiling"] != "transport_only" or value["mathematical_outcome"] != "not_evaluated":
            raise AdapterExecutionError("execution_failed cannot assert mathematical state")
    elif status == "delivered":
        if transport["status"] != "delivered" or transport["attempted"] is not True:
            raise AdapterError("delivered receipt must record delivered transport")
        if handoff is None:
            if execution["status"] != "pending":
                raise AdapterError("delivery without output must have execution=pending")
            if value["claim_ceiling"] != "transport_only" or value["mathematical_outcome"] != "not_evaluated":
                raise AdapterError("delivery without output cannot assert mathematical state")
            if value.get("completed_at") is not None:
                raise AdapterError("delivery-only receipt cannot have completed_at")
        else:
            if execution["status"] != "succeeded":
                raise AdapterExecutionError("delivered handoff must have succeeded execution")
            if handoff.get("outcome") == "candidate":
                raise AdapterExecutionError("candidate handoff requires status=candidate")
            if value["mathematical_outcome"] != handoff.get("outcome"):
                raise AdapterIdentityError("delivered handoff outcome drift")
            if value["claim_ceiling"] != _expected_claim_ceiling(str(handoff.get("outcome"))):
                raise AdapterIdentityError("delivered handoff claim ceiling drift")
    elif status == "candidate":
        if transport["status"] != "delivered" or execution["status"] != "succeeded":
            raise AdapterExecutionError("candidate requires delivered transport and successful execution")
        if not isinstance(handoff, Mapping) or handoff.get("outcome") != "candidate":
            raise AdapterExecutionError("candidate receipt requires candidate HandoffEnvelope")
        if value["claim_ceiling"] != "candidate_only" or value["mathematical_outcome"] != "candidate":
            raise AdapterExecutionError("candidate receipt claim/outcome ceiling drift")
    if status in {"delivered", "candidate"} and value.get("error") is not None:
        raise AdapterError(f"{status} receipt cannot carry an error")
    if request_value is not None and request_value["channel"] == "web_chatgpt":
        _validate_web_output_metadata(request_value, execution)
    if handoff is not None:
        if selected is None or request_value is None:
            try:
                normalized_handoff = normalize_handoff(
                    handoff,
                    schema_path=_schema_path(project_root, "handoff-envelope.schema.json"),
                )
            except HandoffError as exc:
                raise AdapterSchemaError(f"receipt handoff is invalid: {exc}") from exc
            if selected is not None:
                outcome = str(normalized_handoff.get("outcome"))
                if not _adapter_allows_outcome(selected, outcome):
                    raise AdapterCapabilityError(
                        f"adapter claim ceiling {selected.claim_ceiling} cannot carry outcome={outcome}"
                    )
                producer = normalized_handoff.get("producer")
                if not isinstance(producer, Mapping):
                    raise AdapterIdentityError("receipt handoff producer is missing")
                _producer_for(
                    {"principal": producer.get("principal")},
                    selected,
                    _expected_claim_ceiling(outcome),
                    producer,
                )
        else:
            expected_handoff = ReferenceAdapter(selected, registry=registry).normalize_output(
                request_value,
                {"handoff": handoff},
                project_root=project_root,
            )
            if expected_handoff != dict(handoff):
                raise AdapterIdentityError("receipt handoff is not the canonical normalized envelope")
        handoff_digest = canonical_json_sha256(handoff)
        if value.get("handoff_sha256") != handoff_digest:
            raise AdapterIdentityError("receipt handoff_sha256 mismatch")
        if value.get("output") != {"media_type": "application/json", "sha256": handoff_digest}:
            raise AdapterIdentityError("receipt output digest mismatch")
        if execution.get("output_digest") != handoff_digest:
            raise AdapterIdentityError("receipt execution output_digest mismatch")
    elif any(key in value for key in ("handoff_sha256", "output")):
        raise AdapterSchemaError("receipt output metadata requires a handoff")
    if request_value is not None and value["identity"].get("project_id") != request_value.get("project_id"):
        # project_id is optional in the receipt identity, but if request has it
        # the two representations must agree.
        raise AdapterIdentityError("receipt project_id drift")
    return value


validate_adapter_receipt = validate_receipt
validate_runtime_adapter_receipt = validate_receipt


def dispatch_adapter(
    request: Mapping[str, Any],
    output: Mapping[str, Any] | None = None,
    *,
    adapter: RuntimeAdapter | Mapping[str, Any] | str | None = None,
    registry: AdapterRegistry | None = None,
    delivered: bool = True,
    transport_error: str | None = None,
    execution_error: str | None = None,
    stage: str | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Functional entry point for pure reference dispatch."""
    selected = resolve_adapter(adapter or request.get("adapter_id", ""), registry=registry)
    return ReferenceAdapter(selected, registry=registry).execute(
        request,
        output,
        delivered=delivered,
        transport_error=transport_error,
        execution_error=execution_error,
        stage=stage,
        project_root=project_root,
    )


execute_adapter = dispatch_adapter
run_adapter = dispatch_adapter


__all__ = [
    "AdapterCapabilityError",
    "AdapterError",
    "AdapterExecutionError",
    "AdapterIdentityError",
    "AdapterReceipt",
    "AdapterRegistrationError",
    "AdapterSchemaError",
    "AdapterTransportError",
    "AdapterRegistry",
    "AdapterRequest",
    "CHANNELS",
    "DEFAULT_REGISTRY",
    "MATURITY_STATES",
    "RECEIPT_STATUSES",
    "ReferenceAdapter",
    "ReferenceRuntimeAdapter",
    "RuntimeAdapter",
    "RuntimeAdapterError",
    "RuntimeAdapterRegistry",
    "RuntimeAdapterSchemaError",
    "SyntheticAdapter",
    "SyntheticRuntimeAdapter",
    "build_adapter_request",
    "build_receipt",
    "build_request",
    "build_web_program",
    "build_web_research_program",
    "canonical_json_bytes",
    "canonical_json_sha256",
    "create_adapter_receipt",
    "create_adapter_request",
    "create_request",
    "default_registry",
    "dispatch_adapter",
    "execute_adapter",
    "get_adapter",
    "list_adapters",
    "make_adapter_receipt",
    "make_adapter_request",
    "make_request",
    "normalize_adapter_output",
    "normalize_output",
    "register_adapter",
    "resolve_adapter",
    "run_adapter",
    "validate_adapter",
    "validate_adapter_receipt",
    "validate_adapter_request",
    "validate_receipt",
    "validate_request",
    "validate_runtime_adapter_receipt",
    "validate_runtime_adapter_request",
]
