"""Evidence-aware ATT&CK candidate mapping for host syscall alerts."""
from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


MAPPER_PATH = (
    Path(__file__).resolve().parents[1]
    / "attack_mappers"
    / "host_syscall_attack_mapper.json"
)
_WINDOWS_API_NAMES = {
    "openprocess",
    "minidumpwritedump",
    "regsetvalue",
    "regsetvalueex",
    "ntsetvaluekey",
}


def load_syscall_profiles(path: str | Path = MAPPER_PATH) -> dict[str, dict[str, Any]]:
    """Load syscall profiles keyed by stable catalog ID."""
    with Path(path).open(encoding="utf-8") as mapper_file:
        data = json.load(mapper_file)

    profiles = data.get("syscall_attack_profiles")
    if not isinstance(profiles, list):
        raise ValueError("Host ATT&CK mapper must contain syscall_attack_profiles")

    indexed: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("id"), str):
            raise ValueError("Every syscall attack profile must have a string id")
        if profile["id"] in indexed:
            raise ValueError(f"Duplicate syscall attack profile id: {profile['id']}")
        indexed[profile["id"]] = profile
    return indexed


def _event(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        raw = dict(record)
    else:
        raw = {
            name: getattr(record, name)
            for name in ("timestamp", "pid", "uid", "comm", "syscall", "args")
            if hasattr(record, name)
        }

    event_name = (
        raw.get("syscall")
        or raw.get("event_name")
        or raw.get("api")
        or raw.get("event_type")
        or ""
    )
    args = raw.get("args")
    if not isinstance(args, Mapping):
        args = {}
    return {
        "name": str(event_name).strip().casefold(),
        "args": dict(args),
        "pid": raw.get("pid"),
        "uid": raw.get("uid"),
    }


def _target_pid(event: dict[str, Any]) -> Any:
    return event["args"].get("target_pid", event["args"].get("pid"))


def _same_actor(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return first["pid"] is None or second["pid"] is None or first["pid"] == second["pid"]


def _text_arg(event: dict[str, Any], *names: str) -> str:
    for name in names:
        value = event["args"].get(name)
        if value is not None:
            return str(value)
    return ""


def _is_root_target(value: Any) -> bool:
    try:
        return int(value) == 0
    except (TypeError, ValueError):
        return False


def _is_non_root_uid(value: Any) -> bool:
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return False


def _target_uid(event: dict[str, Any]) -> bool:
    if event["name"] == "setuid":
        return _is_root_target(event["args"].get("uid"))
    if event["name"] == "setgid":
        return False
    return any(
        _is_root_target(event["args"].get(key))
        for key in ("euid", "ruid", "suid")
        if event["args"].get(key) is not None
    )


def _run_key_path(event: dict[str, Any]) -> str:
    path = _text_arg(event, "registry_path", "key_path", "key", "path").casefold()
    return path.replace("/", "\\")


def _has_run_key(path: str) -> bool:
    return any(part in {"run", "runonce"} for part in path.split("\\"))


def _candidate(
    profiles: dict[str, dict[str, Any]],
    profile_id: str,
    evidence: list[str],
    evidence_complete: bool,
    host_features: Mapping[str, float],
) -> dict[str, Any]:
    profile = profiles[profile_id]
    trigger_features = profile.get("trigger_features", [])
    feature_values = {
        name: float(host_features[name])
        for name in trigger_features
        if name in host_features
    }
    return {
        "attack_type": profile["attack_type"],
        "mitre_tactic": profile["mitre_tactic"],
        "mitre_technique": profile["mitre_technique"],
        "technique_id": profile["technique_id"],
        "technique_url": profile["technique_url"],
        "severity": profile["severity"],
        "evidence": evidence,
        "evidence_complete": evidence_complete,
        "matched_features": feature_values,
        "limitations": profile.get("limitations", []),
    }


def classify_host_syscalls(
    records: Sequence[Any],
    host_anomaly_score: float,
    threshold: float,
    host_features: Mapping[str, float] | None = None,
    mapper_path: str | Path = MAPPER_PATH,
) -> dict[str, Any]:
    """Return evidence-qualified ATT&CK candidates for one scored host window.

    The caller must provide a calibrated threshold from benign validation data.
    Candidate mappings are not ground-truth technique assertions.
    """
    score = float(host_anomaly_score)
    cutoff = float(threshold)
    if not math.isfinite(score) or score < 0:
        raise ValueError("host_anomaly_score must be a finite non-negative number")
    if not math.isfinite(cutoff) or cutoff < 0:
        raise ValueError("threshold must be a finite non-negative number")

    feature_values: dict[str, float] = {}
    for name, value in (host_features or {}).items():
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError(f"Host feature {name!r} must have a finite value")
        feature_values[str(name)] = numeric

    events = [_event(record) for record in records]
    profiles = load_syscall_profiles(mapper_path)
    candidates: list[dict[str, Any]] = []
    explanation = [f"Host anomaly score {score:.6g}; calibrated threshold {cutoff:.6g}."]

    if score <= cutoff:
        return {
            "host_anomaly_score": score,
            "host_mapping_status": "below_threshold",
            "host_attack_mappings": [],
            "host_explanation": explanation + ["No ATT&CK mapping attempted below threshold."],
        }

    ptrace_events = [event for event in events if event["name"] == "ptrace"]
    memory_read_events = [event for event in events if event["name"] == "process_vm_readv"]
    for ptrace in ptrace_events:
        matched_pair = False
        for memory_read in memory_read_events:
            ptrace_target = _target_pid(ptrace)
            read_target = _target_pid(memory_read)
            same_target = (
                ptrace_target is None
                or read_target is None
                or ptrace_target == read_target
            )
            if _same_actor(ptrace, memory_read) and same_target:
                complete = ptrace_target is not None and read_target is not None
                evidence = ["ptrace and process_vm_readv observed for the same actor"]
                if complete:
                    evidence.append("both events target the same process")
                else:
                    evidence.append("target process identity is incomplete")
                candidates.append(
                    _candidate(profiles, "SYS-001", evidence, complete, feature_values)
                )
                matched_pair = True
                break
        if not matched_pair:
            candidates.append(
                _candidate(
                    profiles,
                    "SYS-001",
                    ["ptrace observed; process_vm_readv corroboration is missing or targets a different process"],
                    False,
                    feature_values,
                )
            )
        break

    open_process_events = [event for event in events if event["name"] == "openprocess"]
    dump_events = [event for event in events if event["name"] == "minidumpwritedump"]
    for open_process in open_process_events:
        target = _text_arg(open_process, "target_process", "process_name", "image", "name")
        if "lsass" not in target.casefold():
            continue
        dump = next((event for event in dump_events if _same_actor(open_process, event)), None)
        if dump:
            candidates.append(
                _candidate(
                    profiles,
                    "SYS-002",
                    ["OpenProcess targeted LSASS and MiniDumpWriteDump was observed for the same actor"],
                    True,
                    feature_values,
                )
            )
            break

    registry_events = [
        event for event in events if event["name"] in {"regsetvalue", "regsetvalueex", "ntsetvaluekey"}
    ]
    for event in registry_events:
        path = _run_key_path(event)
        value_data = _text_arg(event, "value_data", "data", "command")
        if _has_run_key(path) and value_data:
            candidates.append(
                _candidate(
                    profiles,
                    "SYS-003",
                    ["registry value write under a startup key", "startup value data is present"],
                    True,
                    feature_values,
                )
            )
            break

    module_events = [event for event in events if event["name"] in {"init_module", "finit_module"}]
    if module_events:
        module = module_events[0]
        module_name = _text_arg(module, "module_name", "umod", "filename")
        evidence = ["init_module or finit_module observed"]
        if module_name:
            evidence.append("module identifier is present")
        candidates.append(
            _candidate(
                profiles,
                "SYS-004",
                evidence,
                False,
                feature_values,
            )
        )

    privilege_events = [
        event for event in events if event["name"] in {"setuid", "setresuid", "setgid"}
    ]
    for event in privilege_events:
        caller_uid = event["uid"]
        if _target_uid(event) and _is_non_root_uid(caller_uid):
            candidates.append(
                _candidate(
                    profiles,
                    "SYS-005",
                    ["non-root process requested a transition to UID 0"],
                    True,
                    feature_values,
                )
            )
            break
        candidates.append(
            _candidate(
                profiles,
                "SYS-005",
                ["privilege-changing syscall observed; unauthorized transition is unverified"],
                False,
                feature_values,
            )
        )
        break

    # openat frequency is intentionally not a T1486 rule: file-write/change
    # evidence is needed to distinguish encryption from ordinary file access.
    if not candidates:
        explanation.append("No host ATT&CK signature met its required evidence.")
        if any(event["name"] == "openat" for event in events):
            explanation.append(
                "openat activity alone is insufficient evidence for T1486; "
                "file-write and file-change telemetry is required."
            )

    if candidates:
        explanation.extend(
            f"{item['technique_id']} candidate: {'; '.join(item['evidence'])}."
            for item in candidates
        )
    return {
        "host_anomaly_score": score,
        "host_mapping_status": "candidate" if candidates else "no_match",
        "host_attack_mappings": candidates,
        "host_explanation": explanation,
    }


def enrich_scored_alert(
    alert: Mapping[str, Any],
    records: Sequence[Any],
    host_anomaly_score: float,
    threshold: float,
    host_features: Mapping[str, float] | None = None,
    mapper_path: str | Path = MAPPER_PATH,
) -> dict[str, Any]:
    """Return a ScoredAlert copy augmented with optional host mapping fields."""
    enriched = dict(alert)
    enriched.update(
        classify_host_syscalls(
            records,
            host_anomaly_score,
            threshold,
            host_features=host_features,
            mapper_path=mapper_path,
        )
    )
    return enriched
