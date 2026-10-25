"""Interfaces for calibrated three-pillar risk fusion and alert enrichment."""
from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class CalibratedRiskPredictor(Protocol):
    """Fitted binary classifier calibrated on held-out, labeled pillar scores."""

    classes_: Sequence[Any]

    def predict_proba(self, samples: Sequence[Sequence[float]]) -> Any: ...


@dataclass(frozen=True)
class PillarScores:
    """Normalized [0, 1] anomaly scores in fixed network/identity/host order."""

    network: float
    identity: float
    host: float

    def __post_init__(self) -> None:
        for name in ("network", "identity", "host"):
            if isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} score must be a finite number in [0, 1]")
            try:
                score = float(getattr(self, name))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} score must be a finite number in [0, 1]") from exc
            if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise ValueError(f"{name} score must be a finite number in [0, 1]")
            object.__setattr__(self, name, score)

    def as_vector(self) -> list[float]:
        return [self.network, self.identity, self.host]

    def as_dict(self) -> dict[str, float]:
        return {
            "network": self.network,
            "identity": self.identity,
            "host": self.host,
        }


def calibrated_risk_probability(
    scores: PillarScores,
    predictor: CalibratedRiskPredictor,
) -> float:
    """Get the learned positive-class probability; never substitutes hand weights."""
    classes = list(predictor.classes_)
    if 1 not in classes:
        raise ValueError("Risk predictor classes_ must include positive class 1")
    positive_index = classes.index(1)
    probabilities = predictor.predict_proba([scores.as_vector()])
    try:
        if len(probabilities) != 1 or len(probabilities[0]) != len(classes):
            raise ValueError("Risk predictor returned probabilities with an invalid shape")
        probability = float(probabilities[0][positive_index])
    except (IndexError, KeyError, TypeError) as exc:
        raise ValueError("Risk predictor returned probabilities with an invalid shape") from exc
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError("Risk predictor returned an invalid positive-class probability")
    return probability


_PRIVATE_HOST_FIELDS = {
    "uid", "euid", "ruid", "suid", "effective_uid", "real_uid",
    "pid", "ppid", "parent_pid", "process_id", "comm", "command",
    "command_line", "cmdline", "process", "process_name", "process_path",
    "path", "file_path", "filename", "registry_path", "registry_key",
    "target_path", "target_process", "module_name", "args", "arguments",
    "argv", "image", "executable", "executable_path", "cwd", "user",
    "username", "user_name", "host_events", "host_records",
}
_HOST_MAPPING_FIELDS = (
    "host_anomaly_score",
    "host_mapping_status",
    "host_attack_mappings",
    "host_explanation",
)
_FEATURE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")


def _without_host_identifiers(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _without_host_identifiers(item)
            for key, item in value.items()
            if str(key).casefold() not in _PRIVATE_HOST_FIELDS
        }
    if isinstance(value, (list, tuple)):
        return [_without_host_identifiers(item) for item in value]
    return value


def _safe_shap_features(features: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for item in features:
        name = item.get("feature")
        try:
            contribution = float(item.get("shap_value"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Every host SHAP item must have a numeric shap_value") from exc
        if not isinstance(name, str) or not _FEATURE_NAME_RE.fullmatch(name):
            raise ValueError("Host SHAP feature names must be safe identifier tokens")
        if not math.isfinite(contribution):
            raise ValueError("Host SHAP values must be finite")
        sanitized.append({
            "feature": name,
            "shap_value": contribution,
            "direction": (
                "increases_anomaly" if contribution > 0
                else "decreases_anomaly" if contribution < 0
                else "neutral"
            ),
        })
    return sanitized


def build_unified_alert(
    base_alert: Mapping[str, Any],
    scores: PillarScores,
    predictor: CalibratedRiskPredictor,
    *,
    risk_model_source: str,
    host_mapping: Mapping[str, Any] | None = None,
    host_shap_features: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Return a unified alert without serializing raw host identity telemetry.

    ``predictor`` must already be trained and calibrated by the caller. This
    module intentionally does not fit, calibrate, or invent a fallback model.
    """
    if not isinstance(risk_model_source, str) or not risk_model_source.strip():
        raise ValueError("risk_model_source must be non-empty")
    source = risk_model_source.strip()

    probability = calibrated_risk_probability(scores, predictor)
    alert = _without_host_identifiers(base_alert)
    alert.update({
        "pillar_scores": scores.as_dict(),
        # Keep the dashboard's existing top-level score fields populated while
        # exposing the canonical grouped representation to API consumers.
        "network_score": scores.network,
        "identity_score": scores.identity,
        "host_score": scores.host,
        "risk_probability": probability,
        "risk_score": int(round(probability * 100)),
        "confidence": probability,
        "risk_model_source": source,
        "host_shap_features": _safe_shap_features(host_shap_features),
    })

    if host_mapping is not None:
        safe_mapping = _without_host_identifiers(host_mapping)
        for field in _HOST_MAPPING_FIELDS:
            if field in safe_mapping:
                alert[field] = safe_mapping[field]
    return alert
