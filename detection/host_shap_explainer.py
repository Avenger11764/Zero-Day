"""SHAP explanations for reconstruction-error host autoencoders."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np
import torch
from torch import nn

from capture.host_feature_extractor import HostFeatureExtractor


class _ReconstructionError(nn.Module):
    def __init__(self, autoencoder: nn.Module):
        super().__init__()
        self.autoencoder = autoencoder

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        reconstruction = self.autoencoder(features)
        if reconstruction.shape != features.shape:
            raise ValueError(
                "Host autoencoder output shape must match its input shape; "
                f"got {tuple(reconstruction.shape)} and {tuple(features.shape)}"
            )
        return torch.mean((reconstruction - features) ** 2, dim=1, keepdim=True)


def feature_names_from_checkpoint(
    checkpoint: Mapping[str, Any],
    syscall_names: Mapping[int, str] | None = None,
) -> tuple[str, ...]:
    """Name the V+3 syscall-count vector stored by the legacy host checkpoint."""
    vocab = checkpoint.get("vocab")
    if not isinstance(vocab, Mapping):
        raise ValueError("Host checkpoint must contain a syscall-number vocabulary")

    try:
        vocab_size = int(checkpoint["V"])
        input_dim = int(checkpoint["n_dim"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Host checkpoint must declare integer V and n_dim values") from exc
    if vocab_size < 1 or input_dim != vocab_size + 3 or len(vocab) != vocab_size:
        raise ValueError("Host checkpoint vocabulary does not match its V+3 input dimension")

    names: list[str | None] = [None] * vocab_size
    for raw_number, raw_index in vocab.items():
        try:
            number, index = int(raw_number), int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ValueError("Host checkpoint vocabulary entries must be integer pairs") from exc
        if not 0 <= index < vocab_size or names[index] is not None:
            raise ValueError("Host checkpoint vocabulary indices must be unique and contiguous")

        raw_name = (syscall_names or {}).get(number, "")
        name = raw_name if isinstance(raw_name, str) else ""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            name = f"nr_{number}"
        names[index] = f"syscall_{name}"

    if any(name is None for name in names):
        raise ValueError("Host checkpoint vocabulary indices must cover the entire feature block")
    return tuple(names) + (
        "trace_log10_length",
        "trace_unique_rate",
        "trace_unknown_fraction",
    )


def _as_matrix(values: Any, label: str) -> np.ndarray:
    if isinstance(values, torch.Tensor):
        values = values.detach().cpu().numpy()
    array = np.asarray(values, dtype=np.float32)
    if array.ndim != 2 or array.shape[0] == 0 or array.shape[1] == 0:
        raise ValueError(f"{label} must be a non-empty 2D feature matrix")
    if not np.isfinite(array).all():
        raise ValueError(f"{label} must contain only finite values")
    return array


def explain_host_anomaly(
    autoencoder: nn.Module,
    samples: Any,
    background: Any,
    *,
    feature_names: Sequence[str] | None = None,
    checkpoint_metadata: Mapping[str, Any] | None = None,
    syscall_names: Mapping[int, str] | None = None,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Explain host reconstruction scores for model-ready vectors.

    ``samples`` and ``background`` must use the exact same feature layout and
    scaling that the supplied autoencoder was trained with. Returned entries
    intentionally omit raw feature values; callers can safely attach the top
    attributions to a minimized alert payload.
    """
    sample_matrix = _as_matrix(samples, "samples")
    background_matrix = _as_matrix(background, "background")
    if sample_matrix.shape[1] != background_matrix.shape[1]:
        raise ValueError("samples and background must have the same feature dimension")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k < 1:
        raise ValueError("top_k must be a positive integer")

    dimension = sample_matrix.shape[1]
    if feature_names is None:
        if dimension == HostFeatureExtractor.VECTOR_DIM:
            names = tuple(HostFeatureExtractor.FEATURE_NAMES)
        elif checkpoint_metadata is not None:
            names = feature_names_from_checkpoint(checkpoint_metadata, syscall_names)
        else:
            raise ValueError(
                "feature_names are required unless the input is the canonical "
                "128-D HostFeatureVector or checkpoint_metadata is provided"
            )
    else:
        names = tuple(feature_names)
    if len(names) != dimension:
        raise ValueError(
            f"Expected {dimension} feature names for this model input, got {len(names)}"
        )
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise ValueError("feature_names must contain non-empty strings")
    if len(set(names)) != len(names):
        raise ValueError("feature_names must be unique")

    import shap

    parameter = next(autoencoder.parameters(), None)
    device = parameter.device if parameter is not None else torch.device("cpu")
    was_training = autoencoder.training
    autoencoder.eval()
    scorer = _ReconstructionError(autoencoder).to(device)
    sample_tensor = torch.as_tensor(sample_matrix, dtype=torch.float32, device=device)
    background_tensor = torch.as_tensor(background_matrix, dtype=torch.float32, device=device)
    try:
        explainer = shap.DeepExplainer(scorer, background_tensor)
        raw_values = explainer.shap_values(sample_tensor, check_additivity=False)
        if isinstance(raw_values, list):
            if len(raw_values) != 1:
                raise ValueError("Host reconstruction scorer must have exactly one output")
            raw_values = raw_values[0]

        values = np.asarray(raw_values)
        if values.ndim == 3 and values.shape[-1] == 1:
            values = values[..., 0]
        if values.shape == (dimension, len(sample_matrix)):
            values = values.T
        if values.shape != sample_matrix.shape:
            raise RuntimeError(
                "Unexpected SHAP output shape: "
                f"expected {sample_matrix.shape}, got {values.shape}"
            )

        with torch.no_grad():
            scores = scorer(sample_tensor).detach().cpu().numpy().reshape(-1)
        expected_values = np.asarray(explainer.expected_value).reshape(-1)
        if expected_values.size != 1:
            raise ValueError("Host reconstruction scorer must have one expected value")
        base_value = float(expected_values[0])

        results: list[dict[str, Any]] = []
        for score, contributions in zip(scores, values, strict=True):
            order = np.argsort(-np.abs(contributions), kind="stable")[: min(top_k, dimension)]
            top_features = []
            for index in order:
                contribution = float(contributions[index])
                top_features.append({
                    "feature": names[int(index)],
                    "shap_value": contribution,
                    "direction": (
                        "increases_anomaly" if contribution > 0
                        else "decreases_anomaly" if contribution < 0
                        else "neutral"
                    ),
                })
            results.append({
                "anomaly_score": float(score),
                "base_value": base_value,
                "top_features": top_features,
            })
        return results
    finally:
        autoencoder.train(was_training)
