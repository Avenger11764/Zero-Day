"""
LEGACY / STALE since 2026-08-25d — do NOT wire into new paths.
================================================================
The shipped plain M5a (autoencoder_v2-256.pt, this module's score_flow) measured
actively harmful in multi-window fusion (0.9482, RC-26) and is superseded by the
REVIVED 87-dim ctx AE (detection/m5a_revived_ctx.pt, served inside
alert_pipeline.score_window by default).

This file is KEPT because Checkpoint-1, the dashboard and the red-team harness
call score_flow(), and ensembler/eval scripts load it as an ablation arm.
Do not delete; do not extend; do not raise its threshold expectations.
"""
import logging
import os
import sys
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, List, Optional

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger(__name__)

EXPECTED_FEATURES = 76
DEFAULT_THRESHOLD = 0.5
MODEL_PATH = Path(__file__).with_name("autoencoder_v2-256.pt")

_FEATURE_NAMES = [
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s",
    "bwd_pkts_s", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max",
    "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std",
    "pkt_len_var", "fwd_header_len", "bwd_header_len",
    "fwd_seg_size_min", "fwd_act_data_pkts", "flow_iat_mean",
    "flow_iat_max", "flow_iat_min", "flow_iat_std", "fwd_iat_tot",
    "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean",
    "bwd_iat_std", "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags",
    "bwd_urg_flags", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
    "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "init_fwd_win_byts",
    "init_bwd_win_byts", "active_max", "active_min", "active_mean",
    "active_std", "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg",
    "bwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_blk_rate_avg",
    "fwd_seg_size_avg", "bwd_seg_size_avg", "cwr_flag_count",
    "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts",
]


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int = EXPECTED_FEATURES):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 32),
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((recon - x) ** 2, dim=1)


_cached_model: Optional[Autoencoder] = None


def _get_model() -> Autoencoder:
    global _cached_model
    if _cached_model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

        model = Autoencoder(input_dim=EXPECTED_FEATURES)
        try:
            model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu", weights_only=True))
        except TypeError:
            model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
        model.eval()
        _cached_model = model
    return _cached_model


def _coerce_feature_vector(feature_vector: Any) -> List[float]:
    if isinstance(feature_vector, np.ndarray):
        values = feature_vector.astype(float).tolist()
    else:
        values = list(feature_vector)

    if len(values) != EXPECTED_FEATURES:
        raise ValueError(f"Expected {EXPECTED_FEATURES} features, got {len(values)}")

    return [float(v) for v in values]


def _try_shap_explanation(feature_vector: List[float]) -> tuple[Optional[list], Optional[list], str, str]:
    try:
        from .shap_explainer import SHAPExplainer, guess_attack_type
    except Exception:
        try:
            from detection.shap_explainer import SHAPExplainer, guess_attack_type
        except Exception as exc:
            logger.warning("SHAP explanation unavailable: %s", exc)
            return None, None, "unknown", "unknown"

    try:
        explainer = SHAPExplainer()
        x_np = np.array([feature_vector], dtype=np.float32)
        sv = explainer.shap_values(x_np)[0]
        ranked = np.argsort(np.abs(sv))[::-1][:10]

        top_features = []
        explanation = []
        for rank, idx in enumerate(ranked, 1):
            feature_name = _FEATURE_NAMES[idx] if idx < len(_FEATURE_NAMES) else f"feat_{idx}"
            top_features.append(
                {
                    "feature": feature_name,
                    "shap_value": round(float(sv[idx]), 6),
                    "input_value": round(float(feature_vector[idx]), 6),
                }
            )
            direction = "increases" if sv[idx] > 0 else "decreases"
            explanation.append(
                f"{rank}. {feature_name} (={feature_vector[idx]:.4f}) {direction} anomaly score by {abs(sv[idx]):.6f}"
            )

        attack_type, mitre_technique, _ = guess_attack_type(sv, _FEATURE_NAMES, top_k=5)
        return top_features, explanation, attack_type, mitre_technique
    except Exception as exc:
        logger.warning("SHAP explanation failed: %s", exc)
        return None, None, "unknown", "unknown"


def score_flow(feature_vector: Any, threshold: float = DEFAULT_THRESHOLD) -> dict:
    """Score a single 76-feature flow vector and return a full alert payload."""
    normalized_vector = _coerce_feature_vector(feature_vector)
    model = _get_model()

    x = torch.tensor([normalized_vector], dtype=torch.float32)
    score = model.anomaly_score(x).item()
    score = float(score)

    top_features, explanation, attack_type_guess, mitre_technique = _try_shap_explanation(normalized_vector)
    if top_features is None:
        top_features = []
    if explanation is None:
        explanation = []

    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "anomaly_score": round(score, 6),
        "confidence": round(max(0.0, 1 - score), 6),
        "risk_score": min(int(score * 100), 100),
        "attack_type_guess": attack_type_guess,
        "mitre_technique": mitre_technique,
        "explanation": explanation,
        "model_source": "autoencoder-v2-256",
        "is_adversarial_test": False,
        "is_anomaly": score > threshold,
        "threshold": threshold,
        "feature_vector": normalized_vector,
        "top_features": top_features,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    fake_vector = ([0.1, 0.4, 0.2, 0.9, 0.3, 0.1, 0.5, 0.2] * 10)[:EXPECTED_FEATURES]
    result = score_flow(fake_vector)
    print("Alert output:", result)


# if __name__ == "__main__":
#     fake_vector = [0.4] * 76
#     result = score_flow(fake_vector)
#     print("Alert output:", result)
