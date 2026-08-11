"""
The seam: turn a window of flows into ScoredAlerts carrying BOTH detector scores.

WHY A NEW MODULE INSTEAD OF EDITING stub_detector.py
-----------------------------------------------------
stub_detector.score_flow() is what Checkpoint-1, the dashboard, and the red-team
harness all call. It must keep working exactly as it does. More importantly it
has the wrong *shape* for a graph detector: it takes ONE flow, and a graph score
is undefined for a single flow in isolation -- you cannot compute "this host
contacted 200 peers" from one row. That is the whole thesis of Pillar 1.

So the graph detector needs a different entry point, one that accepts a WINDOW
of flows. score_window() below is that entry point. score_flow() is untouched.

WHAT COMES OUT
--------------
ScoredAlert objects (schemas/scored_alert.json) with the frozen required fields
intact, plus additive sub-scores so C's risk model and D's dashboard can show
which pillar fired:

    network_subscores: {per_flow, relational, fused}

Additive only -- no existing field changes type or meaning, so nothing
downstream breaks.
"""

from __future__ import annotations

import uuid
from datetime import datetime, UTC
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from graph_builder import build_graphs, normalize_columns
from gnn_model import GraphAutoencoder, NodeScaler
from stub_detector import EXPECTED_FEATURES, _get_model, _FEATURE_NAMES

MODEL_PATH = Path(__file__).resolve().parent / "gnn_autoencoder_v1.pt"

_m5b = None
_scaler = None


def _load_m5b():
    """Load the trained graph autoencoder once."""
    global _m5b, _scaler
    if _m5b is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"{MODEL_PATH.name} not found -- train it first with "
                "`python detection/gnn_model.py <benign.csv>`"
            )
        blob = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
        model = GraphAutoencoder()
        model.load_state_dict(blob["model"])
        model.eval()
        scaler = NodeScaler().load_state_dict(blob["scaler"])
        _m5b, _scaler = model, scaler
    return _m5b, _scaler


def score_window(df: pd.DataFrame, feature_columns: list[str] | None = None,
                 threshold: float = 0.5, window_seconds: int = 60) -> list[dict]:
    """Score a window of flows with both detectors and emit ScoredAlerts.

    One alert per graph EDGE (a src -> dst conversation), because the frozen
    ScoredAlert schema requires src_ip and dst_ip -- an edge maps onto that
    cleanly, a node does not.
    """
    df = normalize_columns(df)
    graphs = build_graphs(df, window_seconds=window_seconds)
    if not graphs:
        return []

    model, scaler = _load_m5b()

    # ---- M5a: per-flow, then lifted to per-host (max over that host's flows)
    per_host_flow_score: dict[str, float] = {}
    if feature_columns and all(c in df.columns for c in feature_columns):
        feats = df[feature_columns].apply(pd.to_numeric, errors="coerce")
        feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        arr = feats.to_numpy(dtype=np.float32)
        lo, hi = arr.min(axis=0), arr.max(axis=0)
        arr = np.clip((arr - lo) / np.where(hi - lo > 0, hi - lo, 1.0), 0.0, 1.0)
        with torch.no_grad():
            fs = _get_model().anomaly_score(torch.tensor(arr)).numpy()
        per_host_flow_score = (
            pd.DataFrame({"h": df["src_ip"].values, "s": fs})
            .groupby("h")["s"].max().to_dict()
        )

    alerts = []
    for g in graphs:
        with torch.no_grad():
            node_scores = model.node_scores(
                scaler.transform(g.x), g.edge_index
            ).numpy()

        src_idx, dst_idx = g.edge_index[0].tolist(), g.edge_index[1].tolist()
        for e, (si, di) in enumerate(zip(src_idx, dst_idx)):
            src, dst = g.hosts[si], g.hosts[di]
            relational = float((node_scores[si] + node_scores[di]) / 2.0)
            per_flow = float(per_host_flow_score.get(src, 0.0))
            # Max, not mean: either detector finding it suspicious is enough.
            # Averaging would let a confident detector be diluted by a blind one.
            fused = max(relational, per_flow)

            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": datetime.now(UTC).isoformat(),
                "src_ip": src,
                "dst_ip": dst,
                "anomaly_score": round(min(fused, 1.0), 6),
                "confidence": round(max(0.0, 1.0 - fused), 6),
                "risk_score": min(int(fused * 100), 100),
                "attack_type_guess": _guess(g.x[si]),
                "mitre_technique": _technique(g.x[si]),
                "explanation": _explain(g.x[si], relational, per_flow),
                "model_source": "ensemble-v1(autoencoder-v2-256+gnn-v1)",
                "is_adversarial_test": False,
                "is_anomaly": fused > threshold,
                "threshold": threshold,
                "feature_vector": [0.0] * EXPECTED_FEATURES,
                "network_subscores": {
                    "per_flow": round(per_flow, 6),
                    "relational": round(relational, 6),
                    "fused": round(fused, 6),
                },
            })
    return alerts


def _guess(node: torch.Tensor) -> str:
    """Rule-style naming lives here, in the MAPPING layer -- never in detection."""
    out_deg, _, _, _, _, _, ports, _ = node.tolist()
    if ports > 50 and out_deg <= 2:
        return "vertical_port_scan"
    if out_deg > 20:
        return "horizontal_scan"
    return "anomalous_host_behaviour"


def _technique(node: torch.Tensor) -> str:
    out_deg, _, _, _, _, _, ports, _ = node.tolist()
    if ports > 50 or out_deg > 20:
        return "T1046"       # Network Service Discovery
    return "T1071"           # Application Layer Protocol


def _explain(node: torch.Tensor, relational: float, per_flow: float) -> list[str]:
    out_deg, in_deg, out_flows, _, _, _, ports, _ = node.tolist()
    lines = [
        f"host contacted {int(out_deg)} distinct peers across {int(ports)} distinct ports",
        f"sent {int(out_flows)} flows in this window (in-degree {int(in_deg)})",
        f"relational score {relational:.6f} vs per-flow score {per_flow:.6f}",
    ]
    # Only claim the relational view won when M5a actually ran (per_flow > 0)
    # and the gap is real. Without that guard, per_flow == 0.0 makes
    # `relational > per_flow * 2` trivially true and every alert -- including
    # risk-0 benign ones -- would claim a relational catch.
    if per_flow > 0 and relational > per_flow * 2:
        lines.append("flagged by RELATIONAL structure -- per-flow view saw nothing unusual")
    return lines


if __name__ == "__main__":
    import sys
    from graph_builder import read_flows

    src = sys.argv[1] if len(sys.argv) > 1 else str(
        Path(__file__).resolve().parent.parent / "training_data" / "dataset_10k_normal.csv")
    frame = normalize_columns(read_flows(src, limit=5000))
    out = score_window(frame)
    print(f"{len(out)} alerts from {src}")
    for a in sorted(out, key=lambda r: -r["anomaly_score"])[:3]:
        print(f"\n  {a['src_ip']} -> {a['dst_ip']}  risk={a['risk_score']} "
              f"({a['attack_type_guess']}, {a['mitre_technique']})")
        for line in a["explanation"]:
            print(f"    - {line}")
