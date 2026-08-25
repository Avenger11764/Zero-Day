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

from graph_builder import build_graphs, normalize_columns, NODE_FEATURE_NAMES, V2_FEATURE_NAMES, _window_key
from gnn_model import GraphAutoencoder, NodeScaler
from stub_detector import EXPECTED_FEATURES, _FEATURE_NAMES

try:
    from drift_monitor import DetectorDriftMonitors
except ImportError:
    from detection.drift_monitor import DetectorDriftMonitors

try:
    from exp_m5a_revival import build_ctx, CtxScaler, RevivedAE
except ImportError:
    from detection.exp_m5a_revival import build_ctx, CtxScaler, RevivedAE

MODEL_PATH = Path(__file__).resolve().parent / "gnn_autoencoder_v1.pt"
# Optional logscale checkpoint (produced after A2 fix); used if present.
LOGSCALE_PATH = Path(__file__).resolve().parent / "gnn_autoencoder_v1_logscale.pt"
# v2 checkpoint (19 feats) — only produced after explicit retrain; E3 opt-in.
V2_LOGSCALE_PATH = Path(__file__).resolve().parent / "gnn_autoencoder_v1_logscale_v2.pt"
V2_PATH = Path(__file__).resolve().parent / "gnn_autoencoder_v1_v2.pt"
# REVIVED M5a (87-dim ctx AE) — production per-flow pillar since 2026-08-25d.
REVIVED_PATH = Path(__file__).resolve().parent / "m5a_revived_ctx.pt"

_m5b = None
_scaler = None
_revived = None
_revived_meta = None


def _load_m5b(feature_set: str = "v1"):
    """Load the trained graph autoencoder once — prefers logscale checkpoint if present.

    feature_set="v2" requires a 19-dim checkpoint (gnn_autoencoder_v1[_logscale]_v2.pt);
    scoring v2 graphs with the 8-dim production checkpoint would crash or silently
    misalign, so we refuse loudly instead (gotcha #23 dimension guard).
    """
    global _m5b, _scaler
    want_v2 = feature_set == "v2"
    in_dim = len(V2_FEATURE_NAMES) if want_v2 else len(NODE_FEATURE_NAMES)
    if _m5b is not None and getattr(_scaler, "lo", None) is not None and _scaler.lo.shape[0] != in_dim:
        _m5b, _scaler = None, None  # cached checkpoint mismatches requested feature set
    if _m5b is None:
        if want_v2:
            path = V2_LOGSCALE_PATH if V2_LOGSCALE_PATH.exists() else V2_PATH
        else:
            path = LOGSCALE_PATH if LOGSCALE_PATH.exists() else MODEL_PATH
        if not path.exists():
            if want_v2:
                raise FileNotFoundError(
                    f"No v2 (19-feat) checkpoint found ({path.name}). Train one first: "
                    "`python detection/gnn_model.py <benign.csv> --feature-set v2 --seed 0` "
                    "-- until then use feature_set='v1' (production default)."
                )
            raise FileNotFoundError(
                f"{path.name} not found -- train it first with "
                "`python detection/gnn_model.py <benign.csv>`"
            )
        blob = torch.load(path, map_location="cpu", weights_only=False)
        model = GraphAutoencoder(in_dim=in_dim)
        model.load_state_dict(blob["model"])
        model.eval()
        scaler = NodeScaler().load_state_dict(blob["scaler"])
        if scaler.lo.shape[0] != in_dim:
            raise RuntimeError(
                f"Checkpoint {path.name} has {scaler.lo.shape[0]} features but "
                f"feature_set='{feature_set}' builds {in_dim}. Checkpoint/feature_set mismatch."
            )
        _m5b, _scaler = model, scaler
    return _m5b, _scaler


def _load_revived():
    """Load the REVIVED 87-dim per-flow AE (m5a_revived_ctx.pt) once.

    Returns (model, canonical, flow_lo, flow_hi, ctx_scaler) or (None,)*5 when
    the checkpoint is absent — caller then falls back to RC-26 pure relational.
    Train it with: python detection/train_m5a_revived.py --seed 0
    """
    global _revived, _revived_meta
    if _revived is None and _revived_meta is None:
        if not REVIVED_PATH.exists():
            _revived_meta = {"missing": True}
            return None, None, None, None, None
        blob = torch.load(REVIVED_PATH, map_location="cpu", weights_only=False)
        model = RevivedAE(blob["input_dim"])
        model.load_state_dict(blob["state_dict"])
        model.eval()
        csc = CtxScaler()
        csc.lo, csc.hi = blob["ctx_lo"], blob["ctx_hi"]
        _revived = model
        _revived_meta = {
            "canonical": blob["canonical"],
            "flow_lo": blob["flow_lo"], "flow_hi": blob["flow_hi"],
            "ctx_scaler": csc,
        }
    if _revived is None:
        return None, None, None, None, None
    m = _revived_meta
    return _revived, m["canonical"], m["flow_lo"], m["flow_hi"], m["ctx_scaler"]


def _rank01(x):
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def _noisyor(a, b):
    return 1.0 - (1.0 - a) * (1.0 - b)


_drift_monitors: DetectorDriftMonitors | None = None

def get_drift_monitors() -> DetectorDriftMonitors | None:
    return _drift_monitors

def init_drift_monitors(baseline_rel_scores: list[float], baseline_flow_scores: list[float] | None = None):
    global _drift_monitors
    m = DetectorDriftMonitors()
    m.set_baselines(baseline_rel_scores, baseline_flow_scores)
    _drift_monitors = m
    return m


def score_window(df: pd.DataFrame, feature_columns: list[str] | None = None,
                 threshold: float | None = None, window_seconds: int = 60, k: int = 0,
                 feature_set: str = "v1", drift: DetectorDriftMonitors | None = None) -> list[dict]:
    """Score a window of flows with both detectors and emit ScoredAlerts.

    One alert per graph EDGE (a src -> dst conversation), because the frozen
    ScoredAlert schema requires src_ip and dst_ip -- an edge maps onto that
    cleanly, a node does not.

    If k > 0, builds graphs with k nearest-neighbour auxiliary edges per host.
    """
    df = normalize_columns(df)
    # Production since 2026-08-25d (CHANGELOG): M5b relational + REVIVED 87-dim
    # per-flow AE, fused by within-window rank noisyor (the 7/7x4 rule).
    # feature_columns forces the LEGACY shipped-M5a path instead (ablation only — it hurts, -5pts RC-26).
    graphs = build_graphs(df, window_seconds=window_seconds, k=k, feature_set=feature_set)
    if not graphs:
        return []

    model, scaler = _load_m5b(feature_set)

    # ---- REVIVED per-flow pillar: host scores via max over flows ----------
    rev, r_canonical, r_lo, r_hi, csc = _load_revived()
    revived_host_score: dict[str, float] = {}
    use_rev = rev is not None and all(c in df.columns for c in r_canonical)
    if use_rev:
        feats = df[r_canonical].apply(pd.to_numeric, errors="coerce")
        feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        arr = feats.to_numpy(dtype=np.float32)
        span = np.where(r_hi - r_lo > 0, r_hi - r_lo, 1.0)
        xl = np.clip((arr - r_lo) / span, 0.0, 1.0).astype(np.float32)
        xc = csc.transform(build_ctx(df, _window_key(df, 60)))
        x87 = np.concatenate([xl, xc], axis=1)
        outs = []
        with torch.no_grad():
            for i in range(0, len(x87), 8192):
                xb = torch.tensor(x87[i:i + 8192])
                outs.append(rev.anomaly_score(xb).numpy())
        rs = np.concatenate(outs)
        revived_host_score = (
            pd.DataFrame({"h": df["src_ip"].values, "s": rs})
            .groupby("h")["s"].max().to_dict()
        )

    # ---- LEGACY shipped M5a path (opt-in ablation only) -------------------
    per_host_flow_score: dict[str, float] = {}
    use_m5a = feature_columns is not None and all(c in df.columns for c in feature_columns)
    if use_m5a:
        from stub_detector import _get_model
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

    # ---- pass 1: collect raw edge scores ----------------------------------
    edges = []
    for g in graphs:
        with torch.no_grad():
            node_scores = model.node_scores(
                scaler.transform(g.x), g.edge_index
            ).numpy()
        real_mask = g.edge_attr[:, 0] > 0
        if not real_mask.any():
            continue
        src_idx = g.edge_index[0][real_mask].tolist()
        dst_idx = g.edge_index[1][real_mask].tolist()
        for si, di in zip(src_idx, dst_idx):
            src, dst = g.hosts[si], g.hosts[di]
            edges.append({
                "si": si, "src": src, "dst": dst,
                "node": g.x[si],
                "relational": float((node_scores[si] + node_scores[di]) / 2.0),
                "revived_raw": float(revived_host_score.get(src, 0.0)) if use_rev else 0.0,
                "per_flow": float(per_host_flow_score.get(src, 0.0)) if use_m5a else 0.0,
            })
    if not edges:
        return []
    # ---- pass 2: within-window rank fusion (noisyor; gotcha #17 batch-only)
    rel_r = _rank01(np.array([e["relational"] for e in edges]))
    rev_r = _rank01(np.array([e["revived_raw"] for e in edges])) if use_rev else None
    alerts = []
    for i, e in enumerate(edges):
        if use_rev:
            fused = float(_noisyor(rel_r[i], rev_r[i]))
            revived_pct = float(rev_r[i])
        else:
            fused = e["relational"]  # fallback: raw relational (no revived checkpoint)
            revived_pct = 0.0

        # Feed drift monitors (M6) if wired — tracks queue saturation (RC-27/28)
        dm = drift if drift is not None else _drift_monitors
        if dm is not None:
            dm.add(e["relational"], e["revived_raw"] if use_rev else None, fused)

        # Threshold: if None, caller should use percentile-calibrated threshold downstream;
        # default 0.5 only for backward compat when fused is raw MSE (uncalibrated gotcha #7).
        is_anomaly = (fused > threshold) if threshold is not None else False
        node = e["node"]
        alerts.append({
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "src_ip": e["src"],
            "dst_ip": e["dst"],
            "anomaly_score": round(min(fused, 1.0), 6),
            "confidence": round(max(0.0, 1.0 - fused), 6),
            "risk_score": min(int(fused * 100), 100),
            "attack_type_guess": _guess(node),
            "mitre_technique": _technique(node),
            "explanation": _explain(node, e["relational"], e["per_flow"]),
            "model_source": ("revived-v1(gnn-logscale+m5a-ctx87,noisyor)" if use_rev
                             else ("gnn-v1-logscale" if LOGSCALE_PATH.exists() else "gnn-v1")),
            "is_adversarial_test": False,
            "is_anomaly": is_anomaly,
            "threshold": threshold,
            "feature_vector": [0.0] * EXPECTED_FEATURES,
            "network_subscores": {
                "per_flow": round(e["per_flow"], 6),
                "relational": round(rel_r[i], 6) if use_rev else round(e["relational"], 6),
                "revived": round(revived_pct, 6),
                "fused": round(fused, 6),
            },
        })
    return alerts


def _guess(node: torch.Tensor) -> str:
    """Rule-style naming lives here, in the MAPPING layer -- never in detection."""
    # Index by position (0 and 6) — gotcha #23: never a,b,c = node.tolist() (breaks on v2 19 feats)
    out_deg = float(node[0].item() if node.numel() > 0 else 0)
    ports = float(node[6].item() if node.numel() > 6 else 0)
    if ports > 50 and out_deg <= 2:
        return "vertical_port_scan"
    if out_deg > 20:
        return "horizontal_scan"
    return "anomalous_host_behaviour"


def _technique(node: torch.Tensor) -> str:
    out_deg = float(node[0].item() if node.numel() > 0 else 0)
    ports = float(node[6].item() if node.numel() > 6 else 0)
    if ports > 50 or out_deg > 20:
        return "T1046"       # Network Service Discovery
    return "T1071"           # Application Layer Protocol


def _explain(node: torch.Tensor, relational: float, per_flow: float) -> list[str]:
    out_deg = float(node[0].item() if node.numel() > 0 else 0)
    in_deg = float(node[1].item() if node.numel() > 1 else 0)
    out_flows = float(node[2].item() if node.numel() > 2 else 0)
    ports = float(node[6].item() if node.numel() > 6 else 0)
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
