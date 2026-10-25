"""SHAP explainer for the revived 87-dim M5a checkpoint (m5a_revived_ctx.pt).

Key differences from the legacy 76-feature explainer in shap_explainer.py:
  - 87-dim input: 76 canonical flow features + 11 window-context dims (ws_*/wd_*)
  - Uses shap.DeepExplainer (10-100x faster than KernelExplainer)
  - Background is real benign flows scaled identically to training, not random noise
  - Batch explain_batch() for whole-CSV explanations
  - Outputs: JSON, CSV, bar plots, beeswarm plots

Usage (script):
    python detection/shap_revived_ctx.py \\
        --csv data/GeneratedLabelledFlows/TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv \\
        --top-k 10 --n-flows 100 --plot-bar --out-json shap_out.json

Usage (import):
    from detection.shap_revived_ctx import load_checkpoint, explain_batch
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import shap
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import normalize_columns, read_flows, _window_key

# Import canonical training utilities to avoid drift from the training code.
try:
    from experiments.exp_m5a_revival import (
        build_ctx, CtxScaler, RevivedAE, CTX_DIMS, pin_canonical, flow_matrix, MinMax,
    )
except ModuleNotFoundError:
    from detection.exp_m5a_revival import (  # type: ignore[no-redef]
        build_ctx, CtxScaler, RevivedAE, CTX_DIMS, pin_canonical, flow_matrix, MinMax,
    )

log = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().with_name("m5a_revived_ctx.pt")

# --------------------------------------------------------------------------- #
# 76 canonical CICIDS2017 flow feature names (pinned, same order as training). #
# DO NOT reorder – SHAP attribution is position-sensitive.                    #
# --------------------------------------------------------------------------- #
FLOW_FEATURE_NAMES: list[str] = [
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
    "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
    "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
    "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_max", "active_min", "active_mean", "active_std",
    "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts",
    "subflow_fwd_byts", "subflow_bwd_byts",
]
assert len(FLOW_FEATURE_NAMES) == 76, f"Expected 76 flow dims, got {len(FLOW_FEATURE_NAMES)}"

REVIVED_FEATURE_NAMES: list[str] = FLOW_FEATURE_NAMES + list(CTX_DIMS)
assert len(REVIVED_FEATURE_NAMES) == 87, f"Expected 87 total dims, got {len(REVIVED_FEATURE_NAMES)}"

# Fast index lookup: feature name -> position in the 87-dim vector
_FIDX: dict[str, int] = {n: i for i, n in enumerate(REVIVED_FEATURE_NAMES)}


# --------------------------------------------------------------------------- #
# Flow-level attack classifier (CICIDS2017 families + MITRE ATT&CK)           #
#                                                                               #
# NOTE: this is the network mapper, separate from the UEBA and host mappers.    #
# M5a scores network FLOWS, so the rules reference flow-level features (IAT,    #
# flags, rates, and window context).                                            #
# --------------------------------------------------------------------------- #
def _fv(name: str, xrow: np.ndarray) -> float:
    """Scaled input value [0,1] for a named feature."""
    return float(xrow[_FIDX[name]]) if name in _FIDX else 0.0


def _sv(name: str, sv: np.ndarray) -> float:
    """SHAP value for a named feature."""
    return float(sv[_FIDX[name]]) if name in _FIDX else 0.0


def _load_json_mapper(mapper_path: str | Path | None = None) -> list[dict]:
    """Loads network attack profiles from JSON mapper if available."""
    candidates = []
    if mapper_path:
        candidates.append(Path(mapper_path))
    candidates.extend([
        ROOT / "attack_mappers" / "network_attack_mapper.json",
        ROOT / "attack_mappers" / "network_attack_mapper_legacy.json",
    ])
    for c in candidates:
        if c.exists():
            try:
                with open(c) as f:
                    data = json.load(f)
                return data.get("attack_profiles", [])
            except Exception:
                pass
    return []


_MAPPER_PROFILES: list[dict] = []


def classify_network_attack(
    shap_vals: np.ndarray,
    xrow: np.ndarray,
    score: float,
    threshold: float = 0.005,
    mapper_path: str | Path | None = None,
) -> dict:
    """Rule-based and JSON-mapper driven attack family classifier from SHAP attributions.

    Rules fire in order of specificity. Each rule checks:
      - The scaled feature value (xrow, 0-1) for magnitude evidence.
      - The SHAP value for that feature (positive = driving anomaly up).

    CICIDS2017 families covered:
      DDoS, PortScan (H/V), DoS-SYNFlood, DoS-Volume (Hulk/GoldenEye),
      DoS-SlowRate (Slowloris), Brute Force (FTP/SSH Patator),
      Botnet/C2-Beaconing, Infiltration/Exfiltration, Web Attacks.

    Returns a dict with:
      verdict, attack_family, mitre_id, mitre_tactic,
      mitre_technique, mitre_url, severity, confidence, reason
    """
    if score < threshold:
        return {
            "verdict": "BENIGN",
            "attack_family": "—",
            "mitre_id": "—",
            "mitre_tactic": "—",
            "mitre_technique": "—",
            "mitre_url": "—",
            "severity": "none",
            "confidence": "high",
            "reason": f"score {score:.6f} < threshold {threshold:.4f} — within benign range",
        }

    # ----- feature value shortcuts ----------------------------------------
    pkts_s    = _fv("flow_pkts_s",       xrow)
    byts_s    = _fv("flow_byts_s",       xrow)
    syn       = _fv("syn_flag_cnt",      xrow)
    rst       = _fv("rst_flag_cnt",      xrow)
    fin       = _fv("fin_flag_cnt",      xrow)
    psh       = _fv("psh_flag_cnt",      xrow)
    ack       = _fv("ack_flag_cnt",      xrow)
    duration  = _fv("flow_duration",     xrow)
    iat_mean  = _fv("flow_iat_mean",     xrow)
    iat_std   = _fv("flow_iat_std",      xrow)
    fwd_win   = _fv("init_fwd_win_byts", xrow)
    bwd_len   = _fv("bwd_pkt_len_mean",  xrow)
    ws_flows  = _fv("ws_flows",          xrow)
    ws_dst    = _fv("ws_dst",            xrow)
    ws_ports  = _fv("ws_ports",          xrow)
    wd_src    = _fv("wd_src",            xrow)

    # ----- SHAP value shortcuts (positive = suspicious) --------------------
    sh_pkts   = _sv("flow_pkts_s",       shap_vals)
    sh_byts   = _sv("flow_byts_s",       shap_vals)
    sh_syn    = _sv("syn_flag_cnt",      shap_vals)
    sh_fin    = _sv("fin_flag_cnt",      shap_vals)
    sh_psh    = _sv("psh_flag_cnt",      shap_vals)
    sh_dur    = _sv("flow_duration",     shap_vals)
    sh_iat_m  = _sv("flow_iat_mean",     shap_vals)
    sh_iat_s  = _sv("flow_iat_std",      shap_vals)
    sh_bwd    = _sv("bwd_pkt_len_mean",  shap_vals)
    sh_wflows = _sv("ws_flows",          shap_vals)
    sh_wdst   = _sv("ws_dst",            shap_vals)
    sh_wports = _sv("ws_ports",          shap_vals)
    sh_wdsrc  = _sv("wd_src",            shap_vals)

    # -----------------------------------------------------------------------
    # Rule 1 — DDoS: many sources converging on same destination OR high volume
    # Signal: wd_src high + rate spike, or extreme flow_byts_s / flow_pkts_s
    # -----------------------------------------------------------------------
    if (wd_src > 0.4 and sh_wdsrc > 0) or ((byts_s > 0.5 or pkts_s > 0.5) and (sh_byts > 0 or sh_pkts > 0)):
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "DDoS / DoS Volume Flood",
            "mitre_id": "T1498",
            "mitre_tactic": "Impact",
            "mitre_technique": "Network Denial of Service",
            "mitre_url": "https://attack.mitre.org/techniques/T1498/",
            "severity": "critical",
            "confidence": "high",
            "reason": f"wd_src={wd_src:.2f}, byts_s={byts_s:.2f}, pkts_s={pkts_s:.2f}: volume flood / multi-source traffic",
        }

    # -----------------------------------------------------------------------
    # Rule 2 — Horizontal Port Scan: high distinct destination count
    # -----------------------------------------------------------------------
    if ws_dst > 0.4 and sh_wdst > 0:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Port Scan — Horizontal",
            "mitre_id": "T1046",
            "mitre_tactic": "Discovery",
            "mitre_technique": "Network Service Discovery",
            "mitre_url": "https://attack.mitre.org/techniques/T1046/",
            "severity": "high",
            "confidence": "high",
            "reason": f"ws_dst={ws_dst:.2f}: src contacted many distinct IPs in window",
        }

    # -----------------------------------------------------------------------
    # Rule 3 — Vertical Port Scan: high distinct destination port count
    # -----------------------------------------------------------------------
    if ws_ports > 0.4 and sh_wports > 0 and ws_dst < 0.3:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Port Scan — Vertical",
            "mitre_id": "T1046",
            "mitre_tactic": "Discovery",
            "mitre_technique": "Network Service Discovery",
            "mitre_url": "https://attack.mitre.org/techniques/T1046/",
            "severity": "high",
            "confidence": "high",
            "reason": f"ws_ports={ws_ports:.2f}: src probed many ports on same target IP",
        }

    # -----------------------------------------------------------------------
    # Rule 4 — DoS SYN Flood: syn high + positive SHAP + low FIN + low window
    # -----------------------------------------------------------------------
    if syn > 0.4 and sh_syn > 0 and fin < 0.2:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "DoS — SYN Flood",
            "mitre_id": "T1498.001",
            "mitre_tactic": "Impact",
            "mitre_technique": "Direct Network Flood",
            "mitre_url": "https://attack.mitre.org/techniques/T1498/001/",
            "severity": "critical",
            "confidence": "high",
            "reason": f"syn={syn:.2f}, fin={fin:.2f}: unacknowledged SYN handshake flood",
        }

    # -----------------------------------------------------------------------
    # JSON Attack Profiles Matching (requires >= 2 matched trigger features)
    # -----------------------------------------------------------------------
    global _MAPPER_PROFILES
    if not _MAPPER_PROFILES:
        _MAPPER_PROFILES = _load_json_mapper(mapper_path)

    if _MAPPER_PROFILES:
        pos_shaps = {REVIVED_FEATURE_NAMES[i]: float(shap_vals[i]) for i in range(len(REVIVED_FEATURE_NAMES)) if shap_vals[i] > 0}
        best_prof = None
        best_score = -1.0
        best_matched = []

        for p in _MAPPER_PROFILES:
            triggers = p.get("trigger_features", [])
            matched = [f for f in triggers if f in pos_shaps]
            if len(matched) >= 2:
                score_sum = sum(pos_shaps[f] for f in matched)
                if score_sum > best_score:
                    best_score = score_sum
                    best_prof = p
                    best_matched = matched

        if best_prof:
            return {
                "verdict": "ANOMALOUS",
                "attack_family": best_prof.get("attack_type", "Anomalous Traffic"),
                "mitre_id": best_prof.get("mitre_technique", "T1071"),
                "mitre_tactic": best_prof.get("mitre_tactic", "Command and Control"),
                "mitre_technique": best_prof.get("attack_type", "Network Attack"),
                "mitre_url": best_prof.get("mitre_url", "https://attack.mitre.org/"),
                "severity": best_prof.get("severity", "medium"),
                "confidence": "high" if len(best_matched) >= 3 else "medium",
                "reason": f"Pattern: {best_prof.get('pattern', '')}. Triggers: {', '.join(best_matched)}",
            }

    # -----------------------------------------------------------------------
    # Rule 5 — High-Volume DoS (Hulk / GoldenEye): extreme packet/byte rate
    # -----------------------------------------------------------------------
    if (pkts_s > 0.65 and sh_pkts > 0) or (byts_s > 0.65 and sh_byts > 0):
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "DoS — Volume Flood (Hulk / GoldenEye)",
            "mitre_id": "T1498",
            "mitre_tactic": "Impact",
            "mitre_technique": "Network Denial of Service",
            "mitre_url": "https://attack.mitre.org/techniques/T1498/",
            "severity": "critical",
            "confidence": "medium",
            "reason": f"flow_pkts_s={pkts_s:.2f}, flow_byts_s={byts_s:.2f}: extreme traffic rate",
        }

    # -----------------------------------------------------------------------
    # Rule 6 — Slow-Rate DoS (Slowloris): long duration + FIN + low rate
    # -----------------------------------------------------------------------
    if duration > 0.6 and sh_dur > 0 and fin > 0.3 and pkts_s < 0.2:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "DoS — Slow-Rate (Slowloris / SlowHTTPTest)",
            "mitre_id": "T1499",
            "mitre_tactic": "Impact",
            "mitre_technique": "Endpoint Denial of Service",
            "mitre_url": "https://attack.mitre.org/techniques/T1499/",
            "severity": "high",
            "confidence": "medium",
            "reason": f"duration={duration:.2f}, fin={fin:.2f}, pkts_s={pkts_s:.2f}: slow-close pattern",
        }

    # -----------------------------------------------------------------------
    # Rule 7 — Brute Force (FTP/SSH Patator): many flows same port, high SYN
    # -----------------------------------------------------------------------
    if ws_flows > 0.4 and sh_wflows > 0 and syn > 0.25 and ws_ports < 0.15:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Brute Force — FTP / SSH (Patator)",
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force",
            "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            "severity": "high",
            "confidence": "medium",
            "reason": f"ws_flows={ws_flows:.2f} (many attempts same service), syn={syn:.2f}",
        }

    # -----------------------------------------------------------------------
    # Rule 8 — Botnet / C2 Beaconing (ARES): periodic IAT anomaly
    # -----------------------------------------------------------------------
    if (sh_iat_m > 0 or sh_iat_s > 0) and ws_flows > 0.2:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Botnet / C2 Beaconing (ARES)",
            "mitre_id": "T1071",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "Application Layer Protocol",
            "mitre_url": "https://attack.mitre.org/techniques/T1071/",
            "severity": "high",
            "confidence": "low",
            "reason": "Periodic IAT pattern + elevated src flow count suggests C2 beaconing",
        }

    # -----------------------------------------------------------------------
    # Rule 9 — Infiltration / Exfiltration: anomalous backward traffic volume
    # -----------------------------------------------------------------------
    if bwd_len > 0.5 and sh_bwd > 0:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Infiltration / Data Exfiltration",
            "mitre_id": "T1041",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "Exfiltration Over C2 Channel",
            "mitre_url": "https://attack.mitre.org/techniques/T1041/",
            "severity": "critical",
            "confidence": "medium",
            "reason": f"bwd_pkt_len_mean={bwd_len:.2f}: unusually large reverse payload size",
        }

    # -----------------------------------------------------------------------
    # Rule 10 — Web Attack (Brute Force / XSS / SQLi): PSH+ACK payload pattern
    # -----------------------------------------------------------------------
    if psh > 0.5 and sh_psh > 0 and ack > 0.5:
        return {
            "verdict": "ANOMALOUS",
            "attack_family": "Web Attack (Brute Force / XSS / SQLi)",
            "mitre_id": "T1190",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "Exploit Public-Facing Application",
            "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            "severity": "high",
            "confidence": "low",
            "reason": f"psh={psh:.2f} + ack={ack:.2f}: HTTP payload flag pattern",
        }

    # -----------------------------------------------------------------------
    # Rule 11 — Generic anomaly: anomaly score exceeded threshold but no
    # dominant rule fires. Report top 3 suspicious features.
    # -----------------------------------------------------------------------
    top_pos = sorted(
        [(shap_vals[i], REVIVED_FEATURE_NAMES[i]) for i in range(87) if shap_vals[i] > 0],
        reverse=True,
    )[:3]
    reason = (
        ", ".join(f"{n}(+{v:.4f})" for v, n in top_pos)
        if top_pos else "no dominant suspicious feature identified"
    )
    return {
        "verdict": "ANOMALOUS",
        "attack_family": "Unknown / Generic Anomaly",
        "mitre_id": "T1071",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/",
        "severity": "medium",
        "confidence": "low",
        "reason": f"Top suspicious features: {reason}",
    }


# --------------------------------------------------------------------------- #
# Thin scoring wrapper so DeepExplainer gets a single-output nn.Module.       #
# --------------------------------------------------------------------------- #
class _AnomalyScoreWrapper(nn.Module):
    """Wraps RevivedAE so forward() returns per-sample MSE (shape [N, 1]).

    DeepExplainer requires a differentiable nn.Module whose output is a tensor.
    The real anomaly_score() uses torch.no_grad() so gradients don't flow;
    we replicate it here without the no_grad context.
    """

    def __init__(self, ae: RevivedAE) -> None:
        super().__init__()
        self.ae = ae

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        recon = self.ae(x)
        # keepdim=True → shape [N, 1]; DeepExplainer requires a 2-D output.
        # check_additivity=False is set at call-time to tolerate MSE rounding noise.
        return torch.mean((recon - x) ** 2, dim=1, keepdim=True)


# --------------------------------------------------------------------------- #
# Checkpoint loading                                                          #
# --------------------------------------------------------------------------- #
def load_checkpoint(path: str | Path = MODEL_PATH) -> dict:
    """Load the revived checkpoint and return a metadata dict.

    Returns:
        {
          "model":      RevivedAE (eval mode, CPU),
          "wrapper":    _AnomalyScoreWrapper around the model,
          "canonical":  list[str] of 76 feature names (pinned at training time),
          "flow_scaler": MinMax fitted on Monday benign flows,
          "ctx_scaler":  CtxScaler fitted on Monday benign ctx,
        }
    """
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    model = RevivedAE(ckpt["input_dim"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    wrapper = _AnomalyScoreWrapper(model)
    wrapper.eval()

    flow_scaler = MinMax()
    flow_scaler.lo = ckpt["flow_lo"]
    flow_scaler.hi = ckpt["flow_hi"]

    ctx_scaler = CtxScaler()
    ctx_scaler.lo = ckpt["ctx_lo"]
    ctx_scaler.hi = ckpt["ctx_hi"]

    return {
        "model": model,
        "wrapper": wrapper,
        "canonical": ckpt["canonical"],
        "flow_scaler": flow_scaler,
        "ctx_scaler": ctx_scaler,
    }


# --------------------------------------------------------------------------- #
# Data preparation                                                             #
# --------------------------------------------------------------------------- #
def _prep_df(csv_path: str | Path, benign_only: bool = True) -> pd.DataFrame:
    """Read, normalise columns, and optionally keep only BENIGN rows.

    Path resolution order (to handle both absolute paths and various relative
    conventions without requiring the user to know the exact on-disk layout):
      1. As given (absolute, or relative to CWD).
      2. Relative to ROOT (project root).
      3. training_data/<basename> — covers the common case where the file is
         in training_data/ but was passed as a data/.../<name> style path.
    """
    p = Path(csv_path)
    candidates = [
        p,
        ROOT / p,
        ROOT / "training_data" / p.name,
    ]
    resolved: Path | None = None
    for c in candidates:
        if c.exists():
            resolved = c
            break
    if resolved is None:
        tried = "\n  ".join(str(c) for c in candidates)
        raise FileNotFoundError(
            f"CSV not found. Tried:\n  {tried}\n"
            f"Tip: the Monday benign file is usually at "
            f"training_data/Monday-WorkingHours.pcap_ISCX.csv"
        )

    df = normalize_columns(read_flows(str(resolved)))
    missing = [c for c in ("src_ip", "dst_ip") if c not in df.columns]
    if missing:
        raise ValueError(
            f"{resolved}: missing essential IP columns {missing}. "
            "Use standard netflow CSVs with Source IP and Destination IP."
        )
    if "label" not in df.columns:
        df["label"] = "UNLABELLED"

    if benign_only and "label" in df.columns:
        df = df[df["label"].astype(str).str.upper().str.strip() == "BENIGN"].copy()
    df = df[~df["src_ip"].isna() & ~df["dst_ip"].isna()].copy()
    return df.reset_index(drop=True)



def _build_x87(
    df: pd.DataFrame,
    canonical: list[str],
    flow_scaler: MinMax,
    ctx_scaler: CtxScaler,
    window_seconds: int = 60,
) -> np.ndarray:
    """Assemble the 87-dim scaled input matrix (N_flows × 87)."""
    wk = _window_key(df, window_seconds)
    flow_raw = flow_matrix(df, canonical)          # uses exp_m5a_revival.flow_matrix
    flow_scaled = flow_scaler.transform(flow_raw)
    ctx_raw = build_ctx(df, wk)                    # uses exp_m5a_revival.build_ctx
    ctx_scaled = ctx_scaler.transform(ctx_raw)
    return np.concatenate([flow_scaled, ctx_scaled], axis=1).astype(np.float32)


# --------------------------------------------------------------------------- #
# Core explain functions                                                       #
# --------------------------------------------------------------------------- #
def _build_background(
    x87: np.ndarray,
    n_bg: int = 100,
    seed: int = 0,
) -> torch.Tensor:
    """Sample n_bg rows from the already-scaled benign matrix as DeepExplainer background.

    Using real benign flows (not uniform noise) makes SHAP values relative to the
    trained benign distribution — the correct reference for an anomaly detector.
    Falls back to zero vector if x87 is too small.
    """
    rng = np.random.default_rng(seed)
    if len(x87) >= n_bg:
        idx = rng.choice(len(x87), size=n_bg, replace=False)
        bg = x87[idx]
    else:
        # fewer benign rows than requested; use all of them + zero-padding row
        bg = np.vstack([x87, np.zeros((1, x87.shape[1]), dtype=np.float32)])
    return torch.tensor(bg, dtype=torch.float32)


def explain_batch(
    df: pd.DataFrame,
    ckpt: dict,
    n_bg: int = 100,
    seed: int = 0,
    use_kernel: bool = False,
    nsamples: int = 200,
    window_seconds: int = 60,
    batch_size: int = 512,
) -> tuple[np.ndarray, np.ndarray]:
    """Explain anomaly scores for every row in df using the revived M5a.

    Args:
        df:              DataFrame of flows (normalised columns; benign OR mixed).
        ckpt:            Dict returned by load_checkpoint().
        n_bg:            Number of background samples for DeepExplainer.
        seed:            RNG seed for background sampling.
        use_kernel:      Fall back to KernelExplainer (slow, model-agnostic).
        nsamples:        nsamples for KernelExplainer (ignored for DeepExplainer).
        window_seconds:  Time-window bucket size (must match training; default 60s).
        batch_size:      Rows per forward pass when scoring (CPU-safe default).

    Returns:
        shap_values: np.ndarray shape (N, 87) — one SHAP value per feature per flow.
        scores:      np.ndarray shape (N,)   — raw MSE anomaly score per flow.
    """
    canonical = ckpt["canonical"]
    model = ckpt["model"]
    wrapper = ckpt["wrapper"]
    flow_scaler = ckpt["flow_scaler"]
    ctx_scaler = ckpt["ctx_scaler"]

    x87 = _build_x87(df, canonical, flow_scaler, ctx_scaler, window_seconds)

    # --- anomaly scores (batched, no_grad) ---
    scores_list = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(x87), batch_size):
            xb = torch.tensor(x87[start : start + batch_size])
            scores_list.append(model.anomaly_score(xb).numpy())
    scores = np.concatenate(scores_list)

    # --- SHAP ---
    background = _build_background(x87, n_bg=n_bg, seed=seed)
    x_tensor = torch.tensor(x87, dtype=torch.float32)

    if use_kernel:
        log.info("Using KernelExplainer (slow; nsamples=%d)", nsamples)

        def _predict(arr: np.ndarray) -> np.ndarray:
            with torch.no_grad():
                return model.anomaly_score(torch.tensor(arr, dtype=torch.float32)).numpy()

        explainer = shap.KernelExplainer(_predict, background.numpy())
        sv = explainer.shap_values(x87, nsamples=nsamples)
        if isinstance(sv, list):
            sv = sv[0]
        shap_values = np.asarray(sv, dtype=np.float32)
    else:
        log.info("Using DeepExplainer (background n=%d)", len(background))
        wrapper.eval()
        explainer = shap.DeepExplainer(wrapper, background)
        # check_additivity=False: the autoencoder's mean-MSE output accumulates
        # small float rounding across 87 dims that can exceed SHAP's 0.01 tolerance.
        # The attributions are still correct; we just skip the strict sum check.
        sv = explainer.shap_values(x_tensor, check_additivity=False)
        # DeepExplainer may return list[array] (one per output) or a single array
        if isinstance(sv, list):
            sv = sv[0]
        # sv shape: (N, 87) — squeeze trailing dim if somehow present
        sv = np.asarray(sv, dtype=np.float32)
        if sv.ndim == 3:
            sv = sv[:, :, 0]
        shap_values = sv

    return shap_values, scores


def top_k_table(
    shap_values: np.ndarray,
    scores: np.ndarray,
    x87: np.ndarray,
    k: int = 10,
    threshold: float = 0.005,
    mapper_path: str | Path | None = None,
) -> list[dict]:
    """Build a per-flow top-k attribution table (list of dicts, one per flow)."""
    results = []
    for i, (sv, score, xrow) in enumerate(zip(shap_values, scores, x87)):
        ranked = np.argsort(np.abs(sv))[::-1][:k]
        features = [
            {
                "rank": int(r + 1),
                "feature": REVIVED_FEATURE_NAMES[idx],
                "shap_value": float(sv[idx]),
                "input_scaled": float(xrow[idx]),
                "direction": "↑ anomaly" if sv[idx] > 0 else "↓ anomaly",
            }
            for r, idx in enumerate(ranked)
        ]
        classification = classify_network_attack(
            sv, xrow, float(score), threshold=threshold, mapper_path=mapper_path
        )
        results.append({
            "flow_idx": i,
            "anomaly_score": float(score),
            "classification": classification,
            "top_features": features,
        })
    return results


# --------------------------------------------------------------------------- #
# Output helpers                                                               #
# --------------------------------------------------------------------------- #
def save_json(table: list[dict], path: str | Path) -> None:
    with open(path, "w") as f:
        json.dump(table, f, indent=2)
    print(f"[SHAP] JSON saved → {path}")


def save_csv(shap_values: np.ndarray, path: str | Path) -> None:
    df_out = pd.DataFrame(shap_values, columns=REVIVED_FEATURE_NAMES)
    df_out.to_csv(path, index=False)
    print(f"[SHAP] CSV saved → {path}")


def plot_bar(
    shap_values: np.ndarray,
    flow_idx: int = 0,
    top_k: int = 15,
    out_path: Optional[str | Path] = None,
) -> None:
    """Horizontal bar chart of SHAP values for a single flow."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("[SHAP] matplotlib not available — skipping bar plot.")
        return

    sv = shap_values[flow_idx]
    ranked = np.argsort(np.abs(sv))[::-1][:top_k]
    names = [REVIVED_FEATURE_NAMES[i] for i in ranked]
    vals = [sv[i] for i in ranked]
    colors = ["#e74c3c" if v > 0 else "#2980b9" for v in vals]

    fig, ax = plt.subplots(figsize=(9, max(4, top_k * 0.45)))
    y_pos = range(len(names))
    ax.barh(y_pos, vals[::-1], color=colors[::-1], edgecolor="none")
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(names[::-1], fontsize=9)
    ax.axvline(0, color="#333", linewidth=0.8)
    ax.set_xlabel("SHAP value  (positive = drives anomaly score up)", fontsize=9)
    ax.set_title(f"SHAP attribution — flow {flow_idx}  |  top {top_k} features", fontsize=10)
    fig.tight_layout()

    if out_path:
        fig.savefig(out_path, dpi=150)
        print(f"[SHAP] bar plot saved → {out_path}")
    else:
        fig.savefig(f"shap_bar_flow{flow_idx}.png", dpi=150)
        print(f"[SHAP] bar plot saved → shap_bar_flow{flow_idx}.png")
    plt.close(fig)


def plot_beeswarm(
    shap_values: np.ndarray,
    out_path: Optional[str | Path] = None,
    max_display: int = 20,
) -> None:
    """SHAP beeswarm summary plot across all explained flows."""
    try:
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("[SHAP] matplotlib not available — skipping beeswarm plot.")
        return

    out = out_path or "shap_beeswarm.png"
    shap.summary_plot(
        shap_values,
        feature_names=REVIVED_FEATURE_NAMES,
        max_display=max_display,
        show=False,
    )
    import matplotlib.pyplot as plt
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[SHAP] beeswarm plot saved → {out}")


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SHAP explainer for the revived 87-dim M5a autoencoder.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    default_csv = ROOT / "training_data" / "Monday-WorkingHours.pcap_ISCX.csv"
    p.add_argument("--csv", default=str(default_csv),
                   help="CICIDS2017 TrafficLabelling CSV (must have Source IP / Destination IP).")
    p.add_argument("--model", default=str(MODEL_PATH), help="Path to m5a_revived_ctx.pt.")
    p.add_argument("--n-flows", type=int, default=1,
                   help="Number of benign flows to explain (0 = all).")
    p.add_argument("--top-k", type=int, default=10, help="Features to show per flow.")
    p.add_argument("--n-bg", type=int, default=100,
                   help="Background samples for DeepExplainer.")
    p.add_argument("--kernel", action="store_true",
                   help="Use KernelExplainer instead of DeepExplainer (slow).")
    p.add_argument("--nsamples", type=int, default=200,
                   help="KernelExplainer nsamples (ignored for DeepExplainer).")
    p.add_argument("--window", type=int, default=60,
                   help="Time-window bucket size in seconds (must match training).")
    p.add_argument("--out-json", default="", help="Save full results to this JSON file.")
    p.add_argument("--out-csv", default="", help="Save SHAP value matrix to this CSV file.")
    p.add_argument("--plot-bar", action="store_true",
                   help="Save a bar chart for each explained flow.")
    p.add_argument("--plot-beeswarm", action="store_true",
                   help="Save a beeswarm summary plot across all explained flows.")
    p.add_argument("--seed", type=int, default=0, help="RNG seed for background sampling.")
    p.add_argument(
        "--threshold", type=float, default=0.005,
        help="Anomaly score threshold for BENIGN vs ANOMALOUS verdict. "
             "Flows scoring below this are classified BENIGN. "
             "Default 0.005 is calibrated for Monday-benign; attack flows typically score >0.01.",
    )
    p.add_argument(
        "--all-labels", action="store_true",
        help="Explain ALL rows (not just BENIGN). Use this when passing attack CSVs "
             "so attack rows are not filtered out.",
    )
    p.add_argument(
        "--label", default="",
        help="Filter rows to those whose 'label' column contains this string "
             "(case-insensitive). E.g. --label PortScan, --label DDoS, --label DoS. "
             "Implies --all-labels automatically.",
    )
    p.add_argument(
        "--shuffle", action="store_true",
        help="Randomly shuffle rows before selecting --n-flows. "
             "Use this to sample attack rows from a mixed CSV instead of "
             "always getting the first (usually BENIGN) rows.",
    )
    p.add_argument(
        "--mapper", default="",
        help="Path to network attack mapper JSON file (e.g. attack_mappers/network_attack_mapper.json "
             "or attack_mappers/network_attack_mapper_legacy.json). Defaults to auto-detecting.",
    )
    p.add_argument("--verbose", action="store_true")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    print(f"[SHAP] Loading checkpoint: {args.model}")
    ckpt = load_checkpoint(args.model)
    canonical = ckpt["canonical"]
    print(f"[SHAP] Checkpoint OK — input_dim=87, canonical={len(canonical)} flow features")

    print(f"[SHAP] Reading CSV: {args.csv}")
    # --label implies --all-labels
    if args.label:
        args.all_labels = True

    benign_only = not args.all_labels
    df = _prep_df(args.csv, benign_only=benign_only)

    # --label: filter to rows whose label contains the given string
    if args.label:
        all_avail = df["label"].astype(str).unique().tolist() if "label" in df.columns else []
        mask = df["label"].astype(str).str.upper().str.contains(
            args.label.upper(), regex=False
        )
        df = df[mask].copy()
        if df.empty:
            raise RuntimeError(
                f"No rows with label containing '{args.label}' found.\n"
                f"Available labels in this CSV: {all_avail[:10]}"
            )
        label_info = f"label='{args.label}' ({len(df):,} rows)"
    else:
        label_info = "all labels" if args.all_labels else "BENIGN rows only"

    if df.empty:
        if benign_only:
            raise RuntimeError(
                f"No BENIGN rows found in: {args.csv}\n"
                "If this is an attack CSV, re-run with --all-labels to include all rows."
            )
        raise RuntimeError(f"CSV is empty after loading: {args.csv}")
    print(f"[SHAP] Loaded {len(df):,} rows ({label_info})")

    # Subset to the columns the model knows about (drop unknown cols silently)
    missing_canonical = [c for c in canonical if c not in df.columns]
    if missing_canonical:
        raise ValueError(
            f"CSV is missing {len(missing_canonical)} canonical flow features "
            f"(e.g. {missing_canonical[:3]}). "
            "Use the CICIDS2017 GeneratedLabelledFlows/TrafficLabelling release."
        )

    n = args.n_flows if args.n_flows > 0 else len(df)
    n = min(n, len(df))

    if args.shuffle:
        df = df.sample(frac=1, random_state=args.seed).reset_index(drop=True)
        print(f"[SHAP] Shuffled rows (seed={args.seed}) — sampling {n} random flow(s)")

    sample = df.head(n).copy()
    # Show label distribution of the sample so user knows what they're explaining
    if "label" in sample.columns:
        dist = sample["label"].astype(str).value_counts().to_dict()
        dist_str = ", ".join(f"{v}×{k}" for k, v in dist.items())
        print(f"[SHAP] Sample label distribution: {dist_str}")

    print(f"[SHAP] Explaining {n} flow(s) with "
          f"{'KernelExplainer' if args.kernel else 'DeepExplainer'} "
          f"(background n={args.n_bg}) ...")

    shap_values, scores = explain_batch(
        sample, ckpt,
        n_bg=args.n_bg,
        seed=args.seed,
        use_kernel=args.kernel,
        nsamples=args.nsamples,
        window_seconds=args.window,
    )

    # Build X87 for display (we need scaled input values in the table)
    x87 = _build_x87(sample, canonical, ckpt["flow_scaler"], ckpt["ctx_scaler"], args.window)

    table = top_k_table(
        shap_values, scores, x87,
        k=args.top_k,
        threshold=args.threshold,
        mapper_path=args.mapper,
    )

    # --- console output ---
    _VERDICT_COLOUR = {"BENIGN": "\033[32m", "ANOMALOUS": "\033[31m"}
    _RESET = "\033[0m"
    _SEV_COLOUR = {"none": "", "low": "\033[33m", "medium": "\033[33m",
                   "high": "\033[31m", "critical": "\033[35m"}
    for entry in table:
        c   = entry["classification"]
        vc  = _VERDICT_COLOUR.get(c["verdict"], "")
        sc  = _SEV_COLOUR.get(c["severity"], "")
        print(f"\n{'='*70}")
        print(f"Flow {entry['flow_idx']:4d}  anomaly_score={entry['anomaly_score']:.6f}  "
              f"verdict: {vc}{c['verdict']}{_RESET}")
        print(f"  Attack family : {sc}{c['attack_family']}{_RESET}")
        print(f"  MITRE         : {c['mitre_id']} | {c['mitre_tactic']} — {c['mitre_technique']}")
        print(f"  Severity      : {sc}{c['severity'].upper()}{_RESET}  "
              f"Confidence: {c['confidence']}")
        print(f"  Evidence      : {c['reason']}")
        print(f"  URL           : {c['mitre_url']}")
        print(f"{'='*70}")
        print(f"  {'Rank':<5} {'Feature':<30} {'SHAP':>10}  {'Scaled val':>10}  Direction")
        print(f"  {'-'*4} {'-'*29} {'-'*10}  {'-'*10}  {'-'*14}")
        for f in entry["top_features"]:
            print(
                f"  {f['rank']:<5} {f['feature']:<30} {f['shap_value']:>+10.6f}"
                f"  {f['input_scaled']:>10.4f}  {f['direction']}"
            )

    # --- file outputs ---
    if args.out_json:
        save_json(table, args.out_json)
    if args.out_csv:
        save_csv(shap_values, args.out_csv)
    if args.plot_bar:
        for i in range(len(table)):
            plot_bar(shap_values, flow_idx=i, top_k=args.top_k,
                     out_path=f"shap_bar_flow{i}.png")
    if args.plot_beeswarm:
        plot_beeswarm(shap_values, out_path="shap_beeswarm.png", max_display=args.top_k)


if __name__ == "__main__":
    main()
