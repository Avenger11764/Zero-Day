"""
shap_explainer.py — SHAP explanations for Autoencoder v2-256

Explains *why* a given network flow is anomalous by computing
per-feature SHAP values on the reconstruction error.

Usage as CLI:
    python detection/shap_explainer.py <csv_path> [--top-k 10] [--save-plots]

Usage as library:
    from detection.shap_explainer import explain_anomaly
    result = explain_anomaly(feature_vector_76)
"""

import argparse
import json
import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "m5a_revived_ctx.pt"
)
ATTACK_MAPPER_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..",
    "attack_mappers",
    "network_attack_mapper_legacy.json",
))

FLOW_FEATURE_NAMES = [
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

CTX_DIMS = [
    "ws_flows", "ws_dst", "ws_ports", "ws_fwd", "ws_bwd",
    "ws_pkts_f", "ws_pkts_b", "ws_dur", "wd_flows", "wd_src", "wd_dur"
]

REVIVED_FEATURE_NAMES = FLOW_FEATURE_NAMES + CTX_DIMS
assert len(REVIVED_FEATURE_NAMES) == 87


def _resolve_path(path):
    if path is None:
        return None
    if os.path.isabs(path):
        return path

    candidates = [
        os.path.abspath(path),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", path)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), path)),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]

# ---------------------------------------------------------------------------
# Autoencoder definition (matches autoencoder.py / stub_detector.py)
# ---------------------------------------------------------------------------
class Autoencoder(nn.Module):
    def __init__(self, input_dim=76):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256), nn.ReLU(),
            nn.Linear(256, 128),       nn.ReLU(),
            nn.Linear(128, 32),
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 128),  nn.ReLU(),
            nn.Linear(128, 256), nn.ReLU(),
            nn.Linear(256, input_dim), nn.Sigmoid(),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ---------------------------------------------------------------------------
# Attack mapper — maps top SHAP features -> likely CICIDS2017 attack type
# ---------------------------------------------------------------------------
def load_attack_mapper():
    """Load network_attack_mapper.json from same directory."""
    if not os.path.exists(ATTACK_MAPPER_PATH):
        return None
    with open(ATTACK_MAPPER_PATH) as f:
        return json.load(f)


def guess_attack_type(shap_values, feature_names, top_k=5):
    """Given SHAP values, guess the most likely attack type.

    Scores each attack profile by how many of its trigger_features appear
    in the top-K SHAP features. Returns (attack_type, mitre_technique,
    matched_features).
    """
    mapper = load_attack_mapper()
    if mapper is None:
        return "unknown", "unknown", []

    ranked_idx = np.argsort(np.abs(shap_values))[::-1][:top_k]
    top_feature_set = {feature_names[i] for i in ranked_idx if i < len(feature_names)}

    best_attack = "unknown"
    best_mitre = "unknown"
    best_score = 0
    best_matched = []

    for profile in mapper.get("attack_profiles", []):
        triggers = set(profile.get("trigger_features", []))
        matched = list(top_feature_set & triggers)
        if len(matched) > best_score:
            best_score = len(matched)
            best_attack = profile["attack_type"]
            best_mitre = profile["mitre_technique"]
            best_matched = matched

    return best_attack, best_mitre, best_matched


def load_background(csv_path, n=200):
    resolved_path = _resolve_path(csv_path)
    if not os.path.exists(resolved_path):
        raise FileNotFoundError(f"CSV not found: {resolved_path}")

    df = pd.read_csv(resolved_path)
    df.columns = df.columns.str.strip()
    df = df.drop(columns=[
        "Label", "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    ], errors="ignore")
    df = df.replace([float("inf"), float("-inf")], float("nan"))
    df = df.dropna(axis=1)
    df = df.select_dtypes(include=[float, int])
    if df.shape[1] != 76:
        raise ValueError(f"Expected 76 features, got {df.shape[1]}")
    scaler = MinMaxScaler()
    data = scaler.fit_transform(df)
    if n is not None and n < len(data):
        idx = np.random.RandomState(42).choice(len(data), size=n, replace=False)
        data = data[idx]
    return data


# ---------------------------------------------------------------------------
# SHAPExplainer — singleton wrapper around shap.KernelExplainer
# ---------------------------------------------------------------------------
class SHAPExplainer:
    def __init__(self, model_path=MODEL_PATH, model=None, background=None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if model is not None:
            ae = model.to(self.device)
        else:
            ae = Autoencoder(input_dim=76).to(self.device)
            ae.load_state_dict(torch.load(model_path,
                                          map_location=self.device,
                                          weights_only=True))
        ae.eval()
        self.ae = ae

        if background is None:
            rng = np.random.RandomState(0)
            background = rng.uniform(0.2, 0.6, size=(200, 76)).astype(np.float32)

        self.background = background
        self._kernel_explainer = None

    def _score_fn(self, x_np):
        """Score a batch of numpy arrays -> anomaly scores (numpy)."""
        x = torch.tensor(x_np, dtype=torch.float32, device=self.device)
        with torch.no_grad():
            recon = self.ae(x)
            error = torch.mean((recon - x) ** 2, dim=1)
        return error.cpu().numpy()

    def _get_kernel(self):
        """Lazily create KernelExplainer (expensive background fit)."""
        if self._kernel_explainer is None:
            self._kernel_explainer = shap.KernelExplainer(
                self._score_fn, self.background)
        return self._kernel_explainer

    @torch.no_grad()
    def anomaly_score(self, x_np):
        return self._score_fn(x_np)

    def shap_values(self, x_np, nsamples=200):
        kernel = self._get_kernel()
        sv = kernel.shap_values(x_np, nsamples=nsamples)
        if isinstance(sv, list):
            sv = sv[0]
        return np.array(sv)


# ---------------------------------------------------------------------------
# Public API — explain a single flow
# ---------------------------------------------------------------------------
_explainer = None


def _get_explainer():
    global _explainer
    if _explainer is None:
        _explainer = SHAPExplainer()
    return _explainer


def explain_anomaly(feature_vector, background_csv=None, top_k=10, model=None):
    """Explain why a single flow is anomalous.

    Parameters
    ----------
    feature_vector : list of 76 floats (MinMaxScaler-normalised)
    background_csv : optional path to a CSV of normal flows for SHAP background
    top_k          : number of top contributing features to return
    model          : optional pre-loaded Autoencoder instance

    Returns
    -------
    dict with keys:
        anomaly_score, top_features, explanation, shap_values
    """
    x = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
    assert x.shape[1] == 76, f"Expected 76 features, got {x.shape[1]}"

    bg = load_background(background_csv) if background_csv else None
    if model is not None:
        explainer = SHAPExplainer(model=model, background=bg)
    elif bg is not None:
        explainer = SHAPExplainer(background=bg)
    else:
        explainer = _get_explainer()

    score = explainer.anomaly_score(x)[0]
    sv = explainer.shap_values(x)[0]

    ranked_idx = np.argsort(np.abs(sv))[::-1][:top_k]
    top_features = []
    explanations = []
    for rank, idx in enumerate(ranked_idx, 1):
        fname = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"feat_{idx}"
        top_features.append({
            "feature": fname,
            "shap_value": round(float(sv[idx]), 6),
            "input_value": round(float(x[0, idx]), 6),
        })
        direction = "increases" if sv[idx] > 0 else "decreases"
        explanations.append(
            f"{rank}. {fname} (={x[0, idx]:.4f}) {direction} "
            f"anomaly score by {abs(sv[idx]):.6f}"
        )

    # --- Attack type guess from mapper ---
    attack_type, mitre_technique, matched = guess_attack_type(sv, FEATURE_NAMES, top_k=5)

    return {
        "anomaly_score": round(float(score), 6),
        "attack_type_guess": attack_type,
        "mitre_technique": mitre_technique,
        "matched_trigger_features": matched,
        "top_features": top_features,
        "explanation": explanations,
        "shap_values": sv.tolist(),
    }

def run_shap_check(csv_path=None, top_k=5):
    default_csv = os.path.join(os.path.dirname(__file__), "..", "training_data", "Monday-WorkingHours.pcap_ISCX.csv")
    csv_path = _resolve_path(csv_path or default_csv)
    if not os.path.exists(csv_path):
        print(f"Sample check skipped: CSV not found at {csv_path}")
        return

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    df = df.drop(columns=[
        "Label", "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"
    ], errors="ignore")

    df = df.replace([float("inf"), float("-inf")], float("nan"))
    df = df.dropna(axis=1)
    df = df.select_dtypes(include=[float, int])

    if df.shape[1] != 76:
        raise ValueError(f"Expected 76 features, got {df.shape[1]}")

    scaler = MinMaxScaler()
    data = scaler.fit_transform(df)

    sample_row = data[0].tolist()
    result = explain_anomaly(sample_row, top_k=top_k)

    print("Anomaly score:", result["anomaly_score"])
    print("\nAttack guess:", result["attack_type_guess"])
    print("\nMatched trigger features:", result["matched_trigger_features"])
    print("\nTop SHAP features:")
    for item in result["top_features"][:5]:
        print(" -", item["feature"], "=>", item["shap_value"])



# ---------------------------------------------------------------------------
# Plotting helpers
# ---------------------------------------------------------------------------
def plot_shap_summary(shap_values, X, save_path="detection/shap_summary.png"):
    shap.summary_plot(shap_values, X, feature_names=FEATURE_NAMES,
                      plot_type="bar", show=False)
    plt.title("SHAP Feature Importance (mean |SHAP|)")
    plt.tight_layout()
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"\n  Summary plot saved to {save_path}")


def plot_shap_force(shap_values, X, save_path="detection/shap_force.png"):
    if hasattr(shap_values, "shape") and len(shap_values.shape) > 1:
        shap_values = shap_values[0]
    if hasattr(X, "ndim") and X.ndim > 1:
        X = X[0]

    shap_values = np.asarray(shap_values, dtype=np.float32).reshape(-1)
    X = np.asarray(X, dtype=np.float32).reshape(-1)

    explanation = shap.Explanation(
        values=shap_values,
        base_values=0,
        data=X,
        feature_names=FEATURE_NAMES,
    )

    try:
        shap.plots.waterfall(explanation, show=False)
    except Exception:
        top_k = min(20, len(shap_values))
        ranked_idx = np.argsort(np.abs(shap_values))[-top_k:][::-1]
        labels = [FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"feat_{i}" for i in ranked_idx]
        values = shap_values[ranked_idx]
        plt.figure(figsize=(10, 6))
        plt.barh(labels, values)
        plt.axvline(0, color="black", linewidth=0.8)
        plt.title("Top SHAP contributions")
        plt.tight_layout()

    plt.tight_layout()
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Force plot saved to {save_path}")


def write_shap_report(output_path, scores, data, sv_all, selected_idx, top_k, threshold):
    if not os.path.isabs(output_path):
        candidates = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), output_path)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", output_path)),
            os.path.abspath(output_path),
        ]
        output_path = next((candidate for candidate in candidates if not candidate.endswith(os.sep)), candidates[1])

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    lines = []
    lines.append("SHAP Analysis Report")
    lines.append("=" * 60)
    lines.append(f"Threshold: {threshold}")
    lines.append(f"Flows analyzed: {len(scores)}")
    lines.append(f"Flows included: {len(selected_idx)}")
    lines.append("")

    for i, fidx in enumerate(selected_idx):
        sv = sv_all[i]
        ranked = np.argsort(np.abs(sv))[::-1][:top_k]
        lines.append(f"Flow #{fidx}  (anomaly_score={scores[fidx]:.6f})")
        lines.append(f"  {'Rank':<5} {'Feature':<28} {'SHAP':>10} {'Input':>10}")
        lines.append(f"  {'-'*55}")
        for rank, idx in enumerate(ranked, 1):
            fname = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"feat_{idx}"
            lines.append(f"  {rank:<5} {fname:<28} {sv[idx]:>+10.6f} {data[fidx, idx]:>10.4f}")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SHAP Explainer for Autoencoder v2-256")
    parser.add_argument("csv", nargs="?",
                        help="CSV of flows to analyse (default: training_data/Monday-WorkingHours.pcap_ISCX.csv)")
    parser.add_argument("--threshold", type=float, default=0.01,
                        help="Anomaly-score cutoff for flagging flows (default: 0.01)") # lowered the thrushold value
    parser.add_argument("--n-background", type=int, default=200)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--max-flows", type=int, default=20,
                        help="Maximum number of flows to include in the report")
    parser.add_argument("--output-file", default="results/shap_report.txt",
                        help="Path to save the detailed SHAP report")
    parser.add_argument("--save-plots", action="store_true")
    parser.add_argument("--sample-check", action="store_true",
                        help="Run a short sample SHAP explanation after the main analysis")
    args = parser.parse_args()

    default_csv = os.path.join(
        os.path.dirname(__file__),
        "..",
        "training_data",
        "Monday-WorkingHours.pcap_ISCX.csv",
    )
    csv_path = args.csv or default_csv

    if csv_path:
        resolved_csv = _resolve_path(csv_path)
        print(f"Loading flows from {resolved_csv}")
        bg = load_background(resolved_csv, n=args.n_background)
        data = load_background(resolved_csv, n=None)
        if data.shape[0] > bg.shape[0]:
            rng = np.random.RandomState(42)
            idx = rng.choice(data.shape[0], size=bg.shape[0], replace=False)
            bg = data[idx]
    else:
        print("No CSV provided — generating synthetic test flows")
        rng = np.random.RandomState(42)
        normal = rng.uniform(0.2, 0.5, (50, 76))
        attack = rng.uniform(0.7, 1.0, (5, 76))
        data = np.vstack([normal, attack])
        bg = None

    print(f"Initialising SHAP explainer (background={args.n_background} samples)...")
    explainer = SHAPExplainer(background=bg)

    scores = explainer.anomaly_score(data)
    print(f"\nAnomaly scores: min={scores.min():.6f}  "
          f"mean={scores.mean():.6f}  max={scores.max():.6f}")

    flagged = (scores > args.threshold).sum()
    print(f"Flagged (> {args.threshold}): {flagged}/{len(scores)}")

    flagged_idx = np.where(scores > args.threshold)[0]
    if len(flagged_idx) == 0:
        flagged_idx = np.array([np.argmax(scores)])
        print("No flows exceeded threshold — explaining the worst case instead")

    ranked_idx = flagged_idx[np.argsort(scores[flagged_idx])[::-1]]
    selected_idx = ranked_idx[: min(args.max_flows, len(ranked_idx))]
    flagged_data = data[selected_idx]
    sv_all = explainer.shap_values(flagged_data)

    output_path = write_shap_report(
        args.output_file,
        scores,
        data,
        sv_all,
        selected_idx,
        args.top_k,
        args.threshold,
    )

    print(f"\n{'='*60}")
    print(f"SHAP analysis saved to {output_path}")
    print(f"Showing top {len(selected_idx)} flow(s) with the highest anomaly scores.")

    if args.save_plots:
        plot_shap_summary(sv_all, flagged_data)
        plot_shap_force(sv_all[0:1], flagged_data[0:1])

    print(f"\n{'='*60}")
    print("SHAP analysis complete.")

    if args.sample_check:
        run_shap_check(args.csv, top_k=args.top_k)


if __name__ == "__main__":
    main()
