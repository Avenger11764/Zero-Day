"""
Multi-Window Fusion Evaluation (60s + 300s LogScaler)
Properly fuses host-window scores across 60s and 300s windows at host level.
"""
from __future__ import annotations

import sys
from pathlib import Path
import json

import numpy as np
import torch
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.gnn_model import GraphAutoencoder
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from detection.stub_detector import EXPECTED_FEATURES, _get_model

class LogScaler:
    def __init__(self):
        self.lo = None
        self.hi = None

    def fit(self, graphs):
        allx = torch.log1p(torch.cat([g.x for g in graphs], dim=0).clamp(min=0))
        self.lo = allx.min(dim=0).values
        self.hi = allx.max(dim=0).values
        return self

    def transform(self, x):
        x = torch.log1p(x.clamp(min=0))
        span = torch.where((self.hi - self.lo) > 0, self.hi - self.lo,
                           torch.ones_like(self.hi))
        return torch.clamp((x - self.lo.to(x.device)) / span.to(x.device), 0.0, 1.0)

    def state_dict(self):
        return {"lo": self.lo, "hi": self.hi}

    def load_state_dict(self, d):
        self.lo, self.hi = d["lo"], d["hi"]
        return self


class PercentileCalibrator:
    def __init__(self, benign_scores):
        self.baseline = np.sort(np.asarray(benign_scores, dtype=np.float64))
    def __call__(self, scores):
        idx = np.searchsorted(self.baseline, np.asarray(scores), side="right")
        return idx / max(len(self.baseline), 1)


def _rank01(x):
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def fuse_scores(score_arrays, method="rank_max"):
    if not score_arrays:
        raise ValueError("No score arrays provided")
    if len(score_arrays) == 1:
        return score_arrays[0]
    n = len(score_arrays[0])
    for arr in score_arrays:
        if len(arr) != n:
            raise ValueError("All score arrays must have same length")
    if method == "max":
        return np.maximum.reduce(score_arrays)
    elif method == "mean":
        return np.mean(score_arrays, axis=0)
    elif method == "rank_max":
        ranked = [_rank01(arr) for arr in score_arrays]
        return np.maximum.reduce(ranked)
    elif method == "rank_mean":
        ranked = [_rank01(arr) for arr in score_arrays]
        return np.mean(ranked, axis=0)
    else:
        raise ValueError(f"Unknown fusion method: {method}")


_META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp", "label", "flow_id"]

def pin_canonical(tr):
    feats = tr.drop(columns=[c for c in _META if c in tr.columns], errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    if feats.shape[1] == 77 and "dst_port" in feats.columns:
        feats = feats.drop(columns=["dst_port"])
    return list(feats.columns)


def flow_feats(df, canonical):
    feats = df[canonical].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    lo, hi = arr.min(axis=0), arr.max(axis=0)
    span = np.where(hi - lo > 0, hi - lo, 1.0)
    return np.clip((arr - lo) / span, 0.0, 1.0)


def m5a_per_host_window(df, graphs, m5a, canonical):
    x = flow_feats(df, canonical)
    if x is None:
        return {}
    with torch.no_grad():
        scores = m5a.anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
    tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
    return tmp.groupby("src_ip")["score"].max().to_dict()


def load_logscale_checkpoint(path, device):
    blob = torch.load(path, map_location=device, weights_only=False)
    model = GraphAutoencoder().to(device)
    model.load_state_dict(blob["model"])
    model.eval()
    scaler = LogScaler().load_state_dict(blob["scaler"])
    return model, scaler


_META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp", "label", "flow_id"]

ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

def load_benign(limit=None):
    df = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv", limit=limit))
    df = df[df["label"].astype(str).str.strip().str.upper() == "BENIGN"]
    return df

def load_attack(name, limit=None):
    path = FLOWS / name
    df = normalize_columns(read_flows(path, limit=limit))
    df = df[df["src_ip"].map(lambda v: isinstance(v, str))
            & df["dst_ip"].map(lambda v: isinstance(v, str))]
    df["label"] = df["label"].astype(str).str.strip()
    return df


def _rank01(x):
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def fuse_scores(score_arrays, method="rank_max"):
    if not score_arrays:
        raise ValueError("No score arrays provided")
    if len(score_arrays) == 1:
        return score_arrays[0]
    n = len(score_arrays[0])
    for arr in score_arrays:
        if len(arr) != n:
            raise ValueError("All score arrays must have same length")
    if method == "max":
        return np.maximum.reduce(score_arrays)
    elif method == "mean":
        return np.mean(score_arrays, axis=0)
    elif method == "rank_max":
        ranked = [_rank01(arr) for arr in score_arrays]
        return np.maximum.reduce(ranked)
    elif method == "rank_mean":
        ranked = [_rank01(arr) for arr in score_arrays]
        return np.mean(ranked, axis=0)
    else:
        raise ValueError(f"Unknown fusion method: {method}")


def load_logscale_checkpoint(path, device):
    blob = torch.load(path, map_location=device, weights_only=False)
    model = GraphAutoencoder().to(device)
    model.load_state_dict(blob["model"])
    model.eval()
    scaler = LogScaler().load_state_dict(blob["scaler"])
    return model, scaler


def evaluate_model(model, scaler, device, graphs):
    """Returns (scores, hosts) for all graphs"""
    scores = []
    hosts = []
    for g in graphs:
        ns = model.node_scores(scaler.transform(g.x).to(device),
                               g.edge_index.to(device)).cpu().numpy()
        scores.append(ns)
        hosts.extend(g.hosts)
    return np.concatenate(scores), hosts


def build_host_score_dict(graphs, model, scaler, device):
    """Build dict: host -> list of scores (one per window the host appears in)"""
    host_scores = {}
    for g in graphs:
        ns = model.node_scores(scaler.transform(g.x).to(device),
                               g.edge_index.to(device)).cpu().numpy()
        for i, host in enumerate(g.hosts):
            if host not in host_scores:
                host_scores[host] = []
            host_scores[host].append(ns[i])
    return host_scores


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # Load checkpoints
    ckpt_60 = ROOT / "detection" / "gnn_autoencoder_v1_logscale_60s.pt"
    ckpt_300 = ROOT / "detection" / "gnn_autoencoder_v1_logscale.pt"
    model_60, scaler_60 = load_logscale_checkpoint(ckpt_60, device)
    model_300, scaler_300 = load_logscale_checkpoint(ckpt_300, device)

    # Load benign for calibration
    tr = load_benign()
    print(f"Monday benign flows: {len(tr):,}")

    graphs_60 = build_graphs(tr, window_seconds=60, k=0)
    graphs_300 = build_graphs(tr, window_seconds=300, k=0)
    print(f"Benign graphs: 60s={len(graphs_60)}, 300s={len(graphs_300)}")

    # Calibrate each window separately
    print("Calibrating...")
    b_60 = evaluate_model(model_60, scaler_60, device, graphs_60)[0]
    b_300 = evaluate_model(model_300, scaler_300, device, graphs_300)[0]
    cal_60 = PercentileCalibrator(b_60)
    cal_300 = PercentileCalibrator(b_300)
    print(f"  60s baseline: {len(b_60)} host-windows")
    print(f"  300s baseline: {len(b_300)} host-windows")

    # M5a calibration
    m5a = _get_model()
    tr_all = load_benign()
    tr_all = tr_all[tr_all["label"].astype(str).str.strip().str.upper() == "BENIGN"]
    _META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp", "label", "flow_id"]
    canonical = tr.drop(columns=[c for c in _META if c in tr.columns], errors="ignore")
    canonical = canonical.apply(pd.to_numeric, errors="coerce")
    canonical = canonical.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    if canonical.shape[1] == 77 and "dst_port" in canonical.columns:
        canonical = canonical.drop(columns=["dst_port"])
    canonical = list(canonical.columns)

    def flow_feats(df):
        feats = df[canonical].apply(pd.to_numeric, errors="coerce")
        feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        arr = feats.to_numpy(dtype=np.float32)
        lo, hi = arr.min(axis=0), arr.max(axis=0)
        span = np.where(hi - lo > 0, hi - lo, 1.0)
        return np.clip((arr - lo) / span, 0.0, 1.0)

    m5a = _get_model()
    canonical = pin_canonical(tr)

    def flow_feats(df):
        feats = df[canonical].apply(pd.to_numeric, errors="coerce")
        feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        arr = feats.to_numpy(dtype=np.float32)
        lo, hi = arr.min(axis=0), arr.max(axis=0)
        span = np.where(hi - lo > 0, hi - lo, 1.0)
        return np.clip((arr - lo) / span, 0.0, 1.0)

    def m5a_per_host_window(df, graphs, m5a):
        x = flow_feats(df)
        with torch.no_grad():
            scores = m5a.anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
        tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
        return tmp.groupby("src_ip")["score"].max().to_dict()

    b_m5a_map = m5a_per_host_window(tr, graphs_60, m5a)
    cal_a = PercentileCalibrator(np.array(list(b_m5a_map.values())))
    print(f"  M5a baseline: {len(b_m5a_map)} hosts, 60s: {len(b_60)}, 300s: {len(b_300)}")

    results = {}
    methods = ["max", "mean", "rank_max", "rank_mean"]

    for family, filename in ATTACK_FILES.items():
        print(f"\n{family}...")
        df = normalize_columns(read_flows(FLOWS / filename, limit=None))
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        if not bad:
            continue

        g60 = build_graphs(df, window_seconds=60, k=0)
        g300 = build_graphs(df, window_seconds=300, k=0)
        if not g60 or not g300:
            continue

        # M5a per-host
        a_map = m5a_per_host_window(df, g60, m5a)
        if not a_map:
            continue

        # Build host -> list of scores for each window
        h60 = build_host_score_dict(g60, model_60, scaler_60, device)
        h300 = build_host_score_dict(g300, model_300, scaler_300, device)

        # Get all hosts that appear in either window
        all_hosts = set(h60.keys()) | set(h300.keys()) | set(a_map.keys())
        if not all_hosts:
            continue

        # For each host, collect scores from both windows
        host_data = {}
        for host in all_hosts:
            scores_60 = h60.get(host, [])
            scores_300 = h300.get(host, [])
            m5a_score = a_map.get(host, 0.0)
            
            if not scores_60 and not scores_300:
                continue
            
            # Aggregate multiple windows per host (mean of windows)
            s60 = np.mean(scores_60) if scores_60 else None
            s300 = np.mean(scores_300) if scores_300 else None
            pa = m5a_score
            
            host_data[host] = {"60s": s60, "300s": s300, "m5a": pa, "label": 1 if host in malicious_hosts(df) else 0}

        if not host_data:
            continue

        # Separate by window availability
        hosts_60 = [h for h, d in host_data.items() if d["60s"] is not None]
        hosts_300 = [h for h, d in host_data.items() if d["300s"] is not None]
        
        # 60s only
        if hosts_60:
            pa_60 = cal_a(np.array([host_data[h]["m5a"] for h in hosts_60]))
            pb_60 = cal_60(np.array([host_data[h]["60s"] for h in hosts_60]))
            y_60 = np.array([host_data[h]["label"] for h in hosts_60])
        else:
            pa_60 = pb_60 = y_60 = np.array([])

        # 300s only
        if hosts_300:
            pa_300 = cal_a(np.array([host_data[h]["m5a"] for h in hosts_300]))
            pb_300 = cal_300(np.array([host_data[h]["300s"] for h in hosts_300]))
            y_300 = np.array([host_data[h]["label"] for h in hosts_300])
        else:
            pa_300 = pb_300 = y_300 = np.array([])

        # FUSION: For hosts that appear in BOTH windows, fuse their scores
        both_hosts = [h for h in all_hosts if h in h60 and h in h300]
        if both_hosts:
            pa_both = cal_a(np.array([host_data[h]["m5a"] for h in both_hosts]))
            pb_60_b = cal_60(np.array([host_data[h]["60s"] for h in both_hosts]))
            pb_300_b = cal_300(np.array([host_data[h]["300s"] for h in both_hosts]))
            y_both = np.array([host_data[h]["label"] for h in both_hosts])
            
            if y_both.sum() > 0:
                results[family] = {"both_hosts": len(both_hosts)}
                
                # Individual windows
                for name, pa, pb, y in [("60s", pa_both, pb_60_b, y_both), 
                                        ("300s", pa_both, pb_300_b, y_both)]:
                    for method in methods:
                        fused = fuse_scores([pa, pb], method)
                        order = np.argsort(fused)[::-1]
                        auc = round(float(roc_auc(fused, y)), 4)
                        p100 = round(float(y[order[:100]].mean()), 3)
                        results[family].setdefault(method, {})[name] = {"auc": auc, "p100": p100}

                # Multi-window fusion (fuse 60s and 300s scores)
                for method in methods:
                    fused_60 = fuse_scores([pa_both, pb_60_b], method)
                    fused_300 = fuse_scores([pa_both, pb_300_b], method)
                    # Fuse across windows: max of the two fused scores
                    fused_multi = np.maximum(fused_60, fused_300)
                    order = np.argsort(fused_multi)[::-1]
                    auc = round(float(roc_auc(fused_multi, y_both)), 4)
                    p100 = round(float(y_both[order[:100]].mean()), 3)
                    results[family].setdefault(f"multi_{method}", {})["multi"] = {"auc": auc, "p100": p100}

    return results


if __name__ == "__main__":
    results = main()
    print("\n" + "="*60)
    print("MULTI-WINDOW FUSION RESULTS")
    print("="*60)
    
    for method in ["max", "mean", "rank_max", "rank_mean"]:
        print(f"\n--- Method: {method} ---")
        for fam, data in results.items():
            if method in data:
                for window, vals in data[method].items():
                    print(f"  {fam} {window}: AUC={vals['auc']:.4f} P@100={vals['p100']:.3f}")
    
    # Multi-window methods
    for method in ["max", "mean", "rank_max", "rank_mean"]:
        key = f"multi_{method}"
        print(f"\n--- Multi-window {method} ---")
        for fam, data in results.items():
            if key in data:
                vals = data[key]["multi"]
                print(f"  {fam}: AUC={vals['auc']:.4f} P@100={vals['p100']:.3f}")

    # Save
    out = ROOT / "experiments" / "multiwindow_fusion_results.json"
    json.dump(results, open(out, "w"), indent=2)
    print(f"\nSaved: {out}")