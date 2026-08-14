"""
LODO training: Leave-One-Day-Out (actually All-Days-In) — train M5b on
benign rows from ALL 5 CIC-IDS-2017 weekdays, evaluate on the 7 attack families.
No leakage: each day's benign rows are used only for training; attack rows are
never seen during training.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure repo root is on sys.path for absolute imports
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
import torch

from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.gnn_model import train as train_gnn
from detection.stub_detector import EXPECTED_FEATURES, _get_model
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc


# ---- config ---------------------------------------------------------------

TRAIN_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

# metadata columns to drop
_META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp",
         "label", "flow_id"]

_CANONICAL: list[str] | None = None


def pin_canonical(df: pd.DataFrame) -> list[str]:
    global _CANONICAL
    feats = df.drop(columns=[c for c in _META if c in df.columns], errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    if feats.shape[1] == EXPECTED_FEATURES + 1 and "dst_port" in feats.columns:
        feats = feats.drop(columns=["dst_port"])
    if feats.shape[1] != EXPECTED_FEATURES:
        raise ValueError(f"expected {EXPECTED_FEATURES} feature columns, got {feats.shape[1]}")
    _CANONICAL = list(feats.columns)
    return _CANONICAL


def flow_features(df: pd.DataFrame) -> np.ndarray | None:
    if _CANONICAL is None:
        raise RuntimeError("pin_canonical() must be called on the training file first")
    missing = [c for c in _CANONICAL if c not in df.columns]
    if missing:
        return None
    feats = df[_CANONICAL].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    lo, hi = arr.min(axis=0), arr.max(axis=0)
    span = np.where(hi - lo > 0, hi - lo, 1.0)
    return np.clip((arr - lo) / span, 0.0, 1.0)


def m5a_per_host_window(df: pd.DataFrame, graphs, m5a) -> dict:
    x = flow_features(df)
    if x is None:
        return {}
    with torch.no_grad():
        scores = m5a.anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
    tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
    return tmp.groupby("src_ip")["score"].max().to_dict()


class PercentileCalibrator:
    def __init__(self, benign_scores: np.ndarray):
        self.baseline = np.sort(np.asarray(benign_scores, dtype=np.float64))

    def __call__(self, scores) -> np.ndarray:
        idx = np.searchsorted(self.baseline, np.asarray(scores), side="right")
        return idx / max(len(self.baseline), 1)


def _rank01(x: np.ndarray) -> np.ndarray:
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def metrics(scores: np.ndarray, labels: np.ndarray) -> dict:
    order = np.argsort(scores)[::-1]
    top = labels[order[:100]]
    best = int(np.where(labels[order] == 1)[0][0]) + 1 if labels.sum() else -1
    return {
        "roc_auc": round(roc_auc(scores, labels), 4),
        "precision_at_100": round(float(top.mean()), 3),
        "recall_at_100": round(float(top.sum() / max(labels.sum(), 1)), 3),
        "best_rank": best,
    }


def load_benign(path: Path, limit: int | None) -> pd.DataFrame:
    """Read a CSV and return only BENIGN rows, dropping bad IPs."""
    df = normalize_columns(read_flows(path, limit=limit))
    before = len(df)
    df = df[df["src_ip"].map(lambda v: isinstance(v, str))
            & df["dst_ip"].map(lambda v: isinstance(v, str))]
    df["label"] = df["label"].astype(str).str.strip()
    df = df[df["label"].str.upper() == "BENIGN"]
    dropped = before - len(df)
    if dropped:
        print(f"  {path.name}: dropped {dropped:,}/{before:,} rows (bad IPs or non-benign)")
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description="LODO training: all 5 weekdays benign.")
    ap.add_argument("--seed", type=int, default=None,
                    help="seed torch/numpy before training")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0,
                    help="row limit per file (0 = full)")
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    limit = args.limit if args.limit and args.limit > 0 else None
    if args.seed is not None:
        torch.manual_seed(args.seed)
        np.random.seed(args.seed)

    print("=" * 74)
    print("LODO TRAINING — M5b on 5 weekdays benign")
    print(f"device={device}  limit={'FULL FILE' if limit is None else limit}  epochs={args.epochs}")
    if args.seed is not None:
        print(f"seed={args.seed}")
    print("=" * 74)

    # ---- collect benign graphs from all 5 days ----------------------------
    print("\nLoading benign rows from all 5 days...")
    all_benign_dfs = []
    for fname in TRAIN_FILES:
        path = FLOWS / fname
        if not path.exists():
            print(f"  MISSING: {fname}")
            continue
        df = load_benign(path, limit)
        if len(df) == 0:
            print(f"  {fname}: no benign rows after filtering")
            continue
        all_benign_dfs.append(df)
        print(f"  {fname}: {len(df):,} benign flows")

    if not all_benign_dfs:
        raise SystemExit("No benign data found.")

    benign = pd.concat(all_benign_dfs, ignore_index=True)
    print(f"\nTotal benign flows: {len(benign):,}")

    # pin canonical from the combined benign
    pin_canonical(benign)
    print(f"Pinned {len(_CANONICAL)} feature columns")

    # build graphs
    print(f"\nBuilding graphs (window={args.window}s)...")
    benign_graphs = build_graphs(benign, window_seconds=args.window)
    print(f"  {len(benign_graphs)} benign graphs")

    # ---- train M5b --------------------------------------------------------
    print(f"\nTraining M5b on {len(benign_graphs)} graphs ({args.epochs} epochs)...")
    m5b, scaler, losses = train_gnn(benign_graphs, epochs=args.epochs,
                                    device=device, quiet=False)
    print(f"  final loss {losses[-1]:.6f}")

    # ---- calibrate M5b on benign ------------------------------------------
    print("\nCalibrating M5b against benign traffic...")
    b_m5b = np.concatenate([
        m5b.node_scores(scaler.transform(g.x).to(device),
                        g.edge_index.to(device)).cpu().numpy()
        for g in benign_graphs])
    cal_b = PercentileCalibrator(b_m5b)
    print(f"  M5b baseline over {len(b_m5b)} host-windows")

    # M5a calibrator (fixed shipped checkpoint)
    m5a = _get_model()
    b_m5a_map = m5a_per_host_window(benign, benign_graphs, m5a)
    if not b_m5a_map:
        raise SystemExit("M5a feature shape mismatch on benign data.")
    cal_a = PercentileCalibrator(np.array(list(b_m5a_map.values())))
    print(f"  M5a baseline over {len(b_m5a_map)} hosts")

    # ---- evaluate each family ---------------------------------------------
    rows = []
    for family, filename in ATTACK_FILES.items():
        path = FLOWS / filename
        if not path.exists():
            print(f"\n{family}: MISSING {filename}")
            continue
        print(f"\n{family}...")
        df = normalize_columns(read_flows(path, limit=limit))
        before = len(df)
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        dropped = before - len(df)
        if dropped:
            print(f"  dropped {dropped:,}/{before:,} rows (bad IPs)")
        df["label"] = df["label"].astype(str).str.strip()

        bad = malicious_hosts(df)
        if not bad:
            print("  no malicious hosts; skipping")
            continue

        graphs = build_graphs(df, window_seconds=args.window)
        a_map = m5a_per_host_window(df, graphs, m5a)
        if not a_map:
            print("  M5a feature shape mismatch; skipping")
            continue

        sa, sb, ys = [], [], []
        for g in graphs:
            gb = m5b.node_scores(scaler.transform(g.x).to(device),
                                 g.edge_index.to(device)).cpu().numpy()
            for i, host in enumerate(g.hosts):
                sa.append(a_map.get(host, 0.0))
                sb.append(gb[i])
                ys.append(1 if host in bad else 0)

        y = np.array(ys)
        if y.sum() == 0:
            print("  no malicious host-windows; skipping")
            continue

        pa, pb = cal_a(np.array(sa)), cal_b(np.array(sb))
        fused_max = np.maximum(pa, pb)
        fused_mean = (pa + pb) / 2.0
        fused_rank_max = np.maximum(_rank01(pa), _rank01(pb))

        r = {
            "family": family,
            "host_windows": int(len(y)), "malicious": int(y.sum()),
            "M5a": metrics(pa, y),
            "M5b": metrics(pb, y),
            "fused_max": metrics(fused_max, y),
            "fused_mean": metrics(fused_mean, y),
            "fused_rank_max": metrics(fused_rank_max, y),
        }
        rows.append(r)
        print(f"  M5a AUC={r['M5a']['roc_auc']:.4f}  "
              f"M5b AUC={r['M5b']['roc_auc']:.4f}  "
              f"fused(max) AUC={r['fused_max']['roc_auc']:.4f}  "
              f"fused(mean) AUC={r['fused_mean']['roc_auc']:.4f}  "
              f"fused(rank-max) AUC={r['fused_rank_max']['roc_auc']:.4f}")

    if not rows:
        raise SystemExit("No families evaluated.")

    # ---- print table ------------------------------------------------------
    L = ["# LODO Ablation — M5a vs M5b vs ensemble", "",
         "Trained on benign rows from ALL 5 weekdays (Monday–Friday).",
         "Every family below was unseen during training. Scores calibrated to",
         "percentiles against the combined benign baseline, then compared at",
         "**host-window** granularity.", "",
         f"Seed: {args.seed} · Limit: {'FULL' if limit is None else limit} · Window: {args.window}s · Epochs: {args.epochs}",
         "",
         "## ROC-AUC", "",
         "| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Fused rank-max | Winner |",
         "| --- | --- | --- | --- | --- | --- | --- |"]

    wins = {"M5a": 0, "M5b": 0, "fused_max": 0, "fused_mean": 0, "fused_rank_max": 0}
    for r in rows:
        cand = {k: r[k]["roc_auc"] for k in ("M5a", "M5b", "fused_max",
                                             "fused_mean", "fused_rank_max")}
        best = max(cand, key=lambda k: cand[k])
        wins[best] += 1
        L.append(f"| {r['family']} | {cand['M5a']:.4f} | {cand['M5b']:.4f} | "
                 f"{cand['fused_max']:.4f} | {cand['fused_mean']:.4f} | "
                 f"{cand['fused_rank_max']:.4f} | **{best}** |")

    means = {k: np.mean([r[k]["roc_auc"] for r in rows])
             for k in ("M5a", "M5b", "fused_max", "fused_mean", "fused_rank_max")}
    L.append(f"| **mean** | **{means['M5a']:.4f}** | **{means['M5b']:.4f}** | "
             f"**{means['fused_max']:.4f}** | **{means['fused_mean']:.4f}** | "
             f"**{means['fused_rank_max']:.4f}** | |")

    L += ["", "## Precision@100", "",
          "| Family | M5a | M5b | Fused max | Fused mean | Fused rank-max |",
          "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        L.append(f"| {r['family']} | {r['M5a']['precision_at_100']:.3f} | "
                 f"{r['M5b']['precision_at_100']:.3f} | "
                 f"{r['fused_max']['precision_at_100']:.3f} | "
                 f"{r['fused_mean']['precision_at_100']:.3f} | "
                 f"{r['fused_rank_max']['precision_at_100']:.3f} |")

    L += ["", f"Family wins by ROC-AUC: {wins}", ""]
    overall = max(means, key=lambda k: means[k])
    L.append(f"**Overall best by mean ROC-AUC: {overall} ({means[overall]:.4f}).**")

    print("\n" + "\n".join(L))

    # ---- write outputs ----------------------------------------------------
    OUT_DIR = Path(__file__).resolve().parent
    OUT_MD = OUT_DIR / f"lodo_ablation_seed{args.seed if args.seed is not None else 'none'}.md"
    OUT_JSON = OUT_DIR / f"lodo_ablation_seed{args.seed if args.seed is not None else 'none'}.json"
    OUT_MD.write_text("\n".join(L), encoding="utf-8")
    OUT_JSON.write_text(json.dumps(rows, indent=2))
    print(f"\nWrote {OUT_MD.name} and {OUT_JSON.name}")


if __name__ == "__main__":
    main()