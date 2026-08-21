"""
External-dataset replication #1: CSE-CIC-IDS2018, Tue 20 Feb 2018 (DDoS LOIC-HTTP),
multi-seeded.

Graphs are seed-independent: built ONCE, then only model training + scoring
repeat per seed. Reports per-seed and mean +/- std summaries.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import json
import argparse

os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.eval_mw_ablation_4seed import (
    LogScaler, PercentileCalibrator, set_seed,
    train_model, node_scores,
)
from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.evaluate_gnn import roc_auc

PATH = ROOT / "data" / "CSE-CIC-IDS2018" / "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
OUT = ROOT / "experiments" / "external_ids2018_multiseed.json"


def p_at_k(scores, y, k):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())


def evaluate_seed(seed, train_df, eval_df, bg60, eg, scaler, device, epochs):
    set_seed(seed)
    model, loss = train_model(bg60, scaler, device, epochs)
    cal = PercentileCalibrator(
        np.concatenate([ns for _, ns in node_scores(bg60, model, scaler, device)]))

    scored = node_scores(eg, model, scaler, device)
    sc = np.concatenate([ns for _, ns in scored])
    sz = np.concatenate([np.full(len(h), len(h), dtype=int) for h, _ in scored])

    bad_hosts = set(eval_df.loc[eval_df["label"].str.upper() != "BENIGN", "src_ip"])
    all_hosts = sorted({h for hosts_w, _ in scored for h in hosts_w})
    y_host = np.array([1 if h in bad_hosts else 0 for h in all_hosts])
    acc = {}
    for hosts_w, ns in scored:
        for h, s in zip(hosts_w, ns):
            acc.setdefault(h, []).append(float(s))
    host_mean = np.array([np.mean(acc[h]) for h in all_hosts])
    host_max = np.array([np.max(acc[h]) for h in all_hosts])

    order = np.argsort(host_mean)[::-1]
    ranks = sorted(int(np.where(order == i)[0][0]) + 1 for i in np.where(y_host == 1)[0])
    n_bad = int(y_host.sum())
    yw = np.array([1 if h in bad_hosts else 0 for hosts_w, _ in scored for h in hosts_w])

    return {
        "final_loss": round(float(loss), 8),
        "hosts_total": len(all_hosts), "hosts_bad": n_bad,
        "attacker_ranks": ranks,
        "best_rank_percentile": round(float(min(ranks)) / len(all_hosts), 6),
        "recall_at_100_meanagg": round(float(y_host[order[:100]].mean()), 3),
        "recall_at_100_maxagg": round(float(
            y_host[np.argsort(host_max)[::-1][:100]].mean()), 3),
        "hw_p100": round(p_at_k(sc, yw, 100), 3),
        "hw_p500": round(p_at_k(sc, yw, 500), 3),
        "n_windows": int(len(sz)),
    }


def summarize(per_seed):
    keys = ["best_rank_percentile", "recall_at_100_meanagg",
            "recall_at_100_maxagg", "hw_p100", "hw_p500"]
    out = {}
    for k in keys:
        v = [per_seed[str(s)][k] for s in sorted(per_seed, key=int)]
        out[k] = {"mean": round(float(np.mean(v)), 4),
                  "std": round(float(np.std(v, ddof=1)), 4) if len(v) > 1 else 0.0}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    df = normalize_columns(read_flows(PATH, limit=args.limit))
    print(f"Flows loaded: {len(df):,}")
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df = df[df["src_ip"].map(lambda v: isinstance(v, str))
            & df["dst_ip"].map(lambda v: isinstance(v, str))]
    df["label"] = df["label"].astype(str).str.strip()
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)

    labels = df["label"].str.upper()
    is_benign = labels == "BENIGN"
    attack_start = df.loc[~is_benign, "ts"].min()
    print(f"Attack labels: {sorted(df.loc[~is_benign, 'label'].unique())}")
    print(f"First attack flow: {attack_start}")

    train_df = df[is_benign & (df["ts"] < attack_start)]
    eval_df = df[df["ts"] >= attack_start].copy()
    print(f"Train: {len(train_df):,} | Eval: {len(eval_df):,}")

    bg60 = build_graphs(train_df, window_seconds=60, k=0)
    eg = build_graphs(eval_df, window_seconds=60, k=0)
    scaler = LogScaler().fit(bg60)
    print(f"Graphs (built once): train={len(bg60)}, eval={len(eg)}")

    per_seed = {}
    for seed in args.seeds:
        print(f"\n===== SEED {seed} =====")
        per_seed[str(seed)] = evaluate_seed(
            seed, train_df, eval_df, bg60, eg, scaler, device, args.epochs)
        r = per_seed[str(seed)]
        print(f"  loss={r['final_loss']} | ranks={r['attacker_ranks']}")
        print(f"  r@100={r['recall_at_100_meanagg']}/{r['recall_at_100_maxagg']} "
              f"| hw P@100={r['hw_p100']} P@500={r['hw_p500']} "
              f"| best-rank pct={r['best_rank_percentile']}")

    summary = summarize(per_seed)
    print("\n=== SUMMARY (mean +/- std) ===")
    for k, v in summary.items():
        print(f"  {k}: {v['mean']} +/- {v['std']}")

    json.dump({"attack_labels": sorted(df.loc[~is_benign, 'label'].unique()),
               "attack_start": str(attack_start),
               "per_seed": per_seed, "summary": summary},
              open(OUT, "w"), indent=2)
    print(f"\nSaved: {OUT}")


if __name__ == "__main__":
    main()
