"""
External-dataset replication: CSE-CIC-IDS2018, Tue 20 Feb 2018 (DDoS LOIC-HTTP).

Adapts a foreign dataset to the pipeline our model expects:
  read_flows (latin-1) -> normalize_columns (handles the 'Tot Fwd Pkts' third
  convention) -> build_graphs (60s time windows) -> GraphAutoencoder + LogScaler.

Protocol adapted to a single capture day:
  train : benign flows BEFORE the first attack timestamp (time split, no leakage)
  eval  : every host-window AFTER that timestamp
Reports attacker ranks at unique-host level (with the bad/100 structural cap for
P@100) and P@100/P@500 at host-window level, including the small-window filter
from diag_p100b.
"""
from __future__ import annotations

import sys
from pathlib import Path
import json

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

PATH = ROOT / "data" / "CSE-CIC-IDS2018" / "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
OUT = ROOT / "experiments" / "external_ids2018_results.json"


def p_at_k(scores, y, k):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(0)
    print(f"Device: {device}")

    df = normalize_columns(read_flows(PATH))
    print(f"Flows loaded: {len(df):,}")
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df = df[df["src_ip"].map(lambda v: isinstance(v, str))
            & df["dst_ip"].map(lambda v: isinstance(v, str))]
    df["label"] = df["label"].astype(str).str.strip()
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)

    labels = df["label"].str.upper()
    is_benign = labels == "BENIGN"
    attack_names = sorted(df.loc[~is_benign, "label"].unique())
    attack_start = df.loc[~is_benign, "ts"].min()
    print(f"Attack labels: {attack_names}")
    print(f"First attack flow: {attack_start}")
    print(f"Window: {df['ts'].min()} .. {df['ts'].max()}")

    train_df = df[is_benign & (df["ts"] < attack_start)]
    eval_df = df[df["ts"] >= attack_start].copy()
    print(f"Train (pre-attack benign): {len(train_df):,} flows")
    print(f"Eval  (post-attack-start): {len(eval_df):,} flows")

    graphs = build_graphs(train_df, window_seconds=60, k=0)
    print(f"Train graphs: {len(graphs)}")
    scaler = LogScaler().fit(graphs)
    model, loss = train_model(graphs, scaler, device, 200)
    print(f"Final loss: {loss:.6f}")
    cal = PercentileCalibrator(
        np.concatenate([ns for _, ns in node_scores(graphs, model, scaler, device)]))

    eg = build_graphs(eval_df, window_seconds=60, k=0)
    print(f"Eval graphs: {len(eg)}")
    scored = node_scores(eg, model, scaler, device)
    sc = np.concatenate([ns for _, ns in scored])
    sz = np.concatenate([np.full(len(hosts_w), len(hosts_w), dtype=int)
                         for hosts_w, _ in scored])

    results = {"attack_labels": attack_names,
               "attack_start": str(attack_start),
               "train_flows": int(len(train_df)),
               "eval_flows": int(len(eval_df)),
               "train_graphs": len(graphs),
               "eval_graphs": len(eg)}

    bad_hosts = set(eval_df.loc[~is_benign, "src_ip"])
    all_hosts = sorted({h for hosts_w, _ in scored for h in hosts_w})
    y_host = np.array([1 if h in bad_hosts else 0 for h in all_hosts])
    acc = {}
    for hosts_w, ns in scored:
        for h, s in zip(hosts_w, ns):
            acc.setdefault(h, []).append(float(s))
    host_mean = np.array([np.mean(acc[h]) for h in all_hosts])
    host_max = np.array([np.max(acc[h]) for h in all_hosts])

    order = np.argsort(host_mean)[::-1]
    ranks = {all_hosts[i]: int(np.where(order == i)[0][0]) + 1
             for i in np.where(y_host == 1)[0]}
    n_bad = int(y_host.sum())
    results["hosts"] = {
        "n_total": len(all_hosts), "n_bad": n_bad,
        "p100_ceiling": round(n_bad / 100, 4),
        "attacker_ranks_meanagg": dict(sorted(ranks.items(), key=lambda kv: kv[1])),
        "recall_at_100_meanagg": round(float(y_host[np.argsort(host_mean)[::-1][:100]].mean()), 3),
        "recall_at_100_maxagg": round(float(y_host[np.argsort(host_max)[::-1][:100]].mean()), 3),
    }
    print(f"\nHosts: {len(all_hosts):,} total, {n_bad} malicious "
          f"(P@100 ceiling {n_bad / 100:.2f})")
    print(f"Attacker ranks (mean agg): {results['hosts']['attacker_ranks_meanagg']}")

    yw = np.array([1 if h in bad_hosts else 0 for hosts_w, _ in scored for h in hosts_w])
    results["host_window"] = {
        "n_windows": int(len(sz)),
        "n_attacker_windows": int(yw.sum()),
        "p100_raw": round(p_at_k(sc, yw, 100), 3),
        "p500_raw": round(p_at_k(sc, yw, 500), 3),
    }
    for k in (2, 3, 5, 10):
        keep = sz >= k
        results["host_window"][f"p100_min{k}nodes"] = round(p_at_k(sc[keep], yw[keep], 100), 3)
    print(f"Host-windows: {len(sz):,}, attacker windows {int(yw.sum()):,}")
    print(f"P@100 raw={results['host_window']['p100_raw']}  "
          f"P@500={results['host_window']['p500_raw']}")
    for k in (2, 3, 5, 10):
        print(f"  P@100 min-{k}-node windows: {results['host_window'][f'p100_min{k}nodes']}")

    json.dump(results, open(OUT, "w"), indent=2)
    print(f"\nSaved: {OUT}")


if __name__ == "__main__":
    main()
