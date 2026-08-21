"""
External-dataset replication #2: CTU-13, multi-seeded.

Scenario data + graphs are seed-independent: loaded/built ONCE per scenario,
then only model training + scoring repeat per seed. Reports per-seed and
mean +/- std summaries for recall@100 and infected-host rank percentile.
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
    LogScaler, PercentileCalibrator, set_seed, train_model, node_scores,
)
from detection.graph_builder import build_graphs

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "arp": 2054, "rtp": 0}

SCENARIOS = {
    "s1_neris": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s1_neris.binetflow",
        infected="147.32.84.165"),
    "s13_virut": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s13_virut.binetflow",
        infected="147.32.84.165"),
    "s3_rbot": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s3_rbot.binetflow",
        infected="147.32.84.165"),
}

OUT = ROOT / "experiments" / "external_ctu13_multiseed.json"


def load_binetflow(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]
    ren = {"srcaddr": "src_ip", "dstaddr": "dst_ip", "sport": "src_port",
           "dport": "dst_port", "starttime": "timestamp", "dur": "flow_duration",
           "srcbytes": "fwd_bytes", "dstbytes": "bwd_bytes"}
    df = df.rename(columns=ren)
    df["protocol"] = df["proto"].astype(str).str.strip().str.lower().map(PROTO_NUM).fillna(0)
    df["label"] = df["label"].astype(str).str.strip()
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    return df.dropna(subset=["ts", "src_ip", "dst_ip"])


def p_at_k(scores, y, k):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())


def evaluate_seed(seed, bad_hosts, bg60, eg, scaler, device, epochs):
    set_seed(seed)
    model, loss = train_model(bg60, scaler, device, epochs)
    cal = PercentileCalibrator(
        np.concatenate([ns for _, ns in node_scores(bg60, model, scaler, device)]))

    scored = node_scores(eg, model, scaler, device)
    sc = np.concatenate([ns for _, ns in scored])
    sz = np.concatenate([np.full(len(h), len(h), dtype=int) for h, _ in scored])

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
    yw = np.array([1 if h in bad_hosts else 0 for hosts_w, _ in scored for h in hosts_w])

    return {
        "final_loss": round(float(loss), 8),
        "hosts_total": len(all_hosts), "hosts_bad": int(y_host.sum()),
        "attacker_ranks": ranks,
        "best_rank_percentile": round(float(min(ranks)) / len(all_hosts), 6),
        "recall_at_100_meanagg": round(float(y_host[order[:100]].mean()), 3),
        "recall_at_100_maxagg": round(float(
            y_host[np.argsort(host_max)[::-1][:100]].mean()), 3),
        "hw_p100": round(p_at_k(sc, yw, 100), 3),
        "hw_p500": round(p_at_k(sc, yw, 500), 3),
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
    ap.add_argument("--scenarios", nargs="+", default=list(SCENARIOS.keys()))
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--epochs", type=int, default=200)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    out = {}
    try:
        out = json.load(open(OUT))
    except Exception:
        pass

    for name in args.scenarios:
        cfg = SCENARIOS[name]
        if not cfg["path"].exists():
            print(f"{name}: file missing, skipping")
            continue
        print(f"\n{'=' * 60}\n{name}\n{'=' * 60}")
        df = load_binetflow(cfg["path"])
        is_bot = df["label"].str.contains("From-Botnet", regex=False)
        attack_start = df.loc[is_bot, "ts"].min()
        train_df = df[~is_bot & (df["ts"] < attack_start)]
        eval_df = df[df["ts"] >= attack_start]
        bad_hosts = set(eval_df.loc[is_bot, "src_ip"].unique()) | \
                    set(eval_df.loc[is_bot, "dst_ip"].unique())
        print(f"Flows {len(df):,} | botnet {int(is_bot.sum()):,} | "
              f"train {len(train_df):,} | eval {len(eval_df):,}")
        print(f"First botnet flow: {attack_start}")

        bg60 = build_graphs(train_df, window_seconds=60, k=0)
        eg = build_graphs(eval_df, window_seconds=60, k=0)
        scaler = LogScaler().fit(bg60)
        print(f"Graphs (built once): train={len(bg60)}, eval={len(eg)}")

        per_seed = {}
        for seed in args.seeds:
            print(f"--- seed {seed} ---")
            per_seed[str(seed)] = evaluate_seed(
                seed, bad_hosts, bg60, eg, scaler, device, args.epochs)
            r = per_seed[str(seed)]
            print(f"  loss={r['final_loss']} best_rank={min(r['attacker_ranks'])} "
                  f"pct={r['best_rank_percentile']} "
                  f"r@100={r['recall_at_100_meanagg']}/{r['recall_at_100_maxagg']} "
                  f"hw={r['hw_p100']}/{r['hw_p500']}")

        summary = summarize(per_seed)
        out[name] = {"attack_start": str(attack_start),
                     "per_seed": per_seed, "summary": summary}
        json.dump(out, open(OUT, "w"), indent=2)
        print(f"SUMMARY {name}: " + json.dumps(summary))

    print(f"\nSaved: {OUT}")


if __name__ == "__main__":
    main()
