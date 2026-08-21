"""
Feature set v2 evaluation: 19 node features vs the original 8.

Same protocol as eval_mw_ablation_4seed (LogScaler, 60s+300s, pure rank_mean
fusion, CUDA-deterministic seeding) but with feature_set="v2" graphs and
GraphAutoencoder(in_dim=19). Compare against experiments/mw_ablation_4seed.json.
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
    LogScaler, PercentileCalibrator, ATTACK_FILES, set_seed,
    load_benign, node_scores, _rank01,
)
from detection.graph_builder import build_graphs
from detection.gnn_model import GraphAutoencoder
from detection.evaluate_gnn import roc_auc


def train_model(graphs, scaler, device, epochs, in_dim, latent=8):
    model = GraphAutoencoder(in_dim=in_dim, latent=latent).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = torch.nn.MSELoss()
    pre = [(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        total = 0.0
        for x, ei in pre:
            loss = loss_fn(model(x, ei), x)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
    return model, total / max(len(pre), 1)


def host_mean_scores(graphs, model, scaler, device):
    acc = {}
    for hosts_w, ns in node_scores(graphs, model, scaler, device):
        for h, s in zip(hosts_w, ns):
            acc.setdefault(h, []).append(float(s))
    return {h: float(np.mean(v)) for h, v in acc.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--latent", type=int, default=8,
                    help="latent width; 19 with in_dim=19 removes the bottleneck (control)")
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    tr = load_benign(limit=args.limit)
    print(f"Monday benign flows: {len(tr):,}")
    bg60 = build_graphs(tr, window_seconds=60, k=0, feature_set="v2")
    bg300 = build_graphs(tr, window_seconds=300, k=0, feature_set="v2")
    print(f"Benign graphs: 60s={len(bg60)}, 300s={len(bg300)}, x={tuple(bg60[0].x.shape)}")
    s60, s300 = LogScaler().fit(bg60), LogScaler().fit(bg300)

    fams = {}
    for family, filename in ATTACK_FILES.items():
        df = normalize_columns_safe(filename)
        bad = malicious(df)
        if not bad:
            continue
        g60 = build_graphs(df, window_seconds=60, k=0, feature_set="v2")
        g300 = build_graphs(df, window_seconds=300, k=0, feature_set="v2")
        if not g60 or not g300:
            continue
        fams[family] = {"g60": g60, "g300": g300, "bad": bad}
        print(f"  {family}: cached ({len(g60)}x60s)")

    results = {str(s): {} for s in args.seeds}
    for seed in args.seeds:
        print(f"\n===== SEED {seed} =====")
        set_seed(seed)
        m60, l60 = train_model(bg60, s60, device, args.epochs, 19, args.latent)
        m300, l300 = train_model(bg300, s300, device, args.epochs, 19, args.latent)
        print(f"losses: 60s={l60:.6f} 300s={l300:.6f}")
        cal60 = PercentileCalibrator(np.concatenate([ns for _, ns in node_scores(bg60, m60, s60, device)]))
        cal300 = PercentileCalibrator(np.concatenate([ns for _, ns in node_scores(bg300, m300, s300, device)]))

        for family, d in fams.items():
            h60 = host_mean_scores(d["g60"], m60, s60, device)
            h300 = host_mean_scores(d["g300"], m300, s300, device)
            hosts = sorted(set(h60) & set(h300))
            y = np.array([1 if h in d["bad"] else 0 for h in hosts])
            if y.sum() == 0 or not hosts:
                continue
            w60 = cal60(np.array([h60[h] for h in hosts]))
            w300 = cal300(np.array([h300[h] for h in hosts]))
            fused = np.mean([_rank01(w60), _rank01(w300)], axis=0)

            order = np.argsort(fused)[::-1]
            ranks = sorted(int(np.where(order == i)[0][0]) + 1 for i in np.where(y == 1)[0])
            row = {
                "w60_auc": round(float(roc_auc(w60, y)), 4),
                "w300_auc": round(float(roc_auc(w300, y)), 4),
                "pure_rank_mean_auc": round(float(roc_auc(fused, y)), 4),
                "p100": round(float(y[order[:100]].mean()), 3),
                "attacker_ranks": ranks,
                "n_hosts": len(hosts), "n_bad": int(y.sum()),
            }
            results[str(seed)][family] = row
            print(f"  {family}: fused={row['pure_rank_mean_auc']:.4f} "
                  f"w60={row['w60_auc']:.4f} w300={row['w300_auc']:.4f} ranks={ranks}")

    print("\n=== V2 SUMMARY (mean over seeds) ===")
    fams_all = sorted({f for r in results.values() for f in r})
    for f in fams_all:
        vals = [results[str(s)][f]["pure_rank_mean_auc"] for s in args.seeds if f in results[str(s)]]
        print(f"  {f:<20} {np.mean(vals):.4f}")
    all_means = [np.mean([results[str(s)][f]["pure_rank_mean_auc"]
                          for f in results[str(s)]]) for s in args.seeds]
    print(f"  {'MEAN':<20} {np.mean(all_means):.4f} +/- {np.std(all_means, ddof=1):.4f}" if len(args.seeds) > 1
          else f"  {'MEAN':<20} {all_means[0]:.4f}")

    out = ROOT / "experiments" / "feature_set_v2_results.json"
    json.dump(results, open(out, "w"), indent=2)
    print(f"Saved: {out}")


def normalize_columns_safe(filename):
    from detection.graph_builder import normalize_columns, read_flows
    from detection.evaluate_gnn import FLOWS
    df = normalize_columns(read_flows(FLOWS / filename))
    df = df[df["src_ip"].map(lambda v: isinstance(v, str))
            & df["dst_ip"].map(lambda v: isinstance(v, str))]
    df["label"] = df["label"].astype(str).str.strip()
    return df


def malicious(df):
    return set(df.loc[df["label"].str.upper() != "BENIGN", "src_ip"].unique())


if __name__ == "__main__":
    main()
