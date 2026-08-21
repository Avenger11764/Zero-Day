"""
Are tiny/degenerate windows crowding the top-100 alert queue?

For each family (seed 0): score every 60s host-window, then report P@100 over
host-windows after filtering out windows smaller than K nodes (K = 0/3/5/10).
Also shows the size distribution of the false-positive windows that occupy the
top-100 queue.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.eval_mw_ablation_4seed import (
    LogScaler, ATTACK_FILES, set_seed, load_benign,
    train_model, node_scores, normalize_columns, read_flows,
    build_graphs, malicious_hosts, FLOWS,
)


def p_at_k(scores, y, k=100):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    set_seed(0)

    tr = load_benign()
    bg60 = build_graphs(tr, window_seconds=60, k=0)
    s60 = LogScaler().fit(bg60)
    m60, _ = train_model(bg60, s60, device, 200)

    ks = [0, 2, 3, 5, 10]
    print(f"\n{'family':<18} {'wins':>6} | {'P@100 K=0':>9} {'K=2':>6} {'K=3':>6} {'K=5':>6} {'K=10':>6} | "
          f"{'FP med nodes':>12} {'atk wins':>8}")
    for family, filename in ATTACK_FILES.items():
        df = normalize_columns(read_flows(FLOWS / filename))
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        g60 = build_graphs(df, window_seconds=60, k=0)
        if not bad or not g60:
            continue

        scored = node_scores(g60, m60, s60, device)
        sc = np.concatenate([ns for _, ns in scored])
        lb = np.array([1 if h in bad else 0 for hosts_w, _ in scored for h in hosts_w])
        sz = np.concatenate([np.full(len(hosts_w), len(hosts_w), dtype=int)
                         for hosts_w, _ in scored])

        atk_wins = int(len(set(h for hosts_w, _ in scored for h in hosts_w if h in bad)))

        row = []
        for k in ks:
            keep = sz >= max(k, 1)
            row.append(p_at_k(sc[keep], lb[keep]))

        order = np.argsort(sc)[::-1][:100]
        fp_sizes = sz[order][lb[order] == 0]
        fp_med = int(np.median(fp_sizes)) if len(fp_sizes) else -1

        print(f"{family:<18} {len(sz):>6} | {row[0]:>9.3f} {row[1]:>6.3f} {row[2]:>6.3f} "
              f"{row[3]:>6.3f} {row[4]:>6.3f} | {fp_med:>12} {atk_wins:>8}")


if __name__ == "__main__":
    main()
