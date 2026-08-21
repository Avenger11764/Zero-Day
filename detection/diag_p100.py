"""
P@100 diagnostic: is the dead alert queue a detector problem or a tie-breaking artifact?

Checks, per family (seed 0):
  1. What fraction of hosts saturate the percentile calibrator at exactly 1.0?
  2. Where do attackers actually rank under raw-score fusion vs calibrated fusion?
  3. P@100 under: calibrated fusion (current), raw-score fusion, rank_max variants,
     and the old host-WINDOW unit (attacker counted once per window it appears in).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.eval_mw_ablation_4seed import (
    LogScaler, PercentileCalibrator, ATTACK_FILES, set_seed,
    load_benign, pin_canonical, train_model, node_scores, host_mean_scores,
    normalize_columns, read_flows, build_graphs, malicious_hosts, FLOWS, fuse,
)

def host_agg_scores(graphs, model, scaler, device, agg="mean"):
    acc = {}
    for hosts_w, ns in node_scores(graphs, model, scaler, device):
        for h, s in zip(hosts_w, ns):
            acc.setdefault(h, []).append(float(s))
    fn = {"mean": np.mean, "max": np.max,
          "q90": lambda v: np.quantile(v, 0.9)}[agg]
    return {h: float(fn(v)) for h, v in acc.items()}


def p_at_k(scores, y, k=100):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    set_seed(0)

    tr = load_benign()
    bg60 = build_graphs(tr, window_seconds=60, k=0)
    bg300 = build_graphs(tr, window_seconds=300, k=0)
    s60, s300 = LogScaler().fit(bg60), LogScaler().fit(bg300)
    m60, _ = train_model(bg60, s60, device, 200)
    m300, _ = train_model(bg300, s300, device, 200)
    cal60 = PercentileCalibrator(np.concatenate([ns for _, ns in node_scores(bg60, m60, s60, device)]))
    cal300 = PercentileCalibrator(np.concatenate([ns for _, ns in node_scores(bg300, m300, s300, device)]))

    print(f"\n{'family':<18} {'bad':>4} | {'P100_mean':>9} {'P100_max':>8} {'P100_q90':>8} {'P100_win':>8} | "
          f"{'atk_rank_mean':>14} {'atk_rank_max':>13}")
    for family, filename in ATTACK_FILES.items():
        df = normalize_columns(read_flows(FLOWS / filename))
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        g60 = build_graphs(df, window_seconds=60, k=0)
        g300 = build_graphs(df, window_seconds=300, k=0)
        if not bad or not g60 or not g300:
            continue

        raw60 = host_agg_scores(g60, m60, s60, device, "mean")
        raw300 = host_agg_scores(g300, m300, s300, device, "mean")
        max60 = host_agg_scores(g60, m60, s60, device, "max")
        max300 = host_agg_scores(g300, m300, s300, device, "max")
        q90_60 = host_agg_scores(g60, m60, s60, device, "q90")
        q90_300 = host_agg_scores(g300, m300, s300, device, "q90")
        hosts = sorted(set(raw60) & set(raw300))
        y = np.array([1 if h in bad else 0 for h in hosts])
        r60 = np.array([raw60[h] for h in hosts])
        r300 = np.array([raw300[h] for h in hosts])
        m60v = np.array([max60[h] for h in hosts])
        m300v = np.array([max300[h] for h in hosts])
        q60v = np.array([q90_60[h] for h in hosts])
        q300v = np.array([q90_300[h] for h in hosts])

        p_raw = p_at_k(fuse([r60, r300], "rank_mean"), y)
        p_max = p_at_k(fuse([m60v, m300v], "rank_mean"), y)
        p_q90 = p_at_k(fuse([q60v, q300v], "rank_mean"), y)

        hw_scores, hw_y = [], []
        for hosts_w, ns in node_scores(g60, m60, s60, device):
            hw_scores.extend(ns.tolist())
            hw_y.extend([1 if h in bad else 0 for h in hosts_w])
        p_win = p_at_k(np.array(hw_scores), np.array(hw_y))

        order_m = np.argsort(fuse([r60, r300], "rank_mean"))[::-1]
        atk_m = [int(np.where(order_m == i)[0][0]) + 1 for i in np.where(y == 1)[0]]
        order_x = np.argsort(fuse([m60v, m300v], "rank_mean"))[::-1]
        atk_x = [int(np.where(order_x == i)[0][0]) + 1 for i in np.where(y == 1)[0]]

        print(f"{family:<18} {int(y.sum()):>4} | {p_raw:>9.3f} {p_max:>8.3f} {p_q90:>8.3f} {p_win:>8.3f} | "
              f"{str(atk_m):>14} {str(atk_x):>13}")

if __name__ == "__main__":
    main()
