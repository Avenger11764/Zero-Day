"""
Held-out-attack-family evaluation for M5b on real CICIDS2017 data.

THE PROTOCOL (reference PDF section 17)
---------------------------------------
Train on Monday, which is 100% benign. Test on an attack day the model has
never seen. This is not an 80/20 random split -- a random split would prove the
model memorised samples. Removing an ENTIRE attack family from training and
asking whether the model still catches it is the only honest proxy for "would
this catch a genuinely new attack", which is the whole premise of the project.

WHAT IS SCORED
--------------
Nodes are hosts. A host is ground-truth malicious if any of its flows carry a
non-BENIGN label. We report where the real attacker ranks among all hosts by
reconstruction error, plus ROC-AUC over hosts.

AN HONEST CAVEAT WORTH SAYING OUT LOUD
--------------------------------------
The CICIDS2017 PortScan is a VERTICAL scan: one attacker, one victim, 1000
ports. So out_degree (distinct peers) is 1 and the horizontal-scan intuition
does not apply. What fires instead is unique_dst_ports, a per-host aggregate.
That is still something M5a structurally cannot compute -- it sees one flow,
therefore one port -- but the win here comes from per-host AGGREGATION rather
than from message passing between hosts. Do not overclaim "the graph topology
caught it"; the accurate claim is "per-flow features destroyed the evidence and
per-host structure recovered it". DDoS (many hosts -> one victim) is the family
that genuinely exercises topology.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

try:
    from detection.graph_builder import (
        NODE_FEATURE_NAMES,
        build_graphs,
        graph_health,
        normalize_columns,
        read_flows,
    )
    from detection.gnn_model import NodeScaler, train
except ImportError:  # script-style execution: python detection/evaluate_gnn.py
    from graph_builder import (
        NODE_FEATURE_NAMES,
        build_graphs,
        graph_health,
        normalize_columns,
        read_flows,
    )
    from gnn_model import NodeScaler, train

REPO_ROOT = Path(__file__).resolve().parent.parent
FLOWS = REPO_ROOT / "data" / "GeneratedLabelledFlows" / "TrafficLabelling"


def load(name: str, limit: int | None) -> pd.DataFrame:
    df = normalize_columns(read_flows(FLOWS / name, limit=limit))
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
    return df


def malicious_hosts(df: pd.DataFrame) -> set[str]:
    """Hosts that sent at least one non-BENIGN flow."""
    if "label" not in df.columns:
        return set()
    return set(df.loc[df["label"].str.upper() != "BENIGN", "src_ip"].unique())


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """AUC via rank statistic; no sklearn import needed for one number."""
    pos, neg = labels == 1, labels == 0
    if pos.sum() == 0 or neg.sum() == 0:
        return float("nan")
    ranks = scores.argsort().argsort() + 1
    return float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2)
                 / (pos.sum() * neg.sum()))


def main() -> None:
    ap = argparse.ArgumentParser(description="Held-out attack-family eval for M5b.")
    ap.add_argument("--train", default="Monday-WorkingHours.pcap_ISCX.csv")
    ap.add_argument("--attack", default="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--limit", type=int, default=150000)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("=" * 70)
    print("M5b HELD-OUT ATTACK-FAMILY EVALUATION  (real CICIDS2017)")
    print("=" * 70)

    # ---- train on benign only ------------------------------------------
    print(f"\nTRAIN  {args.train}")
    tr = load(args.train, args.limit)
    if "label" in tr.columns:
        tr = tr[tr["label"].str.upper() == "BENIGN"]
    print(f"  {len(tr)} benign flows")
    h = graph_health(tr)
    print(f"  hosts={h['hosts']} edges={h['edges']} "
          f"peers/src min={h['peers_per_src_min']} max={h['peers_per_src_max']} "
          f"collapsed={h['collapsed']}")

    tr_graphs = build_graphs(tr, window_seconds=args.window)
    print(f"  {len(tr_graphs)} training graphs")
    model, scaler, losses = train(tr_graphs, epochs=args.epochs,
                                  device=device, quiet=True)
    print(f"  trained, final loss {losses[-1]:.6f}")

    # ---- evaluate on an unseen attack family ---------------------------
    print(f"\nTEST   {args.attack}")
    te = load(args.attack, args.limit)
    bad = malicious_hosts(te)
    print(f"  {len(te)} flows, {len(bad)} malicious host(s): {sorted(bad)[:5]}")

    te_graphs = build_graphs(te, window_seconds=args.window)
    print(f"  {len(te_graphs)} test graphs")

    all_scores, all_labels, all_hosts = [], [], []
    for g in te_graphs:
        x = scaler.transform(g.x).to(device)
        s = model.node_scores(x, g.edge_index.to(device)).cpu().numpy()
        all_scores.append(s)
        all_labels.append(np.array([1 if h in bad else 0 for h in g.hosts]))
        all_hosts.extend(g.hosts)

    scores = np.concatenate(all_scores)
    labels = np.concatenate(all_labels)

    print("\n" + "-" * 70)
    print("RESULTS")
    print("-" * 70)
    print(f"  scored {len(scores)} host-windows, {int(labels.sum())} malicious")
    print(f"  ROC-AUC                : {roc_auc(scores, labels):.4f}")

    order = np.argsort(scores)[::-1]
    top100 = labels[order[:100]]
    print(f"  precision@100          : {top100.mean():.3f}")
    print(f"  mean score (malicious) : {scores[labels == 1].mean():.6f}")
    print(f"  mean score (benign)    : {scores[labels == 0].mean():.6f}")

    if labels.sum():
        best = int(np.where(labels[order] == 1)[0][0]) + 1
        print(f"  best malicious rank    : {best} of {len(scores)}")

    # which node feature actually separated the classes
    print("\n  feature separation (malicious mean / benign mean):")
    X = torch.cat([g.x for g in te_graphs], dim=0).numpy()
    for i, name in enumerate(NODE_FEATURE_NAMES):
        m = X[labels == 1, i].mean() if labels.sum() else 0.0
        b = X[labels == 0, i].mean()
        ratio = m / b if b > 0 else float("inf")
        flag = "  <<<" if ratio > 3 or ratio < 0.33 else ""
        print(f"    {name:18s} mal={m:12.2f}  ben={b:12.2f}  x{ratio:8.2f}{flag}")


if __name__ == "__main__":
    main()
