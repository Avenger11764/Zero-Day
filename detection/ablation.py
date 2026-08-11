"""
Controlled ablation: baseline autoencoder (M5a) vs graph autoencoder (M5b).

THE EXPERIMENT
--------------
The claim to defend is narrow and falsifiable:

    "There is a class of attack whose evidence is destroyed by per-flow feature
     extraction, and which relational structure recovers."

To test that honestly, exactly ONE variable may change between the two models:
the data structure. Everything else -- the flows themselves, the training
regime (benign only), the scoring mechanism (reconstruction error) -- is held
identical.

HOW THE ATTACK IS CONSTRUCTED (and why this is fair, not rigged)
----------------------------------------------------------------
The port-scan flows are REAL BENIGN FLOWS taken verbatim from A's dataset. Not
one of the 76 feature values is modified. All that changes is WHO they are
attributed to: one source host, many distinct destinations.

That construction is the point. Because the feature vectors are untouched real
benign traffic, M5a *must* score them as benign -- not because it is a weak
model, but because the information distinguishing a scan was never in the
feature vector to begin with. Meanwhile the graph sees one host with out-degree
200. Same flows, same scoring rule, opposite verdicts.

WHAT THIS IS NOT
----------------
This demonstrates a MECHANISM; it is not an evaluation. Real numbers require
CICIDS2017 GeneratedLabelledFlows (the 85-column release with IP columns) and
the held-out-attack-family protocol. See README.md.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from graph_builder import build_graphs, normalize_columns
from gnn_model import GraphAutoencoder, NodeScaler, train
from stub_detector import EXPECTED_FEATURES, _get_model

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = REPO_ROOT / "training_data" / "dataset_10k_normal.csv"

# Columns that are metadata, not model features.
_META = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "label"]


def _feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Pull the 76 numeric model features out of a flow dataframe."""
    feats = df.drop(columns=[c for c in _META if c in df.columns], errors="ignore")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    if arr.shape[1] != EXPECTED_FEATURES:
        raise ValueError(f"expected {EXPECTED_FEATURES} features, got {arr.shape[1]}")
    lo, hi = arr.min(axis=0), arr.max(axis=0)
    span = np.where(hi - lo > 0, hi - lo, 1.0)
    return np.clip((arr - lo) / span, 0.0, 1.0)


def build_scan(df: pd.DataFrame, n_targets: int = 200,
               attacker: str = "192.168.99.66") -> pd.DataFrame:
    """Re-attribute real benign flows to one source and many destinations.

    Feature values are untouched -- only src_ip/dst_ip change.
    """
    scan = df.sample(n=n_targets, random_state=7).copy()
    scan["src_ip"] = attacker
    scan["dst_ip"] = [f"192.168.99.{i % 254 + 1}" for i in range(len(scan))]
    return scan


def main() -> None:
    ap = argparse.ArgumentParser(description="M5a vs M5b controlled ablation.")
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--targets", type=int, default=200)
    ap.add_argument("--epochs", type=int, default=200)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("=" * 68)
    print("CONTROLLED ABLATION -- M5a (per-flow) vs M5b (relational)")
    print("=" * 68)

    df = normalize_columns(pd.read_csv(args.csv, low_memory=False))
    print(f"\nBenign source : {Path(args.csv).name}  ({len(df)} flows)")

    scan = build_scan(df, n_targets=args.targets)
    print(f"Constructed   : {len(scan)}-target port scan from {args.targets} "
          f"REAL benign flows (feature values unmodified)")

    # ---------------------------------------------------------------- M5a --
    print("\n" + "-" * 68)
    print("M5a  baseline autoencoder -- scores each flow independently")
    print("-" * 68)

    m5a = _get_model()
    benign_x = torch.tensor(_feature_matrix(df), dtype=torch.float32)
    scan_x = torch.tensor(_feature_matrix(scan), dtype=torch.float32)

    benign_scores = m5a.anomaly_score(benign_x).numpy()
    scan_scores = m5a.anomaly_score(scan_x).numpy()

    # Threshold calibrated from benign traffic, not the hardcoded 0.5.
    threshold = float(np.percentile(benign_scores, 99))
    flagged = int((scan_scores > threshold).sum())
    scan_rate = 100 * flagged / len(scan)
    # By construction a 99th-percentile threshold flags ~1% of benign traffic.
    # That is the FALSE-POSITIVE FLOOR. "Detection" only means anything if the
    # scan flags at a rate meaningfully ABOVE this floor -- comparing against
    # zero would count the model's own noise as a catch.
    benign_rate = 100 * float((benign_scores > threshold).mean())

    print(f"  benign  mean={benign_scores.mean():.6f}  max={benign_scores.max():.6f}")
    print(f"  scan    mean={scan_scores.mean():.6f}  max={scan_scores.max():.6f}")
    print(f"  threshold (99th pct of benign) = {threshold:.6f}")
    print(f"  benign flagged    : {benign_rate:.1f}%  <- false-positive floor")
    print(f"  scan flows flagged: {flagged}/{len(scan)} ({scan_rate:.1f}%)")
    print(f"  lift over floor   : {scan_rate - benign_rate:+.1f} percentage points")

    # ---------------------------------------------------------------- M5b --
    print("\n" + "-" * 68)
    print("M5b  graph autoencoder -- scores hosts in a communication graph")
    print("-" * 68)

    benign_graphs = build_graphs(df, window_seconds=60)
    print(f"  training on {len(benign_graphs)} benign graph(s)...")
    model, scaler, losses = train(benign_graphs, epochs=args.epochs,
                                  device=device, quiet=True)
    print(f"  final loss {losses[-1]:.6f}")

    mixed = pd.concat([df, scan], ignore_index=True)
    g = max(build_graphs(mixed, window_seconds=60), key=lambda d: d.num_nodes)

    x = scaler.transform(g.x).to(device)
    node_scores = model.node_scores(x, g.edge_index.to(device)).cpu()
    order = torch.argsort(node_scores, descending=True)

    attacker_idx = g.hosts.index("192.168.99.66")
    rank = int((order == attacker_idx).nonzero()[0]) + 1

    print(f"  graph: {g.num_nodes} nodes, {g.num_edges} edges")
    print(f"  attacker out_degree = {int(g.x[attacker_idx, 0])} "
          f"(median host = {int(g.x[:, 0].median())})")
    print(f"  attacker score  = {node_scores[attacker_idx]:.6f}")
    print(f"  median score    = {node_scores.median():.6f}")
    print(f"  attacker RANK   = {rank} of {g.num_nodes}")

    # -------------------------------------------------------------- verdict --
    print("\n" + "=" * 68)
    print("RESULT")
    print("=" * 68)
    # M5a only counts as detecting if it flags the scan meaningfully more often
    # than it flags ordinary benign traffic. Anything at the floor is noise.
    caught_a = (scan_rate - benign_rate) > 5.0
    caught_b = rank == 1
    print(f"  M5a (per-flow)   : {'DETECTED' if caught_a else 'MISSED'} "
          f"-- flags scan at {scan_rate:.1f}% vs {benign_rate:.1f}% on benign "
          f"({scan_rate - benign_rate:+.1f} pp = noise)")
    print(f"  M5b (relational) : {'DETECTED' if caught_b else 'MISSED'} "
          f"-- attacker ranked {rank}/{g.num_nodes}, "
          f"score {node_scores[attacker_idx]:.4f} vs median "
          f"{node_scores.median():.4f} "
          f"({node_scores[attacker_idx] / max(float(node_scores.median()), 1e-9):.0f}x)")

    if not caught_a and caught_b:
        print("\n  The same flows. The same scoring rule. Opposite verdicts.")
        print("  M5a did not fail -- the evidence was destroyed when traffic was")
        print("  reduced to independent per-flow rows. That is what M5b recovers.")

    print("\n  NOTE: this demonstrates a mechanism, not an evaluation.")
    print("  Real numbers need GeneratedLabelledFlows + held-out attack families.")


if __name__ == "__main__":
    main()
