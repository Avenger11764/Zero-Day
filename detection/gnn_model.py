"""
Graph autoencoder for the GNN-Temporal detector (M5b, Person B / Week 3).

WHY AN AUTOENCODER AND NOT A CLASSIFIER
---------------------------------------
CICIDS2017 is fully labelled, so a supervised classifier would be easier and
would post a bigger accuracy number. It is the wrong tool here for two reasons:

  1. A classifier can only recognise the attack families in its training labels.
     A zero-day has no label by definition, so a classifier is structurally
     incapable of the thing this project exists to do. An autoencoder learns
     only "normal" and flags deviation, so it can fire on a family that did not
     exist at training time.

  2. The ablation would become meaningless. M5a scores by reconstruction error;
     if M5b scored by class probability we would be comparing a distance to a
     probability -- no shared threshold, no comparable ROC, no way to run the
     same evasion attack against both. A controlled ablation changes exactly ONE
     variable (per-flow vs relational). Everything else must match.

WHAT THIS MODEL DOES
--------------------
  encoder: node features + graph structure -> embedding (via message passing)
  decoder: embedding -> reconstructed node features
  score  : ||reconstructed - original||^2   (same MSE idea as the baseline AE)

Message passing is the entire point. A node's embedding is built from ITS OWN
features AND its neighbours' features. That is how "this host contacted 200
distinct peers" becomes representable -- the baseline AE, seeing one flow at a
time, has no mechanism to encode it.

EDGE-LEVEL SCORING
------------------
The frozen ScoredAlert schema needs src_ip AND dst_ip, so alerts are emitted per
EDGE. An edge's score is the mean reconstruction error of its two endpoints: if
either participant is behaving abnormally, the conversation is suspicious.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv

from graph_builder import (  # noqa: E402
    NODE_FEATURE_NAMES,
    build_graphs,
    normalize_columns,
    _synthetic_flows,
)

OUT_DIR = Path(__file__).resolve().parent
MODEL_PATH = OUT_DIR / "gnn_autoencoder_v1.pt"


class GraphAutoencoder(nn.Module):
    """GraphSAGE encoder + MLP decoder, scored by node reconstruction error.

    SAGEConv is chosen over GCNConv because it handles the wildly uneven degrees
    of real network traffic (a DNS server with 5000 neighbours next to a laptop
    with 3). GCN's symmetric normalisation washes out exactly the degree signal
    we are trying to detect.
    """

    def __init__(self, in_dim: int = len(NODE_FEATURE_NAMES),
                 hidden: int = 32, latent: int = 8):
        super().__init__()
        self.conv1 = SAGEConv(in_dim, hidden)
        self.conv2 = SAGEConv(hidden, latent)
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden),
            nn.ReLU(),
            nn.Linear(hidden, in_dim),
        )

    def encode(self, x, edge_index):
        h = torch.relu(self.conv1(x, edge_index))
        return self.conv2(h, edge_index)

    def forward(self, x, edge_index):
        return self.decoder(self.encode(x, edge_index))

    @torch.no_grad()
    def node_scores(self, x, edge_index) -> torch.Tensor:
        """Per-node reconstruction error -- the anomaly score."""
        recon = self.forward(x, edge_index)
        return torch.mean((recon - x) ** 2, dim=1)

    @torch.no_grad()
    def edge_scores(self, x, edge_index) -> torch.Tensor:
        """Per-edge score = mean error of its two endpoints.

        Emitted per edge because ScoredAlert requires src_ip and dst_ip.
        """
        n = self.node_scores(x, edge_index)
        return (n[edge_index[0]] + n[edge_index[1]]) / 2.0


class NodeScaler:
    """Min-max scaler fitted across all training graphs.

    Node features are raw counts on wildly different scales (out_degree ~200,
    bytes_sent ~5,000,000). Without scaling, MSE is dominated by whichever
    feature happens to have the largest units and the degree signal is lost.
    Mirrors the MinMaxScaler the baseline AE already uses, so the two models
    stay comparable.
    """

    def __init__(self):
        self.lo = None
        self.hi = None

    def fit(self, graphs):
        allx = torch.cat([g.x for g in graphs], dim=0)
        self.lo = allx.min(dim=0).values
        self.hi = allx.max(dim=0).values
        return self

    def transform(self, x):
        span = torch.where((self.hi - self.lo) > 0, self.hi - self.lo,
                           torch.ones_like(self.hi))
        return torch.clamp((x - self.lo) / span, 0.0, 1.0)

    def state_dict(self):
        return {"lo": self.lo, "hi": self.hi}

    def load_state_dict(self, d):
        self.lo, self.hi = d["lo"], d["hi"]
        return self


def train(graphs, epochs: int = 200, lr: float = 0.01, device=None, quiet=False):
    """Train on BENIGN graphs only -- that is what makes it a zero-day detector."""
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scaler = NodeScaler().fit(graphs)

    model = GraphAutoencoder().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    losses = []

    for epoch in range(epochs):
        epoch_loss = 0.0
        for g in graphs:
            x = scaler.transform(g.x).to(device)
            ei = g.edge_index.to(device)
            recon = model(x, ei)
            loss = loss_fn(recon, x)
            opt.zero_grad()
            loss.backward()
            opt.step()
            epoch_loss += loss.item()
        avg = epoch_loss / max(len(graphs), 1)
        losses.append(avg)
        if not quiet and epoch % 40 == 0:
            print(f"  epoch {epoch:3d} | loss {avg:.6f}")

    return model, scaler, losses


def _self_test() -> None:
    """Train on clean traffic, then prove the scanner scores highest.

    Needs no download -- validates the whole M5b path end to end.
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Self-test on synthetic topology (device={device})\n")

    print("Step 1: build BENIGN graphs (no scanner) and train")
    benign = build_graphs(normalize_columns(_synthetic_flows(scan=False, seed=1)),
                          window_seconds=60)
    print(f"  {len(benign)} benign graphs")
    model, scaler, losses = train(benign, epochs=200, device=device)
    print(f"  final loss {losses[-1]:.6f}\n")

    print("Step 2: score UNSEEN traffic that contains a port scan")
    attack = build_graphs(normalize_columns(_synthetic_flows(scan=True, seed=2)),
                          window_seconds=60)
    g = max(attack, key=lambda d: d.num_nodes)

    x = scaler.transform(g.x).to(device)
    scores = model.node_scores(x, g.edge_index.to(device)).cpu()

    order = torch.argsort(scores, descending=True)
    print(f"  graph: {g.num_nodes} nodes, {g.num_edges} edges")
    print("\n  top 5 most anomalous hosts:")
    for rank, i in enumerate(order[:5], 1):
        i = int(i)
        print(f"    {rank}. {g.hosts[i]:<18} score={scores[i]:.6f}  "
              f"out_degree={int(g.x[i, 0])}")

    scanner_idx = g.hosts.index("192.168.1.66") if "192.168.1.66" in g.hosts else None
    if scanner_idx is not None:
        rank = int((order == scanner_idx).nonzero()[0]) + 1
        print(f"\n  scanner 192.168.1.66 ranked {rank} of {g.num_nodes} "
              f"(score={scores[scanner_idx]:.6f}, median={scores.median():.6f})")
        print("  PASS -- caught by relational structure alone."
              if rank == 1 else "  check: scanner did not rank first")

    torch.save({"model": model.state_dict(), "scaler": scaler.state_dict()},
               MODEL_PATH)
    print(f"\n  saved -> {MODEL_PATH.name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the M5b graph autoencoder.")
    ap.add_argument("csv", nargs="?", help="benign flow CSV (omit for self-test)")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    if args.csv is None:
        _self_test()
        return

    import pandas as pd
    df = normalize_columns(pd.read_csv(args.csv, nrows=args.limit, low_memory=False))
    if "label" in df.columns:
        before = len(df)
        df = df[df["label"].astype(str).str.strip().str.upper() == "BENIGN"]
        print(f"Filtered to BENIGN: {len(df)}/{before} flows")

    graphs = build_graphs(df, window_seconds=args.window)
    print(f"Built {len(graphs)} graphs")
    model, scaler, losses = train(graphs, epochs=args.epochs)
    torch.save({"model": model.state_dict(), "scaler": scaler.state_dict()},
               MODEL_PATH)
    print(f"Saved -> {MODEL_PATH}  (final loss {losses[-1]:.6f})")


if __name__ == "__main__":
    main()
