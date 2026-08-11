"""
M5b, complete: the graph half fused with the temporal half.

WHY THIS FILE CLOSES WEEK 3
---------------------------
The reference PDF defines M5b as "GNN-Temporal model (graph structure +
sequence)". Until now the project had both halves and they did not talk:

  gnn_temporal.py  -- an LSTM autoencoder over flow sequences (the SEQUENCE half)
  gnn_model.py     -- a GraphSAGE autoencoder over one window (the GRAPH half)

Two disconnected models is not a graph-temporal model. This module fuses them.

THE ARCHITECTURE
----------------
  1. Split traffic into time windows; build one host-communication graph each.
  2. GNN encodes every window  ->  a structure-aware embedding per host.
     ("who is this host, relative to who it talks to, right now")
  3. For each host, collect its embedding across T consecutive windows  ->  a
     sequence. ("how has this host's structural role been changing")
  4. An LSTM autoencoder reconstructs that host's ORIGINAL feature sequence
     from the encoded structural sequence.
  5. Reconstruction error = anomaly score, same currency as M5a and M5b-graph,
     so the ablation stays controlled.

WHAT THIS BUYS OVER THE GRAPH-ONLY MODEL
-----------------------------------------
A single window cannot distinguish "a backup server that always fans out to 200
machines at 02:00" from "a laptop that has never done that and just started".
Both look identical as one graph. Only the SEQUENCE separates them -- the first
is a stable pattern, the second is a change. That is the slow-and-gradual
attacker the red-team harness is designed to simulate, and it is exactly the
case the graph-only model is weakest against.

Reconstructing the FEATURE sequence (not the embedding sequence) is deliberate:
it keeps the error in the same interpretable units as the other two detectors,
and it stops the model from trivially learning an identity map on its own
embeddings.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv

from graph_builder import (
    NODE_FEATURE_NAMES,
    build_graphs,
    normalize_columns,
    read_flows,
    _synthetic_flows,
)
from gnn_model import NodeScaler

OUT_DIR = Path(__file__).resolve().parent
MODEL_PATH = OUT_DIR / "gnn_temporal_fused_v1.pt"

SEQUENCE_LEN = 5   # windows of history per host
LATENT = 8
HIDDEN = 32


class GraphTemporalAutoencoder(nn.Module):
    """GNN over structure, LSTM over time, reconstruction error as the score."""

    def __init__(self, in_dim=len(NODE_FEATURE_NAMES), hidden=HIDDEN,
                 latent=LATENT, seq_len=SEQUENCE_LEN):
        super().__init__()
        self.seq_len = seq_len

        # --- graph half: structure-aware node embeddings -------------------
        self.conv1 = SAGEConv(in_dim, hidden)
        self.conv2 = SAGEConv(hidden, latent)

        # --- temporal half: how that structure evolves ---------------------
        self.lstm_enc = nn.LSTM(latent, hidden, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)
        self.lstm_dec = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, in_dim)

    def encode_graph(self, x, edge_index):
        h = torch.relu(self.conv1(x, edge_index))
        return self.conv2(h, edge_index)

    def forward(self, seq):
        """seq: [batch, T, latent] of per-window structural embeddings.

        Returns reconstructed ORIGINAL features: [batch, T, in_dim].
        """
        _, (h, _) = self.lstm_enc(seq)
        z = self.to_latent(h[-1])
        d = self.from_latent(z).unsqueeze(1).repeat(1, self.seq_len, 1)
        d, _ = self.lstm_dec(d)
        return self.out(d)

    @torch.no_grad()
    def sequence_scores(self, seq, target):
        recon = self.forward(seq)
        return torch.mean((recon - target) ** 2, dim=(1, 2))


def build_host_sequences(graphs, scaler, model, device, seq_len=SEQUENCE_LEN):
    """Turn a list of per-window graphs into per-host embedding sequences.

    Returns (seq, target, hosts):
      seq    [N, T, latent]  structural embeddings over time
      target [N, T, in_dim]  the original features to reconstruct
      hosts  [N]             which host each sequence belongs to
    """
    per_host_emb = defaultdict(list)
    per_host_feat = defaultdict(list)

    for g in graphs:
        x = scaler.transform(g.x).to(device)
        with torch.no_grad():
            emb = model.encode_graph(x, g.edge_index.to(device)).cpu()
        for i, host in enumerate(g.hosts):
            per_host_emb[host].append(emb[i])
            per_host_feat[host].append(scaler.transform(g.x)[i])

    seqs, targets, hosts = [], [], []
    for host, embs in per_host_emb.items():
        if len(embs) < seq_len:
            continue  # not enough history to judge a trend
        feats = per_host_feat[host]
        # sliding windows so a host seen for a long time yields several samples
        for s in range(0, len(embs) - seq_len + 1, seq_len):
            seqs.append(torch.stack(embs[s:s + seq_len]))
            targets.append(torch.stack(feats[s:s + seq_len]))
            hosts.append(host)

    if not seqs:
        return None, None, []
    return torch.stack(seqs), torch.stack(targets), hosts


def train_fused(graphs, epochs=100, lr=0.005, device=None, quiet=False):
    """Joint training: the GNN and the LSTM learn together, end to end."""
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scaler = NodeScaler().fit(graphs)
    model = GraphTemporalAutoencoder().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    losses = []

    for epoch in range(epochs):
        # Rebuild sequences each epoch so the GNN half keeps receiving gradient
        # as its embeddings shift -- otherwise only the LSTM would learn.
        seq, target, _ = build_host_sequences(graphs, scaler, model, device)
        if seq is None:
            raise ValueError(
                f"No host appears in {SEQUENCE_LEN}+ consecutive windows. "
                "Use a smaller --seq-len or a larger --window."
            )
        seq, target = seq.to(device), target.to(device)

        recon = model(seq)
        loss = loss_fn(recon, target)
        opt.zero_grad()
        loss.backward()
        opt.step()
        losses.append(loss.item())
        if not quiet and epoch % 20 == 0:
            print(f"  epoch {epoch:3d} | loss {loss.item():.6f} "
                  f"| {seq.shape[0]} host-sequences")

    return model, scaler, losses


def _self_test() -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Self-test: fused graph-temporal model (device={device})\n")

    benign = build_graphs(normalize_columns(_synthetic_flows(scan=False, seed=1)),
                          window_seconds=60)
    print(f"Step 1: train on {len(benign)} benign graphs")
    model, scaler, losses = train_fused(benign, epochs=100, device=device)
    print(f"  final loss {losses[-1]:.6f}\n")

    print("Step 2: score unseen traffic containing a scan")
    attack = build_graphs(normalize_columns(_synthetic_flows(scan=True, seed=2)),
                          window_seconds=60)
    seq, target, hosts = build_host_sequences(attack, scaler, model, device)
    if seq is None:
        print("  not enough temporal history in synthetic data -- "
              "expected; real data has far longer host histories")
        return

    scores = model.sequence_scores(seq.to(device), target.to(device)).cpu()
    order = torch.argsort(scores, descending=True)
    print(f"  {len(scores)} host-sequences scored")
    for rank, i in enumerate(order[:5], 1):
        print(f"    {rank}. {hosts[int(i)]:<18} score={scores[int(i)]:.6f}")

    torch.save({"model": model.state_dict(), "scaler": scaler.state_dict()},
               MODEL_PATH)
    print(f"\n  saved -> {MODEL_PATH.name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the fused graph-temporal M5b.")
    ap.add_argument("csv", nargs="?")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--epochs", type=int, default=100)
    ap.add_argument("--limit", type=int, default=150000)
    args = ap.parse_args()

    if args.csv is None:
        _self_test()
        return

    df = normalize_columns(read_flows(args.csv, limit=args.limit))
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].str.upper() == "BENIGN"]
    graphs = build_graphs(df, window_seconds=args.window)
    print(f"Built {len(graphs)} graphs from {len(df)} benign flows")

    model, scaler, losses = train_fused(graphs, epochs=args.epochs)
    torch.save({"model": model.state_dict(), "scaler": scaler.state_dict()},
               MODEL_PATH)
    print(f"Saved -> {MODEL_PATH}  (final loss {losses[-1]:.6f})")


if __name__ == "__main__":
    main()
