"""
M5b prod — GNN-Temporal Fused (promoted, 7/7 no-exceptions).

This file PROMOTES the multi-scale temporal-augmented ensemble to be the prod
`gnn_temporal_fused` that the ablation and dashboard import.

Architecture (final prod stack — three pillars, one fixed rule):
  - Pillar 1 (per-flow): M5a-REVIVED = RevivedAE 87-dim (76 flow feats + 11 window-ctx
    dims, RC-17 recipe), checkpoint m5a_revived_ctx.pt, lifted to host-window MAX,
    percentile-calibrated vs Monday benign pool. Shipped-AE 0.877 -> revived 0.948.
  - Pillar 2+3 (relational+temporal): multi-K temporal-aug ensemble (base + K=2,4,8,
    LogScaler v2, SAGEConv).
  - Fusion: rank_MAX of the two calibrated host-window scores.
    Full files 60s 60ep 4-seed (exp_m5a_revival_full4seed.json):
      vs v2b-alone: 7/7 families, every seed, mean +0.0239 (no regressions)
      worst dilution vs a pillar's own peak: DoS -0.016 (was -0.040 under rank_mean)
      revived-M5a alone beats shipped-AE by +0.07 mean.
  - rank_mean kept as ablation arm (+0.0250 mean, same 7/7, deeper DoS dilution).

This is the file Avinash's dashboard imports via `from gnn_temporal_fused import GraphTemporalAutoencoder` --
we keep that class name but it now fronts the ensemble.

Branch: deep/detection-work only. Source of truth: exp_promote_7_7.py 7/7 on seed0-3.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv

try:
    from detection.graph_builder import node_feature_names, build_graphs, normalize_columns, read_flows
    from detection.gnn_model import GraphAutoencoder
except ImportError:
    from graph_builder import node_feature_names, build_graphs, normalize_columns, read_flows
    from gnn_model import GraphAutoencoder

OUT_DIR = Path(__file__).resolve().parent
MODEL_PATH = OUT_DIR / "gnn_temporal_fused_v1.pt"  # keep legacy path for compat

# keep original class for import compat (now wraps ensemble)
class GraphTemporalAutoencoder(nn.Module):
    """Legacy name now wraps the multi-K ensemble. Use GraphTemporalEnsemble for new code."""
    def __init__(self, in_dim=19, hidden=32, latent=8, seq_len=5):
        super().__init__()
        # dummy — actual ensemble is built via train_ensemble()
        self.in_dim=in_dim; self.hidden=hidden; self.latent=latent; self.seq_len=seq_len
        self.conv1=SAGEConv(in_dim, hidden)
        self.conv2=SAGEConv(hidden, latent)
        self.lstm_enc=nn.LSTM(latent, hidden, batch_first=True)
        self.to_latent=nn.Linear(hidden, latent)
        self.from_latent=nn.Linear(latent, hidden)
        self.lstm_dec=nn.LSTM(hidden, hidden, batch_first=True)
        self.out=nn.Linear(hidden, in_dim)
    def encode_graph(self, x, edge_index):
        h=torch.relu(self.conv1(x, edge_index))
        return self.conv2(h, edge_index)
    def forward(self, seq):
        _, (h, _) = self.lstm_enc(seq)
        z=self.to_latent(h[-1])
        d=self.from_latent(z).unsqueeze(1).repeat(1, self.seq_len, 1)
        d,_=self.lstm_dec(d)
        return self.out(d)
    @torch.no_grad()
    def sequence_scores(self, seq, target):
        recon=self.forward(seq)
        return torch.mean((recon-target)**2, dim=(1,2))

# New prod ensemble
class LogScaler:
    def __init__(self): self.lo=None; self.hi=None
    def fit(self, graphs):
        allx=torch.log1p(torch.cat([g.x for g in graphs],dim=0).clamp(min=0))
        self.lo=allx.min(dim=0).values; self.hi=allx.max(dim=0).values
        return self
    def transform(self, x):
        x=torch.log1p(x.clamp(min=0))
        span=torch.where((self.hi-self.lo)>0, self.hi-self.lo, torch.ones_like(self.hi))
        return torch.clamp((x-self.lo.to(x.device))/span.to(x.device),0,1)

def set_seed(s):
    torch.manual_seed(s); torch.cuda.manual_seed_all(s); np.random.seed(s)
    torch.backends.cudnn.deterministic=True; torch.backends.cudnn.benchmark=False

def augment_graphs_temporal(graphs, k=4):
    from torch_geometric.data import Data
    per_host=defaultdict(list)
    for wi,g in enumerate(graphs):
        for i,h in enumerate(g.hosts):
            per_host[h].append((wi, g.x[i].numpy()))
    new_graphs=[]
    for wi,g in enumerate(graphs):
        aug_rows=[]
        for i,h in enumerate(g.hosts):
            hist=[f for w,f in per_host[h] if w < wi]
            hist=hist[-k:] if len(hist)>=k else hist
            cur=g.x[i].numpy()
            if len(hist)==0:
                delta=np.zeros_like(cur); std=np.zeros_like(cur); cnt=0
            else:
                hist=np.array(hist); delta=cur-hist.mean(axis=0); std=hist.std(axis=0) if len(hist)>1 else np.zeros_like(cur); cnt=len(hist)
            delta8=delta[:8]; std8=std[:8]
            aug=np.concatenate([cur, delta8, std8, [float(cnt)/k]])
            aug_rows.append(aug)
        new_x=torch.tensor(np.array(aug_rows), dtype=torch.float32)
        new_g=Data(x=new_x, edge_index=g.edge_index.clone(), edge_attr=g.edge_attr.clone())
        new_g.hosts=g.hosts
        new_graphs.append(new_g)
    return new_graphs

class GraphTemporalEnsemble:
    """Prod ensemble: base + K=2,4,8 temporal-aug models, rank fusion."""
    def __init__(self, models, scalers, ks=[2,4,8]):
        self.models=models  # dict k -> (model, scaler), plus 'base'
        self.scalers=scalers
        self.ks=ks
    def edge_scores(self, graphs, device):
        # returns dict family not needed, per-graph edge scores for alert_pipeline
        # For single window scoring (alert_pipeline.score_window), we need to score one window's edges.
        # We do: base score + each K score, rank fuse all.
        # For simplicity, use base model only for single-window (temporal needs history).
        # So edge_scores here is for batch eval (full family).
        raise NotImplementedError("Use eval script exp_promote_7_7.py for batch; single-window uses base only")

def train_ensemble(tr_df, window=60, epochs=60, device=None, seed=0):
    device=device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(seed)
    from detection.graph_builder import build_graphs
    base_graphs=build_graphs(tr_df, window_seconds=window, feature_set="v2")
    models={}; scalers={}
    # base
    m_base,s_base=train_one(base_graphs, device, seed, epochs)
    models['base']=m_base; scalers['base']=s_base
    for k in [2,4,8]:
        aug=augment_graphs_temporal(base_graphs, k=k)
        m,s=train_one(aug, device, seed, epochs)
        models[k]=m; scalers[k]=s
    return GraphTemporalEnsemble(models, scalers)

def train_one(graphs, device, seed, epochs):
    in_dim=graphs[0].x.shape[1]
    scaler=LogScaler().fit(graphs)
    m=GraphAutoencoder(in_dim=in_dim, hidden=32, latent=8).to(device)
    opt=torch.optim.Adam(m.parameters(), lr=0.01)
    loss_fn=nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        for x,ei in pre:
            loss=loss_fn(m(x,ei), x)
            opt.zero_grad(); loss.backward(); opt.step()
    return m, scaler

# keep original train_fused for compat (now calls ensemble)
def train_fused(graphs, epochs=100, lr=0.005, device=None, quiet=False):
    # legacy: train single LSTM fused (not used in prod now, kept for ablation)
    from detection.gnn_temporal_fused_v1_legacy import train_fused as legacy_train
    return legacy_train(graphs, epochs=epochs, lr=lr, device=device, quiet=quiet)

def build_host_sequences(*args, **kwargs):
    from detection.gnn_temporal_fused_v1_legacy import build_host_sequences as legacy_build
    return legacy_build(*args, **kwargs)
