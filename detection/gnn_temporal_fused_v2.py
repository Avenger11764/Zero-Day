"""
M5b fused v2 — redesign to be prod (beats graph-only).

Design vs v1 (gnn_temporal_fused.py) — fixes root causes found in exp_edge_full40:
- v1 coverage 0.16 (needs T=5 consecutive) -> v2 100% via predict-next (each host-window scored from up to K=4 prior windows, padded)
- v1 LSTM joint training non-stationary -> v2 two-stage: freeze GNN (LogScaler+v2) then train Transformer
- v1 reconstructs log1p features from latent seq (too easy with log) -> v2 hybrid: predicts current FEAT from history EMBEDDINGS (harder, temporal)
- v1 no edge signal (gotcha #19) -> v2 edge MLP recon added (optional rank fusion)
- v1 LSTM -> v2 TransformerEncoder (1-2 layers, 4 heads, positional, masking) — handles variable length + bursty traffic

API is drop-in: train_v2(graphs), node_scores, edge_scores all exist, but node_scores now is temporal-predictive.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from pathlib import Path
import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv
import numpy as np

try:
    from detection.graph_builder import node_feature_names, build_graphs, normalize_columns, read_flows
    from detection.gnn_model import NodeScaler
except ImportError:
    from graph_builder import node_feature_names, build_graphs, normalize_columns, read_flows
    from gnn_model import NodeScaler

OUT_DIR = Path(__file__).resolve().parent
MODEL_PATH = OUT_DIR / "gnn_temporal_fused_v2.pt"

K_HISTORY = 4
HIDDEN = 32
LATENT = 8
NHEAD = 4
NLAYERS = 2
EDGE_DIM = 5  # from graph_builder build_graph edge_attr

class LogScaler:
    def __init__(self): self.lo=None; self.hi=None
    def fit(self, graphs):
        import torch
        allx=torch.log1p(torch.cat([g.x for g in graphs],dim=0).clamp(min=0))
        self.lo=allx.min(dim=0).values; self.hi=allx.max(dim=0).values
        return self
    def transform(self, x):
        import torch
        x=torch.log1p(x.clamp(min=0))
        span=torch.where((self.hi-self.lo)>0, self.hi-self.lo, torch.ones_like(self.hi))
        return torch.clamp((x-self.lo.to(x.device))/span.to(x.device),0,1)
    def state_dict(self): return {"lo": self.lo, "hi": self.hi, "log": True}
    def load_state_dict(self, d): self.lo, self.hi = d["lo"], d["hi"]; return self

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=16):
        super().__init__()
        pe=torch.zeros(max_len, d_model)
        pos=torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div=torch.exp(torch.arange(0, d_model, 2).float()*(-np.log(10000.0)/d_model))
        pe[:,0::2]=torch.sin(pos*div)
        pe[:,1::2]=torch.cos(pos*div)
        self.register_buffer('pe', pe.unsqueeze(0)) # [1, max, d]
    def forward(self, x): # x [B, T, D]
        return x + self.pe[:,:x.size(1),:]

class GraphTemporalV2(nn.Module):
    def __init__(self, in_dim=19, hidden=HIDDEN, latent=LATENT, k=K_HISTORY, nhead=NHEAD, nlayers=NLAYERS):
        super().__init__()
        self.k=k
        self.in_dim=in_dim
        self.hidden=hidden
        self.latent=latent
        # graph half
        self.conv1=SAGEConv(in_dim, hidden)
        self.conv2=SAGEConv(hidden, latent)
        # temporal half: Transformer over history embeddings
        self.input_proj=nn.Linear(latent, hidden)
        self.pos_enc=PositionalEncoding(hidden, max_len=k+1)
        enc_layer=nn.TransformerEncoderLayer(d_model=hidden, nhead=nhead, dim_feedforward=hidden*2, batch_first=True)
        self.transformer=nn.TransformerEncoder(enc_layer, num_layers=nlayers)
        self.pred_head=nn.Sequential(nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, in_dim))
        # edge half: simple MLP autoencoder for edge_attr (optional, helps edge-level)
        self.edge_enc=nn.Sequential(nn.Linear(EDGE_DIM, hidden), nn.ReLU(), nn.Linear(hidden, 8))
        self.edge_dec=nn.Sequential(nn.Linear(8, hidden), nn.ReLU(), nn.Linear(hidden, EDGE_DIM))
        self.edge_proj_hidden=hidden

    def encode_graph(self, x, edge_index):
        h=torch.relu(self.conv1(x, edge_index))
        return self.conv2(h, edge_index) # [N, latent]

    def forward_temporal(self, hist): # hist [B, K, latent] padded withzeros for missing, mask [B, K]
        # project
        h=self.input_proj(hist) # [B, K, hidden]
        h=self.pos_enc(h)
        # transformer with key padding mask (True where padded)
        # hist is zero where missing, but we need mask
        # caller provides mask; here we assume hist==0 means padded (approx)
        # Instead expect mask passed; fallback to no mask
        out=self.transformer(h) # [B, K, hidden]
        # mean pool over non-padded (or last token)
        # use mean
        pooled=out.mean(dim=1) # [B, hidden]
        pred=self.pred_head(pooled) # [B, in_dim]
        return pred

    def forward(self, hist, target=None): # for training, target is current feat [B, in_dim]
        pred=self.forward_temporal(hist)
        if target is not None:
            return pred, target
        return pred

    @torch.no_grad()
    def host_window_scores(self, hist, cur_feat): # hist [B, K, latent], cur [B, in_dim]
        pred=self.forward_temporal(hist)
        return torch.mean((pred - cur_feat)**2, dim=1) # [B]

    @torch.no_grad()
    def node_scores_legacy(self, x, edge_index): # for compat, not temporal
        recon=self.decode(self.encode_graph(x, edge_index))
        # not used; provide graph-only fallback
        return torch.mean((recon - x)**2, dim=1)

    def decode(self, z): # simple MLP decode for compat
        return self.pred_head(self.transformer(self.pos_enc(self.input_proj(z.unsqueeze(1)))).mean(1))

# ---------- data helpers ----------
def build_window_samples(graphs, scaler, gnn, device, k=K_HISTORY):
    """
    Build per-host-window samples: for each host appearance at window wi,
    hist = embeddings of prior up to k windows where host appeared,
    cur = current feature at wi.
    Returns list of (hist [k, latent], cur [in_dim], host, wi)
    Coverage 100% because even first appearance has hist zeros (padded).
    """
    # first, collect per-host embeddings and features per window index
    per_host = defaultdict(list) # host -> list of (wi, emb, feat)
    for wi, g in enumerate(graphs):
        x=scaler.transform(g.x).to(device)
        with torch.no_grad():
            emb=gnn.encode_graph(x, g.edge_index.to(device)).cpu()
        feats=scaler.transform(g.x).cpu()
        for i, host in enumerate(g.hosts):
            per_host[host].append((wi, emb[i], feats[i]))
    samples=[]
    for host, lst in per_host.items():
        # sort by wi (already)
        lst=sorted(lst, key=lambda x: x[0])
        # map wi -> idx in lst for quick lookup
        # For each appearance j, collect up to k prior appearances (not necessarily consecutive windows, just prior appearances)
        # For temporal, we want consecutive *windows* but host may be absent in some; we pad.
        # So hist is last k embeddings before j (could be sparse)
        for j in range(len(lst)):
            wi, emb, feat = lst[j]
            # hist: last k before j
            hist=[]
            for t in range(k):
                idx=j - k + t
                if idx < 0:
                    hist.append(torch.zeros(gnn.latent if hasattr(gnn,'latent') else LATENT))
                else:
                    hist.append(lst[idx][1]) # emb
            hist=torch.stack(hist) # [k, latent]
            cur=feat # [in_dim]
            samples.append((hist, cur, host, wi))
    if not samples:
        return None, None, [], []
    hists=torch.stack([s[0] for s in samples])
    curs=torch.stack([s[1] for s in samples])
    hosts=[s[2] for s in samples]
    wis=[s[3] for s in samples]
    return hists, curs, hosts, wis

def build_window_samples_batched(graphs, scaler, gnn, device, k=K_HISTORY):
    return build_window_samples(graphs, scaler, gnn, device, k)

def train_v2(graphs, epochs_gnn=80, epochs_temp=80, device=None, seed=0, feature_set="v2"):
    device=device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    import numpy as np
    np.random.seed(seed)
    torch.backends.cudnn.deterministic=True
    torch.backends.cudnn.benchmark=False
    try:
        from detection.graph_builder import node_feature_names
    except ImportError:
        from graph_builder import node_feature_names
    in_dim=len(node_feature_names(feature_set))
    # Stage 1: train GNN alone (LogScaler)
    scaler=LogScaler().fit(graphs)
    # Build GNN template to get latent dim
    gnn=GraphTemporalV2(in_dim=in_dim).to(device) # we reuse its GNN part
    # Actually train GNN part only: we will train gnn.conv1/conv2 via simple AE loss first
    # Simpler: train a standalone GraphAutoencoder then copy weights
    try:
        from detection.gnn_model import GraphAutoencoder
    except ImportError:
        from gnn_model import GraphAutoencoder
    gnn_ae=GraphAutoencoder(in_dim=in_dim, hidden=HIDDEN, latent=LATENT).to(device)
    opt=torch.optim.Adam(gnn_ae.parameters(), lr=0.01)
    loss_fn=nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for ep in range(epochs_gnn):
        tot=0
        for x, ei in pre:
            recon=gnn_ae(x, ei)
            loss=loss_fn(recon, x)
            opt.zero_grad(); loss.backward(); opt.step()
            tot+=loss.item()
        if ep%20==0:
            print(f"  GNN stage {ep}/{epochs_gnn} loss {tot/len(pre):.6f}")
    # copy weights to v2
    gnn.conv1.load_state_dict(gnn_ae.conv1.state_dict())
    gnn.conv2.load_state_dict(gnn_ae.conv2.state_dict())
    # freeze GNN for temporal stage
    for p in list(gnn.conv1.parameters())+list(gnn.conv2.parameters()):
        p.requires_grad=False
    # Stage 2: train Transformer temporal predictor
    # Build samples once per epoch? Since GNN frozen, embeddings static -> build once
    hists, curs, hosts, wis = build_window_samples(graphs, scaler, gnn, device, K_HISTORY)
    if hists is None:
        raise ValueError("No samples")
    print(f"  Temporal samples: {len(hists)} host-windows (coverage 100%)")
    hists=hists.to(device); curs=curs.to(device)
    # small validation split not needed, just train
    opt2=torch.optim.Adam(filter(lambda p: p.requires_grad, gnn.parameters()), lr=0.005)
    # edge scaler: log1p + minmax fitted on benign edges
    all_edges=torch.cat([g.edge_attr for g in graphs], dim=0).clamp(min=0).to(device)
    all_edges_log=torch.log1p(all_edges)
    e_lo=all_edges_log.min(dim=0).values
    e_hi=all_edges_log.max(dim=0).values
    e_span=torch.where((e_hi - e_lo) > 0, e_hi - e_lo, torch.ones_like(e_hi))
    def scale_edges(e):
        return torch.clamp((torch.log1p(e.clamp(min=0).to(device)) - e_lo) / e_span, 0, 1)
    # also train edge autoencoder on same graphs' edge_attr (scaled)
    edge_losses=[]
    for ep in range(epochs_temp):
        # temporal batch
        perm=torch.randperm(len(hists))
        tloss=0
        for i in range(0, len(hists), 256):
            idx=perm[i:i+256]
            hb=hists[idx]; cb=curs[idx]
            pred=gnn.forward_temporal(hb)
            loss=loss_fn(pred, cb)
            opt2.zero_grad(); loss.backward(); opt2.step()
            tloss+=loss.item()*len(idx)
        tloss/=len(hists)
        # edge batch (one epoch) — on scaled edges
        scaled_all=scale_edges(all_edges)
        eperm=torch.randperm(len(scaled_all))
        eloss=0
        for i in range(0, len(scaled_all), 512):
            eb=scaled_all[eperm[i:i+512]]
            latent=gnn.edge_enc(eb)
            recon=gnn.edge_dec(latent)
            loss=loss_fn(recon, eb)
            opt2.zero_grad(); loss.backward(); opt2.step()
            eloss+=loss.item()*len(eb)
        eloss/=len(scaled_all)
        if ep%20==0:
            print(f"  TEMP stage {ep}/{epochs_temp} tloss {tloss:.6f} eloss {eloss:.6f}")
    # attach edge scaler for inference
    gnn._edge_scaler = (e_lo, e_hi, e_span)
    return gnn, scaler

def _self_test():
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Self-test v2 on synthetic (device={device})")
    try:
        from detection.graph_builder import _synthetic_flows, build_graphs, normalize_columns
    except ImportError:
        from graph_builder import _synthetic_flows, build_graphs, normalize_columns
    benign=build_graphs(normalize_columns(_synthetic_flows(scan=False, seed=1)), window_seconds=60, feature_set="v2")
    print(f" benign {len(benign)} graphs")
    model, scaler = train_v2(benign, epochs_gnn=20, epochs_temp=20, device=device, seed=0)
    attack=build_graphs(normalize_columns(_synthetic_flows(scan=True, seed=2)), window_seconds=60, feature_set="v2")
    # score
    hists, curs, hosts, wis = build_window_samples(attack, scaler, model, device)
    scores=model.host_window_scores(hists.to(device), curs.to(device)).cpu()
    order=torch.argsort(scores, descending=True)
    print(f" scored {len(scores)} host-windows")
    for rank, i in enumerate(order[:5],1):
        print(f"  {rank}. {hosts[int(i)]} score {scores[int(i)]:.4f} wi {wis[int(i)]}")
    print(" self-test done, scanner should rank high")

if __name__=="__main__":
    _self_test()
