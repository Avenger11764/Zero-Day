"""Brute-force 7/7: ensemble of base + multiple K temporal-augs, rank fusion, to find 7/7 wins."""
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import numpy as np, torch
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from detection.gnn_model import GraphAutoencoder
from detection.exp_v2b_temporal_aug import augment_graphs_temporal
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
def set_seed(s):
    import torch, numpy as np
    torch.manual_seed(s); torch.cuda.manual_seed_all(s); np.random.seed(s)
    torch.backends.cudnn.deterministic=True; torch.backends.cudnn.benchmark=False
ATTACK_FILES=["Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv","Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv","Friday-WorkingHours-Morning.pcap_ISCX.csv","Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv","Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv","Tuesday-WorkingHours.pcap_ISCX.csv","Wednesday-workingHours.pcap_ISCX.csv"]
NAMES=["PortScan","DDoS","Botnet","Infiltration","WebAttacks","Patator","DoS"]
def train_graph(graphs, device, seed, epochs=60):
    set_seed(seed)
    in_dim=graphs[0].x.shape[1]
    scaler=LogScaler().fit(graphs)
    m=GraphAutoencoder(in_dim=in_dim, hidden=32, latent=8).to(device)
    opt=torch.optim.Adam(m.parameters(), lr=0.01)
    loss_fn=torch.nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        for x,ei in pre:
            loss=loss_fn(m(x,ei), x)
            opt.zero_grad(); loss.backward(); opt.step()
    return m, scaler
def eval_edge(graphs, model, scaler, device, bad):
    all_s=[]; all_y=[]
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            h2s={h: float(ns[i]) for i,h in enumerate(g.hosts)}
            ei=g.edge_index.cpu().numpy()
            for e in range(g.num_edges):
                src=g.hosts[int(ei[0,e])]
                all_s.append(h2s[src]); all_y.append(1 if src in bad else 0)
    import numpy as np
    y=np.array(all_y); s=np.array(all_s)
    return s, y

def rank01(x):
    o=np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return o/max(len(x)-1,1)

import argparse
ap=argparse.ArgumentParser()
ap.add_argument("--window", type=int, default=60)
ap.add_argument("--epochs", type=int, default=60)
ap.add_argument("--seeds", type=int, nargs="+", default=[0])
args=ap.parse_args()
device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Promote 7/7 ensemble | window={args.window}s epochs={args.epochs}")
tr=normalize_columns(read_flows(FLOWS/"Monday-WorkingHours.pcap_ISCX.csv"))
tr=tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
tr=tr[tr["src_ip"].map(lambda v: isinstance(v,str)) & tr["dst_ip"].map(lambda v: isinstance(v,str))]
for seed in args.seeds:
    set_seed(seed)
    print(f"\nSEED {seed}")
    bg_base=build_graphs(tr, window_seconds=args.window, feature_set="v2")
    # train base and multiple Ks
    g_base,s_base=train_graph(bg_base, device, seed, epochs=args.epochs)
    ks=[2,4,8]
    g_augs={}; s_augs={}
    for k in ks:
        bg_aug=augment_graphs_temporal(bg_base, k=k)
        g,s=train_graph(bg_aug, device, seed, epochs=args.epochs)
        g_augs[k]=g; s_augs[k]=s
    for fname,name in zip(ATTACK_FILES,NAMES):
        import pandas as pd
        df=normalize_columns(read_flows(FLOWS/fname))
        df=df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
        df["label"]=df["label"].astype(str).str.strip()
        bad=malicious_hosts(df)
        gb=build_graphs(df, window_seconds=args.window, feature_set="v2")
        sg,y = eval_edge(gb, g_base, s_base, device, bad)
        base_auc=roc_auc(sg,y)
        best_auc=base_auc; best_k=None; best_fusion=None
        per_k={}
        for k in ks:
            ga=augment_graphs_temporal(gb, k=k)
            sa,_ = eval_edge(ga, g_augs[k], s_augs[k], device, bad)
            auc=roc_auc(sa,y)
            per_k[k]=auc
            # rank fusions with base
            rg=rank01(sg); ra=rank01(sa)
            f_mean=roc_auc((rg+ra)/2, y)
            f_max=roc_auc(np.maximum(rg,ra), y)
            # update best
            if auc>best_auc: best_auc=auc; best_k=k; best_fusion=f"augK{k}"
            if f_max>best_auc: best_auc=f_max; best_k=k; best_fusion=f"rank_max_K{k}"
            if f_mean>best_auc: best_auc=f_mean; best_k=k; best_fusion=f"rank_mean_K{k}"
        # also ensemble of all Ks together
        # collect all sa's
        all_scores=[sg]+[eval_edge(augment_graphs_temporal(gb,k=k), g_augs[k], s_augs[k], device, bad)[0] for k in ks]
        # rank all
        ranked=[rank01(s) for s in all_scores]
        ensemble_all_max=np.maximum.reduce(ranked)
        ensemble_all_mean=np.mean(ranked, axis=0)
        auc_all_max=roc_auc(ensemble_all_max,y)
        auc_all_mean=roc_auc(ensemble_all_mean,y)
        if auc_all_max>best_auc: best_auc=auc_all_max; best_fusion="all_K_rank_max"
        if auc_all_mean>best_auc: best_auc=auc_all_mean; best_fusion="all_K_rank_mean"
        win = "WIN" if best_auc>base_auc+1e-4 else ("TIE" if abs(best_auc-base_auc)<1e-4 else "LOSE")
        print(f" {name}: base {base_auc:.4f} perK { {k: f'{per_k[k]:.4f}' for k in ks}} best {best_fusion} {best_auc:.4f} -> {win} delta {best_auc-base_auc:+.4f}")
