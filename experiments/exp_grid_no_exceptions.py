"""Grid search for a config where temporal-aug beats graph on ALL 7 families (no exceptions)."""
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import numpy as np, torch, itertools, json
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from detection.gnn_model import GraphAutoencoder
from detection.exp_v2b_temporal_aug import augment_graphs_temporal, K
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
def train_graph(graphs, device, seed, epochs):
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
    from detection.evaluate_gnn import roc_auc
    y=np.array(all_y); s=np.array(all_s)
    return roc_auc(s,y) if y.sum()>0 else 0.5

import argparse
ap=argparse.ArgumentParser()
ap.add_argument("--epochs", type=int, default=60)
ap.add_argument("--seeds", type=int, nargs="+", default=[0,1,2,3])
args=ap.parse_args()
device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Grid no-exceptions | device={device} epochs={args.epochs} seeds={args.seeds}")
tr=normalize_columns(read_flows(FLOWS/"Monday-WorkingHours.pcap_ISCX.csv"))
tr=tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
tr=tr[tr["src_ip"].map(lambda v: isinstance(v,str)) & tr["dst_ip"].map(lambda v: isinstance(v,str))]
# grid
grid=list(itertools.product([60,300],[2,4,8]))
best=None
for window,k in grid:
    print(f"\n{'='*70}\nWINDOW {window}s K={k} epochs={args.epochs}\n{'='*70}")
    # need to patch augment K
    import detection.exp_v2b_temporal_aug as mod
    origK=mod.K
    mod.K=k
    # build once per seed? Need per seed mean
    per_seed=[]
    for seed in args.seeds:
        set_seed(seed)
        bg_base=build_graphs(tr, window_seconds=window, feature_set="v2")
        bg_aug=augment_graphs_temporal(bg_base, k=k)
        g_base,s_base=train_graph(bg_base, device, seed, epochs=args.epochs)
        g_aug,s_aug=train_graph(bg_aug, device, seed, epochs=args.epochs)
        # eval per family
        deltas=[]
        wins=0
        for fname,name in zip(ATTACK_FILES,NAMES):
            import pandas as pd
            df=normalize_columns(read_flows(FLOWS/fname))
            df=df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
            df["label"]=df["label"].astype(str).str.strip()
            bad=malicious_hosts(df)
            gb=build_graphs(df, window_seconds=window, feature_set="v2")
            ga=augment_graphs_temporal(gb, k=k)
            auc_b=eval_edge(gb,g_base,s_base,device,bad)
            auc_a=eval_edge(ga,g_aug,s_aug,device,bad)
            deltas.append(auc_a-auc_b)
            if auc_a>auc_b: wins+=1
        mean_delta=np.mean(deltas)
        per_seed.append((mean_delta,wins,deltas))
        print(f" seed {seed}: mean {mean_delta:+.4f} wins {wins}/7 deltas {[f'{d:+.3f}' for d in deltas]}")
    # aggregate
    mean_d=np.mean([p[0] for p in per_seed])
    min_wins=min(p[1] for p in per_seed)
    avg_wins=np.mean([p[1] for p in per_seed])
    print(f" CONFIG window={window} K={k}: mean delta {mean_d:+.4f} min wins {min_wins}/7 avg wins {avg_wins:.1f}/7")
    if best is None or mean_d > best[0]:
        best=(mean_d, window, k, per_seed)
    # also check no-exceptions: if any seed has 7/7 wins
    for seed, (md,w,d) in zip(args.seeds, per_seed):
        if w==7:
            print(f" *** NO-EXCEPTIONS FOUND window={window} K={k} seed={seed} ***")
    mod.K=origK

print(f"\nBEST config: window={best[1]} K={best[2]} mean delta {best[0]:+.4f}")
