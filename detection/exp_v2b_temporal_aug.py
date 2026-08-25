"""
v2b: temporal-augmented GNN — append per-host temporal stats to node features.

For each host at window wi, compute over last K appearances (K=8):
  delta = cur - mean(hist), std, slope (linear), count_hist
Augmented dims: 8 base temporal stats (+ 4 for v2 shape? keep simple 8*2=16 -> total 35)
Then train GraphAutoencoder on augmented graphs (LogScaler).
Evaluates host-window + edge (all edges) vs graph-only.

Coverage 100% because stats are zero for first appearance (padded).
"""
from __future__ import annotations
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import json, argparse, numpy as np, pandas as pd, torch, torch.nn as nn
from collections import defaultdict

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from detection.graph_builder import build_graphs, normalize_columns, read_flows, node_feature_names
from detection.gnn_model import GraphAutoencoder
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc

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

ATTACK_FILES={
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

K=4

def augment_graphs_temporal(graphs, k=K):
    """Append temporal stats per host. Returns new list of Data with augmented x."""
    # collect per-host history of raw features (before scaling, but we will augment raw then scale)
    per_host=defaultdict(list) # host -> list of (wi, feat)
    # we need to know original feat per host per window before augmentation
    for wi,g in enumerate(graphs):
        for i,h in enumerate(g.hosts):
            per_host[h].append((wi, g.x[i].numpy()))
    # For each window, build augmented x
    from torch_geometric.data import Data
    new_graphs=[]
    for wi,g in enumerate(graphs):
        # for each host in this window, compute stats from prior k appearances (excluding current)
        aug_rows=[]
        for i,h in enumerate(g.hosts):
            hist=[f for w,f in per_host[h] if w < wi]
            # take last k
            hist=hist[-k:] if len(hist)>=k else hist
            cur=g.x[i].numpy()
            if len(hist)==0:
                delta=np.zeros_like(cur)
                std=np.zeros_like(cur)
                cnt=0
            else:
                hist=np.array(hist)
                delta=cur - hist.mean(axis=0)
                std=hist.std(axis=0) if len(hist)>1 else np.zeros_like(cur)
                cnt=len(hist)
            # select subset of features to augment: use 8 base (0-7) deltas/stds, not all 19 to keep dim manageable
            # Use delta and std for first 8 dims only -> 16 extra + cnt
            delta8=delta[:8]
            std8=std[:8]
            # For v2, also add cnt as feature
            aug=np.concatenate([cur, delta8, std8, [float(cnt)/k]])
            aug_rows.append(aug)
        new_x=torch.tensor(np.array(aug_rows), dtype=torch.float32)
        new_g=Data(x=new_x, edge_index=g.edge_index.clone(), edge_attr=g.edge_attr.clone())
        new_g.hosts=g.hosts
        new_graphs.append(new_g)
    return new_graphs

def train_graph(graphs, device, seed, epochs=60):
    set_seed(seed)
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

def eval_host(graphs, model, scaler, device, bad):
    # per-host mean score
    acc=defaultdict(list)
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            for h,s in zip(g.hosts, ns): acc[h].append(float(s))
    maps={h: float(np.mean(v)) for h,v in acc.items()}
    common=sorted(maps)
    y=np.array([1 if h in bad else 0 for h in common])
    scores=np.array([maps[h] for h in common])
    return roc_auc(scores, y) if y.sum()>0 and y.sum()<len(y) else 0.5, maps

def eval_edge_all(graphs, model, scaler, device, bad):
    all_sg=[]; all_y=[]
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            h2s={h: float(ns[i]) for i,h in enumerate(g.hosts)}
            ei=g.edge_index.cpu().numpy()
            for e in range(g.num_edges):
                src=g.hosts[int(ei[0,e])]
                all_sg.append(h2s[src])
                all_y.append(1 if src in bad else 0)
    y=np.array(all_y); sg=np.array(all_sg)
    return roc_auc(sg, y) if y.sum()>0 else 0.5

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=150000)
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--out", default="experiments/exp_v2b_temporal_aug.json")
    args=ap.parse_args()
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"v2b temporal-aug | device={device} window={args.window}s epochs={args.epochs} limit={args.limit}")
    lim = None if args.limit in (None, 0) else args.limit
    tr=normalize_columns(read_flows(FLOWS/"Monday-WorkingHours.pcap_ISCX.csv", limit=lim))
    tr=tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
    tr=tr[tr["src_ip"].map(lambda v: isinstance(v,str)) & tr["dst_ip"].map(lambda v: isinstance(v,str))]
    print(f"Monday benign {len(tr):,}")
    all_res={}
    for seed in args.seeds:
        print(f"\n{'='*70}\nSEED {seed}\n{'='*70}")
        set_seed(seed)
        # build base graphs v2
        bg_base=build_graphs(tr, window_seconds=args.window, feature_set="v2")
        print(f" Base graphs {len(bg_base)} in_dim {bg_base[0].x.shape[1]}")
        bg_aug=augment_graphs_temporal(bg_base, k=K)
        print(f" Aug graphs {len(bg_aug)} in_dim {bg_aug[0].x.shape[1]}")
        # train both
        g_base, s_base = train_graph(bg_base, device, seed, epochs=args.epochs)
        g_aug, s_aug = train_graph(bg_aug, device, seed, epochs=args.epochs)
        # eval per family
        per={}
        for fam,fname in ATTACK_FILES.items():
            df=normalize_columns(read_flows(FLOWS/fname, limit=lim))
            df=df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
            df["label"]=df["label"].astype(str).str.strip()
            bad=malicious_hosts(df)
            if not bad: continue
            graphs_base=build_graphs(df, window_seconds=args.window, feature_set="v2")
            graphs_aug=augment_graphs_temporal(graphs_base, k=K)
            if not graphs_base: continue
            # host
            auc_h_base,_=eval_host(graphs_base, g_base, s_base, device, bad)
            auc_h_aug,_=eval_host(graphs_aug, g_aug, s_aug, device, bad)
            # edge
            auc_e_base=eval_edge_all(graphs_base, g_base, s_base, device, bad)
            auc_e_aug=eval_edge_all(graphs_aug, g_aug, s_aug, device, bad)
            per[fam]={"host_base": round(float(auc_h_base),4), "host_aug": round(float(auc_h_aug),4), "host_delta": round(float(auc_h_aug-auc_h_base),4),
                      "edge_base": round(float(auc_e_base),4), "edge_aug": round(float(auc_e_aug),4), "edge_delta": round(float(auc_e_aug-auc_e_base),4)}
            print(f"  {fam}: host {auc_h_base:.4f}->{auc_h_aug:.4f} ({auc_h_aug-auc_h_base:+.4f}) edge {auc_e_base:.4f}->{auc_e_aug:.4f} ({auc_e_aug-auc_e_base:+.4f})")
        mh_base=np.mean([v["host_base"] for v in per.values()]); mh_aug=np.mean([v["host_aug"] for v in per.values()])
        me_base=np.mean([v["edge_base"] for v in per.values()]); me_aug=np.mean([v["edge_aug"] for v in per.values()])
        print(f"\nHOST MEAN base {mh_base:.4f} aug {mh_aug:.4f} delta {mh_aug-mh_base:+.4f}")
        print(f"EDGE MEAN base {me_base:.4f} aug {me_aug:.4f} delta {me_aug-me_base:+.4f}")
        all_res[str(seed)]=per
    out=ROOT/args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"per_seed": all_res, "config": vars(args)}, open(out,"w"), indent=2)
    print(f"\nSaved {out}")

if __name__=="__main__":
    main()
