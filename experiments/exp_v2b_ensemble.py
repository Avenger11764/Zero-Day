"""Quick ensemble test: base vs v2b temporal-aug, rank fusions."""
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import numpy as np, torch
from collections import defaultdict
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
import json, argparse

def set_seed(s):
    import torch, numpy as np
    torch.manual_seed(s); torch.cuda.manual_seed_all(s); np.random.seed(s)
    torch.backends.cudnn.deterministic=True; torch.backends.cudnn.benchmark=False

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

def _rank01(x):
    o=np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return o/max(len(x)-1,1)

from detection.gnn_model import GraphAutoencoder
from detection.exp_v2b_temporal_aug import augment_graphs_temporal, K

ATTACK_FILES={
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

def train_graph(graphs, device, seed, epochs=60):
    set_seed(seed)
    in_dim=graphs[0].x.shape[1]
    scaler=LogScaler().fit(graphs)
    m=GraphAutoencoder(in_dim=in_dim, hidden=32, latent=8).to(device)
    import torch
    opt=torch.optim.Adam(m.parameters(), lr=0.01)
    loss_fn=torch.nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        for x,ei in pre:
            loss=loss_fn(m(x,ei), x)
            opt.zero_grad(); loss.backward(); opt.step()
    return m, scaler

def eval_edge_scores(graphs, model, scaler, device, bad):
    all_s=[]; all_y=[]
    import torch
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            h2s={h: float(ns[i]) for i,h in enumerate(g.hosts)}
            ei=g.edge_index.cpu().numpy()
            for e in range(g.num_edges):
                src=g.hosts[int(ei[0,e])]
                all_s.append(h2s[src])
                all_y.append(1 if src in bad else 0)
    return np.array(all_s), np.array(all_y)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0,1,2,3])
    args=ap.parse_args()
    import torch
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Ensemble base vs v2b window={args.window}s epochs={args.epochs}")
    tr=normalize_columns(read_flows(FLOWS/"Monday-WorkingHours.pcap_ISCX.csv"))
    tr=tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
    tr=tr[tr["src_ip"].map(lambda v: isinstance(v,str)) & tr["dst_ip"].map(lambda v: isinstance(v,str))]
    all_res={}
    for seed in args.seeds:
        print(f"\nSEED {seed}")
        set_seed(seed)
        bg_base=build_graphs(tr, window_seconds=args.window, feature_set="v2")
        bg_aug=augment_graphs_temporal(bg_base, k=K)
        g_base, s_base = train_graph(bg_base, device, seed, epochs=args.epochs)
        g_aug, s_aug = train_graph(bg_aug, device, seed, epochs=args.epochs)
        per={}
        for fam,fname in ATTACK_FILES.items():
            import pandas as pd
            df=normalize_columns(read_flows(FLOWS/fname))
            df=df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
            df["label"]=df["label"].astype(str).str.strip()
            bad=malicious_hosts(df)
            if not bad: continue
            gb=build_graphs(df, window_seconds=args.window, feature_set="v2")
            ga=augment_graphs_temporal(gb, k=K)
            sg, y = eval_edge_scores(gb, g_base, s_base, device, bad)
            sa, _ = eval_edge_scores(ga, g_aug, s_aug, device, bad)
            # y same for both (same edges count? bg and aug have same edges per graph, same count)
            # ensure same length (they should be equal, same graphs)
            # fuse
            rg=_rank01(sg); ra=_rank01(sa)
            f_mean=(rg+ra)/2; f_max=np.maximum(rg,ra); f_min=np.minimum(rg,ra)
            # also raw mean/max
            f_raw_mean=(sg+sa)/2; f_raw_max=np.maximum(sg,sa)
            def auc(sc): return roc_auc(sc, y)
            per[fam]={"base": round(float(auc(sg)),4), "aug": round(float(auc(sa)),4),
                      "rank_mean": round(float(auc(f_mean)),4), "rank_max": round(float(auc(f_max)),4),
                      "rank_min": round(float(auc(f_min)),4), "raw_max": round(float(auc(f_raw_max)),4),
                      "base_raw": round(float(auc(sg)),4)}
            print(f"  {fam}: base {per[fam]['base']:.4f} aug {per[fam]['aug']:.4f} rank_mean {per[fam]['rank_mean']:.4f} rank_max {per[fam]['rank_max']:.4f}")
        # summary
        for name in ["base","aug","rank_mean","rank_max"]:
            vals=[per[f][name] for f in per]
            print(f"  MEAN {name}: {np.mean(vals):.4f}")
        all_res[str(seed)]=per
    json.dump(all_res, open("experiments/exp_v2b_ensemble.json","w"), indent=2)
    print("Saved experiments/exp_v2b_ensemble.json")

if __name__=="__main__":
    main()
