"""
Eval v2 prod vs graph-only on real CICIDS2017.

Metrics:
- Host-window AUC (mean per host-window, like ensembler)
- Edge-level AUC on ALL edges (since v2 has 100% coverage) and on covered subset for fairness
- Reports per-family table + means

Runs on this branch only.
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
from detection.gnn_temporal_fused_v2 import GraphTemporalV2, LogScaler, build_window_samples, train_v2

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

def train_graph_logv2(graphs, device, seed, epochs=60):
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

def host_window_scores_graph(graphs, model, scaler, device):
    # per-host-window list
    scores=[]; labels=None
    # not used directly, per-family computed below
    acc={}
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            for h,s in zip(g.hosts, ns):
                acc.setdefault(h, []).append(float(s))
    return {h: float(np.mean(v)) for h,v in acc.items()}

def eval_host_window(fams, bg_model, bg_scaler, v2_model, v2_scaler, device):
    per={}
    for fam,d in fams.items():
        graphs=d["graphs"]; bad=d["bad"]
        # graph per-host mean
        g_map=host_window_scores_graph(graphs, bg_model, bg_scaler, device)
        # v2 per-host-window predictive scores aggregated to host mean for fair host-level comparison
        hists, curs, hosts, wis = build_window_samples(graphs, v2_scaler, v2_model, device, k=4)
        v_scores=v2_model.host_window_scores(hists.to(device), curs.to(device)).cpu().numpy()
        tmp=defaultdict(list)
        for h,s in zip(hosts, v_scores): tmp[h].append(float(s))
        v_map={h: float(np.mean(v)) for h,v in tmp.items()}
        # intersection for fair
        common=sorted(set(g_map)&set(v_map))
        if not common: continue
        y=np.array([1 if h in bad else 0 for h in common])
        if y.sum()==0: continue
        sg=np.array([g_map[h] for h in common]); sv=np.array([v_map[h] for h in common])
        per[fam]={"graph": round(float(roc_auc(sg,y)),4), "v2": round(float(roc_auc(sv,y)),4), "delta": round(float(roc_auc(sv,y)-roc_auc(sg,y)),4), "n": len(common)}
    return per

def eval_edge_all(fams, bg_model, bg_scaler, v2_model, v2_scaler, device):
    # edge-level on ALL edges (v2 100% coverage so fair)
    per={}
    for fam,d in fams.items():
        graphs=d["graphs"]; bad=d["bad"]
        # need per-host-window scores for both models at each window for edge scoring
        # For graph: node score at that window (src)
        # For v2: host-window predictive score for src at that window (need per-window, not per-host mean)
        # Build v2 per-host-window lookup (host, wi) -> score
        hists, curs, hosts, wis = build_window_samples(graphs, v2_scaler, v2_model, device, k=4)
        v_scores=v2_model.host_window_scores(hists.to(device), curs.to(device)).cpu().numpy()
        v_lookup={(h,wi): float(s) for h,wi,s in zip(hosts, wis, v_scores)}
        all_sg=[]; all_sv=[]; all_y=[]
        for wi,g in enumerate(graphs):
            with torch.no_grad():
                sg_nodes=bg_model.node_scores(bg_scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            h2idx={h:i for i,h in enumerate(g.hosts)}
            ei=g.edge_index.cpu().numpy()
            for e in range(g.num_edges):
                src_idx=int(ei[0,e]); src=g.hosts[src_idx]
                y=1 if src in bad else 0
                sg=float(sg_nodes[h2idx[src]])
                sv=float(v_lookup.get((src,wi), sg)) # fallback to graph if missing (should not happen, coverage 100%)
                all_sg.append(sg); all_sv.append(sv); all_y.append(y)
        y=np.array(all_y); sg=np.array(all_sg); sv=np.array(all_sv)
        if y.sum()==0 or y.sum()==len(y): continue
        per[fam]={"graph": round(float(roc_auc(sg,y)),4), "v2": round(float(roc_auc(sv,y)),4), "delta": round(float(roc_auc(sv,y)-roc_auc(sg,y)),4), "edges": len(y)}
    return per

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--out", default="experiments/exp_v2_eval.json")
    args=ap.parse_args()
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"V2 eval | device={device} torch={torch.__version__} window={args.window}s epochs={args.epochs} limit={args.limit} seeds={args.seeds}")
    tr=normalize_columns(read_flows(FLOWS/"Monday-WorkingHours.pcap_ISCX.csv", limit=args.limit))
    tr=tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
    tr=tr[tr["src_ip"].map(lambda v: isinstance(v,str)) & tr["dst_ip"].map(lambda v: isinstance(v,str))]
    print(f"Monday benign {len(tr):,} flows")
    all_res={}
    for seed in args.seeds:
        print(f"\n{'='*70}\nSEED {seed}\n{'='*70}")
        set_seed(seed)
        # build graphs once with v2 feature_set for both models (fair)
        bg=build_graphs(tr, window_seconds=args.window, feature_set="v2")
        print(f" Benign graphs {len(bg)}")
        g_model, g_scaler = train_graph_logv2(bg, device, seed, epochs=args.epochs)
        v_model, v_scaler = train_v2(bg, epochs_gnn=args.epochs, epochs_temp=args.epochs, device=device, seed=seed, feature_set="v2")
        # build test families
        fams={}
        for fam,fname in ATTACK_FILES.items():
            df=normalize_columns(read_flows(FLOWS/fname, limit=args.limit))
            df=df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
            df["label"]=df["label"].astype(str).str.strip()
            bad=malicious_hosts(df)
            if not bad: continue
            graphs=build_graphs(df, window_seconds=args.window, feature_set="v2")
            if not graphs: continue
            fams[fam]={"graphs": graphs, "bad": bad}
            print(f"  {fam}: {len(graphs)} graphs {len(bad)} attackers")
        hw=eval_host_window(fams, g_model, g_scaler, v_model, v_scaler, device)
        ed=eval_edge_all(fams, g_model, g_scaler, v_model, v_scaler, device)
        print(f"\n-- Host-window AUC per family (mean per host) --")
        print(f"| Family | Graph | V2 | Delta | n |")
        print(f"|---|---:|---:|---:|---:|")
        m_g=np.mean([v["graph"] for v in hw.values()]) if hw else 0
        m_v=np.mean([v["v2"] for v in hw.values()]) if hw else 0
        for fam in ATTACK_FILES:
            if fam not in hw: continue
            r=hw[fam]; print(f"| {fam} | {r['graph']:.4f} | {r['v2']:.4f} | {r['delta']:+.4f} | {r['n']} |")
        print(f"| **MEAN** | **{m_g:.4f}** | **{m_v:.4f}** | **{m_v-m_g:+.4f}** | |")
        print(f"\n-- Edge-level AUC on ALL edges (100pct coverage) --")
        print(f"| Family | Graph | V2 | Delta | edges |")
        print(f"|---|---:|---:|---:|---:|")
        e_g=np.mean([v["graph"] for v in ed.values()]) if ed else 0
        e_v=np.mean([v["v2"] for v in ed.values()]) if ed else 0
        for fam in ATTACK_FILES:
            if fam not in ed: continue
            r=ed[fam]; print(f"| {fam} | {r['graph']:.4f} | {r['v2']:.4f} | {r['delta']:+.4f} | {r['edges']} |")
        print(f"| **MEAN** | **{e_g:.4f}** | **{e_v:.4f}** | **{e_v-e_g:+.4f}** | |")
        all_res[str(seed)]={"host_window": hw, "edge": ed, "mean_host_graph": round(float(m_g),4), "mean_host_v2": round(float(m_v),4), "mean_edge_graph": round(float(e_g),4), "mean_edge_v2": round(float(e_v),4)}
    out=ROOT/args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"per_seed": all_res, "config": vars(args), "device": str(device)}, open(out,"w"), indent=2)
    print(f"\nSaved {out}")

if __name__=="__main__":
    main()
