"""
Exp 2: Make fused beat GNN alone — staged fixes, one variable at a time.

Stages (ordered by predicted effect):
 1. LogScaler (vs plain NodeScaler) — the #1 lever (gotcha #14)
 2. Feature set v2 (19 dims) — keeps indices 0-7 stable (gotcha #23)
 3. Seq len T=3 vs T=5 (coverage)
 4. Two-stage training (freeze GNN, then train LSTM)
 5. Window 300s vs 60s
Each stage reports per-family Delta and coverage; only winner advances.
"""
from __future__ import annotations
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import json
import argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import build_graphs, normalize_columns, read_flows, node_feature_names
from detection.gnn_model import GraphAutoencoder, NodeScaler
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
import detection.gnn_temporal_fused as fused_mod

class LogScaler:
    def __init__(self):
        self.lo=None; self.hi=None
    def fit(self, graphs):
        allx=torch.log1p(torch.cat([g.x for g in graphs],dim=0).clamp(min=0))
        self.lo=allx.min(dim=0).values; self.hi=allx.max(dim=0).values
        return self
    def transform(self, x):
        x=torch.log1p(x.clamp(min=0))
        span=torch.where((self.hi-self.lo)>0, self.hi-self.lo, torch.ones_like(self.hi))
        return torch.clamp((x-self.lo.to(x.device))/span.to(x.device),0.0,1.0)

def set_seed(seed):
    torch.manual_seed(seed); torch.cuda.manual_seed_all(seed); np.random.seed(seed)
    torch.backends.cudnn.deterministic=True; torch.backends.cudnn.benchmark=False

ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

def build_host_sequences(graphs, scaler, model, device, seq_len):
    per_host_emb=defaultdict(list)
    per_host_feat=defaultdict(list)
    for g in graphs:
        x=scaler.transform(g.x).to(device)
        with torch.no_grad():
            emb=model.encode_graph(x, g.edge_index.to(device)).cpu()
        for i,host in enumerate(g.hosts):
            per_host_emb[host].append(emb[i])
            per_host_feat[host].append(scaler.transform(g.x)[i])
    seqs,targets,hosts=[],[],[]
    for host, embs in per_host_emb.items():
        if len(embs)<seq_len: continue
        feats=per_host_feat[host]
        for s in range(0, len(embs)-seq_len+1, seq_len):
            seqs.append(torch.stack(embs[s:s+seq_len]))
            targets.append(torch.stack(feats[s:s+seq_len]))
            hosts.append(host)
    if not seqs: return None,None,[]
    return torch.stack(seqs), torch.stack(targets), hosts

def train_graph(graphs, scaler, device, epochs, seed):
    set_seed(seed)
    m=GraphAutoencoder(in_dim=graphs[0].x.shape[1]).to(device) if graphs else GraphAutoencoder().to(device)
    opt=torch.optim.Adam(m.parameters(), lr=0.01)
    loss_fn=nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        for x,ei in pre:
            loss=loss_fn(m(x,ei), x)
            opt.zero_grad(); loss.backward(); opt.step()
    return m

def train_fused_joint(graphs, scaler, device, epochs, seed, seq_len, feature_set):
    set_seed(seed)
    in_dim=len(node_feature_names(feature_set))
    m=fused_mod.GraphTemporalAutoencoder(in_dim=in_dim, seq_len=seq_len).to(device)
    opt=torch.optim.Adam(m.parameters(), lr=0.005)
    loss_fn=nn.MSELoss()
    for _ in range(epochs):
        seq,target,_=build_host_sequences(graphs, scaler, m, device, seq_len)
        if seq is None: raise ValueError(f"No host with {seq_len}+ windows")
        seq,target=seq.to(device), target.to(device)
        loss=loss_fn(m(seq), target)
        opt.zero_grad(); loss.backward(); opt.step()
    return m

def train_fused_twostage(graphs, scaler, device, epochs, seed, seq_len, feature_set, graph_epochs=100):
    # Stage 1: train GNN alone, freeze, then train LSTM on frozen embeddings
    set_seed(seed)
    # First train graph part separately to get stable scaler? Use same scaler
    in_dim=len(node_feature_names(feature_set))
    # Train GNN
    g_model=GraphAutoencoder(in_dim=in_dim).to(device)
    opt_g=torch.optim.Adam(g_model.parameters(), lr=0.01)
    loss_fn=nn.MSELoss()
    pre=[(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(graph_epochs):
        for x,ei in pre:
            loss=loss_fn(g_model(x,ei), x)
            opt_g.zero_grad(); loss.backward(); opt_g.step()
    # Now init fused and copy GNN weights, freeze them
    m=fused_mod.GraphTemporalAutoencoder(in_dim=in_dim, seq_len=seq_len).to(device)
    m.conv1.load_state_dict(g_model.conv1.state_dict())
    m.conv2.load_state_dict(g_model.conv2.state_dict())
    # Freeze GNN part
    for p in list(m.conv1.parameters())+list(m.conv2.parameters()):
        p.requires_grad=False
    # Train only LSTM part
    opt=torch.optim.Adam(filter(lambda p: p.requires_grad, m.parameters()), lr=0.005)
    for _ in range(epochs):
        seq,target,_=build_host_sequences(graphs, scaler, m, device, seq_len)
        if seq is None: raise ValueError(f"No host with {seq_len}+ windows")
        seq,target=seq.to(device), target.to(device)
        loss=loss_fn(m(seq), target)
        opt.zero_grad(); loss.backward(); opt.step()
    return m

def host_mean_scores(graphs, model, scaler, device):
    acc={}
    with torch.no_grad():
        for g in graphs:
            ns=model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            for h,s in zip(g.hosts, ns):
                acc.setdefault(h, []).append(float(s))
    return {h: float(np.mean(v)) for h,v in acc.items()}

def eval_pair(bg, fams, scaler, m_graph, m_fused, device, seq_len):
    per_family={}
    # coverage stats on benign
    host_windows_benign = defaultdict(list)
    for idx,g in enumerate(bg):
        for h in g.hosts: host_windows_benign[h].append(idx)
    consec=[0]
    for h, wins in host_windows_benign.items():
        wins=sorted(wins); run=1; maxrun=1
        for i in range(1,len(wins)):
            if wins[i]==wins[i-1]+1: run+=1; maxrun=max(maxrun,run)
            else: run=1
        consec.append(maxrun)
    cov_benign = sum(1 for c in consec if c>=seq_len)
    for fam,d in fams.items():
        graphs=d["graphs"]; bad=d["bad"]
        g_scores=host_mean_scores(graphs, m_graph, scaler, device)
        seq,target,hosts=build_host_sequences(graphs, scaler, m_fused, device, seq_len)
        f_map={}
        if seq is not None:
            with torch.no_grad():
                f_scores=m_fused.sequence_scores(seq.to(device), target.to(device)).cpu().numpy()
            tmp=defaultdict(list)
            for h,s in zip(hosts, f_scores): tmp[h].append(float(s))
            f_map={h: float(np.mean(v)) for h,v in tmp.items()}
        # Fair comparison on intersection
        inter=sorted(set(g_scores)&set(f_map))
        if not inter: 
            per_family[fam]={"graph_hosts":len(g_scores),"fused_hosts":len(f_map),"intersection":0,"note":"no intersection"}
            continue
        y=np.array([1 if h in bad else 0 for h in inter])
        if y.sum()==0: continue
        sg=np.array([g_scores[h] for h in inter])
        sf=np.array([f_map[h] for h in inter])
        # Percentile calibrate both on their own benign baselines computed here? For quick stage comparisons, use raw rank AUC (no calibration) to isolate model quality
        # But we also compute calibrated version later if needed
        # Use simple rank01 for AUC (AUC invariant to monotonic transform, so calibration doesn't matter for AUC)
        auc_g=roc_auc(sg, y)
        auc_f=roc_auc(sf, y)
        per_family[fam]={"graph_auc": round(float(auc_g),4), "fused_auc": round(float(auc_f),4), "delta": round(float(auc_f-auc_g),4), "graph_hosts": len(g_scores), "fused_hosts": len(f_map), "intersection": len(inter), "coverage": round(len(f_map)/max(len(g_scores),1),3)}
    return per_family, cov_benign

def run_stage(name, bg, fams, device, seed, epochs, seq_len, feature_set, scaler_type, training):
    print(f"\n{'='*70}\nSTAGE: {name} | scaler={scaler_type} feats={feature_set} seq_len={seq_len} window={bg[0].num_nodes if bg else '?'} training={training}\n{'='*70}")
    # Build scaler
    if scaler_type=="log":
        scaler=LogScaler().fit(bg)
    else:
        scaler=NodeScaler().fit(bg)
    # Train graph baseline for this same scaler (fair)
    m_graph=train_graph(bg, scaler, device, epochs, seed)
    # Train fused variant
    if training=="joint":
        m_fused=train_fused_joint(bg, scaler, device, epochs, seed, seq_len, feature_set)
    elif training=="twostage":
        m_fused=train_fused_twostage(bg, scaler, device, epochs, seed, seq_len, feature_set)
    else:
        raise ValueError(training)
    per_family, cov_benign = eval_pair(bg, fams, scaler, m_graph, m_fused, device, seq_len)
    # Print scorecard
    print(f"Coverage benign hosts with >={seq_len} windows: {cov_benign}")
    print(f"| Family | Graph AUC | Fused AUC | Delta(F-G) | Cover | Winner |")
    print(f"|---|---:|---:|---:|---:|---|")
    means_g=[]; means_f=[]
    for fam in ATTACK_FILES:
        if fam not in per_family: continue
        r=per_family[fam]
        if "graph_auc" not in r: continue
        winner="GRAPH" if r["graph_auc"]>r["fused_auc"] else "FUSED"
        print(f"| {fam} | {r['graph_auc']:.4f} | {r['fused_auc']:.4f} | {r['delta']:+.4f} | {r['coverage']:.2f} | {winner} |")
        means_g.append(r["graph_auc"]); means_f.append(r["fused_auc"])
    mean_g=float(np.mean(means_g)) if means_g else 0
    mean_f=float(np.mean(means_f)) if means_f else 0
    print(f"| **MEAN** | **{mean_g:.4f}** | **{mean_f:.4f}** | **{mean_f-mean_g:+.4f}** | | |")
    return per_family, {"mean_graph": round(mean_g,4), "mean_fused": round(mean_f,4), "delta": round(mean_f-mean_g,4), "cov_benign": cov_benign}

def main():
    ap=argparse.ArgumentParser(description="Exp2: staged fused improvements")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--out", default="experiments/exp2_fused_improve.json")
    args=ap.parse_args()
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Exp2 staged | device={device} torch={torch.__version__} limit={args.limit} window={args.window}s")
    # Load benign and attacks (v1 graphs for cache, but stages rebuild with feature_set)
    tr_base = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv", limit=args.limit))
    tr_base = tr_base[tr_base["label"].astype(str).str.strip().str.upper()=="BENIGN"]
    tr_base = tr_base[tr_base["src_ip"].map(lambda v: isinstance(v,str)) & tr_base["dst_ip"].map(lambda v: isinstance(v,str))]
    # Build per-stage bg/fams on demand? Cache base df and rebuild
    all_results={}
    stages=[
        ("S0_baseline",        dict(scaler_type="plain", feature_set="v1", seq_len=5, training="joint")),
        ("S1_log",              dict(scaler_type="log",   feature_set="v1", seq_len=5, training="joint")),
        ("S2_log_v2",           dict(scaler_type="log",   feature_set="v2", seq_len=5, training="joint")),
        ("S3_log_v2_T3",        dict(scaler_type="log",   feature_set="v2", seq_len=3, training="joint")),
        ("S4_log_v2_T3_2stage", dict(scaler_type="log",   feature_set="v2", seq_len=3, training="twostage")),
    ]
    for stage_name, cfg in stages:
        stage_out={}
        for seed in args.seeds:
            set_seed(seed)
            # Rebuild graphs with correct feature_set and window
            bg = build_graphs(tr_base, window_seconds=args.window, feature_set=cfg["feature_set"])
            fams={}
            for fam, fname in ATTACK_FILES.items():
                df = normalize_columns(read_flows(FLOWS / fname, limit=args.limit))
                df = df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
                df["label"]=df["label"].astype(str).str.strip()
                bad=malicious_hosts(df)
                if not bad: continue
                graphs=build_graphs(df, window_seconds=args.window, feature_set=cfg["feature_set"])
                if not graphs: continue
                fams[fam]={"graphs": graphs, "bad": bad}
            per_family, summary = run_stage(f"{stage_name} seed{seed}", bg, fams, device, seed, args.epochs, cfg["seq_len"], cfg["feature_set"], cfg["scaler_type"], cfg["training"])
            stage_out[str(seed)]={"per_family": per_family, "summary": summary, "config": cfg}
        all_results[stage_name]=stage_out
        # Print stage summary across seeds if multiple
        if len(args.seeds)>1:
            deltas=[stage_out[str(s)]["summary"]["delta"] for s in args.seeds]
            print(f"\n{stage_name} summary across seeds: delta mean {np.mean(deltas):+.4f} +/- {np.std(deltas):.4f} per-seed {deltas}")

    # Final tabular scorecard: stages vs mean delta
    print(f"\n{'='*70}\nEXP2 SUMMARY — staged deltas (Fused - Graph) on intersection\n{'='*70}")
    print(f"| Stage | Config | Mean Graph | Mean Fused | Delta | Cov benign |")
    print(f"|---|---|---:|---:|---:|---:|")
    for sname, cfg in stages:
        # average across seeds
        per_seed = all_results[sname]
        mean_g = np.mean([per_seed[str(sd)]["summary"]["mean_graph"] for sd in args.seeds])
        mean_f = np.mean([per_seed[str(sd)]["summary"]["mean_fused"] for sd in args.seeds])
        delta = mean_f - mean_g
        cov = np.mean([per_seed[str(sd)]["summary"]["cov_benign"] for sd in args.seeds])
        print(f"| {sname} | {cfg} | {mean_g:.4f} | {mean_f:.4f} | {delta:+.4f} | {cov:.0f} |")

    out=ROOT/args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"stages": all_results, "config": vars(args), "device": str(device), "torch": torch.__version__}, open(out,"w"), indent=2)
    print(f"\nSaved: {out}")
    md=ROOT/args.out.replace(".json",".md")
    with open(md,"w") as f:
        f.write(f"# Exp2 — Staged Fused Fixes (window={args.window}s, {args.epochs}ep)\n\n")
        for sname in [s[0] for s in stages]:
            f.write(f"## {sname}\n\n")
            for seed in args.seeds:
                summ=all_results[sname][str(seed)]["summary"]
                f.write(f"Seed {seed}: graph {summ['mean_graph']:.4f} fused {summ['mean_fused']:.4f} Delta {summ['delta']:+.4f} cov {summ['cov_benign']}\n\n")
                pf=all_results[sname][str(seed)]["per_family"]
                f.write("| Family | Graph | Fused | Delta | Cover |\n|---|---|---|---|---|\n")
                for fam in ATTACK_FILES:
                    if fam not in pf or "graph_auc" not in pf[fam]: continue
                    r=pf[fam]
                    f.write(f"| {fam} | {r['graph_auc']:.4f} | {r['fused_auc']:.4f} | {r['delta']:+.4f} | {r['coverage']:.2f} |\n")
                f.write("\n")
    print(f"Markdown: {md}")

if __name__=="__main__":
    main()
