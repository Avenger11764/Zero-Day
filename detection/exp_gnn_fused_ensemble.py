"""
Exp 1: Combine GNN (graph-only, prod) + Fused (graph+LSTM) to win on all families.

Reproduces RC-20 protocol but on LogScaler + full fixes where noted, and tests
multiple fusion strategies on IDENTICAL host/edge populations.

Outputs tabular scorecards after each run (markdown + json).
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.gnn_model import GraphAutoencoder
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
import detection.gnn_temporal_fused as fused_mod

# --- LogScaler (the prod scaler since 2026-08-12, gotcha #14) ---
class LogScaler:
    def __init__(self):
        self.lo = None
        self.hi = None
    def fit(self, graphs):
        allx = torch.log1p(torch.cat([g.x for g in graphs], dim=0).clamp(min=0))
        self.lo = allx.min(dim=0).values
        self.hi = allx.max(dim=0).values
        return self
    def transform(self, x):
        x = torch.log1p(x.clamp(min=0))
        span = torch.where((self.hi - self.lo) > 0, self.hi - self.lo, torch.ones_like(self.hi))
        return torch.clamp((x - self.lo.to(x.device)) / span.to(x.device), 0.0, 1.0)
    def state_dict(self):
        return {"lo": self.lo, "hi": self.hi, "log": True}
    def load_state_dict(self, d):
        self.lo, self.hi = d["lo"], d["hi"]
        return self

class PercentileCalibrator:
    def __init__(self, benign_scores):
        self.baseline = np.sort(np.asarray(benign_scores, dtype=np.float64))
    def __call__(self, scores):
        idx = np.searchsorted(self.baseline, np.asarray(scores), side="right")
        return idx / max(len(self.baseline), 1)

def _rank01(x):
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x)-1, 1)

def fuse_rank(arrays, method):
    ranked = [_rank01(a) for a in arrays]
    if method == "rank_mean":
        return np.mean(ranked, axis=0)
    if method == "rank_max":
        return np.maximum.reduce(ranked)
    raise ValueError(method)

def set_seed(seed):
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

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
    from collections import defaultdict
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
            continue
        feats = per_host_feat[host]
        for s in range(0, len(embs) - seq_len + 1, seq_len):
            seqs.append(torch.stack(embs[s:s+seq_len]))
            targets.append(torch.stack(feats[s:s+seq_len]))
            hosts.append(host)
    if not seqs:
        return None, None, []
    return torch.stack(seqs), torch.stack(targets), hosts

def train_graph(graphs, scaler, device, epochs, seed):
    set_seed(seed)
    in_dim = graphs[0].x.shape[1] if graphs else 8
    model = GraphAutoencoder(in_dim=in_dim).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.MSELoss()
    pre = [(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        total=0.0
        for x,ei in pre:
            loss = loss_fn(model(x,ei), x)
            opt.zero_grad(); loss.backward(); opt.step()
            total+=loss.item()
    return model

def train_fused(graphs, scaler, device, epochs, seed, seq_len, feature_set="v1"):
    set_seed(seed)
    # fused model needs in_dim matching feature_set
    from detection.graph_builder import node_feature_names
    in_dim = len(node_feature_names(feature_set))
    model = fused_mod.GraphTemporalAutoencoder(in_dim=in_dim, seq_len=seq_len).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.005)
    loss_fn = nn.MSELoss()
    for epoch in range(epochs):
        seq, target, _ = build_host_sequences(graphs, scaler, model, device, seq_len)
        if seq is None:
            raise ValueError(f"No host with {seq_len}+ consecutive windows (window too small or data too short).")
        seq, target = seq.to(device), target.to(device)
        recon = model(seq)
        loss = loss_fn(recon, target)
        opt.zero_grad(); loss.backward(); opt.step()
    return model

def host_mean_scores(graphs, model, scaler, device):
    acc = {}
    with torch.no_grad():
        for g in graphs:
            ns = model.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy()
            for h,s in zip(g.hosts, ns):
                acc.setdefault(h, []).append(float(s))
    return {h: float(np.mean(v)) for h,v in acc.items()}

def main():
    ap = argparse.ArgumentParser(description="Exp1: GNN+Fused ensemble")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--epochs-fused", type=int, default=60)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--seq-len", type=int, default=5)
    ap.add_argument("--feature-set", choices=["v1","v2"], default="v1")
    ap.add_argument("--out", default="experiments/exp1_ensemble.json")
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Exp1: GNN+Fused ensemble | device={device} torch={torch.__version__} limit={args.limit} window={args.window}s seq_len={args.seq_len} feats={args.feature_set}")
    # Load Monday benign
    tr = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv", limit=args.limit))
    tr = tr[tr["label"].astype(str).str.strip().str.upper()=="BENIGN"]
    # Filter to only rows with IPs (WebAttacks drop pattern)
    before=len(tr)
    # Monday has no NaN IPs but keep consistent
    tr = tr[tr["src_ip"].map(lambda v: isinstance(v, str)) & tr["dst_ip"].map(lambda v: isinstance(v, str))]
    print(f"Monday benign: {len(tr):,} flows (dropped {before-len(tr)})")
    bg = build_graphs(tr, window_seconds=args.window, feature_set=args.feature_set)
    print(f"Benign graphs: {len(bg)}")
    scaler = LogScaler().fit(bg)
    # Cache attack graphs + labels (seed-independent)
    fams={}
    for fam, fname in ATTACK_FILES.items():
        df = normalize_columns(read_flows(FLOWS / fname, limit=args.limit))
        df = df[df["src_ip"].map(lambda v: isinstance(v,str)) & df["dst_ip"].map(lambda v: isinstance(v,str))]
        df["label"]=df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        if not bad: continue
        graphs = build_graphs(df, window_seconds=args.window, feature_set=args.feature_set)
        if not graphs: continue
        fams[fam]={"df": df, "graphs": graphs, "bad": bad}
        print(f"  {fam}: {len(graphs)} graphs, {len(bad)} attackers")
    # Per-seed loop
    all_results={}
    for seed in args.seeds:
        print(f"\n{'='*70}\nSEED {seed}\n{'='*70}")
        set_seed(seed)
        m_graph = train_graph(bg, scaler, device, args.epochs, seed)
        # Calibrate graph scorer on benign
        benign_scores = np.concatenate([m_graph.node_scores(scaler.transform(g.x).to(device), g.edge_index.to(device)).cpu().numpy() for g in bg])
        cal_g = PercentileCalibrator(benign_scores)
        # Train fused
        try:
            m_fused = train_fused(bg, scaler, device, args.epochs_fused, seed, args.seq_len, args.feature_set)
        except ValueError as e:
            print(f"  Fused training failed: {e}")
            continue
        # Calibrate fused on benign host-sequences: use sequence_scores distribution
        # Build benign fused scores (if any)
        seq, target, hosts_b = build_host_sequences(bg, scaler, m_fused, device, args.seq_len)
        if seq is not None:
            fused_benign = m_fused.sequence_scores(seq.to(device), target.to(device)).cpu().numpy()
            cal_f = PercentileCalibrator(fused_benign)
            print(f"  Calibrated: graph over {len(benign_scores)} host-windows, fused over {len(fused_benign)} host-sequences")
        else:
            cal_f = None
            print("  WARNING: no benign fused sequences for calibration; fused scores will be uncalibrated")

        per_family={}
        for fam, d in fams.items():
            graphs = d["graphs"]
            bad = d["bad"]
            # Graph scores per host (mean over windows)
            g_scores = host_mean_scores(graphs, m_graph, scaler, device)
            # Fused scores per host: build sequences for this test family and score
            seq_t, target_t, hosts_t = build_host_sequences(graphs, scaler, m_fused, device, args.seq_len)
            f_map={}
            if seq_t is not None:
                with torch.no_grad():
                    f_scores = m_fused.sequence_scores(seq_t.to(device), target_t.to(device)).cpu().numpy()
                # host may have multiple sequences (sliding) -> mean
                tmp={}
                for h,s in zip(hosts_t, f_scores):
                    tmp.setdefault(h, []).append(float(s))
                f_map = {h: float(np.mean(v)) for h,v in tmp.items()}
            # Intersection population: hosts present in BOTH (fair comparison)
            hosts_inter = sorted(set(g_scores) & set(f_map))
            # Union for coverage-gated
            hosts_union = sorted(set(g_scores) | set(f_map))
            if not hosts_inter:
                print(f"  {fam}: no intersection hosts (graph {len(g_scores)}, fused {len(f_map)}); skipping fused comparison")
                # Still score graph alone on its own population for reference
                hosts_ref = sorted(g_scores)
                y_ref = np.array([1 if h in bad else 0 for h in hosts_ref])
                if y_ref.sum()>0:
                    sc_ref = cal_g(np.array([g_scores[h] for h in hosts_ref]))
                    auc_ref = roc_auc(sc_ref, y_ref)
                    per_family[fam]={"note":"no intersection", "graph_auc": round(float(auc_ref),4), "graph_hosts": len(hosts_ref), "fused_hosts": len(f_map), "intersection":0}
                continue
            y = np.array([1 if h in bad else 0 for h in hosts_inter])
            if y.sum()==0:
                print(f"  {fam}: no malicious in intersection; skipping")
                continue
            # Calibrated scores
            sg = cal_g(np.array([g_scores[h] for h in hosts_inter]))
            sf = cal_f(np.array([f_map[h] for h in hosts_inter])) if cal_f else np.array([f_map[h] for h in hosts_inter])
            # Fusion arms
            # Coverage-gated: for union hosts, use fused where available else graph
            # For fair AUC we still compute on intersection for gated (same as elsewhere) but report coverage separately
            arms = {
                "graph": sg,
                "fused": sf,
                "rank_mean": fuse_rank([sg, sf], "rank_mean"),
                "rank_max": fuse_rank([sg, sf], "rank_max"),
                "mean_val": (sg + sf)/2,
                "max_val": np.maximum(sg, sf),
            }
            # Also compute coverage-gated on union (operational): score = fused if host in f_map else graph (calibrated graph for fallback)
            union_scores_gated=[]
            union_y=[]
            for h in hosts_union:
                if h in f_map:
                    # Need calibrated fused score for that host (over all its sequences)
                    # For hosts in intersection we have sf; for hosts only in fused we need calibrate individually
                    s = cal_f(np.array([f_map[h]]))[0] if cal_f else f_map[h]
                else:
                    s = cal_g(np.array([g_scores[h]]))[0]
                union_scores_gated.append(s)
                union_y.append(1 if h in bad else 0)
            union_scores_gated = np.array(union_scores_gated)
            union_y = np.array(union_y)
            row={}
            for name, sc in arms.items():
                auc = roc_auc(sc, y)
                row[name]=round(float(auc),4)
            # gated AUC on union vs on intersection (for comparability)
            # For gate we report both: intersection rank_mean already captures, but add gated_union
            row["gated_union_auc"]= round(float(roc_auc(union_scores_gated, union_y)),4) if union_y.sum()>0 else None
            row["graph_hosts"]=len(g_scores)
            row["fused_hosts"]=len(f_map)
            row["intersection"]=len(hosts_inter)
            row["union"]=len(hosts_union)
            row["coverage_fused"]=round(len(f_map)/max(len(g_scores),1),3)
            # Winner on intersection
            cand = {k: row[k] for k in ["graph","fused","rank_mean","rank_max","mean_val","max_val"]}
            winner = max(cand, key=lambda k: cand[k])
            row["winner"]=winner
            per_family[fam]=row
            print(f"  {fam}: G={row['graph']:.4f} F={row['fused']:.4f} RM={row['rank_mean']:.4f} RX={row['rank_max']:.4f} MV={row['mean_val']:.4f} MX={row['max_val']:.4f} gatedU={row['gated_union_auc']:.4f} cov={row['coverage_fused']:.2f} -> {winner}")

        # Tabular scorecard
        print(f"\n--- Scorecard seed {seed} ---")
        header = f"| Family | Graph | Fused | RankMean | RankMax | MeanVal | MaxVal | GatedU | Cov | Winner |"
        print(header)
        print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        means={}
        for k in ["graph","fused","rank_mean","rank_max","mean_val","max_val","gated_union_auc"]:
            vals=[per_family[f][k] for f in per_family if k in per_family[f] and per_family[f][k] is not None]
            means[k]= float(np.mean(vals)) if vals else float('nan')
        for fam in ATTACK_FILES:
            if fam not in per_family: continue
            r=per_family[fam]
            print(f"| {fam} | {r.get('graph',0):.4f} | {r.get('fused',0):.4f} | {r.get('rank_mean',0):.4f} | {r.get('rank_max',0):.4f} | {r.get('mean_val',0):.4f} | {r.get('max_val',0):.4f} | {r.get('gated_union_auc',0):.4f} | {r.get('coverage_fused',0):.2f} | {r.get('winner','-')} |")
        print(f"| **MEAN** | **{means['graph']:.4f}** | **{means['fused']:.4f}** | **{means['rank_mean']:.4f}** | **{means['rank_max']:.4f}** | **{means['mean_val']:.4f}** | **{means['max_val']:.4f}** | **{means['gated_union_auc']:.4f}** | | |")
        print(f"Delta fused-graph: {means['fused']-means['graph']:+.4f} | rank_mean-graph: {means['rank_mean']-means['graph']:+.4f}")
        all_results[str(seed)]=per_family
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"per_family": all_results, "config": vars(args), "device": str(device), "torch": torch.__version__}, open(out,"w"), indent=2)
    print(f"\nSaved: {out}")
    # Also write markdown scorecard for latest seed
    md = ROOT / args.out.replace(".json",".md")
    with open(md,"w") as f:
        f.write(f"# Exp1 Ensemble — GNN+Fused (window={args.window}s seq_len={args.seq_len} feats={args.feature_set})\n\n")
        for seed, pf in all_results.items():
            f.write(f"## Seed {seed}\n\n| Family | Graph | Fused | RankMean | RankMax | MeanVal | MaxVal | GatedU | Cov | Winner |\n|---|---|---|---|---|---|---|---|---|---|\n")
            for fam in ATTACK_FILES:
                if fam not in pf: continue
                r=pf[fam]
                f.write(f"| {fam} | {r.get('graph',0):.4f} | {r.get('fused',0):.4f} | {r.get('rank_mean',0):.4f} | {r.get('rank_max',0):.4f} | {r.get('mean_val',0):.4f} | {r.get('max_val',0):.4f} | {r.get('gated_union_auc',0):.4f} | {r.get('coverage_fused',0):.2f} | {r.get('winner','-')} |\n")
            f.write("\n")
    print(f"Markdown: {md}")

if __name__ == "__main__":
    main()
