"""
External replication of the M5a-revived + v2b fusion (rank_max / noisyor)
on IDS2018 (LOIC-HTTP) and CTU-13 (s1/s13/s3).

Protocol per dataset: train both pillars on pre-attack benign only, score the
attack window, report infected/attacker host ranks + recall@100 for
  v2b-alone  vs  fused rank_max  vs  fused noisyor
Fusion happens on percentile-calibrated host scores aggregated to unique hosts
(mean over windows), matching RC-29/RC-32 reporting.
"""
from __future__ import annotations
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import sys
from pathlib import Path
import json, argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import build_graphs, normalize_columns, read_flows, _window_key
from detection.evaluate_gnn import roc_auc
from detection.gnn_model import GraphAutoencoder
from detection.exp_v2b_temporal_aug import augment_graphs_temporal, K, LogScaler as V2BScaler
from detection.exp_m5a_revival import (pin_canonical, flow_matrix, build_ctx,
                                       MinMax, CtxScaler, RevivedAE, CTX_DIMS)

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
IDS2018 = ROOT / "data" / "CSE-CIC-IDS2018" / "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
CTU = {
    "s1_neris": (ROOT / "data" / "CTU-13" / "ctu13_s1_neris.binetflow", "147.32.84.165"),
    "s13_virut": (ROOT / "data" / "CTU-13" / "ctu13_s13_virut.binetflow", "147.32.84.165"),
    "s3_rbot": (ROOT / "data" / "CTU-13" / "ctu13_s3_rbot.binetflow", "147.32.84.165"),
}

def set_seed(s):
    torch.manual_seed(s); torch.cuda.manual_seed_all(s); np.random.seed(s)
    torch.backends.cudnn.deterministic = True; torch.backends.cudnn.benchmark = False

def pin_lenient(df):
    """binetflow has ~17 numeric cols, not CICFlowMeter's 76 -- no assert."""
    feats = df.drop(columns=[c for c in ["src_ip", "dst_ip", "src_port", "protocol",
                                         "timestamp", "label", "flow_id"] if c in df.columns],
                    errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    return list(feats.columns)

def train_revived(train_df, wk, device, epochs=30):
    try:
        canonical = pin_canonical(train_df)
    except AssertionError:
        canonical = pin_lenient(train_df)
        print(f"  [lenient] {len(canonical)} flow columns (foreign schema)")
    fmm = MinMax().fit(flow_matrix(train_df, canonical))
    csc = CtxScaler().fit(build_ctx(train_df, wk))
    X = np.concatenate([fmm.transform(flow_matrix(train_df, canonical)),
                        csc.transform(build_ctx(train_df, wk))], axis=1)
    model = RevivedAE(X.shape[1]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lf = nn.MSELoss()
    Xt = torch.tensor(X)
    loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(Xt),
                                         batch_size=4096, shuffle=True)
    for ep in range(epochs):
        tot = 0.0
        for (b,) in loader:
            b = b.to(device); l = lf(model(b), b)
            opt.zero_grad(); l.backward(); opt.step(); tot += l.item() * len(b)
    return model, canonical, fmm, csc

def revived_host_scores(df, wk, model, canonical, fmm, csc, device):
    X = np.concatenate([fmm.transform(flow_matrix(df, canonical)),
                        csc.transform(build_ctx(df, wk))], axis=1)
    outs = []
    with torch.no_grad():
        for i in range(0, len(X), 8192):
            xb = torch.tensor(X[i:i+8192]).to(device)
            outs.append(model.anomaly_score(xb).cpu().numpy())
    t = pd.DataFrame({"wk": wk.values, "src": df["src_ip"].values,
                      "s": np.concatenate(outs)})
    return t.groupby(["wk", "src"])["s"].max().to_dict()

def v2b_train_and_score(train_df, eval_df, device, epochs=60):
    bg = build_graphs(train_df, window_seconds=60, feature_set="v2")
    if not bg: raise RuntimeError("no benign graphs")
    aug = augment_graphs_temporal(bg, k=K)
    sc = V2BScaler().fit(aug)
    m = GraphAutoencoder(in_dim=aug[0].x.shape[1], hidden=32, latent=8).to(device)
    opt = torch.optim.Adam(m.parameters(), lr=0.01); lf = nn.MSELoss()
    pre = [(sc.transform(g.x).to(device), g.edge_index.to(device)) for g in aug]
    for ep in range(epochs):
        for x, ei in pre:
            l = lf(m(x, ei), x); opt.zero_grad(); l.backward(); opt.step()
    eg = build_graphs(eval_df, window_seconds=60, feature_set="v2")
    eaug = augment_graphs_temporal(eg, k=K) if eg else []
    pool = {}
    with torch.no_grad():
        for wi, g in enumerate(eaug):
            ns = m.node_scores(sc.transform(g.x).to(device),
                               g.edge_index.to(device)).cpu().numpy()
            for h, s in zip(g.hosts, ns): pool[(wi, h)] = float(s)
    return pool

def fuse_report(name, bad_hosts, m5a_map, v2b_map):
    keys = sorted(set(m5a_map) & set(v2b_map))
    if not keys: print(f"{name}: no overlap"); return None
    base_m = np.sort(np.asarray(list(m5a_map.values())))
    cal_m = {k: float(np.searchsorted(base_m, m5a_map[k], side="right") / len(base_m)) for k in keys}
    base_v = np.sort(np.asarray(list(v2b_map.values())))
    cal_v = {k: float(np.searchsorted(base_v, v2b_map[k], side="right") / len(base_v)) for k in keys}
    # aggregate to unique hosts (mean over windows)
    def agg(d):
        acc = {}
        for (wi, h), s in d.items(): acc.setdefault(h, []).append(s)
        return {h: float(np.mean(v)) for h, v in acc.items()}
    am, av = agg(cal_m), agg(cal_v)
    hosts = sorted(set(am) & set(av))
    y = np.array([1 if h in bad_hosts else 0 for h in hosts])
    n_bad = int(y.sum())
    if n_bad == 0: print(f"{name}: no bad hosts"); return None
    sm = np.array([am[h] for h in hosts]); sv = np.array([av[h] for h in hosts])
    rm_ = np.maximum(sm, sv)
    nor = 1 - (1 - sm) * (1 - sv)
    def ranks(sc):
        order = np.argsort(sc)[::-1]
        return sorted(int(np.where(order == i)[0][0]) + 1 for i in np.where(y == 1)[0])
    out = {"hosts": len(hosts), "bad": n_bad}
    for nm, sc in [("m5a", sm), ("v2b", sv), ("rmax", rm_), ("noisyor", nor)]:
        r = ranks(sc)
        out[nm] = {"best_rank": int(min(r)), "median_rank": int(np.median(r)),
                   "pct": round(float(min(r)) / len(hosts), 6),
                   "recall100": round(float(y[np.argsort(sc)[::-1][:100]].mean()), 3)}
    print(f"{name}: hosts={out['hosts']:,} bad={n_bad}")
    for nm in ["m5a", "v2b", "rmax", "noisyor"]:
        o = out[nm]
        print(f"  {nm:<8} best={o['best_rank']:,} med={o['median_rank']} "
              f"pct={o['pct']:.6f} r@100={o['recall100']}")
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", default=["ids2018", "ctu13_s1", "ctu13_s13", "ctu13_s3"])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--ae-epochs", type=int, default=30)
    ap.add_argument("--gnn-epochs", type=int, default=60)
    ap.add_argument("--out", default="experiments/m5a_fusion_external.json")
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(args.seed)
    results = {}

    if "ids2018" in args.datasets and IDS2018.exists():
        print(f"\n{'='*60}\nIDS2018 LOIC-HTTP\n{'='*60}")
        df = normalize_columns(read_flows(IDS2018))
        df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
        df = df.dropna(subset=["ts"])
        df = df[df["src_ip"].map(lambda v: isinstance(v, str)) & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        atk = df.loc[df["label"].str.upper() != "BENIGN", "ts"].min()
        tr = df[df["label"].str.upper() == "BENIGN"][lambda d: d["ts"] < atk]
        ev = df[df["ts"] >= atk]
        bad = set(ev.loc[ev["label"].str.upper() != "BENIGN", "src_ip"].unique()) | \
              set(ev.loc[ev["label"].str.upper() != "BENIGN", "dst_ip"].unique())
        print(f"train {len(tr):,} eval {len(ev):,} bad {len(bad)}")
        wk_tr = _window_key(tr, 60); wk_ev = _window_key(ev, 60)
        m5, cano, fmm, csc = train_revived(tr, wk_tr, device, args.ae_epochs)
        m5a_map = revived_host_scores(ev, wk_ev, m5, cano, fmm, csc, device)
        v2b_map = v2b_train_and_score(tr, ev, device, args.gnn_epochs)
        results["ids2018"] = fuse_report("ids2018", bad, m5a_map, v2b_map)

    _KEYMAP = {"ctu13_s1": "s1_neris", "ctu13_s13": "s13_virut", "ctu13_s3": "s3_rbot"}
    for key in ["ctu13_s1", "ctu13_s13", "ctu13_s3"]:
        if key not in args.datasets: continue
        path, inf = CTU[_KEYMAP[key]]
        if not path.exists(): print(f"{key}: missing"); continue
        print(f"\n{'='*60}\nCTU-13 {key}\n{'='*60}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().lower() for c in df.columns]
        df = df.rename(columns={"srcaddr": "src_ip", "dstaddr": "dst_ip",
                                "dur": "flow_duration", "srcbytes": "fwd_bytes",
                                "dstbytes": "bwd_bytes", "sport": "src_port", "dport": "dst_port"})
        df["protocol"] = df["proto"].astype(str).str.lower().map(PROTO_NUM).fillna(0)
        df["label"] = df["label"].astype(str).str.strip()
        df["ts"] = pd.to_datetime(df["starttime"], errors="coerce", format="mixed")
        df = df.dropna(subset=["ts", "src_ip", "dst_ip"])
        is_bot = df["label"].str.contains("From-Botnet", regex=False)
        atk = df.loc[is_bot, "ts"].min()
        tr = df[~is_bot & (df["ts"] < atk)]
        ev = df[df["ts"] >= atk]
        bad = set(ev.loc[is_bot, "src_ip"].unique()) | set(ev.loc[is_bot, "dst_ip"].unique())
        print(f"train {len(tr):,} eval {len(ev):,} bad {len(bad)}")
        wk_tr = _window_key(tr, 60); wk_ev = _window_key(ev, 60)
        m5, cano, fmm, csc = train_revived(tr, wk_tr, device, args.ae_epochs)
        m5a_map = revived_host_scores(ev, wk_ev, m5, cano, fmm, csc, device)
        v2b_map = v2b_train_and_score(tr, ev, device, args.gnn_epochs)
        results[key] = fuse_report(key, bad, m5a_map, v2b_map)

    out = ROOT / args.out
    json.dump({"per_dataset": results, "seed": args.seed, "device": str(device)},
              open(out, "w"), indent=2)
    print(f"\nSaved {out}")

if __name__ == "__main__":
    main()
