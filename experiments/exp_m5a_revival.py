"""
M5a revival: bring the per-flow pillar back into prod legitimately.

Redesign (RC-17 recipe + calibration fix):
  1. ctx features: append 11 window-context dims (ws_flows/ws_dst/ws_ports/ws_fwd/
     ws_bwd/ws_pkts_f/ws_pkts_b/ws_dur/wd_flows/wd_src/wd_dur) to the 76 flow
     features -> 87-dim input. RC-17 measured flow-level 0.8429 -> 0.9036 with
     richer ctx; this is the known lever.
  2. Lifted to host-window via MAX over the host's flows in the window
     (ensembler convention), calibrated as percentile vs Monday benign pool.
  3. Fused with the v2b temporal-aug GNN at HOST-WINDOW level using FIXED rules
     (rank_mean / rank_max / agreement) -- never max-on-raw (gotcha #21).

Verdict table decides promotion: fused must beat v2b-alone on MEAN without
losing families wholesale, else M5a stays out (honest negative).
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

from detection.graph_builder import (build_graphs, normalize_columns, read_flows,
                                     _window_key)
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
try:
    from detection.stub_detector import Autoencoder as ShippedAE, EXPECTED_FEATURES, MODEL_PATH
except ModuleNotFoundError:
    from legacy.stub_detector import Autoencoder as ShippedAE, EXPECTED_FEATURES, MODEL_PATH
from detection.gnn_model import GraphAutoencoder
try:
    from detection.exp_v2b_temporal_aug import (augment_graphs_temporal, K,
                                                LogScaler as V2BScaler)
except ModuleNotFoundError:
    from experiments.exp_v2b_temporal_aug import (augment_graphs_temporal, K,
                                                  LogScaler as V2BScaler)

META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp",
        "label", "flow_id"]

CTX_DIMS = ["ws_flows", "ws_dst", "ws_ports", "ws_fwd", "ws_bwd",
            "ws_pkts_f", "ws_pkts_b", "ws_dur", "wd_flows", "wd_src", "wd_dur"]


def set_seed(s):
    torch.manual_seed(s); torch.cuda.manual_seed_all(s); np.random.seed(s)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def pin_canonical(df: pd.DataFrame) -> list[str]:
    feats = df.drop(columns=[c for c in META if c in df.columns], errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    if feats.shape[1] == EXPECTED_FEATURES + 1 and "dst_port" in feats.columns:
        feats = feats.drop(columns=["dst_port"])
    assert feats.shape[1] == EXPECTED_FEATURES, f"got {feats.shape[1]}"
    return list(feats.columns)


def flow_matrix(df, canonical):
    feats = df[canonical].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return feats.to_numpy(dtype=np.float32)


class MinMax:
    def __init__(self): self.lo=None; self.hi=None
    def fit(self, X):
        self.lo = X.min(axis=0); self.hi = X.max(axis=0); return self
    def transform(self, X):
        span = np.where(self.hi - self.lo > 0, self.hi - self.lo, 1.0)
        return np.clip((X - self.lo) / span, 0.0, 1.0).astype(np.float32)


class CtxScaler:
    """log1p + minmax for the 11 count-ish ctx dims."""
    def __init__(self): self.lo=None; self.hi=None
    def fit(self, X):
        Xl = np.log1p(np.clip(X, 0, None))
        self.lo = Xl.min(axis=0); self.hi = Xl.max(axis=0); return self
    def transform(self, X):
        Xl = np.log1p(np.clip(X, 0, None))
        span = np.where(self.hi - self.lo > 0, self.hi - self.lo, 1.0)
        return np.clip((Xl - self.lo) / span, 0.0, 1.0).astype(np.float32)


def build_ctx(df: pd.DataFrame, wk: pd.Series) -> np.ndarray:
    tmp = pd.DataFrame({
        "wk": wk.values, "src": df["src_ip"].values, "dst": df["dst_ip"].values,
        "port": df["dst_port"].values if "dst_port" in df.columns else 0,
        "fwd": df["fwd_bytes"].values if "fwd_bytes" in df.columns else 0.0,
        "bwd": df["bwd_bytes"].values if "bwd_bytes" in df.columns else 0.0,
        "pf": df["fwd_pkts"].values if "fwd_pkts" in df.columns else 0.0,
        "pb": df["bwd_pkts"].values if "bwd_pkts" in df.columns else 0.0,
        "dur": df["flow_duration"].values if "flow_duration" in df.columns else 0.0,
    })
    g = tmp.groupby(["wk", "src"])
    ws = pd.DataFrame({
        "ws_flows": g.size(),
        "ws_dst": g["dst"].nunique(),
        "ws_ports": g["port"].nunique(),
        "ws_fwd": g["fwd"].sum(), "ws_bwd": g["bwd"].sum(),
        "ws_pkts_f": g["pf"].sum(), "ws_pkts_b": g["pb"].sum(),
        "ws_dur": g["dur"].mean(),
    }).reset_index()
    g2 = tmp.groupby(["wk", "dst"])
    wd = pd.DataFrame({
        "wd_flows": g2.size(), "wd_src": g2["src"].nunique(),
        "wd_dur": g2["dur"].mean(),
    }).reset_index()
    m = tmp.merge(ws, on=["wk", "src"], how="left").merge(wd, on=["wk", "dst"], how="left")
    m[CTX_DIMS] = m[CTX_DIMS].fillna(0.0)
    # align back to original row order
    m = m.iloc[np.argsort(m.index)]  # merge preserves order; explicit no-op guard
    return m[CTX_DIMS].to_numpy(dtype=np.float32)


class RevivedAE(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256), nn.ReLU(),
            nn.Linear(256, 128), nn.ReLU(),
            nn.Linear(128, 32))
        self.decoder = nn.Sequential(
            nn.Linear(32, 128), nn.ReLU(),
            nn.Linear(128, 256), nn.ReLU(),
            nn.Linear(256, input_dim), nn.Sigmoid())
    def forward(self, x): return self.decoder(self.encoder(x))
    @torch.no_grad()
    def anomaly_score(self, x):
        return torch.mean((self.forward(x) - x) ** 2, dim=1)


def train_ae(X, epochs, seed, device, batch=4096):
    set_seed(seed)
    model = RevivedAE(X.shape[1]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()
    Xt = torch.tensor(X)
    loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(Xt),
                                         batch_size=batch, shuffle=True)
    for ep in range(epochs):
        tot = 0.0
        for (b,) in loader:
            b = b.to(device)
            loss = loss_fn(model(b), b)
            opt.zero_grad(); loss.backward(); opt.step()
            tot += loss.item() * len(b)
        if ep % 20 == 0:
            print(f"    AE ep{ep} loss {tot/len(Xt):.6f}")
    return model


def score_host_windows(df, wk, model, device, X, batch=8192):
    """Per-(window, src) MAX of per-flow scores."""
    outs = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            xb = torch.tensor(X[i:i+batch]).to(device)
            outs.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(outs)
    t = pd.DataFrame({"wk": wk.values, "src": df["src_ip"].values, "s": scores})
    return t.groupby(["wk", "src"])["s"].max().to_dict()


def calibrate(pool_scores):
    base = np.sort(np.asarray(list(pool_scores.values()), dtype=np.float64))
    def f(target_map, keys):
        raw = np.array([target_map[k] for k in keys])
        idx = np.searchsorted(base, raw, side="right")
        return idx / max(len(base), 1)
    return f


def rank01(x):
    o = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return o / max(len(x) - 1, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--epochs-ae", type=int, default=60)
    ap.add_argument("--epochs-gnn", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0, help="0 = full files")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--out", default="experiments/exp_m5a_revival.json")
    args = ap.parse_args()
    lim = None if args.limit in (0, None) else args.limit
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"M5a revival | device={device} window={args.window}s ae_ep={args.aepochs if hasattr(args,'aepochs') else args.epochs_ae} seeds={args.seeds}")

    tr = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv", limit=lim))
    tr = tr[tr["label"].astype(str).str.strip().str.upper() == "BENIGN"]
    tr = tr[tr["src_ip"].map(lambda v: isinstance(v, str)) & tr["dst_ip"].map(lambda v: isinstance(v, str))]
    wk_tr = _window_key(tr, args.window)
    canonical = pin_canonical(tr)
    print(f"Monday benign {len(tr):,} flows, {len(canonical)} pinned feats")

    all_res = {}
    for seed in args.seeds:
        print(f"\n{'='*70}\nSEED {seed}\n{'='*70}")
        set_seed(seed)
        # ---- M5a variants ----
        Xb_tr = MinMax().fit(flow_matrix(tr, canonical))
        Xlog = Xb_tr.transform(flow_matrix(tr, canonical))          # shipped-style scale
        shipped = ShippedAE(EXPECTED_FEATURES)
        try:
            shipped.load_state_dict(torch.load(MODEL_PATH, map_location="cpu", weights_only=True))
        except TypeError:
            shipped.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
        shipped = shipped.to(device).eval()

        ctx_sc = CtxScaler().fit(build_ctx(tr, wk_tr))
        Xctx_tr = np.concatenate([Xlog, ctx_sc.transform(build_ctx(tr, wk_tr))], axis=1)
        print(f"  training revived AE ({Xctx_tr.shape[1]} dims, {args.epochs_ae} ep)...")
        revived = train_ae(Xctx_tr, args.epochs_ae, seed, device)

        pool_ship = score_host_windows(tr, wk_tr, shipped, device, Xlog)
        pool_rev = score_host_windows(tr, wk_tr, revived, device, Xctx_tr)
        cal_ship = calibrate(pool_ship)
        cal_rev = calibrate(pool_rev)
        print(f"  calibration pools: shipped {len(pool_ship)}, revived {len(pool_rev)}")

        # ---- v2b GNN ----
        bg = build_graphs(tr, window_seconds=args.window, feature_set="v2")
        bg_aug = augment_graphs_temporal(bg, k=K)
        sc_v2b = V2BScaler().fit(bg_aug)
        in_dim = bg_aug[0].x.shape[1]
        gv = GraphAutoencoder(in_dim=in_dim, hidden=32, latent=8).to(device)
        opt = torch.optim.Adam(gv.parameters(), lr=0.01)
        lf = nn.MSELoss()
        pre = [(sc_v2b.transform(g.x).to(device), g.edge_index.to(device)) for g in bg_aug]
        for ep in range(args.epochs_gnn):
            for x, ei in pre:
                l = lf(gv(x, ei), x)
                opt.zero_grad(); l.backward(); opt.step()
        v2b_pool = {}
        with torch.no_grad():
            for wi, g in enumerate(bg_aug):
                ns = gv.node_scores(sc_v2b.transform(g.x).to(device),
                                    g.edge_index.to(device)).cpu().numpy()
                for h, s in zip(g.hosts, ns):
                    v2b_pool[(wi, h)] = float(s)
        base_v2b = np.sort(np.asarray(list(v2b_pool.values())))
        def cal_v2b(tmap, keys):
            raw = np.array([tmap[k] for k in keys])
            return np.searchsorted(base_v2b, raw, side="right") / len(base_v2b)
        print(f"  v2b trained on {len(bg_aug)} aug graphs (K={K}); pool {len(v2b_pool)}")

        # ---- families ----
        fam_res = {}
        for fam, fname in {
            "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
            "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
        }.items():
            df = normalize_columns(read_flows(FLOWS / fname, limit=lim))
            df = df[df["src_ip"].map(lambda v: isinstance(v, str)) & df["dst_ip"].map(lambda v: isinstance(v, str))]
            df["label"] = df["label"].astype(str).str.strip()
            bad = malicious_hosts(df)
            if not bad: continue
            wk = _window_key(df, args.window)
            Xl = Xb_tr.transform(flow_matrix(df, canonical))
            Xc = np.concatenate([Xl, ctx_sc.transform(build_ctx(df, wk))], axis=1)
            m_ship = score_host_windows(df, wk, shipped, device, Xl)
            m_rev = score_host_windows(df, wk, revived, device, Xc)
            graphs = build_graphs(df, window_seconds=args.window, feature_set="v2")
            gaug = augment_graphs_temporal(graphs, k=K)
            m_v2b = {}
            with torch.no_grad():
                for wi, g in enumerate(gaug):
                    ns = gv.node_scores(sc_v2b.transform(g.x).to(device),
                                        g.edge_index.to(device)).cpu().numpy()
                    for h, s in zip(g.hosts, ns):
                        m_v2b[(wi, h)] = float(s)
            keys = sorted(set(m_ship) & set(m_rev) & set(m_v2b))
            if not keys: continue
            y = np.array([1 if h in bad else 0 for _, h in keys])
            if y.sum() == 0 or y.sum() == len(y): continue
            s_ship = cal_ship(m_ship, keys)
            s_rev = cal_rev(m_rev, keys)
            s_v2b = cal_v2b(m_v2b, keys)
            arms = {
                "m5a_shipped": roc_auc(s_ship, y),
                "m5a_revived": roc_auc(s_rev, y),
                "v2b_alone": roc_auc(s_v2b, y),
                "fuse_ship_rm": roc_auc((rank01(s_ship) + rank01(s_v2b)) / 2, y),
                "fuse_rev_rm": roc_auc((rank01(s_rev) + rank01(s_v2b)) / 2, y),
                "fuse_rev_rmax": roc_auc(np.maximum(rank01(s_rev), rank01(s_v2b)), y),
                "fuse_rev_noisyor": roc_auc(1 - (1 - rank01(s_rev)) * (1 - rank01(s_v2b)), y),
                "fuse_rev_w37": roc_auc(0.3 * rank01(s_rev) + 0.7 * rank01(s_v2b), y),
                "agree_rev": roc_auc(((s_rev > np.median(s_rev)) & (s_v2b > np.median(s_v2b))).astype(float)
                                     * 0.5 + (rank01(s_rev) + rank01(s_v2b)) / 2 * 0.5, y),
            }

            # ---- EDGE-level replication of the fusion (src-rule projection) ----
            r_rev, r_v2b = rank01(s_rev), rank01(s_v2b)
            hmap_rev = {k: v for k, v in zip(keys, r_rev)}
            hmap_v2b = {k: v for k, v in zip(keys, r_v2b)}
            e_rev, e_v2b, e_y = [], [], []
            with torch.no_grad():
                for wi, g in enumerate(gaug):
                    ei = g.edge_index.cpu().numpy()
                    for e in range(g.num_edges):
                        src = g.hosts[int(ei[0, e])]
                        k = (wi, src)
                        if k not in hmap_rev or k not in hmap_v2b:
                            continue
                        e_rev.append(hmap_rev[k]); e_v2b.append(hmap_v2b[k])
                        e_y.append(1 if src in bad else 0)
            if e_y and 0 < sum(e_y) < len(e_y):
                e_y = np.array(e_y); ea = np.array(e_rev); eb = np.array(e_v2b)
                arms["EDGE_m5a_rev"] = roc_auc(ea, e_y)
                arms["EDGE_v2b"] = roc_auc(eb, e_y)
                arms["EDGE_rm"] = roc_auc((ea + eb) / 2, e_y)
                arms["EDGE_rmax"] = roc_auc(np.maximum(ea, eb), e_y)
                arms["EDGE_noisyor"] = roc_auc(1 - (1 - ea) * (1 - eb), e_y)

            fam_res[fam] = {k: round(float(v), 4) for k, v in arms.items()}
            fam_res[fam]["n"] = int(len(y)); fam_res[fam]["bad"] = int(y.sum())
            print(f"  {fam}: rm={arms['fuse_rev_rm']:.4f} rmax={arms['fuse_rev_rmax']:.4f} "
                  f"nor={arms['fuse_rev_noisyor']:.4f} w37={arms['fuse_rev_w37']:.4f} | "
                  f"EDGE v2b={arms.get('EDGE_v2b', float('nan')):.4f} "
                  f"rmax={arms.get('EDGE_rmax', float('nan')):.4f} "
                  f"nor={arms.get('EDGE_noisyor', float('nan')):.4f}")
        means = {k: round(float(np.mean([v[k] for v in fam_res.values()])), 4)
                 for k in next(iter(fam_res.values())) if k != "n" and k != "bad"}
        print(f"\n  MEANS: {means}")
        wins = {k: sum(1 for v in fam_res.values() if v[k] >= v["v2b_alone"]) for k in means if k != "v2b_alone"}
        print(f"  WINS vs v2b_alone (of 7): {wins}")
        all_res[str(seed)] = {"per_family": fam_res, "means": means, "wins": wins}

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"per_seed": all_res, "config": vars(args), "device": str(device)},
              open(out, "w"), indent=2)
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
