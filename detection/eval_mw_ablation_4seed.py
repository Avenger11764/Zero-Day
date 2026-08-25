"""
Multi-window ablation, 4-seeded: does fusion beat single windows, and does M5a help or hurt?

Configurations per family, identical host population (hosts present in both windows):
  w60            60s calibrated score alone
  w300           300s calibrated score alone
  pure_rank_mean rank_mean([60s, 300s])          -- no M5a
  pure_rank_max  rank_max([60s, 300s])           -- no M5a
  m5a_multi      max(rm([m5a,60s]), rm([m5a,300s])) -- shipped M5a inside MW
  three_way_rm   rank_mean([m5a, 60s, 300s])
  rev_multi      max(rm([rev,60s]), rm([rev,300s])) -- revived 87-dim ctx M5a inside MW
  three_way_rev_rm rank_mean([rev, 60s, 300s])
  pure_noisyor_rev  noisyor(rank01(pure_rank_mean), rank01(rev))  -- the other session's 7/7 rule vs MW headline
  pure_rmax_rev     maximum(rank01(pure_rank_mean), rank01(rev))

Graphs, M5a scores and scalers are seed-independent and built ONCE; only the GNN
training (+ revived AE) is repeated per seed. CUDA determinism flags set.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import json
import argparse

os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.graph_builder import build_graphs, normalize_columns, read_flows, _window_key
from detection.gnn_model import GraphAutoencoder
from detection.evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from detection.stub_detector import _get_model
from detection.exp_m5a_revival import (
    RevivedAE, CtxScaler, build_ctx, train_ae, CTX_DIMS,
)


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
        span = torch.where((self.hi - self.lo) > 0, self.hi - self.lo,
                           torch.ones_like(self.hi))
        return torch.clamp((x - self.lo.to(x.device)) / span.to(x.device), 0.0, 1.0)


class PercentileCalibrator:
    def __init__(self, benign_scores):
        self.baseline = np.sort(np.asarray(benign_scores, dtype=np.float64))

    def __call__(self, scores):
        idx = np.searchsorted(self.baseline, np.asarray(scores), side="right")
        return idx / max(len(self.baseline), 1)


def _rank01(x):
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def fuse(score_arrays, method):
    ranked = [_rank01(a) for a in score_arrays]
    if method == "rank_mean":
        return np.mean(ranked, axis=0)
    if method == "rank_max":
        return np.maximum.reduce(ranked)
    raise ValueError(method)


_META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp", "label", "flow_id"]

ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

CONFIGS = ["w60", "w300", "pure_rank_mean", "pure_rank_max", "m5a_multi",
           "three_way_rm", "rev_multi", "three_way_rev_rm",
           "pure_noisyor_rev", "pure_rmax_rev"]


def set_seed(seed):
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def load_benign(limit=None):
    df = normalize_columns(read_flows(FLOWS / "Monday-WorkingHours.pcap_ISCX.csv", limit=limit))
    return df[df["label"].astype(str).str.strip().str.upper() == "BENIGN"]


def pin_canonical(tr):
    feats = tr.drop(columns=[c for c in _META if c in tr.columns], errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    if feats.shape[1] == 77 and "dst_port" in feats.columns:
        feats = feats.drop(columns=["dst_port"])
    return list(feats.columns)


def m5a_host_scores(df, canonical, m5a):
    feats = df[canonical].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    lo, hi = arr.min(axis=0), arr.max(axis=0)
    span = np.where(hi - lo > 0, hi - lo, 1.0)
    x = np.clip((arr - lo) / span, 0.0, 1.0).astype(np.float32)
    with torch.no_grad():
        scores = m5a.anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
    tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
    return tmp.groupby("src_ip")["score"].max().to_dict(), x


def revived_host_scores(df, canonical, revived, ctx_scaler, ref_lo, ref_hi):
    """87-dim revived-AE host scores, same per-host max convention as m5a_host_scores."""
    feats = df[canonical].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    span = np.where(ref_hi - ref_lo > 0, ref_hi - ref_lo, 1.0)
    xl = np.clip((arr - ref_lo) / span, 0.0, 1.0).astype(np.float32)
    wkeys = _window_key(df, 60)
    xc = ctx_scaler.transform(build_ctx(df, wkeys))
    x87 = np.concatenate([xl, xc], axis=1)
    outs = []
    with torch.no_grad():
        dev = next(revived.parameters()).device
        for i in range(0, len(x87), 8192):
            xb = torch.tensor(x87[i:i + 8192]).to(dev)
            outs.append(revived.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(outs)
    tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
    return tmp.groupby("src_ip")["score"].max().to_dict()


def node_scores(graphs, model, scaler, device):
    out = []
    with torch.no_grad():
        for g in graphs:
            ns = model.node_scores(scaler.transform(g.x).to(device),
                                   g.edge_index.to(device)).cpu().numpy()
            out.append((g.hosts, ns))
    return out


def host_mean_scores(graphs, model, scaler, device):
    acc = {}
    for hosts, ns in node_scores(graphs, model, scaler, device):
        for h, s in zip(hosts, ns):
            acc.setdefault(h, []).append(float(s))
    return {h: float(np.mean(v)) for h, v in acc.items()}


def train_model(graphs, scaler, device, epochs):
    model = GraphAutoencoder().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = torch.nn.MSELoss()
    pre = [(scaler.transform(g.x).to(device), g.edge_index.to(device)) for g in graphs]
    for _ in range(epochs):
        total = 0.0
        for x, ei in pre:
            loss = loss_fn(model(x, ei), x)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
    return model, total / max(len(pre), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--epochs-ae", type=int, default=60)
    ap.add_argument("--limit", type=int, default=None, help="row limit for smoke tests")
    ap.add_argument("--out", default="experiments/mw_ablation_4seed.json")
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    tr = load_benign(limit=args.limit)
    print(f"Monday benign flows: {len(tr):,}")
    bg60 = build_graphs(tr, window_seconds=60, k=0)
    bg300 = build_graphs(tr, window_seconds=300, k=0)
    print(f"Benign graphs: 60s={len(bg60)}, 300s={len(bg300)}")

    scaler60 = LogScaler().fit(bg60)
    scaler300 = LogScaler().fit(bg300)

    m5a = _get_model()
    canonical = pin_canonical(tr)
    cal_a = PercentileCalibrator(np.array(list(m5a_host_scores(tr, canonical, m5a)[0].values())))

    # ---- Monday reference scaling for the revived 87-dim AE ----------------
    def _scaled_matrix(df):
        feats = df[canonical].apply(pd.to_numeric, errors="coerce")
        feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return feats.to_numpy(dtype=np.float32)

    ref_arr = _scaled_matrix(tr)
    ref_lo, ref_hi = ref_arr.min(axis=0), ref_arr.max(axis=0)
    span_ref = np.where(ref_hi - ref_lo > 0, ref_hi - ref_lo, 1.0)
    tr_x = np.clip((ref_arr - ref_lo) / span_ref, 0.0, 1.0).astype(np.float32)
    ctx_scaler = CtxScaler().fit(build_ctx(tr, _window_key(tr, 60)))
    tr_x87 = np.concatenate([tr_x, ctx_scaler.transform(build_ctx(tr, _window_key(tr, 60)))], axis=1)

    print("Caching attack graphs + M5a scores (once, seed-independent)...")
    fams = {}
    for family, filename in ATTACK_FILES.items():
        df = normalize_columns(read_flows(FLOWS / filename, limit=args.limit))
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        if not bad:
            continue
        g60 = build_graphs(df, window_seconds=60, k=0)
        g300 = build_graphs(df, window_seconds=300, k=0)
        if not g60 or not g300:
            continue
        a_map, _ = m5a_host_scores(df, canonical, m5a)
        rev_map = None  # computed per seed (revived AE retrains per seed)
        fams[family] = {"g60": g60, "g300": g300, "bad": bad, "a_map": a_map,
                        "df": df, "rev_map": rev_map}
        print(f"  {family}: {len(g60)}x60s {len(g300)}x300s {len(bad)} malicious hosts")

    results = {str(s): {} for s in args.seeds}
    for seed in args.seeds:
        print(f"\n{'=' * 60}\nSEED {seed}\n{'=' * 60}")
        set_seed(seed)
        m60, l60 = train_model(bg60, scaler60, device, args.epochs)
        print(f"  60s final loss: {l60:.6f}")
        m300, l300 = train_model(bg300, scaler300, device, args.epochs)
        print(f"  300s final loss: {l300:.6f}")

        cal60 = PercentileCalibrator(
            np.concatenate([ns for _, ns in node_scores(bg60, m60, scaler60, device)]))
        cal300 = PercentileCalibrator(
            np.concatenate([ns for _, ns in node_scores(bg300, m300, scaler300, device)]))

        # ---- revived 87-dim AE, retrained per seed (same recipe as exp_m5a_revival)
        revived = train_ae(tr_x87, args.epochs_ae, seed, device)
        outs = []
        with torch.no_grad():
            for i in range(0, len(tr_x87), 8192):
                xb = torch.tensor(tr_x87[i:i + 8192]).to(device)
                outs.append(revived.anomaly_score(xb).cpu().numpy())
        _s = np.concatenate(outs)
        _t = pd.DataFrame({"src_ip": tr["src_ip"].values, "score": _s})
        pool_rev = _t.groupby("src_ip")["score"].max()
        cal_rev = PercentileCalibrator(pool_rev.values)
        print(f"  revived AE trained ({tr_x87.shape[1]} dims), pool {len(pool_rev)}")

        for family, d in fams.items():
            if d["rev_map"] is None:
                d["rev_map"] = revived_host_scores(d["df"], canonical, revived,
                                                   ctx_scaler, ref_lo, ref_hi)
            h60 = host_mean_scores(d["g60"], m60, scaler60, device)
            h300 = host_mean_scores(d["g300"], m300, scaler300, device)
            hosts = sorted(set(h60) & set(h300))
            if not hosts:
                continue
            y = np.array([1 if h in d["bad"] else 0 for h in hosts])
            if y.sum() == 0:
                continue
            w60 = cal60(np.array([h60[h] for h in hosts]))
            w300 = cal300(np.array([h300[h] for h in hosts]))
            pa = cal_a(np.array([d["a_map"].get(h, 0.0) for h in hosts]))
            pr = cal_rev(np.array([d["rev_map"].get(h, 0.0) for h in hosts]))

            pure_rm = fuse([w60, w300], "rank_mean")
            scored = {
                "w60": w60,
                "w300": w300,
                "pure_rank_mean": pure_rm,
                "pure_rank_max": fuse([w60, w300], "rank_max"),
                "m5a_multi": np.maximum(fuse([pa, w60], "rank_mean"),
                                        fuse([pa, w300], "rank_mean")),
                "three_way_rm": fuse([pa, w60, w300], "rank_mean"),
                "rev_multi": np.maximum(fuse([pr, w60], "rank_mean"),
                                        fuse([pr, w300], "rank_mean")),
                "three_way_rev_rm": fuse([pr, w60, w300], "rank_mean"),
                "pure_noisyor_rev": 1 - (1 - _rank01(pure_rm)) * (1 - _rank01(pr)),
                "pure_rmax_rev": np.maximum(_rank01(pure_rm), _rank01(pr)),
            }
            row = {}
            for name, sc in scored.items():
                order = np.argsort(sc)[::-1]
                row[name] = {"auc": round(float(roc_auc(sc, y)), 4),
                             "p100": round(float(y[order[:100]].mean()), 3)}
            results[str(seed)][family] = row
            print(f"  {family}: " +
                  " ".join(f"{n}={row[n]['auc']:.4f}" for n in CONFIGS))

    print("\n" + "=" * 70)
    print(f"MEAN AUC PER CONFIG ({len(args.seeds)} seeds)")
    print("=" * 70)
    summary = {}
    for name in CONFIGS:
        per_seed = []
        for s in args.seeds:
            vals = [results[str(s)][f][name]["auc"] for f in results[str(s)]]
            per_seed.append(float(np.mean(vals)))
        mu, sd = float(np.mean(per_seed)), float(np.std(per_seed, ddof=1))
        summary[name] = {"mean": round(mu, 4), "std": round(sd, 4), "per_seed": per_seed}
        print(f"  {name:<15} {mu:.4f} +/- {sd:.4f}   {[round(v, 4) for v in per_seed]}")

    out = ROOT / args.out
    json.dump({"per_family": results, "summary": summary}, open(out, "w"), indent=2)
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
