"""
Non-relational baselines on IDENTICAL host-window features (paper Table: "same
features, no message passing").

For each seed: build v2 host-window feature matrices from Monday benign + each
attack family, then fit three classic detectors on Monday and score attack days:
  pca  - PCA reconstruction error (95% variance)
  if   - Isolation Forest
  mlpae- plain MLP autoencoder (same hidden=32 / latent=8 as GraphAE, no graph)
Same held-out-family protocol, same units, same metrics (AUC, attacker ranks,
recall@100) as eval_mw_ablation_4seed.py. Graphs are built once; only the
models are re-fit per seed.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import json
import argparse

os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.eval_mw_ablation_4seed import (
    ATTACK_FILES, set_seed, load_benign,
)
from detection.graph_builder import build_graphs, normalize_columns, read_flows
from detection.evaluate_gnn import FLOWS, roc_auc


def window_matrix(graphs):
    """All host-windows as one matrix, plus per-window labels filled later."""
    xs, meta = [], []
    for g in graphs:
        for i, h in enumerate(g.hosts):
            xs.append(g.x[i].numpy())
            meta.append(h)
    return np.stack(xs).astype(np.float32), meta


class MLPAE(torch.nn.Module):
    def __init__(self, in_dim, hidden=32, latent=8):
        super().__init__()
        self.enc = torch.nn.Sequential(
            torch.nn.Linear(in_dim, hidden), torch.nn.ReLU(),
            torch.nn.Linear(hidden, latent))
        self.dec = torch.nn.Sequential(
            torch.nn.Linear(latent, hidden), torch.nn.ReLU(),
            torch.nn.Linear(hidden, in_dim))

    def forward(self, x):
        return self.dec(self.enc(x))


def fit_pca(X, n_components=0.95):
    Xc = X.mean(axis=0)
    Xs = X - Xc
    # log1p first to match LogScaler philosophy, then standardise
    Xs = np.log1p(np.clip(X, min=0))
    mu, sd = Xs.mean(axis=0), Xs.std(axis=0) + 1e-9
    Z = (Xs - mu) / sd
    C = np.cov(Z.T)
    w, V = np.linalg.eigh(C)
    order = np.argsort(w)[::-1]
    w, V = w[order], V[:, order]
    k = max(1, int(np.searchsorted(np.cumsum(w) / w.sum(), n_components) + 1))
    return {"mu": mu, "sd": sd, "V": V[:, :k], "mean": Xc}


def score_pca(model, X):
    Z = (np.log1p(np.clip(X, min=0)) - model["mu"]) / model["sd"]
    R = Z @ model["V"] @ model["V"].T
    return ((Z - R) ** 2).mean(axis=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    tr = load_benign(limit=args.limit)
    print(f"Monday benign flows: {len(tr):,}")
    bg = build_graphs(tr, window_seconds=60, k=0, feature_set="v2")
    Xtr, _ = window_matrix(bg)
    print(f"Benign host-windows: {Xtr.shape}")

    fams = {}
    for family, filename in ATTACK_FILES.items():
        df = normalize_columns(read_flows(FLOWS / filename))
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        df["label"] = df["label"].astype(str).str.strip()
        bad = set(df.loc[df["label"].str.upper() != "BENIGN", "src_ip"].unique())
        g = build_graphs(df, window_seconds=60, k=0, feature_set="v2")
        if not bad or not g:
            continue
        X, hosts = window_matrix(g)
        y = np.array([1 if h in bad else 0 for h in hosts])
        if y.sum() == 0:
            continue
        fams[family] = {"X": X, "y": y}
        print(f"  {family}: {X.shape[0]} windows, {int(y.sum())} attackers")

    results = {str(s): {} for s in args.seeds}
    for seed in args.seeds:
        print(f"\n===== SEED {seed} =====")
        set_seed(seed)
        from sklearn.ensemble import IsolationForest
        iso = IsolationForest(n_estimators=200, random_state=seed,
                              contamination="auto").fit(Xtr)
        pca = fit_pca(Xtr)
        Xtr_t = torch.tensor(np.log1p(np.clip(Xtr, min=0)), dtype=torch.float32)
        mu = Xtr_t.mean(dim=0); sd = Xtr_t.std(dim=0) + 1e-9
        ae = MLPAE(Xtr.shape[1]).to(device)
        opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
        loss_fn = torch.nn.MSELoss()
        Xn = ((Xtr_t - mu) / sd).to(device)
        for epoch in range(100):
            idx = torch.randperm(len(Xn))
            for i in range(0, len(Xn), 4096):
                xb = Xn[idx[i:i + 4096]]
                loss = loss_fn(ae(xb), xb)
                opt.zero_grad(); loss.backward(); opt.step()

        for family, d in fams.items():
            X, y = d["X"], d["y"]
            Xt = torch.tensor(np.log1p(np.clip(X, min=0)), dtype=torch.float32)
            Xns = ((Xt - mu) / sd).to(device)
            with torch.no_grad():
                ae_score = ((ae(Xns) - Xns) ** 2).mean(dim=1).cpu().numpy()
            if_score = -iso.score_samples(X)
            pca_score = score_pca(pca, X)

            row = {}
            for name, sc in [("pca", pca_score), ("if", if_score),
                             ("mlpae", ae_score)]:
                order = np.argsort(sc)[::-1]
                ranks = sorted(int(np.where(order == i)[0][0]) + 1
                               for i in np.where(y == 1)[0])
                row[name] = {
                    "auc": round(float(roc_auc(sc, y)), 4),
                    "r100": round(float(y[order[:100]].mean()), 3),
                    "best_rank": int(min(ranks)) if ranks else None,
                    "attacker_ranks": ranks,
                }
            results[str(seed)][family] = row
            print(f"  {family}: " + " ".join(
                f"{n}={row[n]['auc']:.4f}" for n in ("pca", "if", "mlpae")))

    print("\n=== BASELINE SUMMARY (mean AUC over seeds) ===")
    summary = {}
    for name in ("pca", "if", "mlpae"):
        per_seed = [np.mean([results[str(s)][f][name]["auc"]
                             for f in results[str(s)]]) for s in args.seeds]
        summary[name] = round(float(np.mean(per_seed)), 4)
        print(f"  {name:<6} {np.mean(per_seed):.4f} "
              f"(per-seed {[round(v, 4) for v in per_seed]})")

    out = ROOT / "experiments" / "baselines_4seed.json"
    json.dump({"per_family": results, "summary": summary},
              open(out, "w"), indent=2)
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
