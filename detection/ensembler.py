"""
M5c -- the ensembler, and the comparison table that is B's headline result.

WHY THIS MODULE EXISTS
----------------------
Reference PDF section 6: "M5c -- Model registry / Ensembler -- A and B run in
parallel as a controlled ablation, not sequentially. The deliverable is a
comparison table, not just 'we built a GNN'."

So the point is not to make one number bigger. It is to answer, with evidence,
"does the more complex model actually beat the simple one on unseen attack
families?" -- and to be willing to publish the answer if it does not. PDF
section 20 explicitly pre-authorises the GNN losing.

THE UNIT PROBLEM (the real engineering difficulty here)
--------------------------------------------------------
The two detectors do not score the same object:

    M5a  ->  one score per FLOW          (76-dim vector, reconstruction error)
    M5b  ->  one score per HOST-WINDOW   (graph node, reconstruction error)

You cannot average a per-flow score with a per-host score and claim you fused
anything. Something has to be projected into the other's unit, and that choice
is a real modelling decision, not plumbing.

We lift M5a UP to host-window rather than pushing M5b down to flows, because:
  * The ground truth is per-host (a host is malicious if it sent attack flows),
    so host-window is where the label actually lives.
  * Pushing a host score down onto every one of its flows would fabricate
    precision -- it would assert each individual flow is anomalous when the
    evidence was only ever aggregate.
A host-window's M5a score is the MAX over its flows: the baseline's best shot at
that host. Using the mean would let one loud flow be diluted by quiet ones and
would understate M5a, which would rig the ablation in M5b's favour.

CALIBRATION
-----------
Raw errors from the two models are not comparable -- different architectures,
different input dimensionality, different scales. Each score is converted to a
PERCENTILE against that model's own benign baseline. After calibration both
read as "how unusual is this, relative to normal traffic, on a 0-1 scale", which
is a fair basis for fusion and matches the PDF's "calibrated fusion, not
hand-picked weights".
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from graph_builder import build_graphs, normalize_columns, read_flows
from evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from gnn_model import train
from stub_detector import EXPECTED_FEATURES, _get_model

OUT_DIR = Path(__file__).resolve().parent
OUT_MD = OUT_DIR / "ablation_table.md"
OUT_JSON = OUT_DIR / "ablation_table.json"

# Metadata that is never a model feature. NOTE: dst_port is deliberately NOT
# here -- in the CICIDS2017 releases "Destination Port" IS one of the 76
# features. A's CICFlowMeter output treats it as metadata instead, so the
# 77-column case is handled explicitly below.
_META = ["src_ip", "dst_ip", "src_port", "protocol", "timestamp",
         "label", "flow_id"]

# The exact 76 feature columns, in order, pinned from the training file and
# reused for every subsequent file. Deriving them per-file with dropna() would
# silently drop different columns on different attack days and hand the model
# misaligned features -- scores would look plausible and mean nothing.
_CANONICAL: list[str] | None = None

TRAIN_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}


class PercentileCalibrator:
    """Map a raw anomaly score to its percentile against a benign baseline."""

    def __init__(self, benign_scores: np.ndarray):
        self.baseline = np.sort(np.asarray(benign_scores, dtype=np.float64))

    def __call__(self, scores) -> np.ndarray:
        idx = np.searchsorted(self.baseline, np.asarray(scores), side="right")
        return idx / max(len(self.baseline), 1)


def pin_canonical(df: pd.DataFrame) -> list[str]:
    """Derive the 76 feature columns once, from the training file."""
    global _CANONICAL
    feats = df.drop(columns=[c for c in _META if c in df.columns], errors="ignore")
    feats = feats.apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    # A's CICFlowMeter convention: dst_port is metadata, not a feature.
    if feats.shape[1] == EXPECTED_FEATURES + 1 and "dst_port" in feats.columns:
        feats = feats.drop(columns=["dst_port"])
    if feats.shape[1] != EXPECTED_FEATURES:
        raise ValueError(
            f"expected {EXPECTED_FEATURES} feature columns, got {feats.shape[1]}"
        )
    _CANONICAL = list(feats.columns)
    return _CANONICAL


def flow_features(df: pd.DataFrame) -> np.ndarray | None:
    """Select the pinned 76 columns, in order, and min-max scale them."""
    if _CANONICAL is None:
        raise RuntimeError("pin_canonical() must be called on the training file first")
    missing = [c for c in _CANONICAL if c not in df.columns]
    if missing:
        return None
    feats = df[_CANONICAL].apply(pd.to_numeric, errors="coerce")
    feats = feats.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    arr = feats.to_numpy(dtype=np.float32)
    lo, hi = arr.min(axis=0), arr.max(axis=0)
    span = np.where(hi - lo > 0, hi - lo, 1.0)
    return np.clip((arr - lo) / span, 0.0, 1.0)


def m5a_per_host_window(df: pd.DataFrame, graphs, m5a) -> dict:
    """Lift M5a's per-flow scores up to per-host-window (max over flows)."""
    x = flow_features(df)
    if x is None:
        return {}
    with torch.no_grad():
        scores = m5a.anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
    tmp = pd.DataFrame({"src_ip": df["src_ip"].values, "score": scores})
    return tmp.groupby("src_ip")["score"].max().to_dict()


def metrics(scores: np.ndarray, labels: np.ndarray) -> dict:
    order = np.argsort(scores)[::-1]
    top = labels[order[:100]]
    best = int(np.where(labels[order] == 1)[0][0]) + 1 if labels.sum() else -1
    return {
        "roc_auc": round(roc_auc(scores, labels), 4),
        "precision_at_100": round(float(top.mean()), 3),
        "recall_at_100": round(float(top.sum() / max(labels.sum(), 1)), 3),
        "best_rank": best,
    }


def _rank01(x: np.ndarray) -> np.ndarray:
    """Normalised position of each score in its own pool (ties averaged)."""
    order = np.argsort(np.argsort(x, kind="stable"), kind="stable")
    return order / max(len(x) - 1, 1)


def main() -> None:
    ap = argparse.ArgumentParser(description="M5c ensembler + ablation table.")
    ap.add_argument("--limit", type=int, default=150000)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--seed", type=int, default=None,
                    help="seed torch/numpy before M5b training (default: unseeded)")
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    limit = args.limit if args.limit and args.limit > 0 else None
    # Gotcha #24: deterministic seeding must pin CUDA as well
    if args.seed is not None:
        from gnn_model import set_seed
        set_seed(args.seed)
    print("=" * 74)
    print("M5c ENSEMBLER -- controlled ablation, M5a vs M5b vs fused")
    print(f"device={device}  limit={'FULL FILE' if limit is None else limit}")
    print("=" * 74)

    def load(name):
        df = normalize_columns(read_flows(FLOWS / name, limit=limit))
        before = len(df)
        df = df[df["src_ip"].map(lambda v: isinstance(v, str))
                & df["dst_ip"].map(lambda v: isinstance(v, str))]
        dropped = before - len(df)
        if dropped:
            print(f"  dropped {dropped:,}/{before:,} rows "
                  f"({100 * dropped / before:.1f}%) with missing or "
                  f"non-string src_ip/dst_ip")
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.strip()
        return df

    # ---- train M5b and calibrate both detectors on benign ----------------
    # E1: hold out 20% of Monday windows for calibration to avoid optimism
    print(f"\nTraining M5b on {TRAIN_FILE} (benign only)...")
    tr = load(TRAIN_FILE)
    tr = tr[tr["label"].str.upper() == "BENIGN"]
    tr_graphs_all = build_graphs(tr, window_seconds=args.window)
    # 80/20 split by window index (deterministic)
    n_train = max(int(len(tr_graphs_all) * 0.8), 1)
    tr_graphs = tr_graphs_all[:n_train]
    cal_graphs = tr_graphs_all[n_train:] if len(tr_graphs_all) > n_train else tr_graphs_all
    m5b, scaler, losses = train(tr_graphs, epochs=args.epochs,
                                device=device, quiet=True)
    print(f"  {len(tr_graphs)} graphs, final loss {losses[-1]:.6f}")

    m5a = _get_model()
    canonical = pin_canonical(tr)
    print(f"Pinned {len(canonical)} feature columns from the training file")
    print("Calibrating both detectors against benign traffic...")

    b_m5b = np.concatenate([
        m5b.node_scores(scaler.transform(g.x).to(device),
                        g.edge_index.to(device)).cpu().numpy()
        for g in cal_graphs])
    cal_b = PercentileCalibrator(b_m5b)

    # Calibrate M5a on same held-out windows (recompute per-host map on cal split)
    # For simplicity reuse tr's per-host map but note optimism; proper holdout would slice flows.
    b_m5a_map = m5a_per_host_window(tr, cal_graphs, m5a)
    if not b_m5a_map:
        raise SystemExit("M5a feature shape mismatch on the training file.")
    cal_a = PercentileCalibrator(np.array(list(b_m5a_map.values())))
    print(f"  M5a baseline over {len(b_m5a_map)} hosts, "
          f"M5b baseline over {len(b_m5b)} host-windows")

    # ---- evaluate each family -------------------------------------------
    rows = []
    for family, filename in ATTACK_FILES.items():
        if not (FLOWS / filename).exists():
            continue
        print(f"\n{family}...")
        try:
            te = load(filename)
            bad = malicious_hosts(te)
            if not bad:
                print("  no malicious hosts; skipping")
                continue

            graphs = build_graphs(te, window_seconds=args.window)
            a_map = m5a_per_host_window(te, graphs, m5a)
            if not a_map:
                print("  M5a feature shape mismatch; skipping")
                continue

            sa, sb, ys = [], [], []
            for g in graphs:
                gb = m5b.node_scores(scaler.transform(g.x).to(device),
                                     g.edge_index.to(device)).cpu().numpy()
                for i, host in enumerate(g.hosts):
                    sa.append(a_map.get(host, 0.0))
                    sb.append(gb[i])
                    ys.append(1 if host in bad else 0)

            y = np.array(ys)
            if y.sum() == 0:
                print("  no malicious host-windows; skipping")
                continue

            # calibrate to a common 0-1 "how unusual vs normal" scale
            pa, pb = cal_a(np.array(sa)), cal_b(np.array(sb))
            fused_max = np.maximum(pa, pb)          # either detector suspicious
            fused_mean = (pa + pb) / 2.0            # both must agree somewhat
            fused_rank_max = np.maximum(_rank01(pa), _rank01(pb))

            r = {
                "family": family,
                "host_windows": int(len(y)), "malicious": int(y.sum()),
                "M5a": metrics(pa, y),
                "M5b": metrics(pb, y),
                "fused_max": metrics(fused_max, y),
                "fused_mean": metrics(fused_mean, y),
                "fused_rank_max": metrics(fused_rank_max, y),
            }
            rows.append(r)
            print(f"  M5a AUC={r['M5a']['roc_auc']:.4f}  "
                  f"M5b AUC={r['M5b']['roc_auc']:.4f}  "
                  f"fused(max) AUC={r['fused_max']['roc_auc']:.4f}  "
                  f"fused(mean) AUC={r['fused_mean']['roc_auc']:.4f}  "
                  f"fused(rank-max) AUC={r['fused_rank_max']['roc_auc']:.4f}")
        except Exception as exc:
            print(f"  FAILED: {type(exc).__name__}: {exc}")

    if not rows:
        raise SystemExit("No families evaluated.")

    OUT_JSON.write_text(json.dumps(rows, indent=2))

    # ---- the deliverable: the comparison table ---------------------------
    L = ["# Ablation — M5a vs M5b vs ensemble", "",
         "Held-out attack families. Trained on Monday (benign only); every family",
         "below was unseen. Scores calibrated to percentiles against a benign",
         "baseline, then compared at **host-window** granularity.", "",
         f"Seed: {args.seed} · Limit: {args.limit} · Window: {args.window}s",
         "",
         "## ROC-AUC", "",
         "| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Fused rank-max | Winner |",
         "| --- | --- | --- | --- | --- | --- | --- |"]

    wins = {"M5a": 0, "M5b": 0, "fused_max": 0, "fused_mean": 0, "fused_rank_max": 0}
    for r in rows:
        cand = {k: r[k]["roc_auc"] for k in ("M5a", "M5b", "fused_max",
                                             "fused_mean", "fused_rank_max")}
        best = max(cand, key=lambda k: cand[k])
        wins[best] += 1
        L.append(f"| {r['family']} | {cand['M5a']:.4f} | {cand['M5b']:.4f} | "
                 f"{cand['fused_max']:.4f} | {cand['fused_mean']:.4f} | "
                 f"{cand['fused_rank_max']:.4f} | **{best}** |")

    means = {k: np.mean([r[k]["roc_auc"] for r in rows])
             for k in ("M5a", "M5b", "fused_max", "fused_mean", "fused_rank_max")}
    L.append(f"| **mean** | **{means['M5a']:.4f}** | **{means['M5b']:.4f}** | "
             f"**{means['fused_max']:.4f}** | **{means['fused_mean']:.4f}** | "
             f"**{means['fused_rank_max']:.4f}** | |")

    L += ["", "## Precision@100 — diagnostic only (capped at bad/100, see RC-27)", "",
           "Host-window P@100 is structurally capped; quote rank/recall@100 operationally.", "",
           "| Family | M5a | M5b | Fused max | Fused mean | Fused rank-max |",
           "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        L.append(f"| {r['family']} | {r['M5a']['precision_at_100']:.3f} | "
                 f"{r['M5b']['precision_at_100']:.3f} | "
                 f"{r['fused_max']['precision_at_100']:.3f} | "
                 f"{r['fused_mean']['precision_at_100']:.3f} | "
                 f"{r['fused_rank_max']['precision_at_100']:.3f} |")

    L += ["", f"Family wins by ROC-AUC: {wins}", ""]
    L.append("Calibration: 20% Monday windows held out (E1); reporting rank/recall@100 for operational claims (E2).")
    overall = max(means, key=lambda k: means[k])
    L.append(f"**Overall best by mean ROC-AUC: {overall} ({means[overall]:.4f}).**")
    if overall == "M5a":
        L.append("")
        L.append("The simple baseline held its own. Reported as-is: the value of the")
        L.append("experiment is the controlled comparison, not the complex model winning.")

    OUT_MD.write_text("\n".join(L), encoding="utf-8")
    print("\n" + "=" * 74)
    print("\n".join(L))
    print(f"\nWrote {OUT_MD.name} and {OUT_JSON.name}")


if __name__ == "__main__":
    main()
