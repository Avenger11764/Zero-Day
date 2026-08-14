"""
E1 — SEED-REPEAT PROTOCOL FOR THE SHIPPED STACK (2026-08-13).

One checkpoint is luck. Every number this project reports for the production
stack -- M5b alone 0.8391 AUC, agreement fusion 0.8304 -- comes from ONE
5-member ensemble plus one edge model. CLAUDE.md gotcha #11: two identical
unseeded runs differed by 2.5 AUC points, and PortScan moved 6.5 points on
weight initialisation alone. No comparison with the literature bars
(PIKACHU 0.977, HybridSAGE 0.9957 AUC) or with each other is meaningful until
this protocol has put a band around the true number.

This script trains N independent full checkpoints -- each one a 5-member
ensemble + edge model + M5a calibrator, exactly the shape of the shipped
gnn_autoencoder_v1.pt -- with disjoint seed ranges, and scores every one
through the REAL entry point, alert_pipeline.score_window(), at 300s with the
production config (fusion="agreement", edge_score="rank_mean",
m5a_calibration="rolling").

Reported: per-family and overall mean ± std across the N checkpoints, for
M5b-alone and agreement fusion, anchored against the shipped checkpoint's
numbers. This is the protocol every retrained checkpoint must be judged by.

The shipped checkpoint's recipe (from git history / CHANGELOG):
  - train_ensemble on Monday benign graphs (5 members, seeds 0-4)
  - train_edge_model on the same graphs
  - m5a_calibrator = ScoreCalibrator over M5a per-host scores on Monday
    (max over flows within the host, ensembler.m5a_per_host_window)
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_SYSROOT = _Path(__file__).resolve().parent.parent
_sys.path.insert(0, str(_SYSROOT / "detection"))

import argparse
import json
import time
from typing import Any

import numpy as np
import torch

from evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from graph_builder import build_graphs, normalize_columns, read_flows
from gnn_model import (EdgeScaler, ScoreCalibrator, train_edge_model,
                       GraphAutoencoder, NodeScaler, train, save_ensemble)
from stub_detector import _get_model
import alert_pipeline as AP
import ensembler as ENS

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OUT_DIR = _Path(__file__).resolve().parent
CKPT_DIR = OUT_DIR / "seed_checkpoints"
CKPT_DIR.mkdir(exist_ok=True)

TRAIN_FILE = FLOWS / "Monday-WorkingHours.pcap_ISCX.csv"

ATTACK_FILES = {
    "PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "WebAttacks": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Patator (FTP/SSH)": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "DoS / Heartbleed": "Wednesday-workingHours.pcap_ISCX.csv",
}

# The shipped anchor, so every table reads against reality.
SHIPPED = {"M5b alone": (0.8391, 0.324), "agreement": (0.8304, 0.313)}


def metrics(s: np.ndarray, y: np.ndarray) -> dict:
    if y.sum() == 0 or y.sum() == len(y):
        return {"roc_auc": None, "precision_at_100": None}
    order = np.argsort(s)[::-1]
    return {"roc_auc": round(float(roc_auc(s, y)), 4),
            "precision_at_100": round(float(y[order[:100]].mean()), 3)}


def train_ensemble_seeded(graphs, base_seed: int, n_seeds: int = 5,
                          epochs: int = 200, lr: float = 0.01,
                          device=None, log_scale: bool = True):
    """train_ensemble() but with a seed offset: seeds base_seed..base_seed+n-1."""
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    members = []
    for i in range(n_seeds):
        seed = base_seed + i
        torch.manual_seed(seed)
        np.random.seed(seed)
        model, scaler, losses = train(graphs, epochs=epochs, lr=lr, device=device,
                                      quiet=True, log_scale=log_scale)
        with torch.no_grad():
            benign = np.concatenate([
                model.node_scores(scaler.transform(g.x).to(device),
                                  g.edge_index.to(device)).cpu().numpy()
                for g in graphs])
        members.append((model, scaler, ScoreCalibrator(benign)))
    return members


def m5a_monday_calibrator(monday_df, graphs, m5a) -> ScoreCalibrator:
    """Replicate the shipped checkpoint's M5a calibrator: per-host max over
    Monday's flows (ensembler.m5a_per_host_window), quantiled."""
    scores = ENS.m5a_per_host_window(monday_df, graphs, m5a)
    if not scores:
        raise RuntimeError("m5a lift failed")
    return ScoreCalibrator(np.array(list(scores.values())))


def build_group(base_seed: int, window: int, limit, monday_df, m5a, feats):
    """Train one full checkpoint shape and return (path, graphs, monday_df)."""
    t0 = time.time()
    graphs = build_graphs(monday_df, window_seconds=window, quiet=True)
    print(f"  [{base_seed}] {len(graphs)} training graphs in {time.time()-t0:.0f}s", flush=True)

    t0 = time.time()
    members = train_ensemble_seeded(graphs, base_seed=base_seed)
    print(f"  [{base_seed}] ensemble trained in {time.time()-t0:.0f}s", flush=True)

    t0 = time.time()
    em, es = train_edge_model(graphs)
    _ = EdgeScaler()
    print(f"  [{base_seed}] edge model trained in {time.time()-t0:.0f}s", flush=True)

    cal = m5a_monday_calibrator(monday_df, graphs, m5a)
    path = CKPT_DIR / f"ensemble_seed{base_seed}.pt"
    save_ensemble(members, path, edge=(em, es), m5a_calibrator=cal)
    print(f"  [{base_seed}] saved -> {path.name} ({path.stat().st_size/1024:.0f} KB)")
    return path


def eval_checkpoint(path, limit, feats) -> dict:
    """Point alert_pipeline at one checkpoint and score all families at 300s
    with production config. Returns per-family rows like production_eval."""
    AP.MODEL_PATH = path
    AP._m5b = None
    AP._ensemble = None
    AP._edge = None
    AP._m5a_cal = None
    AP._load_m5b()

    rows = {}
    for family, fn in ATTACK_FILES.items():
        p = FLOWS / fn
        if not p.exists():
            continue
        df = normalize_columns(read_flows(p, limit=limit))
        if "label" in df.columns:
            df["label"] = df["label"].astype(str).str.strip()
        bad = malicious_hosts(df)
        if not bad:
            continue
        fam = {}
        for tag, kwargs in (("M5b alone", {}),
                            ("agreement", {"feature_columns": feats})):
            alerts = AP.score_window(df, window_seconds=300,
                                     edge_score="rank_mean",
                                     fusion="agreement",
                                     m5a_calibration="rolling",
                                     feature_columns=kwargs.get("feature_columns"),
                                     fusion_tau=0.5)
            if not alerts:
                continue
            s = np.array([a["anomaly_score"] for a in alerts])
            y = np.array([1 if a["src_ip"] in bad else 0 for a in alerts])
            fam[tag] = metrics(s, y)
        if fam:
            rows[family] = fam
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed-repeat the shipped stack.")
    ap.add_argument("--groups", type=int, default=3,
                    help="independent checkpoints to train (each 5 seeds)")
    ap.add_argument("--window", type=int, default=300,
                    help="training window; the eval is always 300s")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--base", type=int, default=0,
                    help="first seed of the first group")
    args = ap.parse_args()
    limit = args.limit if args.limit and args.limit > 0 else None

    t_start = time.time()
    print("E1 seed-repeat protocol")
    print(f"groups={args.groups}  train_window={args.window}s  limit={limit}")

    t0 = time.time()
    monday_df = normalize_columns(read_flows(TRAIN_FILE, limit=limit))
    monday_df = monday_df[monday_df["label"].astype(str).str.strip().str.upper() == "BENIGN"]
    print(f"Monday benign: {len(monday_df):,} flows in {time.time()-t0:.0f}s")

    feat_cols = ENS.pin_canonical(monday_df)
    m5a = _get_model()
    print(f"M5a: {len(feat_cols)} feature columns, model loaded")

    results: dict[str, Any] = {"meta": {"groups": args.groups,
                                        "train_window": args.window,
                                        "limit": limit,
                                        "base": args.base,
                                        "shipped_anchor": SHIPPED},
                               "checkpoints": {}}
    for g in range(args.groups):
        base = args.base + g * 5
        t0 = time.time()
        print(f"\n=== group {g}: seeds {base}..{base+4} ===", flush=True)
        path = build_group(base, args.window, limit, monday_df, m5a, feat_cols)
        rows = eval_checkpoint(path, limit, feat_cols)
        results["checkpoints"][str(base)] = {"path": str(path), "families": rows}
        for fam, r in rows.items():
            print(f"  {fam:<20} M5b={r.get('M5b alone', {}).get('roc_auc')} "
                  f"agree={r.get('agreement', {}).get('roc_auc')}")
        print(f"  group done in {time.time()-t0:.0f}s", flush=True)

    # Aggregate: mean ± std across checkpoints, per family and overall.
    L = ["# E1 — seed-repeat protocol for the shipped stack", "",
         f"{args.groups} independent checkpoints, seeds "
         f"{args.base}..{args.base + args.groups*5 - 1}, train window "
         f"{args.window}s, eval 300s / agreement / rank_mean / rolling as "
         "production ships. Each checkpoint = 5-member ensemble + edge model "
         "+ M5a calibrator, trained on Monday benign. Anchored against the "
         "shipped checkpoint (single draw): M5b alone 0.8391 / 0.324, "
         "agreement 0.8304 / 0.313.", ""]
    for tag in ("M5b alone", "agreement"):
        L += [f"## {tag}", "", "| family | mean AUC ± std | mean P@100 ± std |",
              "|---|---|---|"]
        fams = {}
        for ckpt in results["checkpoints"].values():
            for fam, r in ckpt["families"].items():
                if tag in r and r[tag]["roc_auc"] is not None:
                    fams.setdefault(fam, []).append(r[tag])
        aucs, p100s = [], []
        for fam in sorted(fams):
            v = fams[fam]
            a = [x["roc_auc"] for x in v]
            p = [x["precision_at_100"] for x in v]
            aucs += a
            p100s += p
            L.append(f"| {fam} | {np.mean(a):.4f} ± {np.std(a):.4f} "
                     f"| {np.mean(p):.3f} ± {np.std(p):.3f} |")
        L.append(f"| **mean** | **{np.mean(aucs):.4f} ± {np.std(aucs):.4f}** "
                 f"| **{np.mean(p100s):.3f} ± {np.std(p100s):.3f}** |")
        L.append("")
    L += ["## Reading this", "",
          "- The ± column is the honest uncertainty band on every production "
          "number. Differences smaller than it (and the 6-point rule) are "
          "noise; differences larger survive retraining.",
          "- If the band straddles the shipped anchor, the anchor was a fair "
          "draw and the fix/improvement claims stand. If it misses, the "
          "anchor was luck one way or the other."]
    (OUT_DIR / "seed_protocol.md").write_text("\n".join(L), encoding="utf-8")
    (OUT_DIR / "seed_protocol.json").write_text(json.dumps(results, indent=2))
    print("\n" + "\n".join(L))
    print(f"\ntotal {time.time()-t_start:.0f}s")


if __name__ == "__main__":
    main()