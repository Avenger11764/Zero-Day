"""
Full held-out-attack-family sweep for M5b across every CICIDS2017 attack day.

Trains ONCE on Monday (100% benign), then evaluates every attack family the
model has never seen. Emits a markdown table and JSON for the results slide.

Training once and reusing the model is not just a speed optimisation -- it is
the protocol. One model, trained on normal traffic only, judged against every
family. Retraining per family would quietly leak information about each attack
into its own evaluation.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch

from graph_builder import NODE_FEATURE_NAMES, build_graphs, normalize_columns, read_flows
from evaluate_gnn import FLOWS, malicious_hosts, roc_auc
from gnn_model import train

OUT_JSON = Path(__file__).resolve().parent / "evaluation_results.json"
OUT_MD = Path(__file__).resolve().parent / "evaluation_results.md"

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

LIMIT = 150_000
WINDOW = 60
EPOCHS = 60


def load(name, limit=LIMIT):
    df = normalize_columns(read_flows(FLOWS / name, limit=limit))
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
    return df


def main() -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("=" * 74)
    print("M5b EVALUATION SUITE -- held-out attack families, real CICIDS2017")
    print("=" * 74)

    print(f"\nTraining once on {TRAIN_FILE} (benign only)...")
    tr = load(TRAIN_FILE)
    tr = tr[tr["label"].str.upper() == "BENIGN"]
    tr_graphs = build_graphs(tr, window_seconds=WINDOW)
    model, scaler, losses = train(tr_graphs, epochs=EPOCHS, device=device, quiet=True)
    print(f"  {len(tr)} flows -> {len(tr_graphs)} graphs, final loss {losses[-1]:.6f}")

    results = []
    for family, filename in ATTACK_FILES.items():
        path = FLOWS / filename
        if not path.exists():
            print(f"\n  SKIP {family}: {filename} not found")
            continue
        print(f"\n{family}...")
        try:
            te = load(filename)
            bad = malicious_hosts(te)
            if not bad:
                print(f"  no malicious hosts in first {LIMIT} rows -- skipping")
                continue

            graphs = build_graphs(te, window_seconds=WINDOW)
            scores, labels, feats = [], [], []
            for g in graphs:
                x = scaler.transform(g.x).to(device)
                scores.append(model.node_scores(x, g.edge_index.to(device)).cpu().numpy())
                labels.append(np.array([1 if h in bad else 0 for h in g.hosts]))
                feats.append(g.x.numpy())

            s = np.concatenate(scores)
            y = np.concatenate(labels)
            X = np.concatenate(feats)
            if y.sum() == 0:
                print("  no malicious host-windows -- skipping")
                continue

            order = np.argsort(s)[::-1]
            auc = roc_auc(s, y)
            best = int(np.where(y[order] == 1)[0][0]) + 1
            p100 = float(y[order[:100]].mean())
            recall100 = float(y[order[:100]].sum() / y.sum())

            # which node feature separated the classes most
            seps = {}
            for i, nm in enumerate(NODE_FEATURE_NAMES):
                b = X[y == 0, i].mean()
                seps[nm] = float(X[y == 1, i].mean() / b) if b > 0 else float("inf")
            top_feat = max(seps, key=lambda k: seps[k])

            row = {
                "family": family, "file": filename,
                "host_windows": int(len(s)), "malicious": int(y.sum()),
                "roc_auc": round(auc, 4), "precision_at_100": round(p100, 3),
                "recall_at_100": round(recall100, 3), "best_rank": best,
                "mean_score_malicious": float(s[y == 1].mean()),
                "mean_score_benign": float(s[y == 0].mean()),
                "top_feature": top_feat,
                "top_feature_separation": round(seps[top_feat], 1),
                "attackers": sorted(bad)[:5],
            }
            results.append(row)
            print(f"  AUC={auc:.4f}  rank={best}/{len(s)}  "
                  f"P@100={p100:.3f}  top={top_feat} ({seps[top_feat]:.0f}x)")
        except Exception as exc:
            print(f"  FAILED: {type(exc).__name__}: {exc}")

    OUT_JSON.write_text(json.dumps(results, indent=2))

    lines = [
        "# M5b evaluation — held-out attack families",
        "",
        f"Trained once on `{TRAIN_FILE}` (benign only), {len(tr_graphs)} graphs, "
        f"{EPOCHS} epochs. Every family below was unseen during training.",
        "",
        "| Attack family | ROC-AUC | P@100 | R@100 | Best rank | Top feature | Sep |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in sorted(results, key=lambda r: -r["roc_auc"]):
        lines.append(
            f"| {r['family']} | **{r['roc_auc']:.4f}** | {r['precision_at_100']:.3f} "
            f"| {r['recall_at_100']:.3f} | {r['best_rank']} of {r['host_windows']} "
            f"| `{r['top_feature']}` | {r['top_feature_separation']:.0f}x |"
        )
    if results:
        mean_auc = np.mean([r["roc_auc"] for r in results])
        lines += ["", f"Mean ROC-AUC across {len(results)} families: **{mean_auc:.4f}**"]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "=" * 74)
    print("\n".join(lines))
    print(f"\nWrote {OUT_JSON.name} and {OUT_MD.name}")


if __name__ == "__main__":
    main()
