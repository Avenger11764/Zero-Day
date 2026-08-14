"""
Red-team harness for the RELATIONAL detector (M5b).

WHY THIS EXISTS ALONGSIDE run_harness.py
-----------------------------------------
`run_harness.py` attacks `stub_detector.score_flow()` -- one 76-dim vector at a
time. That is the correct shape of attack for M5a and it says nothing about M5b,
which scores per-host aggregates over a time window. Until now the graph model
had never been attacked at all, so "the GNN is more robust" was an untested
claim.

It also could not have been tested with the old harness's data:
`training_data/dataset_10k_normal.csv` has 508 clients all touching the same two
services, so every neighbourhood is identical and no graph can be built from it
(CLAUDE.md gotcha #6). This harness uses CICIDS2017 GeneratedLabelledFlows,
the 85-column release with IP columns.

THE QUESTION IT ANSWERS
-----------------------
Not "can M5b be evaded" -- any detector can. The useful question is **what does
evasion cost the attacker**, measured in the currency the attacker cares about:
scan rate, number of machines, and wasted cover traffic. A detector that is
evaded only by slowing a 200-host sweep to 4 hosts per minute has still done its
job; one evaded by a free change has not.

THE VERDICT RULE (inherited from ablation.py, do not weaken it)
---------------------------------------------------------------
A detection counts only if the attacker scores above the 99th percentile of
BENIGN host-window scores. At that threshold ~1% of benign traffic flags by
construction -- the false-positive floor. Scoring "above zero" or "above the
median" would count the model's own noise as a catch.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "detection"))

# Windows consoles default to cp1252 and the results table contains em-dashes.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from graph_builder import build_graphs, normalize_columns, read_flows  # noqa: E402
from gnn_model import train  # noqa: E402
from ensembler import flow_features, pin_canonical  # noqa: E402
from stub_detector import _get_model  # noqa: E402
from harness.graph_techniques import ALL_TECHNIQUES, ATTACKER  # noqa: E402

FLOWS = REPO_ROOT / "data" / "GeneratedLabelledFlows" / "TrafficLabelling"
BENIGN_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
RESULTS = Path(__file__).resolve().parent / "results"


def load_benign(limit: int | None) -> pd.DataFrame:
    df = normalize_columns(read_flows(FLOWS / BENIGN_FILE, limit=limit))
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].str.upper() == "BENIGN"]
    # Parse timestamps once so crafted attacker flows (real datetimes) and benign
    # flows (CICIDS2017's own string format) share one dtype. Mixing them would
    # make graph_builder._window_key fall back to row-order chunking, which would
    # silently destroy every timing-based evasion measured here.
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    return df.dropna(subset=["timestamp"])


def score_hosts(model, scaler, graphs, device) -> tuple[np.ndarray, list[str]]:
    scores, hosts = [], []
    for g in graphs:
        x = scaler.transform(g.x).to(device)
        scores.append(model.node_scores(x, g.edge_index.to(device)).cpu().numpy())
        hosts.extend(g.hosts)
    return np.concatenate(scores), hosts


def m5a_flag_rate(flows: pd.DataFrame, threshold: float,
                  ref: tuple[np.ndarray, np.ndarray] | None = None) -> float:
    """What fraction of the attacker's flows M5a flags. The control condition.

    `ref` is the (lo, hi) min-max range measured on BENIGN traffic, and passing
    it is not optional in practice. `ensembler.flow_features()` derives its
    scaling from whatever rows it is handed, so calling it on 200 attacker flows
    normalises them against their own range: the same real benign flow lands at
    a completely different position depending on which other rows happen to sit
    beside it. The first run of this harness did exactly that and reported M5a
    flagging 100% of variants -- not a detection, an artefact of rescaling.

    The attacker's flows are real benign rows with only src/dst/port/timestamp
    rewritten, so under the benign scaling M5a must score them as benign. That
    is the whole basis for attributing any M5b detection to structure.
    """
    x = flow_features(flows)
    if x is None:
        return float("nan")
    if ref is not None:
        lo, hi = ref
        raw = flows[_canonical_cols()].apply(pd.to_numeric, errors="coerce")
        raw = raw.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(np.float32)
        span = np.where(hi - lo > 0, hi - lo, 1.0)
        x = np.clip((raw - lo) / span, 0.0, 1.0)
    with torch.no_grad():
        s = _get_model().anomaly_score(torch.tensor(x, dtype=torch.float32)).numpy()
    return float((s > threshold).mean())


def _canonical_cols() -> list[str]:
    import ensembler
    assert ensembler._CANONICAL is not None, "pin_canonical() must run first"
    return ensembler._CANONICAL


def main() -> None:
    ap = argparse.ArgumentParser(description="Red-team harness against M5b.")
    ap.add_argument("--limit", type=int, default=150_000,
                    help="benign rows to read; 0 or negative reads the FULL file")
    ap.add_argument("--targets", type=int, default=200, help="hosts swept")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--window", type=int, default=60)
    args = ap.parse_args()
    limit = args.limit if args.limit and args.limit > 0 else None

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("=" * 74)
    print("RED-TEAM HARNESS -- M5b (relational detector)")
    print(f"device={device}  limit={'FULL FILE' if limit is None else limit}")
    print("=" * 74)

    benign = load_benign(limit)
    print(f"\nBenign traffic: {len(benign):,} flows from {BENIGN_FILE}")

    benign_graphs = build_graphs(benign, window_seconds=args.window)
    print(f"  {len(benign_graphs)} benign graphs -> training M5b...")
    model, scaler, losses = train(benign_graphs, epochs=args.epochs,
                                  device=device, quiet=True)
    print(f"  final loss {losses[-1]:.6f}")

    b_scores, _ = score_hosts(model, scaler, benign_graphs, device)
    m5b_threshold = float(np.percentile(b_scores, 99))
    print(f"  M5b threshold (99th pct of {len(b_scores):,} benign host-windows) "
          f"= {m5b_threshold:.6f}")

    # M5a's own benign floor, for the control comparison.
    pin_canonical(benign)
    bx = flow_features(benign)
    # The benign feature ranges. Every later scaling reuses these so an attacker
    # subset is never normalised against itself.
    braw = benign[_canonical_cols()].apply(pd.to_numeric, errors="coerce")
    braw = braw.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(np.float32)
    ref = (braw.min(axis=0), braw.max(axis=0))
    with torch.no_grad():
        b_flow = _get_model().anomaly_score(torch.tensor(bx, dtype=torch.float32)).numpy()
    m5a_threshold = float(np.percentile(b_flow, 99))
    print(f"  M5a threshold (99th pct of {len(b_flow):,} benign flows) "
          f"= {m5a_threshold:.6f}")

    base_time = benign["timestamp"].min()
    rows = []

    for technique in ALL_TECHNIQUES:
        name, variants = technique(benign, n_targets=args.targets,
                                   base_time=base_time,
                                   window_seconds=args.window)
        print(f"\n{name}")
        for param, attack_flows in variants:
            mixed = pd.concat([benign, attack_flows], ignore_index=True)
            graphs = build_graphs(mixed, window_seconds=args.window)
            scores, hosts = score_hosts(model, scaler, graphs, device)

            mask = np.array([h == ATTACKER for h in hosts])
            if not mask.any():
                print(f"  {param:>5}  attacker absent from every graph -- skipped")
                continue

            best = float(scores[mask].max())
            detected = best > m5b_threshold
            # Rank among all host-windows: what a SOC analyst sorting by score sees.
            rank = int((scores > best).sum()) + 1
            pct = 100.0 * (1.0 - rank / len(scores))
            a_rate = m5a_flag_rate(attack_flows, m5a_threshold, ref)

            rows.append({
                "technique": name, "param": param,
                "attacker_score": round(best, 6),
                "m5b_threshold": round(m5b_threshold, 6),
                "detected_by_m5b": bool(detected),
                "rank": rank, "of": len(scores),
                "percentile": round(pct, 3),
                "m5a_flag_rate": round(a_rate, 4),
                "m5a_detects": bool(a_rate > 0.05),
            })
            print(f"  {param:>5}  M5b {'DETECTED' if detected else 'EVADED  '} "
                  f"score={best:.6f} rank={rank}/{len(scores)}   "
                  f"M5a flags {100 * a_rate:.1f}% of the flows "
                  f"({'detects' if a_rate > 0.05 else 'blind'})")

    RESULTS.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(RESULTS / "m5b_evasion.csv", index=False)
    (RESULTS / "m5b_evasion.json").write_text(json.dumps(rows, indent=2))

    # ---- the deliverable: what did evasion COST the attacker? --------------
    L = ["# Red-team evaluation — M5b (relational detector)", "",
         f"Benign: `{BENIGN_FILE}`, {len(benign):,} flows, "
         f"{len(benign_graphs)} graphs. Sweep size {args.targets} hosts.",
         "",
         f"Detection threshold: 99th percentile of benign host-window scores "
         f"(`{m5b_threshold:.6f}`). Anything at or below that is inside the "
         "false-positive floor and does not count as a catch.", "",
         "| Technique | Evades at | Cost to the attacker |",
         "| --- | --- | --- |"]

    COST = {
        "slow_scan": lambda p: f"sweep stretched over {p} windows "
                               f"({args.targets / p:.0f} hosts/min)",
        "distributed_scan": lambda p: f"needs {p} attacker machines",
        "cover_traffic": lambda p: f"{p} wasted cover flows",
        "port_narrowing": lambda p: f"only {p} distinct port(s) probed",
    }
    for name in df["technique"].unique() if len(df) else []:
        sub = df[df["technique"] == name]
        evaded = sub[~sub["detected_by_m5b"]]
        if len(evaded):
            p = evaded.iloc[0]["param"]
            L.append(f"| {name} | `{p}` | {COST[name](p)} |")
        else:
            L.append(f"| {name} | **never** | detected at every setting tried |")

    if len(df):
        blind = (df["m5a_flag_rate"] <= 0.05).mean()
        L += ["", "## Control — was the attack fair to M5a?", "",
              f"M5a stayed at its false-positive floor on **{100 * blind:.0f}%** of "
              "variants. The attacker's flows are real benign flows with only "
              "`src_ip`/`dst_ip`/`dst_port`/`timestamp` rewritten, so M5a is blind "
              "to them by construction. That is what makes any M5b detection "
              "attributable to structure rather than to odd-looking flows."]

    (RESULTS / "m5b_evasion.md").write_text("\n".join(L), encoding="utf-8")
    print("\n" + "=" * 74)
    print("\n".join(L))
    print(f"\nWrote {RESULTS / 'm5b_evasion.md'} (+ .csv, .json)")


if __name__ == "__main__":
    main()
