"""
External-dataset replication #2: CTU-13 (Stratosphere Lab, real botnet traffic).

binetflow.2format columns (Argus ra -s order):
saddr,daddr,proto,sport,dport,state,stos,dtos,swin,dwin,shops,dhops,
stime,ltime,sttl,dttl,tcprtt,synack,ackdat,spkts,dpkts,sbytes,dbytes,
sappbytes,dappbytes,dur,pkts,bytes,appbytes,rate,srate,drate,label

Protocol arrives as a name (tcp/udp/icmp/...); mapped to IANA numbers so the
v1/v2 protocol features behave as on CIC data. Malicious = label starts with
'From-Botnet' (per dataset README: 'To-Botnet' flows are NOT malicious).
Train = Background flows before the first botnet flow (time split, no leakage);
eval = everything after. Same metrics as eval_external_ids2018.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
import json
import argparse

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.eval_mw_ablation_4seed import (
    LogScaler, PercentileCalibrator, set_seed, train_model, node_scores,
)
from detection.graph_builder import build_graphs
from detection.evaluate_gnn import roc_auc

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "arp": 2054, "rtp": 0}

SCENARIOS = {
    "s1_neris": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s1_neris.binetflow",
        infected="147.32.84.165"),
    "s13_virut": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s13_virut.binetflow",
        infected="147.32.84.165"),
    "s3_rbot": dict(
        path=ROOT / "data" / "CTU-13" / "ctu13_s3_rbot.binetflow",
        infected="147.32.84.165"),
}

OUT = ROOT / "experiments" / "external_ctu13_results.json"


def p_at_k(scores, y, k):
    order = np.argsort(scores)[::-1]
    return float(y[order[:k]].mean())


def load_binetflow(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]
    ren = {"srcaddr": "src_ip", "dstaddr": "dst_ip", "sport": "src_port",
           "dport": "dst_port", "starttime": "timestamp", "dur": "flow_duration",
           "srcbytes": "fwd_bytes", "dstbytes": "bwd_bytes"}
    df = df.rename(columns=ren)
    df["protocol"] = df["proto"].astype(str).str.strip().str.lower().map(PROTO_NUM).fillna(0)
    df["label"] = df["label"].astype(str).str.strip()
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df = df.dropna(subset=["ts", "src_ip", "dst_ip"])
    return df


def run_scenario(name, cfg, device, epochs):
    print(f"\n===== {name} =====")
    df = load_binetflow(cfg["path"])
    # .2format labels look like 'flow=From-Botnet-DGA...' / 'flow=Background...'
    is_bot = df["label"].str.contains("From-Botnet", regex=False)
    attack_start = df.loc[is_bot, "ts"].min()
    print(f"Flows: {len(df):,} | botnet flows: {int(is_bot.sum()):,} | "
          f"window {df['ts'].min()} .. {df['ts'].max()}")
    print(f"First botnet flow: {attack_start}")

    train_df = df[~is_bot & (df["ts"] < attack_start)]
    eval_df = df[df["ts"] >= attack_start].copy()
    print(f"Train (pre-attack background): {len(train_df):,} | "
          f"Eval: {len(eval_df):,}")

    graphs = build_graphs(train_df, window_seconds=60, k=0)
    print(f"Train graphs: {len(graphs)}")
    scaler = LogScaler().fit(graphs)
    model, loss = train_model(graphs, scaler, device, epochs)
    print(f"Final loss: {loss:.6f}")
    cal = PercentileCalibrator(
        np.concatenate([ns for _, ns in node_scores(graphs, model, scaler, device)]))

    eg = build_graphs(eval_df, window_seconds=60, k=0)
    scored = node_scores(eg, model, scaler, device)
    sc = np.concatenate([ns for _, ns in scored])
    sz = np.concatenate([np.full(len(h), len(h), dtype=int) for h, _ in scored])

    bad_hosts = set(eval_df.loc[is_bot, "src_ip"].unique()) | \
                set(eval_df.loc[is_bot, "dst_ip"].unique())
    all_hosts = sorted({h for hosts_w, _ in scored for h in hosts_w})
    y_host = np.array([1 if h in bad_hosts else 0 for h in all_hosts])
    acc = {}
    for hosts_w, ns in scored:
        for h, s in zip(hosts_w, ns):
            acc.setdefault(h, []).append(float(s))
    host_mean = np.array([np.mean(acc[h]) for h in all_hosts])
    host_max = np.array([np.max(acc[h]) for h in all_hosts])

    order = np.argsort(host_mean)[::-1]
    ranks = {all_hosts[i]: int(np.where(order == i)[0][0]) + 1
             for i in np.where(y_host == 1)[0]}
    n_bad = int(y_host.sum())
    res = {"n_flows": int(len(df)), "attack_start": str(attack_start),
           "hosts_total": len(all_hosts), "hosts_bad": n_bad,
           "p100_ceiling": round(n_bad / 100, 4),
           "attacker_ranks_meanagg": dict(sorted(ranks.items(), key=lambda kv: kv[1])),
           "recall_at_100_meanagg": round(float(
               y_host[np.argsort(host_mean)[::-1][:100]].mean()), 3),
           "recall_at_100_maxagg": round(float(
               y_host[np.argsort(host_max)[::-1][:100]].mean()), 3)}
    print(f"Hosts: {len(all_hosts):,} total, {n_bad} malicious "
          f"(P@100 ceiling {n_bad / 100:.2f})")
    print(f"Attacker ranks: {res['attacker_ranks_meanagg']}")

    yw = np.array([1 if (h in bad_hosts) else 0
                   for hosts_w, _ in scored for h in hosts_w])
    res["host_window"] = {"n_windows": int(len(sz)),
                          "attacker_windows": int(yw.sum()),
                          "p100_raw": round(p_at_k(sc, yw, 100), 3),
                          "p500_raw": round(p_at_k(sc, yw, 500), 3)}
    print(f"Host-windows P@100={res['host_window']['p100_raw']} "
          f"P@500={res['host_window']['p500_raw']}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=list(SCENARIOS.keys()))
    ap.add_argument("--epochs", type=int, default=200)
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(0)
    print(f"Device: {device}")

    out = {}
    try:
        out = json.load(open(OUT))
    except Exception:
        pass
    for name in args.scenarios:
        try:
            out[name] = run_scenario(name, SCENARIOS[name], device, args.epochs)
            json.dump(out, open(OUT, "w"), indent=2)
        except FileNotFoundError as e:
            print(f"{name}: file missing, skipping ({e})")
    print(f"\nSaved: {OUT}")


if __name__ == "__main__":
    main()
