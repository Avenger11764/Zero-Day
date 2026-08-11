"""
Graph construction for the GNN-Temporal detector (M5b, Person B / Week 3).

WHY THIS FILE EXISTS
--------------------
The baseline autoencoder (M5a) scores one flow at a time. A 76-dim flow vector
describes a single conversation and nothing else, so any attack whose evidence
is spread across *many individually-normal flows* is arithmetically invisible to
it. The canonical example is an internal port scan: one host opens 200 short,
well-formed connections. Every flow looks fine. Only "one host contacted 200
distinct peers" gives it away -- and that sentence is a property of a NODE IN A
GRAPH (its out-degree), not a property of any row.

So this module changes the data structure: flows -> a host-communication graph
per time window. That is the whole justification for the GNN half of M5b.

DESIGN DECISIONS (own these in the viva)
----------------------------------------
1. Nodes are HOSTS (IPs), not flows and not services. Out-degree then literally
   counts scan targets, which is the signal M5a structurally cannot see.

2. Edges are DIRECTED, src -> dst, aggregated per (src, dst) pair per window.
   Direction matters: "one host talks to many" (scan) and "many talk to one
   host" (server, or DDoS target) are different phenomena and must not collapse
   into the same undirected edge.

3. Scoring is EDGE-LEVEL. The frozen ScoredAlert schema requires both src_ip and
   dst_ip, so an edge maps onto an alert cleanly; a node does not.

4. Windows are TIME-BASED, not fixed-count. "200 peers in 60 seconds" is a rate.
   Chunking by row count would make the same scan look different depending on
   how busy the network was.

COLUMN CONVENTIONS
------------------
Two different CSV layouts feed this, so we normalise both to canonical names:
  * CICIDS2017 GeneratedLabelledFlows -- 'Source IP', 'Destination IP', ...
  * A's CICFlowMeter output           -- 'src_ip', 'dst_ip', ...
The CICIDS2017 *MachineLearningCVE* release has NO IP columns and cannot be used
here; build_graphs() raises a clear error rather than silently degrading.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data

REPO_ROOT = Path(__file__).resolve().parent.parent

# Canonical name -> the aliases we accept from either CSV convention.
_COLUMN_ALIASES = {
    "src_ip": ["src_ip", "Source IP", "Src IP"],
    "dst_ip": ["dst_ip", "Destination IP", "Dst IP"],
    "src_port": ["src_port", "Source Port", "Src Port"],
    "dst_port": ["dst_port", "Destination Port", "Dst Port"],
    "protocol": ["protocol", "Protocol"],
    "timestamp": ["timestamp", "Timestamp"],
    "label": ["label", "Label"],
    # Volume/duration columns used to build node + edge features.
    "flow_duration": ["flow_duration", "Flow Duration"],
    "fwd_bytes": ["totlen_fwd_pkts", "Total Length of Fwd Packets"],
    "bwd_bytes": ["totlen_bwd_pkts", "Total Length of Bwd Packets"],
    "fwd_pkts": ["tot_fwd_pkts", "Total Fwd Packets"],
    "bwd_pkts": ["tot_bwd_pkts", "Total Backward Packets"],
}

# The per-host features each node carries. Order is fixed -- SHAP and the
# ablation table both index into it by position.
NODE_FEATURE_NAMES = [
    "out_degree",        # distinct peers contacted   <- the port-scan signal
    "in_degree",         # distinct peers contacting us
    "out_flows",         # total flows sent
    "in_flows",          # total flows received
    "bytes_sent",
    "bytes_recv",
    "unique_dst_ports",  # distinct ports contacted   <- vertical-scan signal
    "mean_duration",
]


def read_flows(path, limit: int | None = None) -> pd.DataFrame:
    """Read a flow CSV. The CICIDS2017 TrafficLabelling files are not UTF-8."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return pd.read_csv(path, nrows=limit, low_memory=False, encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError(f"could not decode {path}")


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename either CSV convention onto canonical lowercase names."""
    df = df.copy()
    df.columns = df.columns.str.strip()

    rename = {}
    for canonical, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in df.columns and canonical not in rename.values():
                rename[alias] = canonical
                break
    return df.rename(columns=rename)


def assert_graphable(df: pd.DataFrame) -> None:
    """Fail loudly if this CSV cannot form a graph, instead of degrading."""
    missing = [c for c in ("src_ip", "dst_ip") if c not in df.columns]
    if missing:
        raise ValueError(
            f"Cannot build a graph: missing {missing}. "
            "The CICIDS2017 MachineLearningCVE release has no IP columns -- use "
            "the GeneratedLabelledFlows (85-column) release instead."
        )


def graph_health(df: pd.DataFrame) -> dict:
    """Measure whether a dataset has enough structure for a GNN to learn.

    A GNN updates each node from its neighbours. If every client has the SAME
    neighbour set, all embeddings collapse to the same vector and the GNN
    degenerates into an expensive per-flow autoencoder. This is exactly what
    killed training_data/dataset_10k_normal.csv (508 clients, all touching the
    identical 2 services), so we check for it up front rather than after a
    wasted training run.
    """
    peers = df.groupby("src_ip")["dst_ip"].nunique()
    return {
        "flows": len(df),
        "hosts": len(set(df["src_ip"]) | set(df["dst_ip"])),
        "unique_src": df["src_ip"].nunique(),
        "unique_dst": df["dst_ip"].nunique(),
        "edges": df.groupby(["src_ip", "dst_ip"]).ngroups,
        "peers_per_src_mean": float(peers.mean()),
        "peers_per_src_min": int(peers.min()),
        "peers_per_src_max": int(peers.max()),
        # If min == max, every source behaves identically -> collapse.
        "collapsed": bool(peers.min() == peers.max() and df["dst_ip"].nunique() <= 2),
    }


def _window_key(df: pd.DataFrame, window_seconds: int) -> pd.Series:
    """Assign each flow to a time bucket; fall back to row order if no clock."""
    if "timestamp" not in df.columns:
        return pd.Series(np.arange(len(df)) // 1000, index=df.index)

    ts = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    if ts.isna().all():
        return pd.Series(np.arange(len(df)) // 1000, index=df.index)

    epoch = (ts - ts.min()).dt.total_seconds().fillna(0)
    return (epoch // window_seconds).astype(int)


def build_graph(window_df: pd.DataFrame) -> Data | None:
    """Turn one time window of flows into a PyG graph.

    Nodes are hosts, edges are aggregated (src -> dst) communication.
    Returns None if the window has fewer than 2 hosts (no graph to speak of).
    """
    hosts = sorted(set(window_df["src_ip"]) | set(window_df["dst_ip"]))
    if len(hosts) < 2:
        return None
    index = {h: i for i, h in enumerate(hosts)}

    # ---- edges: one per distinct (src, dst) pair in this window -------------
    grouped = window_df.groupby(["src_ip", "dst_ip"])
    edge_index, edge_attr = [], []
    for (src, dst), g in grouped:
        edge_index.append([index[src], index[dst]])
        edge_attr.append([
            len(g),
            float(g["fwd_bytes"].sum()) if "fwd_bytes" in g else 0.0,
            float(g["bwd_bytes"].sum()) if "bwd_bytes" in g else 0.0,
            float(g["flow_duration"].mean()) if "flow_duration" in g else 0.0,
            float(g["dst_port"].nunique()) if "dst_port" in g else 0.0,
        ])

    # ---- nodes: per-host aggregates ----------------------------------------
    x = np.zeros((len(hosts), len(NODE_FEATURE_NAMES)), dtype=np.float32)
    out_peers = window_df.groupby("src_ip")["dst_ip"].nunique()
    in_peers = window_df.groupby("dst_ip")["src_ip"].nunique()
    out_flows = window_df.groupby("src_ip").size()
    in_flows = window_df.groupby("dst_ip").size()

    for host, i in index.items():
        x[i, 0] = out_peers.get(host, 0)
        x[i, 1] = in_peers.get(host, 0)
        x[i, 2] = out_flows.get(host, 0)
        x[i, 3] = in_flows.get(host, 0)

    if "fwd_bytes" in window_df.columns:
        sent = window_df.groupby("src_ip")["fwd_bytes"].sum()
        recv = window_df.groupby("dst_ip")["bwd_bytes"].sum()
        for host, i in index.items():
            x[i, 4] = float(sent.get(host, 0.0))
            x[i, 5] = float(recv.get(host, 0.0))

    if "dst_port" in window_df.columns:
        ports = window_df.groupby("src_ip")["dst_port"].nunique()
        for host, i in index.items():
            x[i, 6] = float(ports.get(host, 0))

    if "flow_duration" in window_df.columns:
        dur = window_df.groupby("src_ip")["flow_duration"].mean()
        for host, i in index.items():
            x[i, 7] = float(dur.get(host, 0.0))

    data = Data(
        x=torch.tensor(x, dtype=torch.float32),
        edge_index=torch.tensor(edge_index, dtype=torch.long).t().contiguous(),
        edge_attr=torch.tensor(edge_attr, dtype=torch.float32),
    )
    data.hosts = hosts  # keep IPs so an edge can become a ScoredAlert later
    return data


def build_graphs(df: pd.DataFrame, window_seconds: int = 60) -> list[Data]:
    """Full pipeline: raw flow dataframe -> list of per-window graphs."""
    df = normalize_columns(df)
    assert_graphable(df)

    graphs = []
    for _, window_df in df.groupby(_window_key(df, window_seconds)):
        g = build_graph(window_df)
        if g is not None:
            graphs.append(g)
    return graphs


def _synthetic_flows(n_clients=60, n_servers=8, scan=True, seed=0) -> pd.DataFrame:
    """Realistic-topology traffic for testing the builder without the download.

    Normal clients each touch a RANDOM SUBSET of servers, so neighbourhoods
    differ and the GNN has something to learn. One host optionally port-scans.
    """
    rng = np.random.default_rng(seed)
    servers = [f"10.0.0.{i + 2}" for i in range(n_servers)]
    rows = []
    for c in range(n_clients):
        src = f"192.168.1.{c + 10}"
        for dst in rng.choice(servers, size=rng.integers(1, 4), replace=False):
            for _ in range(int(rng.integers(1, 6))):
                rows.append({
                    "src_ip": src, "dst_ip": dst,
                    "dst_port": int(rng.choice([80, 443, 53])),
                    "timestamp": f"2017-07-03 09:{rng.integers(0, 60):02d}:00",
                    "flow_duration": float(rng.integers(100, 9000)),
                    "totlen_fwd_pkts": float(rng.integers(100, 5000)),
                    "totlen_bwd_pkts": float(rng.integers(100, 9000)),
                })
    if scan:
        for i in range(200):  # one attacker sweeping the /24
            rows.append({
                "src_ip": "192.168.1.66", "dst_ip": f"192.168.1.{i % 254 + 1}",
                "dst_port": int(rng.choice([22, 445, 3389])),
                "timestamp": "2017-07-03 09:30:00",
                "flow_duration": 50.0,
                "totlen_fwd_pkts": 60.0, "totlen_bwd_pkts": 0.0,
            })
    return pd.DataFrame(rows)


def _self_test() -> None:
    print("Self-test: synthetic traffic with realistic topology\n")
    df = normalize_columns(_synthetic_flows())

    health = graph_health(df)
    print("  health:")
    for k, v in health.items():
        print(f"    {k:22s} {v}")
    print()

    graphs = build_graphs(df, window_seconds=60)
    print(f"  built {len(graphs)} graphs")
    g = max(graphs, key=lambda d: d.num_nodes)
    print(f"  largest: {g.num_nodes} nodes, {g.num_edges} edges, "
          f"x={tuple(g.x.shape)}, edge_attr={tuple(g.edge_attr.shape)}")

    # The whole point: the scanner should top the out-degree ranking.
    out_deg = g.x[:, 0]
    top = int(torch.argmax(out_deg))
    print(f"\n  highest out-degree host: {g.hosts[top]} "
          f"(contacted {int(out_deg[top])} distinct peers)")
    print(f"  median out-degree      : {float(out_deg.median()):.1f}")
    print("\n  ^ M5a cannot compute that number. That is why M5b exists.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build host-communication graphs from flows.")
    ap.add_argument("csv", nargs="?", help="flow CSV (omit to run the self-test)")
    ap.add_argument("--window", type=int, default=60, help="window size in seconds")
    ap.add_argument("--limit", type=int, default=None, help="only read first N rows")
    args = ap.parse_args()

    if args.csv is None:
        _self_test()
        return

    df = normalize_columns(read_flows(args.csv, limit=args.limit))
    assert_graphable(df)

    health = graph_health(df)
    print(f"Graph health for {args.csv}:")
    for k, v in health.items():
        print(f"  {k:22s} {v}")
    if health["collapsed"]:
        print("\n  WARNING: every source has an identical neighbourhood.")
        print("  A GNN will collapse to identical embeddings on this data.")

    graphs = build_graphs(df, window_seconds=args.window)
    print(f"\nBuilt {len(graphs)} graphs (window={args.window}s)")
    if graphs:
        n = [g.num_nodes for g in graphs]
        e = [g.num_edges for g in graphs]
        print(f"  nodes/graph: min={min(n)} mean={np.mean(n):.1f} max={max(n)}")
        print(f"  edges/graph: min={min(e)} mean={np.mean(e):.1f} max={max(e)}")


if __name__ == "__main__":
    main()
