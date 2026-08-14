"""
pcap -> bidirectional flow CSV, in the exact column convention `graph_builder`
already accepts.

WHY NOT CICFlowMeter
--------------------
CICFlowMeter is the canonical tool and it produces all 76 per-flow features.
M5b uses **none of them**. It consumes eight per-host aggregates computed from
who talked to whom, how often, how many bytes, over how many ports:

    src_ip, dst_ip, src_port, dst_port, protocol, timestamp,
    flow_duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts

Eleven columns, all of which fall straight out of a packet dump. Pulling in a
Java toolchain to compute 65 further columns that are then discarded would add a
dependency, a version-skew risk, and a second definition of "a flow" — for
nothing. So this extracts exactly what the graph needs and stops.

The trade-off is explicit: output from this script CANNOT feed M5a, which needs
all 76 features. If you want to score the same capture with both detectors, run
CICFlowMeter as well. For M5b alone, this is sufficient and far simpler.

WHAT COUNTS AS A FLOW
---------------------
A flow is one 5-tuple conversation (src, dst, sport, dport, proto), with the two
directions folded together — the direction that sent the first packet is
"forward". Flows are cut after `--timeout` seconds of silence, matching
CICFlowMeter's default idle timeout of 120s, so a long-lived connection does not
become one flow spanning the whole capture and flatten every time window.

LABELLING
---------
`--attacker IP` marks every flow whose source is that host as malicious, which
is how a self-run nmap scan gets ground truth: you know which machine you ran it
from. Without it every flow is labelled BENIGN.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent

# tshark fields, in order. -E occurrence=f keeps one value per field even when a
# packet has nested layers (e.g. tunnelled IP), which otherwise emits "a,b" into
# a single column and silently corrupts the parse.
FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "frame.len",
]


def run_tshark(pcap: Path, tshark: str) -> pd.DataFrame:
    cmd = [tshark, "-r", str(pcap), "-T", "fields",
           "-E", "separator=,", "-E", "occurrence=f", "-n"]
    for f in FIELDS:
        cmd += ["-e", f]
    print(f"  running tshark on {pcap.name}...")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr[:500]}")

    from io import StringIO
    df = pd.read_csv(StringIO(proc.stdout), names=FIELDS, header=None,
                     low_memory=False)
    return df


def to_flows(pkts: pd.DataFrame, timeout: float = 120.0) -> pd.DataFrame:
    """Fold packets into bidirectional 5-tuple flows."""
    pkts = pkts.dropna(subset=["ip.src", "ip.dst"]).copy()
    if pkts.empty:
        raise ValueError("no IP packets in capture")

    pkts["sport"] = pkts["tcp.srcport"].fillna(pkts["udp.srcport"]).fillna(0).astype("int64")
    pkts["dport"] = pkts["tcp.dstport"].fillna(pkts["udp.dstport"]).fillna(0).astype("int64")
    pkts["proto"] = pkts["ip.proto"].fillna(0).astype("int64")
    pkts["ts"] = pkts["frame.time_epoch"].astype(float)
    pkts["len"] = pkts["frame.len"].fillna(0).astype("int64")
    pkts = pkts.sort_values("ts")

    # Canonical key: the endpoint pair sorted, so A->B and B->A share a flow.
    a = pkts["ip.src"] + ":" + pkts["sport"].astype(str)
    b = pkts["ip.dst"] + ":" + pkts["dport"].astype(str)
    lo = a.where(a < b, b)
    hi = b.where(a < b, a)
    pkts["key"] = lo + "|" + hi + "|" + pkts["proto"].astype(str)

    # Split a key into separate flows across gaps longer than the idle timeout.
    gap = pkts.groupby("key")["ts"].diff().fillna(0.0)
    pkts["episode"] = (gap > timeout).groupby(pkts["key"]).cumsum()

    rows = []
    for (_, _), g in pkts.groupby(["key", "episode"], sort=False):
        first = g.iloc[0]
        src, dst = first["ip.src"], first["ip.dst"]
        fwd = g[(g["ip.src"] == src) & (g["ip.dst"] == dst)]
        bwd = g[(g["ip.src"] == dst) & (g["ip.dst"] == src)]
        rows.append({
            "src_ip": src, "dst_ip": dst,
            "src_port": int(first["sport"]), "dst_port": int(first["dport"]),
            "protocol": int(first["proto"]),
            "timestamp": pd.to_datetime(first["ts"], unit="s"),
            # microseconds, matching the CICIDS2017 'Flow Duration' unit so the
            # same _SHORT_FLOW_US threshold means the same thing on both sources
            "flow_duration": float((g["ts"].max() - g["ts"].min()) * 1e6),
            "fwd_bytes": float(fwd["len"].sum()), "bwd_bytes": float(bwd["len"].sum()),
            "fwd_pkts": float(len(fwd)), "bwd_pkts": float(len(bwd)),
        })
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert a pcap into the flow CSV graph_builder expects.")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="idle seconds before a conversation becomes a new flow")
    ap.add_argument("--attacker", default=None,
                    help="label flows from this source IP as malicious")
    ap.add_argument("--attack-name", default="PortScan")
    ap.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    args = ap.parse_args()

    pcap = Path(args.pcap).resolve()
    if not pcap.exists():
        raise SystemExit(f"no such file: {pcap}")
    if not Path(args.tshark).exists():
        raise SystemExit(f"tshark not found at {args.tshark} -- pass --tshark")

    pkts = run_tshark(pcap, args.tshark)
    print(f"  {len(pkts):,} packets")
    flows = to_flows(pkts, timeout=args.timeout)

    flows["label"] = "BENIGN"
    if args.attacker:
        mask = flows["src_ip"] == args.attacker
        flows.loc[mask, "label"] = args.attack_name
        print(f"  labelled {int(mask.sum()):,} flows from {args.attacker} "
              f"as {args.attack_name}")
        if not mask.any():
            print("  WARNING: no flows matched that source IP -- check it is the "
                  "address the scan actually ran from")

    out = Path(args.out) if args.out else pcap.with_suffix(".flows.csv")
    flows.to_csv(out, index=False)
    print(f"  {len(flows):,} flows -> {out}")

    # Refuse to hand over a capture that cannot form a usable graph. A single-
    # vantage capture often yields a star topology (every edge touches the
    # capturing host), which collapses every embedding -- the failure mode that
    # made A's synthetic datasets unusable.
    sys.path.insert(0, str(REPO_ROOT / "detection"))
    from graph_builder import graph_health  # noqa: E402

    h = graph_health(flows)
    print("\n  graph health:")
    for k, v in h.items():
        print(f"    {k:22s} {v}")
    if h["collapsed"]:
        print("\n  WARNING: every source has an identical neighbourhood. A GNN "
              "will learn nothing from this. Capture from a vantage point that "
              "sees traffic BETWEEN other devices, not only to and from this one.")
    elif h["hosts"] < 20:
        print(f"\n  NOTE: only {h['hosts']} hosts. Enough for a scan demo, far too "
              "few to train on -- CICIDS2017 Monday has 9,709.")


if __name__ == "__main__":
    main()
