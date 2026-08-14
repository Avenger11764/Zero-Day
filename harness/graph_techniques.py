"""
Evasion techniques that target the RELATIONAL detector (M5b), not the per-flow one.

WHY THE EXISTING TECHNIQUES CANNOT TOUCH M5b
---------------------------------------------
`techniques.py` perturbs a 76-dimensional flow feature vector -- mimicry,
padding, slow-drip all move numbers inside one row. That is the right shape of
attack against M5a, which scores exactly that vector.

M5b never sees a flow feature vector. It sees eight per-host aggregates computed
over a time window:

    out_degree, in_degree, out_flows, in_flows,
    bytes_sent, bytes_recv, unique_dst_ports, mean_duration

None of those can be changed by editing a row's `flow_iat_std`. They change only
if the attacker changes its BEHAVIOUR -- who it talks to, how many of them, over
how long, from how many machines. So evading M5b means paying a real operational
cost, and the interesting question is how much.

Every technique here follows `ablation.py`'s fairness rule: the attacker's flows
are REAL BENIGN FLOWS sampled from the dataset with **all 76 feature values
untouched**. Only `src_ip`, `dst_ip`, `dst_port` and `timestamp` are rewritten.
That keeps M5a structurally blind by construction, so any change in detection is
attributable to structure alone and not to the attacker accidentally producing
odd-looking flows.

THE FOUR TECHNIQUES AND WHICH DESIGN DECISION EACH ATTACKS
-----------------------------------------------------------
  slow_scan          spread the sweep over more windows   -> attacks "windows are
                                                              time-based", drives
                                                              out_degree/window down
  distributed_scan   split the sweep across more source   -> attacks "nodes are
                     IPs                                     hosts" / per-host
                                                              aggregation
  cover_traffic      add normal-looking connections       -> attacks the
                     alongside the scan                      neighbourhood shape
                                                              the GNN encodes
  port_narrowing     touch fewer distinct ports per       -> attacks
                     window                                  unique_dst_ports, the
                                                              feature the CICIDS2017
                                                              PortScan eval showed
                                                              actually fires
"""

from __future__ import annotations

import numpy as np
import pandas as pd

WINDOW_SECONDS = 60
ATTACKER = "192.168.99.66"


def _benign_pool(benign: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """Sample n real benign flows, with replacement if the pool is small."""
    replace = n > len(benign)
    return benign.sample(n=n, replace=replace, random_state=seed).copy()


def _assign_windows(n_flows: int, spread_windows: int, base: pd.Timestamp,
                    window_seconds: int = WINDOW_SECONDS) -> list[pd.Timestamp]:
    """Spread n_flows evenly across `spread_windows` consecutive time windows.

    Flows are placed in the MIDDLE of each window so that rounding at the window
    boundary cannot accidentally split one window's traffic across two and make
    the evasion look better than it is.
    """
    per_window = int(np.ceil(n_flows / spread_windows))
    stamps = []
    for i in range(n_flows):
        w = i // per_window
        stamps.append(base + pd.Timedelta(seconds=w * window_seconds + window_seconds // 2))
    return stamps


def craft_scan(benign: pd.DataFrame, n_targets: int = 200, *,
               spread_windows: int = 1, n_sources: int = 1,
               n_ports: int = 3, cover_flows: int = 0,
               attacker: str = ATTACKER, base_time: pd.Timestamp | None = None,
               seed: int = 7, window_seconds: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Build a port scan out of untouched benign flows, with evasion knobs.

    n_targets      how many distinct hosts the attacker sweeps in total
    spread_windows over how many consecutive windows the sweep is spread
    n_sources      how many attacker IPs share the sweep
    n_ports        how many distinct destination ports are used
    cover_flows    extra normal-looking flows the attacker sends to popular hosts
    """
    if base_time is None:
        base_time = pd.Timestamp("2017-07-03 09:00:00")

    scan = _benign_pool(benign, n_targets, seed)
    scan["dst_ip"] = [f"192.168.99.{i % 254 + 1}" for i in range(n_targets)]

    # Split the sweep across n_sources attacker machines. Host 0 keeps the
    # canonical attacker IP so the runner always has a host to look up.
    sources = [attacker] + [f"192.168.99.{200 + k}" for k in range(1, n_sources)]
    scan["src_ip"] = [sources[i % n_sources] for i in range(n_targets)]

    ports = [22, 445, 3389, 23, 139, 135, 8080, 21][:max(1, n_ports)]
    scan["dst_port"] = [ports[i % len(ports)] for i in range(n_targets)]
    scan["timestamp"] = _assign_windows(n_targets, spread_windows, base_time,
                                        window_seconds)

    if cover_flows > 0:
        # The attacker also behaves like an ordinary client: repeat traffic to a
        # handful of popular destinations. This lowers the ratio of "distinct
        # peers" to "total flows" without reducing the scan itself, which is the
        # cheapest evasion available -- it costs no scan coverage at all.
        popular = benign["dst_ip"].value_counts().head(5).index.tolist()
        if popular:
            cover = _benign_pool(benign, cover_flows, seed + 1)
            cover["src_ip"] = attacker
            cover["dst_ip"] = [popular[i % len(popular)] for i in range(cover_flows)]
            common = [80, 443, 53]
            cover["dst_port"] = [common[i % len(common)] for i in range(cover_flows)]
            cover["timestamp"] = _assign_windows(cover_flows, spread_windows,
                                                 base_time, window_seconds)
            scan = pd.concat([scan, cover], ignore_index=True)

    return scan


# ---------------------------------------------------------------------------
# Named techniques: each sweeps exactly ONE knob so the result is attributable.
# Each returns (label, list_of_(param_value, attacker_flows)).
# ---------------------------------------------------------------------------

def slow_scan(benign, n_targets=200, spreads=(1, 2, 5, 10, 20, 50), **kw):
    """Spread the same sweep over progressively more time windows."""
    return "slow_scan", [
        (s, craft_scan(benign, n_targets, spread_windows=s, **kw)) for s in spreads
    ]


def distributed_scan(benign, n_targets=200, sources=(1, 2, 4, 8, 16, 32), **kw):
    """Split the same sweep across progressively more attacker machines."""
    return "distributed_scan", [
        (n, craft_scan(benign, n_targets, n_sources=n, **kw)) for n in sources
    ]


def cover_traffic(benign, n_targets=200, covers=(0, 50, 200, 500, 1000, 2000), **kw):
    """Add progressively more normal-looking traffic alongside the scan."""
    return "cover_traffic", [
        (c, craft_scan(benign, n_targets, cover_flows=c, **kw)) for c in covers
    ]


def port_narrowing(benign, n_targets=200, ports=(8, 4, 3, 2, 1), **kw):
    """Use progressively fewer distinct destination ports."""
    return "port_narrowing", [
        (p, craft_scan(benign, n_targets, n_ports=p, **kw)) for p in ports
    ]


ALL_TECHNIQUES = (slow_scan, distributed_scan, cover_traffic, port_narrowing)
