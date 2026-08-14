# Schema reference — the canonical contract

What every column and feature in the detection pipeline means **in terms of
actual network traffic**, what unit it is in, and which attack it exists to
catch.

Ranges below are measured, not assumed — sampled from
`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, 60,000 flows.

---

## 1. Canonical flow columns

These eleven are the contract. `capture/schema_mapper.py` maps any dataset onto
them; `detection/graph_builder.py` consumes them. Everything else in a
76-feature CSV is ignored by M5b.

| Canonical | Unit | Observed range | What it is, in traffic terms | Why the graph needs it |
| --- | --- | --- | --- | --- |
| `src_ip` | IPv4 string | — | The host that **opened** the conversation | Becomes a **node**, and the tail of a directed edge. Ground truth attaches here: a host is malicious if any of its flows are |
| `dst_ip` | IPv4 string | — | The host that was **contacted** | Becomes a node and the head of the edge. Direction is kept: one→many (scan) and many→one (DDoS) must not collapse |
| `src_port` | int | 0 – 65,534 (median 51,116) | The **ephemeral** port the client picked | Mostly random, so it carries little signal — but a host cycling source ports fast is scanner-like (`unique_src_ports`, v2) |
| `dst_port` | int | 0 – 61,538 (median **80**) | The **service** being asked for | The vertical-scan signal. One host touching 1,000 ports on one victim is a scan even though every flow looks fine |
| `protocol` | IANA number | {0, 6, 17} | 6 = TCP, 17 = UDP, 0 = unspecified | Distinguishes a UDP flood from a TCP session |
| `timestamp` | datetime | `7/7/2017 3:30` | When the flow started | Assigns the flow to a **time window**. "200 peers in 60 seconds" is a rate, so this defines the phenomenon |
| `flow_duration` | **microseconds** | 0 – 119,998,337 (≈120 s) | How long the conversation lasted | A near-zero duration is a probe or a refused connection, not a conversation (`short_flow_ratio`, v2) |
| `fwd_bytes` | bytes | 0 – 120,783 (median 30) | Payload sent **by the initiator** | Feeds `bytes_sent`. Top separator for DDoS (349×) and Botnet (52×) |
| `bwd_bytes` | bytes | 0 – 4,991,419 (median 210) | Payload sent **back by the responder** | Feeds `bytes_recv`. A host that sends and never receives is scanning |
| `fwd_pkts` | count | 1 – 1,681 (median 3) | Packets from the initiator | Distinguishes a 3-packet probe from a real transfer |
| `bwd_pkts` | count | 0 – 2,942 (median 4) | Packets from the responder | `bwd_pkts = 0` means nobody answered |
| `label` | string | `BENIGN`, `DDoS`, … | Ground truth | **Never** a model input. Evaluation only |

**Note on `bwd_bytes` median (210) exceeding `fwd_bytes` median (30):** normal
client traffic is asymmetric — a short request pulls a large response. Attack
traffic often inverts this, which is exactly what `byte_asymmetry` (v2) measures.

---

## 2. The same column across four datasets

The reason `capture/schema_mapper.py` exists. Four conventions for identical
quantities; matching header strings exactly means an unknown spelling silently
does nothing.

| Canonical | CICIDS2017 (GeneratedLabelledFlows) | CSE-CIC-IDS2018 | A's CICFlowMeter | `pcap_to_flows.py` |
| --- | --- | --- | --- | --- |
| `src_ip` | `Source IP` | `Src IP` | `src_ip` | `src_ip` |
| `dst_ip` | `Destination IP` | `Dst IP` | `dst_ip` | `dst_ip` |
| `dst_port` | `Destination Port` | `Dst Port` | `dst_port` | `dst_port` |
| `flow_duration` | `Flow Duration` | `Flow Duration` | `flow_duration` | `flow_duration` |
| `fwd_bytes` | `Total Length of Fwd Packets` | `TotLen Fwd Pkts` | `totlen_fwd_pkts` | `fwd_bytes` |
| `bwd_bytes` | `Total Length of Bwd Packets` | `TotLen Bwd Pkts` | `totlen_bwd_pkts` | `bwd_bytes` |
| `fwd_pkts` | `Total Fwd Packets` | `Tot Fwd Pkts` | `tot_fwd_pkts` | `fwd_pkts` |
| `bwd_pkts` | `Total Backward Packets` | `Tot Bwd Pkts` | `tot_bwd_pkts` | `bwd_pkts` |

**`MachineLearningCVE` has none of the IP columns at all** — 79 columns, no
`Source IP`, no `Destination IP`, no `Timestamp`. It cannot build a graph. It is
fine for the per-flow baseline (M5a) and useless for M5b.

---

## 3. Node features v1 — what M5b actually sees

**A node is one host inside one time window.** These eight are aggregated from
every flow that host sent or received in that window. This is the entire input
to the graph model — it never sees a flow feature vector.

| # | Feature | Unit | Computed as | What it means about the host | Attack it catches |
| --- | --- | --- | --- | --- | --- |
| 0 | `out_degree` | count | distinct `dst_ip` it contacted | How many different machines it talked to | **Horizontal scan** — one host sweeping a subnet |
| 1 | `in_degree` | count | distinct `src_ip` that contacted it | How many machines talked to it | **DDoS victim** — many→one |
| 2 | `out_flows` | count | flows sent | Conversation volume outward | Scans and floods; top separator on 4 of 7 families |
| 3 | `in_flows` | count | flows received | Conversation volume inward | Servers and DDoS targets |
| 4 | `bytes_sent` | bytes | Σ `fwd_bytes` | Data volume pushed out | **Exfiltration, DDoS** (349× separation) |
| 5 | `bytes_recv` | bytes | Σ `bwd_bytes` | Data volume pulled in | Downloads, C2 payloads |
| 6 | `unique_dst_ports` | count | distinct `dst_port` contacted | How many services it probed | **Vertical scan** — 1,000 ports on one victim (199×) |
| 7 | `mean_duration` | µs | mean `flow_duration` | Typical conversation length | Probes are near-instant; sessions are not |

**The point of the whole model:** M5a sees one flow and therefore one port and
one peer. `out_degree = 200` is not computable from any single row. That number
is a property of a **node in a graph**, which is why M5b exists.

---

## 4. Node features v2 — the additions

v1 is eight **raw counts**, and that is its ceiling: a busy fileserver and a port
scanner both read as "many peers, many flows, many ports". These eleven are
deliberately **scale-free** — ratios, entropies, dispersions — so a host is not
flagged merely for being busy. Appended after index 7, so v1 indices keep their
meaning.

| # | Feature | Unit | Computed as | What it means about the host | Why it separates |
| --- | --- | --- | --- | --- | --- |
| 8 | `out_port_entropy` | bits | Shannon entropy of its `dst_port` distribution | Is its port usage focused or spread? | A web client is ~0 bits (all :443). A sweep is high |
| 9 | `out_peer_entropy` | bits | Shannon entropy of its `dst_ip` distribution | Does it favour a few peers or spray evenly? | Normal hosts have favourites; scanners are uniform |
| 10 | `fanout_ratio` | 0–1 | `out_degree / out_flows` | Fraction of flows going somewhere **new** | **1.0 = never repeats a peer**, the signature of a sweep. A server repeats constantly |
| 11 | `ports_per_peer` | ratio | `unique_dst_ports / out_degree` | Ports probed per machine | High = **vertical** scan (many ports, one host). Low = horizontal |
| 12 | `byte_asymmetry` | 0–1 | `sent / (sent + recv + 1)` | Does it talk, or converse? | ≈1.0 = sends and gets nothing back — scans and floods |
| 13 | `mean_pkts_out` | count | mean `fwd_pkts` per flow | Packets per outbound conversation | 2–3 packets = probe; hundreds = transfer |
| 14 | `mean_pkts_in` | count | mean `bwd_pkts` per flow | Packets per reply | ≈0 = nobody is answering it |
| 15 | `duration_std` | µs | std of `flow_duration` | Are its conversations uniform? | Machine-generated probes are uniformly instant; humans vary |
| 16 | `short_flow_ratio` | 0–1 | fraction of flows under 1,000 µs | Fraction that were probes/refusals | Closed ports reject instantly — a scan is mostly sub-millisecond |
| 17 | `reciprocity` | 0–1 | fraction of peers that also sent to it | **Do the peers answer back?** | The strongest scan discriminator: a busy server has the same `out_degree` and is answered by nearly all; a scanner by almost none |
| 18 | `unique_src_ports` | count | distinct `src_port` used | How fast it burns local ports | Scanners cycle source ports far faster than clients |

**Why `reciprocity` is the important one:** `out_degree` alone cannot separate a
scanner from a fileserver — both talk to many machines. Whether those machines
*reply* separates them cleanly, and it is not derivable from any single flow.

---

## 5. Edge features

**An edge is one directed `(src → dst)` pair within one window**, aggregating
every flow between them. Edges become alerts, because the frozen `ScoredAlert`
schema requires both `src_ip` and `dst_ip` — an edge maps onto that, a node
does not.

| # | Feature | Unit | Meaning |
| --- | --- | --- | --- |
| 0 | `n_flows` | count | Conversations between this pair in this window |
| 1 | `fwd_bytes` | bytes | Total sent along the edge |
| 2 | `bwd_bytes` | bytes | Total returned |
| 3 | `mean_duration` | µs | Typical conversation length for this pair |
| 4 | `unique_dst_ports` | count | Distinct services this pair touched |

---

## 6. What is deliberately NOT a model input

| Field | Why excluded |
| --- | --- |
| `label` | Ground truth. Training on it would make this a classifier, which can only recognise families in its labels — defeating the zero-day premise |
| `src_ip` / `dst_ip` as **values** | Used as node identity, never as a feature. Learning "10.0.0.5 is bad" memorises the dataset instead of the behaviour |
| `flow_id` | A join key |
| The other 65 CICFlowMeter columns | M5a's input, not M5b's. M5b consumes per-host aggregates; per-flow statistics are what it exists to look past |

---

## 7. Units — the ones that bite

| Quantity | Unit | Trap |
| --- | --- | --- |
| `flow_duration` | **microseconds** | Not seconds and not milliseconds. `_SHORT_FLOW_US = 1000.0` is **1 ms**. Reading it as seconds makes every flow look short |
| `window_seconds` | **seconds** | The one time value that is not microseconds |
| entropies | **bits** (log₂) | Not nats |
| `bytes_*` | bytes | Payload only, not including headers |
