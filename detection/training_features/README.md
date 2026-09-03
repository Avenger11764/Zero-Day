# Training features — frozen catalogue

> **Frozen as of 2026-08-25.** Every training / scoring / logging path indexes into
> these lists by position. Do not reorder.

Two independent schemas. Do not mix them.

---

## A) Per-flow vector — `87 dims`

> 76 base + 11 window-context dims. Bundle travels inside
> `detection/m5a_revived_ctx.pt` (`canonical`, `flow_lo/hi`, `ctx_lo/hi`).

### A0. Source dataset
CICIDS2017 **MachineLearningCSV** + **GeneratedLabelledFlows** — the pinned 76.
Column order = `pin_canonical()` (alphabetical via `dropna` once on Monday).
Consumers: `legacy/stub_detector` (old, stale), `train_m5a_revived.py` → `RevivedAE`.

### A1. Flow — `76 dims`, MinMax [0,1]

| # | Name | What it measures (that flow) | Signal |
|---|---|---|---|
| 1 | flow_duration | how long it lived (µs) | bursts vs slow |
| 2 | flow_byts_s | bytes per second | rate |
| 3 | flow_pkts_s | packets per second | rate |
| 4 | fwd_pkts_s | forward packets/s | dir rate |
| 5 | bwd_pkts_s | backward packets/s | dir rate |
| 6 | tot_fwd_pkts | count forward packets | volume |
| 7 | tot_bwd_pkts | count backward packets | volume |
| 8 | totlen_fwd_pkts | total bytes forward | volume |
| 9 | totlen_bwd_pkts | total bytes backward | volume |
| 10 | fwd_pkt_len_max | biggest forward packet | MTU/flood style |
| 11 | fwd_pkt_len_min | smallest forward | size floor |
| 12 | fwd_pkt_len_mean | avg forward size | payload size |
| 13 | fwd_pkt_len_std | spread forward | variability |
| 14 | bwd_pkt_len_max | biggest backward | server responses |
| 15 | bwd_pkt_len_min | smallest backward | ack size |
| 16 | bwd_pkt_len_mean | avg backward | server payload |
| 17 | bwd_pkt_len_std | spread backward | variability |
| 18 | pkt_len_max | biggest packet overall | overall size |
| 19 | pkt_len_min | smallest overall | smallest segment |
| 20 | pkt_len_mean | avg overall packet | central size |
| 21 | pkt_len_std | spread overall | jitter |
| 22 | pkt_len_var | variance overall | tail |
| 23 | fwd_header_len | bytes of forward headers | handshake cost |
| 24 | bwd_header_len | bytes of backward headers | server header cost |
| 25 | fwd_seg_size_min | min forward segment | segment floor |
| 26 | fwd_act_data_pkts | forward with data | data rate |
| 27 | flow_iat_mean | mean gap between flows | persistence |
| 28 | flow_iat_max | largest gap | idle time |
| 29 | flow_iat_min | smallest gap | close arrivals |
| 30 | flow_iat_std | spread of gaps | burstiness |
| 31 | fwd_iat_tot | total forward gap time | host dwell |
| 32 | fwd_iat_max | max forward gap | client think time |
| 33 | fwd_iat_min | min forward gap | client rate |
| 34 | fwd_iat_mean | avg forward gap | client periodicity |
| 35 | fwd_iat_std | spread forward | cadence |
| 36 | bwd_iat_tot | total backward gap | server dwell |
| 37 | bwd_iat_max | max backward gap | server think |
| 38 | bwd_iat_min | min backward gap | server rate |
| 39 | bwd_iat_mean | avg backward gap | server periodicity |
| 40 | bwd_iat_std | spread backward | server jitter |
| 41 | fwd_psh_flags | forward PSH count | urgent burst |
| 42 | bwd_psh_flags | backward PSH | server echo |
| 43 | fwd_urg_flags | forward URG | priority |
| 44 | bwd_urg_flags | backward URG | priority |
| 45 | fin_flag_cnt | FIN closes | session end |
| 46 | syn_flag_cnt | SYN opens | new session |
| 47 | rst_flag_cnt | RST resets | failed scans |
| 48 | psh_flag_cnt | PSH | push style |
| 49 | ack_flag_cnt | ACK | ack volume |
| 50 | urg_flag_cnt | URG | urgent |
| 51 | ece_flag_cnt | ECE (ECN) | congestion |
| 52 | down_up_ratio | download/upload ratio | asymmetry |
| 53 | pkt_size_avg | avg packet size both dirs | size |
| 54 | init_fwd_win_byts | initial forward window | client buffer |
| 55 | init_bwd_win_byts | initial backward window | server buffer |
| 56 | active_max | longest active stretch | burst |
| 57 | active_min | shortest active | micro-burst |
| 58 | active_mean | avg active | duty cycle |
| 59 | active_std | spread active | stability |
| 60 | idle_max | longest idle | sleeping |
| 61 | idle_min | shortest idle | polling |
| 62 | idle_mean | avg idle | rhythm |
| 63 | idle_std | spread idle | irregularity |
| 64 | fwd_byts_b_avg | forward bytes per bulk | bulk rate |
| 65 | fwd_pkts_b_avg | forward packets per bulk | bulk count |
| 66 | bwd_byts_b_avg | backward bytes per bulk | bulk reply size |
| 67 | bwd_pkts_b_avg | backward packets per bulk | bulk reply count |
| 68 | fwd_blk_rate_avg | forward block rate | blocking |
| 69 | bwd_blk_rate_avg | backward block rate | blocking |
| 70 | fwd_seg_size_avg | forward segment avg | segment tuning |
| 71 | bwd_seg_size_avg | backward segment avg | server segment |
| 72 | cwr_flag_count | CWR (ECN) | congestion mgmt |
| 73 | subflow_fwd_pkts | subflow forward packets | multipath |
| 74 | subflow_bwd_pkts | subflow backward | multipath |
| 75 | subflow_fwd_byts | subflow forward bytes | path volume |
| 76 | subflow_bwd_byts | subflow backward bytes | path volume |

### A2. Window-context — `11 dims` (NEW), log1p+MinMax, rows 1:1 with each flow in same 60-s window

| # | Name | What it measures (this flow's 60-s window) | Why the base 76 needs it |
|---|---|---|---|
| 77 | ws_flows | flows your host sent in window | rate × crowd |
| 78 | ws_dst | distinct destinations your host hit | 100 flows to 1 host ≠ 100 to 100 — scan signal |
| 79 | ws_ports | distinct ports you hit | port-sweep vs host-sweep |
| 80 | ws_fwd | total bytes you sent | burst volume context |
| 81 | ws_bwd | total bytes you got | download context |
| 82 | ws_pkts_f | total forward packets | flood context |
| 83 | ws_pkts_b | total backward packets | reply flood context |
| 84 | ws_dur | avg duration of those flows | many fast = sweep |
| 85 | wd_flows | flows hitting the **dst you're talking to** | unmasks DDoS victim |
| 86 | wd_src | distinct sources hitting that dst | many-to-one victim |
| 87 | wd_dur | their avg duration | victim under burst vs normal |

> `ws_*` = `tmp.groupby(["wk","src"])` ; `wd_*` = `tmp.groupby(["wk","dst"])`
> — `experiments/exp_m5a_revival.py:build_ctx()`.

Frozen order: `CTX_DIMS = ["ws_flows","ws_dst","ws_ports","ws_fwd","ws_bwd","ws_pkts_f","ws_pkts_b","ws_dur","wd_flows","wd_src","wd_dur"]`.
Checkpoint = `train_m5a_revived.py:OUT` (`canonical`, `flow_lo/hi`, `ctx_lo/hi`).

See `schemas/feature_vector.json` (v3.0).

---

## B) Per-host graph vector — `8` (v1) / `19` (v2) dims, log1p+MinMax via `NodeScaler`

> Host nodes in `graph_builder.py`. `feature_set="v2"` is production.

### B1. v1 — `8 dims`, indices `0–7` STABLE forever

| # | Name | What it counts per 60-s window | Sweep signal |
|---|---|---|---|
| 0 | out_degree | distinct peers you talked to | scanner 200 vs normal 2 |
| 1 | in_degree | distinct peers that talked to you | DDoS victim |
| 2 | out_flows | total flows you sent | flood volume |
| 3 | in_flows | total flows you got | victim load |
| 4 | bytes_sent | `fwd_bytes` sum | exfil / flood |
| 5 | bytes_recv | `bwd_bytes` sum | download |
| 6 | unique_dst_ports | distinct dst ports you hit | port-sweep |
| 7 | mean_duration | avg flow duration | beacon vs bulk |

### B2. v2 — `+11` shape dims → `19` total (`indices 0–7 identical`), same scaler

| # | Name | What it counts | Why the raw counts need it |
|---|---|---|---|
| 8 | bytes_ratio | sent/(sent+recv+1) | exfil vs download asymmetry |
| 9 | flows_per_out_peer | `out_flows / out_degree` | scanner ~1/flow:peer; flood victim many |
| 10 | flows_per_in_peer | `in_flows / in_degree` | symmetric |
| 11 | bytes_sent_per_flow | sent / out_flows | packet bloat |
| 12 | bytes_recv_per_flow | recv / in_flows | reply size |
| 13 | unique_src_ports | distinct client ports contacting this host | server vs victim |
| 14 | dst_port_entropy | entropy of dst ports | uniform spread = scan |
| 15 | protocol_entropy | entropy of protocol | mixed-proto abuse |
| 16 | tcp_frac | fraction proto==6 | tcp flood |
| 17 | udp_frac | fraction proto==17 | udp flood |
| 18 | duration_std | std of duration | beacon regularity |

Frozen order: `V2_FEATURE_NAMES = NODE_FEATURE_NAMES + [bytes_ratio, flows_per_out_peer, …, duration_std]` — `graph_builder.py:88`.

Consumers: `gnn_model.py` (produces `gnn_autoencoder_v1_logscale.pt` @ v1 and `_v2.pt` @ v2), `host_ae.py` (Pillar 3 reuses plumbing, no Checkpoint-1 touch).

---

## C) Where to look

* Flows (1–87): `detection/training_features/README.md` (this file) + `schemas/feature_vector.json:3.0` + `experiments/exp_m5a_revival.py:CTX_DIMS`
* Hosts (0–7 / 0–18): `detection/graph_builder.py:NODE_FEATURE_NAMES`, `V2_FEATURE_NAMES`
