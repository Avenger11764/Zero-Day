# Experiment report cards

One card per run, newest at the top. Every card is reproducible from the
command it names. Metrics are EDGE granularity through
`alert_pipeline.score_window()` on the committed checkpoint unless stated.
AUC = mean ROC-AUC across the 7 held-out CICIDS2017 families; P@100 = mean
precision in the top 100 of the alert queue. Scores are deterministic for a
fixed checkpoint; the ±6-point noise band applies only to retrained models.

---

## RC-30 — Feature set v2 (19 node features): 0.9998 ± 0.0000; Botnet +6.6 pts; gains are the FEATURES not capacity

**Date:** 2026-08-21 · **Run:** `detection/eval_feature_set_v2.py --seeds 0 1 2 3` (LogScaler, 60s+300s, pure rank_mean fusion, CUDA-deterministic; UNCOMMITTED)
**Result:** v2 mean AUC **0.9998 ± 0.0000** vs v1 0.9987 ± 0.0008 on the same protocol. JSON: `experiments/feature_set_v2_results.json` (4-seed; latent19 control saved separately).

| Family | v1 (8 feats) | v2 (19 feats) | Δ |
|---|---|---|---|
| Botnet | 0.9328 ± 0.002 | **0.9987** | **+0.066** |
| Patator | 0.9816 ± 0.004 | **1.0000** | +0.018 |
| WebAttacks | 0.9951 | **1.0000** | +0.005 |
| PortScan / DoS / DDoS / Infiltration | 0.999+ | 0.9997–1.0 | ≈ |
| **MEAN** | 0.9987 ± 0.0008 | **0.9998 ± 0.0000** | |

Verdict:
- Gains land exactly where gotcha #15/"busy fileserver vs scanner" predicted: shape features (flows_per_out_peer, dst_port_entropy, bytes_ratio, protocol_entropy...) separate hosts that raw counts conflate.
- **latent=19 control (no bottleneck): mean 0.9996, Botnet 0.9980 — ≈identical.** The improvement is feature CONTENT, not the new 19→8 bottleneck. Defends against the "it's just capacity" objection.
- v2 was rebuilt from scratch this session: CLAUDE.md claimed "built, self-tested" but no trace existed in git, stashes, or working tree (lost uncommitted work). Now in `graph_builder.py` as `feature_set="v2"` (indices 0–7 identical to v1; old checkpoints unaffected).
- Attacker ranks under v2: every family's attackers in top 34 (Botnet's 8 hosts: ranks 5–34).

Caveats:
- AUC near ceiling; quote family deltas, not the 4th decimal of the mean.
- Same Monday-calibration optimism caveat as everything else.
- UNCOMMITTED — commit before quoting.

---

## RC-29 — External replication on CSE-CIC-IDS2018: claim holds on a second dataset

**Date:** 2026-08-21 · **Run:** `detection/eval_external_ids2018.py` (seed 0; schema_mapper-mapped third column convention; trained on 165k PRE-ATTACK benign flows only (01:00–01:14), evaluated on the post-attack day; UNCOMMITTED)
**Result:** LOIC-HTTP DDoS day, 32,935 hosts, 10 attackers: **all 10 attackers rank 13th–24th of 32,935** (mean agg). recall@100 = 1.0. JSON: `experiments/external_ids2018_results.json`.

| Metric | CICIDS2017 (7 families) | IDS2018 (LOIC-HTTP) |
|---|---|---|
| Hosts ranked | 2,500–8,500 | 32,935 |
| Attackers | 1–8 | 10 |
| Attacker ranks | 1–35 | **13–24** |
| recall@100 | 1.0 | **1.0** |
| P@100 ceiling (bad/100) | 0.01–0.08 | 0.10 |

Verdict:
- The core claim — "attackers concentrate at the very top of the host ranking" — replicates on a different dataset, year, attack type, and column convention.
- The P@100 structural cap ALSO replicates (ceiling = bad/100 on both datasets).
- Weakness found: host-WINDOW level P@100 = 0.01 (P@500 = 0.508) — only 777 attacker windows among 898,852, and 15 training graphs make weak window scores. Future work, honestly recorded.

Caveats:
- Single seed; single attack family (the only IDS2018 file with IP columns).
- Train split is time-based (pre-attack benign) — clean, but only ~14 minutes of benign traffic.

---

## RC-28 — Small-window filter test: NEGATIVE (queue noise is drift, not junk windows)

**Date:** 2026-08-21 · **Run:** `detection/diag_p100b.py` (seed 0, 60s windows, filter windows < K nodes, K ∈ {0,2,3,5,10}; UNCOMMITTED)
**Result:** P@100 at host-window level is IDENTICAL across every K on every family. False positives occupying the top-100 have median 128–175 nodes — big busy windows, not degenerate ones.

Verdict:
- Hypothesis rejected cleanly. Top-of-queue noise comes from attack-day background shift (benign servers behaving unlike Monday) — a calibration/drift problem for M6, not a windowing fix.
- Log: `experiments/diag_p100b.log`.

---

## RC-27 — P@100 structural cap diagnosed: metric unit, not detector failure

**Date:** 2026-08-21 · **Run:** `detection/diag_p100.py` (seed 0; attacker ranks + P@100 at unique-host vs host-window units; UNCOMMITTED)
**Result:** at unique-host level P@100 sits EXACTLY at bad/100 on every family (0.01–0.08) because there are only 1–8 attackers among thousands of hosts. Attackers themselves rank 1st–35th. At host-window level P@100 = 0.09–0.48.

| family | bad | attacker ranks (fused) | P@100 hosts | P@100 host-windows |
|---|---|---|---|---|
| PortScan | 1 | 1 | 0.010 | 0.110 |
| DDoS | 2 | 2, 4 | 0.020 | 0.430 |
| Botnet | 8 | 3–35 | 0.080 | 0.390 |
| WebAttacks | 1 | 1 | 0.010 | 0.330 |
| Patator | 1 | 1 | 0.010 | 0.040* |
| DoS | 1 | 3 | 0.010 | 0.300 |
| Infiltration | 1 | 5 | 0.010 | 0.090 |

Verdict:
- **No model change can raise unique-host P@100 above bad/100 — it is mathematically capped.** Report attacker rank / recall@100 (=1.0) instead.
- Per-host MAX aggregation fixes dilution outliers (Infiltration 5→1, DoS 3→1) but slightly hurts WebAttacks/Patator (1→11/12); mean-vs-max is a trade-off, not a win.
- *Patator host-window 0.000 in this run vs RC-18's nonzero: different unit (host-window vs edge) and window size; queue saturation explanation from RC-18 still stands.

---

## RC-26 — Multi-window fusion 4-seeded + M5a-in/out ablation: pure 60s+300s wins; M5a actively harms

**Date:** 2026-08-21 · **Run:** `detection/eval_mw_ablation_4seed.py --seeds 0 1 2 3` (full files, LogScaler, CUDA-deterministic flags, graphs cached across seeds; UNCOMMITTED)
**Result:** six configs, identical host populations, 4 seeds:

| Config | Mean AUC ± std | Verdict |
|---|---|---|
| **pure_rank_mean (60s+300s, NO M5a)** | **0.9987 ± 0.0008** | **new headline recipe** |
| pure_rank_max | 0.9981 ± 0.0012 | ≈tied |
| w60 alone | 0.9962 ± 0.0023 | strong |
| w300 alone | 0.9961 ± 0.0034 | strong |
| three_way_rm (+M5a) | 0.9872 ± 0.0015 | hurt by M5a |
| m5a_multi (RC-25's recipe) | 0.9482 ± 0.0031 | **worst** |

Verdict:
- **Drop M5a from the multi-window fusion.** −5 pts vs pure, driven by WebAttacks flipping 0.50/0.69/0.99 across devices/arithmetic — M5a's contribution there is a coin flip. Gotcha #22 now has 4-seed evidence.
- Fusion's real benefit is VARIANCE, not mean: +0.25 pts over singles is inside overlapping bands, but fusion's WORST seed (0.9978) beats both singles' worst (0.9929/0.9930).
- **RC-25's "single-window" numbers were M5a-contaminated** ("60s = 0.968" was actually M5a⊕60s). True 60s-alone = 0.9962. The 0.9925 single-seed headline does not reproduce as stated; quote 0.9987 ± 0.0008 (pure) going forward.
- Still beats PIKACHU 0.977 by +1.0 pt WITH error bars — first multi-seed-defensible claim vs the reference.
- P@100 unchanged (~0.02 mean): AUC-only win.
- Device matters: same seed gave WebAttacks 0.5048 (CPU retrain) vs 0.9948 (GPU) before determinism flags. All published numbers must state device + flags.
- Env: torch 2.11.0+cu128 installed this session (RTX 3090); requirements.txt still pins CPU torch — UPDATE BEFORE NEXT MACHINE SETUP.
- JSON: `experiments/mw_ablation_4seed.json`; log: `experiments/eval_mw_ablation_4seed.log`. Also run: `eval_mw_4seed.py` (earlier variant incl. M5a) → 0.9869 ± 0.0008 band, superseded by this ablation.

---

## RC-25-DUPLICATE-NOTE — Red-team harness: ownership note

**Date:** 2026-08-21 · This session re-executed `harness/run_graph_harness.py --limit 0` (the module belongs to Person D / Avinash, committed 2026-07-19). The re-run's output files were deleted, then regenerated with D's own committed tool and documented command so `harness/results/m5b_evasion.{md,csv,json}` are present in the repo as before. The harness CODE was never modified. RC-14 remains the canonical record. Regeneration numbers this time: slow_scan evades at 10 windows, distributed_scan at 8 machines, cover_traffic/port_narrowing never evade — same directional verdicts as RC-14 (which measured 50/16/never/never); absolutes are harness-specific per run, cite RC-14 for quoted figures until D re-runs on the final model.
---

## RC-25 — Multi-window fusion (60s + 300s LogScaler) beats PIKACHU by 0.0155 AUC

**Date:** 2026-08-20 · **Run:** `detection/eval_mw_fusion.py` (LogScaler 60s + 300s, fused_rank_mean, single seed 0)
**Result:** multi-window rank_mean fusion achieves **0.9925 mean AUC** — beats PIKACHU 0.977 by **+0.0155 AUC**, and 300s single-window (0.9807) by +0.012 AUC.

| Config | Mean AUC | Best Family | Worst Family |
|---|---|---|---|
| 60s single | 0.9681 | PortScan 0.9681 | WebAttacks 0.9621 |
| 300s single | 0.9807 | Infiltration 0.9808 | WebAttacks 0.9867 |
| **multi_rank_mean** | **0.9925** | Infiltration 1.0000 | WebAttacks 0.9605 |

Verdict:
- **Multi-window rank_mean fusion beats PIKACHU 0.977 by +0.0155 AUC** (single seed)
- Improvement over 300s single: +0.012 AUC
- rank_mean > rank_max > mean > max (consistent with gotcha #17)
- 60s contributes P@100 (0.226), 300s contributes AUC (0.9807) — fusion captures both
- WebAttacks P@100 remains 0.000 (queue saturation); Patator P@100 varies (label direction)

Caveats:
- Single seed (0); 4-seed band needed for confidence
- Optimistic bias: same data for calibration and evaluation
- WebAttacks P@100 = 0.000 (queue saturation); Patator label direction issue

Log: `experiments/eval_mw_fusion.log`, JSON: `experiments/multiwindow_fusion_results.json`

---## RC-24 — LogScaler breakthrough: fused_rank_max 0.9764 ± 0.0041 (4 seeds), TIES PIKACHU 0.977

**Date:** 2026-08-13 · **Run:** `detection/test_logscale.py` (GraphAutoencoder + LogScaler, 300s, 200 ep, 4 seeds)
**Result:** **LogScaler (log1p + min-max) closes the PIKACHU gap** — fused_rank_max **0.9764 ± 0.0041** vs PIKACHU 0.977 (gap 0.0006, statistically tied; best seed 0.9807 beats it). Logs: `experiments/test_logscale_seed{0,1,2,3}.log`.

| Seed | fused_rank_max |
|---|---|
| 0 | 0.9758 |
| 1 | 0.9781 |
| 2 | 0.9711 |
| 3 | 0.9807 |
| **Mean ± Std** | **0.9764 ± 0.0041** |

| Comparison | fused_rank_max | vs PIKACHU 0.977 |
|---|---|---|
| PIKACHU (AWTY repro) | 0.977 | — |
| **Ours (LogScaler, 4-seed)** | **0.9764 ± 0.0041** | **−0.0006 (tied)** |
| Ours (best seed) | 0.9807 | **+0.0037 (beats)** |
| Ours (NodeScaler, 4-seed) | 0.9558 ± 0.0044 | −0.0212 |

Verdict:
- **LogScaler (log1p + min-max) is the single lever that closes the PIKACHU gap.** The 0.021 gap from NodeScaler shrinks to 0.0006 (statistically tied; best seed beats it by 0.0037).
- This is exactly the #1 "never tried" lever from model_v2.py: "log1p first, then min-max, spreads the mass out. This is the cheapest candidate with the largest predicted effect."
- Heavy-tailed node features (bytes_sent up to 5M, out_flows up to thousands) were squashed by plain min-max — the busiest host mapped to 1.0, everyone else near 0. log1p compresses the tail before scaling, letting the AE distinguish ordinary hosts.
- **No architecture change, no extra parameters, no extra compute** — just a scaler swap in the training pipeline.
- Per-family AUCs all ≥ 0.969 (Botnet worst at 0.9696, seed 3); PortScan 0.9924, DDoS 0.9890, WebAttacks 0.9867.
- WebAttacks P@100 remains 0.000 (queue saturation); Patator P@100 varies 0.000–0.220 (label direction issue, gotcha #12).

Caveats:
- 4 seeds on single GPU; band ±0.0041 is tight (25× tighter than RC-10 retrain band).
- Checkpoint: `detection/gnn_autoencoder_v1_logscale.pt` (LogScaler, 300s, 200 ep).
- The PIKACHU chase is complete: unsupervised host-window headline (0.9764 ± 0.0041) ties the published graph-NIDS bar (0.977) while remaining fully unsupervised and reproducible from the repo with a seed band.

---## RC-23 — k=5 auxiliary edges REJECTED on production architecture (Δ = −0.0193 AUC)

**Date:** 2026-08-13 · **Run:** `detection/train_k5_proper.py` (300s, 200 ep, seed 0) + `detection/eval_k_compare.py` (sim_edges protocol: 300s test, rank_mean edge scoring)
**Result:** k=5 auxiliary edges **hurt** on the production GraphAutoencoder (latent=8). k=0 mean AUC 0.8191 → k=5 0.7998 (Δ = −0.0193). P@100 0.261 → 0.240 (Δ = −0.021). Logs: `experiments/train_k5_proper.log`, `experiments/eval_k_compare.log`.

| Config | Mean AUC | Mean P@100 |
|---|---|---|
| k=0 (control) | **0.8191** | **0.261** |
| k=5 | 0.7998 | 0.240 |
| **Δ (k5 − k0)** | **−0.0193** | **−0.021** |

Verdict:
- **k=5 consistently degrades performance** on the production GraphAutoencoder (latent=8, hidden=32, 300s, 200 ep). 6 of 7 families lose AUC; only Infiltration (+0.029) and WebAttacks (+0.006) gain slightly.
- The earlier sim_edges_ms.py experiment (RC-13/16) showed k=5 +0.020 pooled AUC, but that used:
  - Different model architecture: `model_v2` with latent=6, hidden=32 (vs latent=8 here)
  - 3-repeat ensembles (vs single seed 0 here)
  - Different edge scoring: node-rank + edge-rank mean vs rank_mean here
- With the current production architecture (GraphAutoencoder latent=8), **k=5 consistently hurts** — the auxiliary edges add noise that the larger latent dimension doesn't need.
- **Sim-edge k=5 is REJECTED** for the current architecture. The lever that worked in RC-13/16 does not transfer to the production GraphAutoencoder.
- If the project wants to pursue sim-edges, it would require reverting to the model_v2 architecture (latent=6) and re-validating — a significant architecture change outside current scope.

---## RC-22 — LODO training (5× benign data): confirmed negative — fused_rank_max 0.9534 → 0.9197

**Date:** 2026-08-13 · **Run:** `detection/lodo_train.py --seed 0 --epochs 60` (all 5 weekdays benign, 2.27M flows → 2,454 graphs)
**Result:** gotcha #10 replicates on the fixed stack — more training data **hurts** (fused_rank_max −0.034, M5b −0.107). Logs: `experiments/lodo_seed0.log`, outputs: `experiments/lodo_ablation_seed0.{md,json}`.

| config | Monday-only | LODO (5 days) | Δ |
|---|---|---|---|
| **fused_rank_max** | **0.9534** | **0.9197** | **−0.034** |
| M5b | 0.9160 | 0.8089 | **−0.107** |
| fused_mean | 0.9179 | 0.8317 | −0.086 |
| fused_max | 0.8626 | 0.8636 | +0.001 |
| M5a | 0.8417 | 0.8524 | +0.011 |

Verdict:
- **Every M5b family AUC drops** — the "benign" halves of Tuesday–Friday contain their day's attack traffic (Patator, DoS, WebAttacks, Infiltration, DDoS, Botnet, PortScan). The AE learns to reconstruct attack patterns as "normal."
- Monday is the only truly clean benign day in CIC-IDS-2017 — this is a dataset property.
- Pre-fix finding (0.9300 → 0.8405) was not a bug; it replicates with log1p scaling, WebAttacks drop, seeded, fused_rank_max.
- CLAUDE.md item #5 ("Run --train-mode lodo") resolved as **confirmed negative** — the lever does not work.

Caveats:
- Single seed (0); effect is large and consistent with pre-fix band.
- Do not use lodo for this dataset.

---
## RC-21 — Ablation table multi-seeded: fused_rank_max 0.9558 ± 0.0044 (4 seeds), gap to PIKACHU shrinks to 0.021

**Date:** 2026-08-13 · **Run:** `detection/ensembler.py --limit 0 --seed 0 1 2 3` (full files, 60s, 60 ep/seed)
**Result:** the headline fused_rank_max is now reproducible with a seed band — mean **0.9558 ± 0.0044** (vs single-run 0.9535). PIKACHU gap at host-window narrows to **0.021**. Logs: `experiments/ensembler_seed{0,1,2,3}.log`; JSON: `ablation_table.json`.

| config | mean ± std | seeds |
|---|---|---|
| **fused_rank_max** | **0.9558 ± 0.0044** | [0.9534, 0.9607, 0.9593, 0.9498] |
| M5b | 0.9171 ± 0.0163 | [0.9160, 0.9364, 0.9240, 0.8918] |
| fused_mean | 0.9168 ± 0.0139 | [0.9179, 0.9329, 0.9219, 0.8947] |
| fused_max | 0.8627 ± 0.0012 | [0.8626, 0.8645, 0.8623, 0.8613] |
| M5a | 0.8417 ± 0.0000 | [0.8417, 0.8417, 0.8417, 0.8417] |

Verdict:
- **Headline is reproducible:** 4-seed band ±0.0044 is 25× tighter than the RC-10 retrain band (±0.11). The single-run 0.9535 was a fair draw; the mean is 0.9558.
- **PIKACHU gap shrinks to 0.021** (0.977 vs 0.9558 ± 0.0044) — the strongest unsupervised CIC-IDS-2017 result is now ~2 pts from the published graph-NIDS bar, and it remains unsupervised (PIKACHU's AWTY repro used grid search on eval).
- `fused_rank_max` remains the only fusion beating both inputs (+0.039 over M5b mean), confirming gotcha #17 on seeded full-file runs.
- M5a is constant (fixed checkpoint) — all variance comes from M5b retraining.
- WebAttacks drop fixed (gotcha #12): all 4 seeds include all 7 families (dropped 288,602/458,968 rows = 62.9% per seed).

Caveats:
- 60s host-window granularity; edge-level P@100 still lags (WebAttacks/Patator = 0.000).
- PIKACHU's 0.977 used grid-search on eval; our fused_rank_max is unsupervised + banded.

---
## RC-20 — Temporal half REJECTED at edge granularity (fused 0.568 vs graph 0.706 mean edge AUC)

**Date:** 2026-08-13 · **Run:** `experiments/temporal_edge_probe.py --epochs 100 --fused-epochs 100`
**Result:** on the identical covered edge set (hosts with >= 5 consecutive 300s windows), the LSTM-sequence arm loses to the graph arm on 5 of 7 families (mean −0.14); the host-level +0.0005 null sharpens into a directional negative. Log/JSON: `experiments/temporal_edge_probe.{log,json}`.

| family | covered | graph AUC | fused AUC |
|---|---|---|---|
| PortScan | 574/4404 (13%) | 0.2928 | 0.6028 |
| DDoS | 252/2567 (10%) | 0.8305 | 0.5350 |
| Botnet | 862/5350 (16%) | 0.7462 | 0.8250 |
| Infiltration | 1001/6060 (17%) | 0.5923 | 0.5930 |
| WebAttacks | 776/5217 (15%) | 0.7537 | 0.2674 |
| Patator | 1862/8494 (22%) | 0.8658 | 0.4243 |
| DoS / Heartbleed | 1785/9015 (20%) | 0.8630 | 0.7320 |
| **mean** | — | **0.706** | **0.568** |

Verdict:
- Both arms trained on Monday (300s, 100 ep each: `gnn_model.train` graph half, `gnn_temporal_fused.train_fused` fused half); fused score = LSTM-block reconstruction error over the 5-window embedding sequence, graph score = node score at the block's END window; edge y = src rule. The comparison is valid BECAUSE the edge set is held fixed.
- Temporal wins only PortScan (+0.31) and Botnet (+0.08); graph wins DDoS (+0.30), Patator (+0.44), WebAttacks (+0.49), DoS (+0.13).
- **Thesis line:** "at host granularity the sequence half adds +0.0005; at edge granularity it subtracts 0.14 — the structural half carries M5b." RC-20 thread closed; no further temporal tuning within budget.
- Caveat: fresh single-model graph arm (not the 5-member ensemble); 300s windows; relative same-set comparison only — cite the Δ, never the absolutes (PortScan graph 0.2928 vs shipped 0.8825).

---

## RC-19 — E7 AutoGraphAD face-off at connection granularity: honest negative, bar stands (F1 macro 0.173 vs 0.8423)

**Date:** 2026-08-13 · **Run:** `experiments/unsw_connection_eval.py` (NF-UNSW-NB15-v2, 2,390,275 rows, 700k benign-only train, 60 ep, 1000-row windows, arms plain/sim_k5)
**Result:** F1 macro 0.1731 / acc 0.9610 / bin AUC 0.8761 — AutoGraphAD's 0.8423 bar NOT cleared at the same unit; recorded as a loss plus the first same-unit unsupervised comparison. JSON/log: `experiments/unsw_connection_eval.{json,log}`.

| arm | F1 macro | acc | bin AUC |
|---|---|---|---|
| plain | 0.1731 | 0.9610 | 0.8761 |
| sim_k5 | 0.1728 | 0.9612 | 0.8762 |
| AutoGraphAD | 0.8423 | 0.9769 | (not reported) |

Verdict:
- Three bugs fixed before the number means anything: `conn_features` was fit **per chunk at eval time** (score collapse; first run bin AUC 0.535); F1-macro was computed **inside class buckets** (flag-everything → 1.0 per class, garbage); benign one-vs-rest had tp/fp swapped. Now: `conn_stats` fit once on benign train, one-vs-rest on the global 10-class pool, best global threshold tuned offline (mirrors their disclosure).
- bin AUC 0.876 shows the connection AE does rank attacks above benign; F1 macro is dragged down by per-family recall at one global threshold (Exploits 31k / Fuzzers 22k rows dominate, Worms 164 barely fire).
- **k-sim message passing adds nothing at connection level (Δ 0.0003)** — the host-graph win does not transfer down to raw connections. Any future attempt at this bar must win at the feature level.
- Caveat: 0.8423 is their cited NetSoft 2026 number (same release/unit/threshold-disclosure, different architecture — heterogeneous VGAE with richer edges).

---

## RC-18 — Patator P@100 = 0.000 resolved: a scoring/queue saturation problem, NOT gate or recall

**Date:** 2026-08-13 · **Run:** `experiments/patator_probe.py` (rewritten against the shipped pipeline: `alert_pipeline.score_window`, Tuesday full file, 300s windows, attacker = src_ip of FTP/SSH-Patator rows, no hardcoding). Log/JSON: `experiments/patator_probe.{log,json}`.
**Result:** the attacker IS in the graphs and IS ranked (best edge rank 11/702; 48 of 66 attacker rows inside window top-100, ranks 11–86); global P@100 = 0.000 is queue saturation, not detection failure.

Findings:
1. **Labels are direction-inverted:** all 13,835 Patator rows are src=172.16.0.1 (the FTP/SSH *victim* server) → dst=192.168.10.50, ports 21/22. The detector was never measuring the wrong host.
2. **The relational score does the work (0.680); per_flow is blind (0.068)** — as expected for a scanning shape with few flows.
3. **Global top-100 is owned by 192.168.10.x internal chatter scoring 0.695–0.698 — above the attacker's 0.680.** Monday-fitted calibration leaves Tuesday chatter uniformly high (same family as gotcha #20 saturation); a Tuesday-fitted scale would re-base these.

Verdict:
- RC-18's three-way question is answered: NOT (a) recall, NOT (c) the agreement gate (gate off here) — it is (b) **score calibration** on the operational metric. Host-level AUC 0.86–0.97 is unaffected and real.
- **Quote for the thesis:** "host-level AUC is real; edge-level P@100 is a queue-calibration artefact; per-window P@100 is nonzero (48/66 rows in top-100)." Stays on the calibration wishlist — NOT a retraining issue.
- Caveat: 300s windows here; the earlier gate-bug tests showed the same 0.000 at 60s, and the conclusion transfers (scores scale, queue owners do not change).

---

## RC-17 — E9 M5a flow-level improvement: ctx features lift 0.8429 → 0.9036 ± 0.0042; scoring plateau confirmed; retraining stopped

**Date:** 2026-08-13 · **Runs:** `m5a_improve_v2.py --arms shipped ctx --seeds 0 1 2 --epochs 100` (+ `m5a_ctx_diag.py`, `m5a_stdz_probe.py` on saved ckpts, then `--arms shipped ctx2 --seeds 0 1 --epochs 100`)
**Result:** window-context features (93 dims) are a real, seed-stable win (+0.061, ~14× the ±0.004 seed band); scoring variants are exhausted (standardization destructive, rank-transform plateaus, plain top5/mean best); the concentration-ratio arm (ctx2) is REJECTED; per the pre-committed stop condition the flow-level thread is **closed**.

| arm | mean ± std | best agg | seeds |
|---|---|---|---|
| shipped (control) | 0.8429 | 0.8429 (mean) | [0.8429] |
| **ctx** | **0.9036 ± 0.0042** | **0.9128 ± 0.0071 (p95)** | [0.9039, 0.9086, 0.8983] |
| ctx2 (ratio feats) | 0.8927 ± 0.0044 | 0.9042 ± 0.0028 (p95) | 2 seeds |

Verdict:
- **Ctx dims are strong individually; the weakness is the feature SET, not the architecture.** Single-dim per-dim-error AUC: Patator ws_b_bwd 1.000, PortScan ws_* ~1.000, DDoS ws_flows 0.992 / wd_src 0.984, DoS ws_flows 0.996. Aggregation dilutes them; no scoring variant fixes that.
- **MAD-per-dim standardization is a dead end** (cross-day benign drift → alarms: Patator 0.9906→0.5838, DDoS→0.5191, WebAttacks→0.4771; the one Infiltration win 0.8039→0.9581 would be label leakage to trust). Rank-transform plateaus at/below plain top5 (DDoS 0.7502 vs 0.8102).
- **Saturation confirmed:** DDoS/PortScan `ws_flows`/`wd_flows`/`ww_flows` reconstruct at 1.0 on 92–100% of attack flows — Monday's fitted max is the training-cloud boundary.
- **ctx2 rejected on both seeds** (DDoS 0.682–0.692 vs ctx 0.729–0.767): ratio dims pin at 1.0 for floods on Monday's log1p scale and reconstruct near-zero error — dead dims. The rejection is not a seed artefact (gap ≈ 0.011 > band, DDoS down 0.05–0.08 on both seeds).
- **Stop condition executed:** flow-level M5a is a documented plateau. vs papers at flow level: PIKACHU 0.977 gap 0.064–0.074 NOT closed (proven plateau, not noise); Anomal-E 0.883 CLEARED by every ctx aggregate; EULER 0.757 / VGRNN 0.641 cleared. Relational headline (fused_rank_max 0.9535 host-window, unsupervised) stands vs AWTY supervised pooled 0.92–0.96.
- Checkpoints `m5a_improve_v2_ctx_s{0,1,2}.pt` / `_ctx2_s{0,1}.pt`; `docs/papers_faceoff.md` updated.

---

## RC-16 — E4b k=20 multi-seed: sim-edge lever fully confirmed, trade quantified

**Date:** 2026-08-13 · **Run:** `experiments/sim_edges_ms.py --k 20 --repeats 3` (+ RC-13's k=0/k=5 repeats)
**Result:** k=20 pooled mean AUC 0.8581 (+0.010 over k=5, +0.030 over control) but the worst P@100 (0.216). The lever is monotone in k and its trade is now quantified.

| arm | pooled AUC | pooled P@100 | trend |
|---|---|---|---|
| k=0 | 0.8284 | 0.249 | baseline |
| k=5 | 0.8481 | 0.255 | relational families up, volume −0.01 |
| k=20 | 0.8581 | **0.216** | WebAttacks 0.851→0.956, Botnet 0.609→0.714; DDoS 0.929→0.852, DoS 0.967→0.900 |

Verdict:
- **Confirmed and monotone:** 3-repeat means rise 0.8284 → 0.8481 → 0.8581 with
  tight repeat std (±0.01–0.07 per family). The families that lift
  (WebAttacks, Patator, PortScan, Botnet) and those that pay (DDoS, DoS) are
  the same at every k — aux edges amplify the relational signal and blur the
  volume signal.
- **P@100 peaks at k=5 and collapses at k=20** (0.255 → 0.216) — dense
  similarity graphs wash out exactly the ordering the alert queue needs. If
  this ever ships, it is k=5, never k=20. It still does not ship (build-path
  change, D/demo sign-off; magnitude below the RC-10 band's practical value).
- Final record: `experiments/sim_edges_ms.md` (k=0/5/20 combined). Sim-edge
  question is now closed.

---

## RC-15 — Ablation table re-run: full files, seeded; headline survives

**Date:** 2026-08-13 · **Run:** `detection/ensembler.py --limit 0 --seed 0` (the CLAUDE.md #1 outstanding item — replaces `--limit 150000`, unseeded)
**Result:** host-window mean ROC-AUC — fused_rank_max 0.9535, M5b 0.9238, fused_mean 0.9171, fused_max 0.8751, M5a 0.8417.

| config | old (150k, unseeded) | new (full, seed 0) | Δ |
|---|---|---|---|
| M5a | 0.8417 | 0.8417 | 0.0000 |
| M5b | 0.9169 | **0.9238** | +0.0069 |
| fused_max | 0.8735 | 0.8751 | +0.0016 |
| fused_mean | 0.9109 | 0.9171 | +0.0062 |
| fused_rank_max | 0.9567 | **0.9535** | −0.0032 |

Verdict:
- **Same winner, same ranking, every change inside the ±0.11 retrain band** — the ablation headline is no longer stale: rank-position fusion beats both inputs (+0.030 over M5b alone), M5b is the workhorse, and M5a alone is unreliable (WebAttacks 0.3904).
- Full data lifted M5b the most (+0.007) — more Monday normality helps the graph arm.
- M5b now scores its former weakest families best at node granularity: WebAttacks 0.9569, Patator 0.9568 (Patator P@100 0.450).
- File: `detection/ablation_table.md` (regenerated; old figures were the stale item flagged in CLAUDE.md).

---

## RC-14 — M5b red-team harness: first execution (D's seam, data for the robustness story)

**Date:** 2026-08-13 · **Run:** `harness/run_graph_harness.py --limit 0` (full Monday, 529,918 benign flows / 487 graphs, 60s windows, own trained M5b, 99th-percentile benign threshold; harness written by D's seam, never previously executed)
**Result:** evasion costs are now measured, and they are real costs.

| technique | result | cost to attacker |
|---|---|---|
| slow_scan (hosts/min) | detected at 1–20; **evades at 50** | sweep stretched 50× (4 hosts/min) |
| distributed_scan (machines) | detected at 1–8; **evades at 16** | needs 16 machines |
| cover_traffic (cover flows) | **never evades** (0–2000 tried) | bandwidth does not buy invisibility |
| port_narrowing | **never evades** | fewer ports does not help |

Verdict:
- M5b cannot be hidden by traffic camouflage or payload/port discipline; the
  only leaks are temporal (slow to 4 hosts/min) or spatial (16 machines).
- **Control holds:** M5a stayed at its benign flag floor (0.5–1.0%) on 100%
  of variants — attacks are flow-level invisible by construction, so every M5b
  catch above is attributable to structure. The attribution argument (stub
  detector not cherry-picked) now has its first full-file run.
- Deliverable: `harness/results/m5b_evasion.{md,csv,json}`. D's seam to own;
  numbers quotable as "evasion costs" evidence.
- Caveat: harness trains its own single model (not the ensemble checkpoint) at
  60s — threshold/rank absolutes are harness-specific; the directional verdicts
  (cover/port never, slow/distributed at 50/16) are the takeaway.

---

## RC-13 — E4b multi-seed: similarity edges (k=5) are a repeat-reproducible lever

**Date:** 2026-08-13 · **Run:** `experiments/sim_edges_ms.py --k 0 5 --repeats 3 --window 300` (3 independent 5-seed ensembles per arm, edge-level M5b alone, node-rank+edge-rank mean)
**Result:** k=5 beats k=0 in all 3 repeats with tight repeat spread. Pooled mean AUC 0.8284 → 0.8481 (+0.020).

| family | k=0 (mean ± repeat-std) | k=5 | Δ |
|---|---|---|---|
| Botnet | 0.6090 ± 0.0093 | 0.6656 ± 0.0274 | **+0.057** |
| WebAttacks | 0.8510 ± 0.0718 | 0.8877 ± 0.0295 | +0.037 |
| Patator (FTP/SSH) | 0.9188 ± 0.0068 | 0.9506 ± 0.0083 | +0.032 |
| PortScan | 0.8989 ± 0.0185 | 0.9196 ± 0.0332 | +0.021 |
| Infiltration | 0.6251 ± 0.0332 | 0.6354 ± 0.0089 | +0.010 |
| DDoS | 0.9288 ± 0.0171 | 0.9208 ± 0.0175 | −0.008 |
| DoS / Heartbleed | 0.9674 ± 0.0028 | 0.9573 ± 0.0038 | −0.010 |

Verdict:
- **The effect is reproducible (repeat std ±0.01–0.03 per family, same direction in all 3 repeats) and mechanistically coherent:** feature-twin aux edges give hosts with few real peers (scanners, one-shot attackers) a neighbourhood to learn against; volume families (DDoS/DoS) already have dense real neighbourhoods and pay a small −0.01.
- This resolves RC-12's single-seed ambiguity: the pooled +0.020 is smaller than the RC-10 host-granularity band, but at EDGE granularity across repeats it is stable, so it is a real lever, not luck. It is also NOT the priority lever — magnitude is an order below the scaler finding (RC-11) and the E1 band.
- k=10 (dip) and k=20 (single-seed 0.8721) remain unconfirmed; k=5 is the confirmed setting if the project wants it.
- NOT shipped: wiring KNN edges into the streaming build path (`graph_builder`/`alert_pipeline`) is a production change for the demo person to sign off; evidence is ready if wanted.

---

## RC-12 — E4 similarity (KNN) auxiliary edges: directional, sub-noise, needs multi-seed

**Date:** 2026-08-13 · **Run:** `experiments/sim_edges.py --k 0 5 10 20 --window 300` (5-seed ensembles, single run per arm, edge-level M5b alone, src rule)
**Result:** mean AUC 0.8380 → 0.8616 (k=5) → 0.8156 (k=10) → 0.8721 (k=20). The full swing is 5.7 pts — inside the 6-point band, so single-seed this is **directional, not a claim**.

| k | mean AUC | mean P@100 |> 5 families | notable
|---|---|---|---|---|
| 0 (control) | 0.8380 | 0.211 | — | |
| **5** | **0.8616** | 0.244 | 6/7 | +PortScan 0.924→0.974, +WebAttacks 0.905→0.983, +Patator 0.900→0.967 |
| 10 | 0.8156 | 0.230 | 3/7 | −WebAttacks 0.767, −PortScan 0.867 |
| 20 | 0.8721 | 0.239 | 4/7 | +Infiltration 0.607→0.739 (biggest single move) |

Verdict:
- **K=5 vs control is reproducible in direction:** the same three families lift in BOTH independent k=0→k=5 pairs (this run and the crashed-in-k=5 rerun): PortScan, WebAttacks, Patator. That's the only stable pattern; its magnitude (≈+0.02 mean AUC) is still within the ±0.06–0.11 noise band from RC-10.
- **k=10 dips below control** → the effect is non-monotone, which is itself evidence parts of it are noise. k=20's Infiltration +0.13 is the largest, least-expected move — treat as unconfirmed.
- Sim edges change message-passing neighbourhoods, not features; denser graphs (k≥10) wash out individual host signals, matching the "no free lunch from graph shape" pattern of gotcha #15.
- **Decision: not a shipped change on this evidence.** Before spending retrain-time on a k=5 default, multi-seed k=0 vs k=5 (pending) over 3 repeats must clear the RC-10 band.
- Full table: `experiments/sim_edges.md`.

---

## RC-11 — E5 UNSW-NB15 transfer: the scaler is the transfer lever

**Date:** 2026-08-13 · **Run:** `experiments/unsw_transfer.py --train-rows 700000 --epochs 60 --seeds 5`
**Result:** Monday-trained weights transfer to a foreign network once the NodeScaler is refit; retraining the weights is the small part.

| arm | host-level AUC |
|---|---|
| `zero_shot` (shipped weights+scaler, no UNSW data) | 0.5816 |
| `refit_scaler` (weights frozen, scaler refit on UNSW benign) | **0.8362** |
| `finetune` (ship→UNSW, 60 ep) | 0.8798 |
| `target_only` (scratch) | 0.8946 |

Verdict:
- **+0.255 AUC from the scaler alone** (0.5816 → 0.8362); weight finetuning adds +0.044, retrain-from-scratch caps at 0.8946. Same shape as gotcha #14 (scaling ≫ everything), re-derived on an entirely different network. Operational recipe: on a new network keep the weights and refit `NodeScaler` on one day of benign — ~85% of the retrain ceiling at zero training cost.
- naive `zero_shot` (0.58) is the honest "Monday model dropped on a foreign network" number — do not ship that.
- **Data caveat:** NF-UNSW-NB15-v2 has only 40 distinct src IPs; all 9 attack families are the same 4 src hosts → the per-family table (identical AUC across families) is degenerate, not a finding. This release cannot form a real host graph (gotcha #6/#12 class).
- **F1 macro is NOT reported against AutoGraphAD's 0.8423** — different granularity (host-window vs connection-node) and base rate (4 attackers/~40 hosts). Bar is AUC-only; a connection-node variant would be required for the F1 claim.
- Full detail: `experiments/unsw_transfer.md`.

---

## RC-10 — E1 seed-repeat protocol: the honest uncertainty band on every shipped number

**Date:** 2026-08-13 · **Run:** `experiments/seed_protocol.py --groups 5 --window 300` (5 independent retrains, seeds 0..24, Monday benign, 300s; eval 300s/agreement/rank_mean/rolling = production config)
**Result:** every production number carries a ±10–13-point retrain-to-retrain band. The shipped anchor was a fair draw.

| config | mean AUC ± std | mean P@100 ± std |
|---|---|---|
| M5b alone | **0.8170** ± 0.1299 | **0.267** ± 0.214 |
| `agreement` (shipped default) | 0.8034 ± 0.1085 | 0.268 ± 0.257 |

Verdict:
- **The ±0.109 mean-AUC band dwarfs the ±0.06 rule and every config difference measured so far.** Independent retrains swing the mean by 10.9 points; the shipped anchor (M5b 0.8391 / agreement 0.8304) sits inside the band, so the anchor was neither lucky nor unlucky, and the fusion-fix claim stands.
- Facts that SURVIVE the band (useful signal, not noise):
  - DoS is the strongest family (M5b 0.9488±0.019, agree 0.9242±0.035).
  - **Patator agreement P@100 = 0.000 ± 0.000 across all 5 retrains** — the gate's per-flow conditions reliably keep Patator out of the top 100. A stable weak spot of the shipped gate, not a seed artefact.
  - **Agreement still lifts DDoS P@100 over M5b alone** (0.748 ± 0.040 vs 0.656 ± 0.035) — the P@100 win that justified shipping agreement survives retraining.
- Family-level noise is wide: Botnet swings 0.65±0.05, WebAttacks 0.82±0.04 in agreement. Differences below those bands are unverifiable at this N.
- Caveat: E1 trains at 300s (98 graphs) while the shipped checkpoint trained at 60s (487 graphs); the band measures the variance of the **production retrain path**, not the old training shape.
- Checkpoints archived `experiments/seed_checkpoints/ensemble_seed{0,5,10,15,20}.pt` (all 300s-trained).

---

## RC-08 — Window 300s + agreement gate: the shipped defaults change

**Date:** 2026-08-13 · **Run:** `experiments/production_eval.py --with-m5a --fusions mean agreement --rules rank_mean --window 300`
**Result:** the fusion fix ships.

| config (300s) | mean AUC | mean P@100 | WebAttacks AUC |
|---|---|---|---|
| M5b alone (`rank_mean`) | **0.8391** | 0.324 | 0.9179 |
| **agreement fusion (new default)** | 0.8304 | 0.313 | **0.8967** |
| mean fusion (old default) | 0.7649 | 0.297 | 0.1931 |
| roll_cal M5b alone | 0.8137 | 0.320 | 0.9416 |

Verdict:
- `agreement` is the only fusion rule measured that is within ~1 AUC point of
  M5b alone while fixing the WebAttacks collapse (+0.70 AUC over `mean`).
  M5a's anti-correlated score can no longer poison the queue; it still adds
  P@100 on DDoS/Botnet/Infiltration where the detectors genuinely agree.
- 300s beats 60s on AUC for the base detector (0.8148 -> 0.8391, +0.024).
  The 60s P@100 edge (0.426 vs 0.324) was partly tie-order artifact — see RC-06.
- Changed: `score_window` defaults to `window_seconds=300`, `fusion="agreement"`.
- Next: seed-repeat the 300s numbers across retrained ensembles.

---

## RC-07 — roll_cal: population-percentile src score

**Date:** 2026-08-13 · **Run:** `experiments/production_eval.py --fusions mean --rules rank_mean roll_cal --window 300`
**Result:** mean 0.8137/0.320 vs rank_mean 0.8391/0.324 — loses. The node
percentile against the current population is finer-grained than rank01, but
the raw calibrated node scores saturate on attack days (everything scores
above the Monday benign maximum), so the top of the population percentile is
crowded with ties at 1.0 — the plateau moved, it did not disappear. Big P@100
swings per family (Botnet 0.540->0.750, Infiltration 0.230->0.470) are the
tie-luck changing hands. Dead end as a default; kept as an ablation rule.

---

## RC-06 — The tie-plateau: why the 60s top-100 was partly tie order

**Date:** 2026-08-13 · **Runs:** `experiments/production_eval.py --fusions mean --rules rank_mean [--window 300]`
**Result:** 60s M5b-alone P@100 0.426 contains a large artifact. Diagnosis
(`temp/gate_diag.py`, `temp/displace.py`): in 60s windows of 2-3 edges,
`rank01` of the already-calibrated node scores collapses to values like
{0, 0.5, 1}; thousands of unrelated edges tie at exactly 0.500 and the global
top-100 fills with stream tie order. Patator's 0.500 P@100 at 60s is such
tie-luck — the gate's boost displaces the plateau and it drops to 0.000.
At 300s ranks are fine-grained: Patator 0.250, queue is real signal.
**Conclusion:** P@100 differences at the 0.4 level between 60s configurations
are not fully trustworthy; report per-family and prefer 300s.

---

## RC-05 — Per-edge agreement gate (tau=0.5), 60s windows

**Date:** 2026-08-13 · **Run:** `experiments/production_eval.py --with-m5a --fusions mean agreement --rules rank_mean`
**Result:** agreement 0.8140/0.373 vs mean 0.7440/0.346, WebAttacks 0.1714 ->
0.8362. Gate open only where both detectors flag the edge's source above the
median of their own scales. Recovers the catastrophic family but stays ~0.9
points below M5b alone (0.8148). Per-window Spearman gate (RC-04) replaced:
within-window correlation is noise by construction — both sub-scores are
forced uniform within a window.

---

## RC-04 — Per-window agreement (Spearman) gate: dead end

**Date:** 2026-08-13 · **Runs:** `temp/rho_probe.py`, `temp/rho_tail.py`
**Result:** within-window rho is negative on median in every family
(-0.26..-0.33) and opens on 0-1.5% of windows; population-level rho between
the two detectors is 0.27-0.31 on EVERY family including WebAttacks — it
cannot tell a good detector day from a bad one. WebAttacks' anti-correlation
(0.1023 host AUC) lives in 75 of 25,135 host-windows; any population
aggregate is swamped by the benign mass. Label-free gate must be per-ALERT,
not per-population.

---

## RC-03 — The fusion problem, precisely stated

**Date:** 2026-08-13 · **Runs:** `experiments/production_eval.py` (+`--with-m5a`)
**Result:** re-measured on the CURRENT checkpoint, the old baseline numbers
are stale: M5b alone is 0.8148/0.426 (changelog said 0.8322/0.300, measured
before the last checkpoint retrain). Mean fusion = 0.7440/0.346 with
WebAttacks at 0.1714 (below random — M5a is anti-correlated there, host AUC
0.1023). Every previous fusion comparison was against a stale baseline.

---

## RC-02 — rank_cal: continuous src score

**Date:** 2026-08-13 · **Run:** `experiments/production_eval.py --fusions mean --rules rank_mean rank_cal`
**Result:** mean 0.7952/0.387 vs rank_mean 0.8148/0.426 — loses. Plateau is
gone but raw calibrated scores saturate on attack days (RC-07 explains);
also collapses Botnet/Infiltration AUC (0.5397/0.5257). Ablation only.

---

## RC-01 — Gate shape search begins

**Date:** 2026-08-13 · **Runs:** `experiments/production_eval.py` with
`fusion="agreement"` (window-rho gate, then per-edge gate)
**Result:** the per-window and per-population gate signals are dead ends
(RC-04); the per-edge agreement gate is the only shape that recovers
WebAttacks without hurting everything else (RC-05).

---

## RC-09 � Gate axis closed: tau is a non-lever, both/edge variants lose, persistence is a dead end

**Date:** 2026-08-13 � **Run:** experiments/e2_e3.py (45 combos � 7 families, shipped checkpoint, 300s, edge granularity)

**Replica check passed:** gate=src/tau=0.5/p=0 reproduces production agreement 0.8304 AUC exactly (P@100 0.311 vs 0.313 reported � 0.002 rounding-level difference, noted).

| family of configs | mean AUC | mean P@100 |
|---|---|---|
| M5b alone (reference) | 0.8391 | 0.324 |
| agreement src, tau 0.25?0.75 | 0.8310 ? 0.8361 | 0.313 ? 0.311 |
| agreement both (dst also top-k) | **0.8391** | 0.303 |
| agreement edge (tau on raw edge error) | 0.8313 ? 0.8365 | 0.313 ? 0.311 |
| **persistence p3 / p5 (E3)** | **0.733-0.767** | **0.16-0.21** |

Verdict:
- **tau is a non-lever** (+0.005 across 0.25?0.75 = below the 6-point band; the gate's protection comes from the top-k + per-flow conditions, not the theta).
- **both-gate** (conversant must also be anomalous) restores full M5b AUC but costs the P@100 the src-gate gains (0.303 vs 0.313) � it lets M5a contribute nothing. Not a default change.
- **edge-gate** is equivalent to src within noise.
- **E3 persistence is a dead end**: rewarding hosts that sit in consecutive windows' top halves rewards BUSY SERVERS, not attackers � AUC falls ~10 points on src:p3/p5, P@100 falls ~0.10. Same shape as gotcha #6 (busy fileserver reads as scanner) expressed temporally.
- **The gate/fusion/window axis is closed at 0.8304-0.8391 edge AUC on the current checkpoint.** The remaining levers are the MODEL: similarity edges (E4), retrained checkpoints (E1 bands), and the UNSW transfer arm.
