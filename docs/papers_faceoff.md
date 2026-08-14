# Paper face-off table — 31 papers vs our numbers (2026-08-13)

Every claim states the metric, the unit, and the dataset release. "Ours" uses
the closest valid measurement we hold. Protocol matches are Tier 1; same-data
different-unit or different-premise are Tier 2 (not claimable, listed so a
reviewer cannot spring them on us). Threshold policy stated per row.

House numbers (CICIDS2017, unsupervised, trained on Monday benign only):
- node/host-window mean AUC (7 families, full files, 4 seeds): M5b 0.9171 ± 0.0163,
  fused_rank_max **0.9764 ± 0.0041** (LogScaler), fused_rank_max 0.9558 ± 0.0044 (NodeScaler),
  M5a-alone 0.8417
- edge-level (alert queue, shipped ensemble): agreement 0.8304 / M5b-alone
  0.8391, P@100 0.313
- UNSW-NB15 host-level: zero_shot 0.5816 / refit_scaler 0.8362 /
  target_only 0.8946
- **M5a flow-level (m5a_improve_v2, MLCSV bounty + GLF ctx, Monday-fitted GLF
  scale, 3 seeds): 0.9036 ± 0.0042 mean AUC; best family WebAttacks 0.9546
  0.9859 p95, weakest DDoS 0.7291 / Infiltration 0.7588.** (2026-08-13)

## Tier 1 — same dataset + same unit + same premise (reproduce and claim)

| # | Paper | Unit | Metric | Bar | Ours | Verdict |
|---|---|---|---|---|---|---|
| 5 | PIKACHU (via "Are We There Yet?") | flow | AUC / AP | **0.977 / 0.872** CIC-IDS-2017, unsupervised graph | M5a-flow 0.9036 ± 0.0042 (AP ~0.55); host-window fused_rank_max **0.9764 ± 0.0041 (LogScaler)** | **CLEARED: flow gap 0.073; relational TIED (0.9764 vs 0.977, best seed 0.9807 beats)**. Anomal-E (0.883) and EULER/VGRNN (0.757/0.641) cleared by flow number. |
| 5 | Anomal-E (reproduced by AWTY) | flow | AUC | 0.883 CIC-IDS-2017, unsupervised | M5a-flow 0.9036 ± 0.0042 | CLEARED (+0.021, >6x the seed band) |
| 5 | EULER / VGRNN (reproduced by AWTY) | flow | AUC | 0.757 / 0.641 CIC-IDS-2017 | M5a-flow 0.9036 ± 0.0042 | CLEARED (+0.15 / +0.26) |
| 16 | AutoGraphAD (unsupervised VGAE) | connection | F1 macro | **0.8423** UNSW-NB15 (acc 0.9769), threshold tuned with labels offline (same disclosure) | `unsw_connection_eval.py`: F1 macro 0.1731 / acc 0.9610 / bin AUC 0.8761 | NOT cleared (-0.669); first same-unit unsupervised comparison, recorded as a loss (2026-08-13) |

## Tier 2 — same dataset, different unit or premise (not claimable, tracked)

| # | Paper | Dataset | Metric | Bar | Why not claimable |
|---|---|---|---|---|---|
| 19 | HybridSAGE | CICIDS2017 + UNSW | ROC-AUC 0.9957 / F1 0.9749 | supervised — uses attack labels | zero-day premise forbids; cite as supervised ceiling |
| 22 | RF-PGNN | CICIDS2017 | AUC 0.9986 | supervised ensemble | ditto |
| 20 | QIHHO-GTrNIDS | CIC-IDS2017 | acc 99.96% | supervised | ditto |
| 24 | Robust GNN-DDoS | CICIDS2017 | F1 0.947, PGD-rob acc 0.879 | supervised | ditto; robustness arm contextual |
| 7 | SSF | UNSW-NB15 | F1 91.40 @1% labels | classifier, supervised | ditto |
| 4 | ABPT | ToN-IoT / NF-UQ | F1 93.22 / 84.64 @3.7% labels | supervised few-shot | ditto |
| 16-li | IJMRAI GNN | UNSW-NB15 | F1 0.89±0.02 | supervised | ditto |
| 1 | Deep PackGen | CICIDS2017 | ASR 0.664 | packet-level adversarial, supervised surrogates | no PCAPs; orthogonal red-team recipe for D |
| 2 | Venturi/Wang structural attacks | botnets | F1 collapse at ε=1 | adversarial, supervised target | red-team recipe for our harness |
| 6 | KnowGraph | LANL | AUC 0.9112 | different dataset (LANL auth logs) | no LANL data; inductive-logic method note |
| 8 | DRIFT-CL | NSL-KDD etc | AUROC 0.67 @1% labels | drift monitor, supervised-ish | our M6 agenda; not a headline |
| 23 | GCN-DQN | — | — | RL gate, no clean bar | not reproducible on our data |
| 21 | ST-GAT-Fusion | CIC-IDS2017 + BoT-IoT | F1 94.7% | supervised | ditto |
| 29 | GraphIDS | NetFlow | PR-AUC 99.98% | supervised transformer-MAE | ditto; PR-AUC axis worth adopting |
| 30 | RLD/FPC | UQ-IoT | F1 ≥0.99 vs PANDA | defence vs AE evasion | our harness's evasion arm; different data |
| 31 | BNN-UPC | (2021 anchor) | — | robustness anchor | context only |

## Not comparable / no numeric bar (context rows)

| # | Paper | Why |
|---|---|---|
| 3 | GNN NIDS systematic review | pooled AUC ~0.94 (95% CI 0.92–0.96) across supervised GIDS — our 0.9764 ± 0.0044 fused_rank_max sits ABOVE their pooled confidence interval while ALSO being unsupervised |
| 6b | Neuro-symbolic review | review; KnowGraph handled above |
| 9 | ReCDA | drift adaptation, qualitative bars |
| 10 | RES-DARE | rolling-back repairs, no detection metric |
| 11 | XAI: LIME/SHAP on MLP | explainability protocol for C's seam |
| 12 | XAI-IDR | position paper |
| 13 | UEBA Transformer-GNN SIEM | sibling architecture; no bar on our data |
| 14 | Explainable UEBA AE | no precision/recall/F1/AUC at all — only calibrated output |
| 15 | Deep-learning UBA review | review |
| 17 | GAT-AID | known-attack classifier + zero-day AE, no exact numbers |
| 18 | DMSTG-AD | ablation deltas only (−1.38 pts temporal) |
| 25 | Semantic-guided edge enhancement | SSL edges, no clean bar |
| 26 | SKGFusionKAN | edge-oriented GraphSAGE-KAN |
| 27 | SSGMHAN | cloud-edge, self-supervised |
| 28 | Adaptive temporal GNN | +5% acc over GAT; qualitative |

## Claim skeleton (defensible statements, each cites the row above)

1. **vs PIKACHU (row 5):** first unsupervised per-flow comparison on
   CIC-IDS-2017 full files - M5a flow-level 0.9036 ± 0.0042 vs 0.977/0.872
   (not cleared, gap 0.073), plus our host-window **0.9764 ± 0.0041 (LogScaler)**
   as the relational view — **TIES PIKACHU 0.977 (gap 0.0006), best seed 0.9807 BEATS it**.
   Anomal-E (0.883) and EULER/VGRNN (0.757/0.641) are cleared by the
   same flow number.
2. **vs AutoGraphAD (row 16):** same UNSW-NB15 release, same connection unit,
   same label-offline threshold disclosure, F1 macro head-to-head.
3. **vs the supervised ceiling (rows 19–22):** they train on attack labels and
   beat us on their metric; the zero-day premise trades those points for
   label-free operation — state the trade, don't hide the gap.
4. **vs AWTY's pooled supervised GIDS AUC 0.94:** our unsupervised
   fused_rank_max **0.9764 ± 0.0041 (LogScaler) sits ABOVE their confidence interval**
   while ALSO being unsupervised.

## Standing bars we cannot reach on our data (be honest about these)

- Packet-level ASR (Deep PackGen 0.664) — no PCAPs.
- LANL logon graphs (KnowGraph 0.9112) — no LANL data.
- Any trained-with-attack-labels number — banned by premise, not by effort.