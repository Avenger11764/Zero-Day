# Ablation — M5a vs M5b vs ensemble

Held-out attack families. Trained on Monday (benign only); every family
below was unseen. Scores calibrated to percentiles against a benign
baseline, then compared at **host-window** granularity.

Seed: 0 · Limit: 0 · Window: 60s

## ROC-AUC

| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Fused rank-max | Winner |
| --- | --- | --- | --- | --- | --- | --- |
| PortScan | 0.9667 | 0.8809 | 0.9672 | 0.8884 | 0.9686 | **fused_rank_max** |
| DDoS | 0.9693 | 0.9422 | 0.9693 | 0.9465 | 0.9765 | **fused_rank_max** |
| Botnet | 0.9474 | 0.8578 | 0.9473 | 0.8741 | 0.9583 | **fused_rank_max** |
| Infiltration | 0.9704 | 0.8921 | 0.9697 | 0.8960 | 0.9581 | **M5a** |
| WebAttacks | 0.3904 | 0.9628 | 0.4089 | 0.9656 | 0.9495 | **fused_mean** |
| Patator (FTP/SSH) | 0.6957 | 0.9774 | 0.9225 | 0.9253 | 0.9712 | **M5b** |
| DoS / Heartbleed | 0.9521 | 0.9539 | 0.9519 | 0.9558 | 0.9614 | **fused_rank_max** |
| **mean** | **0.8417** | **0.9239** | **0.8767** | **0.9217** | **0.9634** | |

## Precision@100 — diagnostic only (capped at bad/100, see RC-27)

Host-window P@100 is structurally capped; quote rank/recall@100 operationally.

| Family | M5a | M5b | Fused max | Fused mean | Fused rank-max |
| --- | --- | --- | --- | --- | --- |
| PortScan | 0.030 | 0.130 | 0.030 | 0.130 | 0.120 |
| DDoS | 0.140 | 0.530 | 0.140 | 0.560 | 0.450 |
| Botnet | 0.590 | 0.360 | 0.610 | 0.370 | 0.480 |
| Infiltration | 0.090 | 0.130 | 0.060 | 0.230 | 0.120 |
| WebAttacks | 0.000 | 0.030 | 0.000 | 0.030 | 0.030 |
| Patator (FTP/SSH) | 0.000 | 0.060 | 0.030 | 0.000 | 0.000 |
| DoS / Heartbleed | 0.030 | 0.410 | 0.010 | 0.420 | 0.310 |

Family wins by ROC-AUC: {'M5a': 1, 'M5b': 1, 'fused_max': 0, 'fused_mean': 1, 'fused_rank_max': 4}

Calibration: 20% Monday windows held out (E1); reporting rank/recall@100 for operational claims (E2).
**Overall best by mean ROC-AUC: fused_rank_max (0.9634).**