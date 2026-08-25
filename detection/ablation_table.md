# Ablation — M5a vs M5b vs ensemble

Held-out attack families. Trained on Monday (benign only); every family
below was unseen. Scores calibrated to percentiles against a benign
baseline, then compared at **host-window** granularity.

Seed: 0 · Limit: 150000 · Window: 60s

## ROC-AUC

| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Fused rank-max | Winner |
| --- | --- | --- | --- | --- | --- | --- |
| PortScan | 0.5489 | 0.9158 | 0.7429 | 0.9160 | 0.8965 | **fused_mean** |
| DDoS | 0.9845 | 0.9633 | 0.9822 | 0.9662 | 0.9788 | **M5a** |
| Botnet | 0.9625 | 0.9132 | 0.9641 | 0.9178 | 0.9686 | **fused_rank_max** |
| Infiltration | 0.9772 | 0.9157 | 0.9766 | 0.9200 | 0.9668 | **M5a** |
| WebAttacks | 0.4150 | 0.9701 | 0.5222 | 0.9713 | 0.9516 | **fused_mean** |
| Patator (FTP/SSH) | 0.8460 | 0.9997 | 0.9971 | 0.9497 | 0.9985 | **M5b** |
| DoS / Heartbleed | 0.9634 | 0.8938 | 0.9632 | 0.9132 | 0.9891 | **fused_rank_max** |
| **mean** | **0.8139** | **0.9388** | **0.8783** | **0.9363** | **0.9643** | |

## Precision@100 — diagnostic only (capped at bad/100, see RC-27)

Host-window P@100 is structurally capped; quote rank/recall@100 operationally.

| Family | M5a | M5b | Fused max | Fused mean | Fused rank-max |
| --- | --- | --- | --- | --- | --- |
| PortScan | 0.000 | 0.080 | 0.010 | 0.080 | 0.080 |
| DDoS | 0.260 | 0.290 | 0.250 | 0.290 | 0.290 |
| Botnet | 0.560 | 0.690 | 0.610 | 0.710 | 0.640 |
| Infiltration | 0.100 | 0.150 | 0.110 | 0.150 | 0.130 |
| WebAttacks | 0.000 | 0.160 | 0.000 | 0.130 | 0.080 |
| Patator (FTP/SSH) | 0.000 | 0.600 | 0.580 | 0.000 | 0.460 |
| DoS / Heartbleed | 0.040 | 0.400 | 0.040 | 0.420 | 0.300 |

Family wins by ROC-AUC: {'M5a': 2, 'M5b': 1, 'fused_max': 0, 'fused_mean': 2, 'fused_rank_max': 2}

Calibration: 20% Monday windows held out (E1); reporting rank/recall@100 for operational claims (E2).
**Overall best by mean ROC-AUC: fused_rank_max (0.9643).**