# Ablation — M5a vs M5b vs ensemble

Held-out attack families. Trained on Monday (benign only); every family
below was unseen. Scores calibrated to percentiles against a benign
baseline, then compared at **host-window** granularity.

Seed: 3 · Limit: 0 · Window: 60s

## ROC-AUC

| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Fused rank-max | Winner |
| --- | --- | --- | --- | --- | --- | --- |
| PortScan | 0.9667 | 0.8584 | 0.9675 | 0.8691 | 0.9714 | **fused_rank_max** |
| DDoS | 0.9693 | 0.8725 | 0.9693 | 0.8898 | 0.9713 | **fused_rank_max** |
| Botnet | 0.9474 | 0.8646 | 0.9460 | 0.8826 | 0.9573 | **fused_rank_max** |
| Infiltration | 0.9704 | 0.8608 | 0.9702 | 0.8709 | 0.9585 | **M5a** |
| WebAttacks | 0.3904 | 0.8941 | 0.3722 | 0.9091 | 0.8821 | **fused_mean** |
| Patator (FTP/SSH) | 0.6957 | 0.9652 | 0.8519 | 0.9077 | 0.9591 | **M5b** |
| DoS / Heartbleed | 0.9521 | 0.9268 | 0.9518 | 0.9339 | 0.9487 | **M5a** |
| **mean** | **0.8417** | **0.8918** | **0.8613** | **0.8947** | **0.9498** | |

## Precision@100 — what a SOC analyst actually sees

| Family | M5a | M5b | Fused max | Fused mean | Fused rank-max |
| --- | --- | --- | --- | --- | --- |
| PortScan | 0.030 | 0.110 | 0.040 | 0.110 | 0.110 |
| DDoS | 0.140 | 0.420 | 0.140 | 0.420 | 0.540 |
| Botnet | 0.590 | 0.310 | 0.550 | 0.400 | 0.410 |
| Infiltration | 0.090 | 0.390 | 0.110 | 0.400 | 0.390 |
| WebAttacks | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| Patator (FTP/SSH) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| DoS / Heartbleed | 0.030 | 0.300 | 0.020 | 0.310 | 0.230 |

Family wins by ROC-AUC: {'M5a': 2, 'M5b': 1, 'fused_max': 0, 'fused_mean': 1, 'fused_rank_max': 3}

**Overall best by mean ROC-AUC: fused_rank_max (0.9498).**