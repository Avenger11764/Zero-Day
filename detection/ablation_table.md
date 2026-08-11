# Ablation — M5a vs M5b vs ensemble

Held-out attack families. Trained on Monday (benign only); every family
below was unseen. Scores calibrated to percentiles against a benign
baseline, then compared at **host-window** granularity.

## ROC-AUC

| Family | M5a (per-flow) | M5b (relational) | Fused max | Fused mean | Winner |
| --- | --- | --- | --- | --- | --- |
| PortScan | 0.5489 | 0.9350 | 0.6709 | 0.9355 | **fused_mean** |
| DDoS | 0.9845 | 0.9718 | 0.9845 | 0.9755 | **M5a** |
| Botnet | 0.9625 | 0.9128 | 0.9607 | 0.9241 | **M5a** |
| Infiltration | 0.9772 | 0.9059 | 0.9777 | 0.9148 | **fused_max** |
| WebAttacks | 0.4150 | 0.9291 | 0.4148 | 0.9357 | **fused_mean** |
| Patator (FTP/SSH) | 0.8460 | 0.9909 | 0.8888 | 0.9331 | **M5b** |
| DoS / Heartbleed | 0.9634 | 0.9523 | 0.9719 | 0.9590 | **fused_max** |
| **mean** | **0.8139** | **0.9425** | **0.8385** | **0.9397** | |

## Precision@100 — what a SOC analyst actually sees

| Family | M5a | M5b | Fused max | Fused mean |
| --- | --- | --- | --- | --- |
| PortScan | 0.000 | 0.040 | 0.010 | 0.040 |
| DDoS | 0.260 | 0.360 | 0.260 | 0.370 |
| Botnet | 0.560 | 0.560 | 0.570 | 0.640 |
| Infiltration | 0.100 | 0.200 | 0.150 | 0.220 |
| WebAttacks | 0.000 | 0.000 | 0.000 | 0.000 |
| Patator (FTP/SSH) | 0.000 | 0.000 | 0.000 | 0.000 |
| DoS / Heartbleed | 0.040 | 0.260 | 0.100 | 0.260 |

Family wins by ROC-AUC: {'M5a': 2, 'M5b': 1, 'fused_max': 2, 'fused_mean': 2}

**Overall best by mean ROC-AUC: M5b (0.9425).**