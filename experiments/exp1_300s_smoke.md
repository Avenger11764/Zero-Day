# Exp1 Ensemble — GNN+Fused (window=300s seq_len=5 feats=v1)

## Seed 0

| Family | Graph | Fused | RankMean | RankMax | MeanVal | MaxVal | GatedU | Cov | Winner |
|---|---|---|---|---|---|---|---|---|---|
| PortScan | 1.0000 | 0.9983 | 1.0000 | 0.9983 | 1.0000 | 1.0000 | 0.9957 | 0.13 | graph |
| DDoS | 1.0000 | 0.9920 | 1.0000 | 0.9960 | 1.0000 | 1.0000 | 0.9938 | 0.10 | graph |
| Botnet | 0.9838 | 0.9833 | 0.9921 | 0.9810 | 0.9909 | 0.9817 | 0.9660 | 0.16 | rank_mean |
| Infiltration | 0.9980 | 0.9920 | 0.9970 | 0.9960 | 0.9960 | 0.9980 | 0.9741 | 0.17 | graph |
| WebAttacks | 1.0000 | 0.9974 | 1.0000 | 0.9987 | 1.0000 | 1.0000 | 0.9921 | 0.15 | graph |
| Patator (FTP/SSH) | 1.0000 | 0.9989 | 1.0000 | 0.9995 | 1.0000 | 1.0000 | 0.9815 | 0.22 | graph |
| DoS / Heartbleed | 1.0000 | 0.9983 | 1.0000 | 0.9994 | 1.0000 | 0.9994 | 0.9925 | 0.20 | graph |

