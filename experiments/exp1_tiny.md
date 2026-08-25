# Exp1 Ensemble — GNN+Fused (window=60s seq_len=3 feats=v2)

## Seed 0

| Family | Graph | Fused | RankMean | RankMax | MeanVal | MaxVal | GatedU | Cov | Winner |
|---|---|---|---|---|---|---|---|---|---|
| PortScan | 1.0000 | 0.9809 | 0.9877 | 1.0000 | 0.9864 | 1.0000 | 0.9625 | 0.32 | graph |
| DDoS | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.32 | graph |
| Botnet | 0.9963 | 0.9951 | 0.9975 | 0.9938 | 0.9951 | 0.9951 | 0.9967 | 0.34 | rank_mean |
| WebAttacks | 1.0000 | 0.9944 | 0.9986 | 1.0000 | 0.9944 | 1.0000 | 0.9940 | 0.33 | graph |
| Patator (FTP/SSH) | 1.0000 | 0.9889 | 0.9954 | 0.9991 | 0.9926 | 1.0000 | 0.9809 | 0.34 | graph |
| DoS / Heartbleed | 1.0000 | 0.9871 | 0.9954 | 1.0000 | 0.9954 | 1.0000 | 0.9795 | 0.33 | graph |

