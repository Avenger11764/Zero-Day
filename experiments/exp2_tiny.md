# Exp2 — Staged Fused Fixes (window=60s, 20ep)

## S0_baseline

Seed 0: graph 0.9852 fused 0.8916 Delta -0.0936 cov 115

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9571 | 0.7771 | -0.1800 | 0.15 |
| Botnet | 0.9929 | 0.9882 | -0.0047 | 0.18 |
| WebAttacks | 0.9795 | 0.7333 | -0.2462 | 0.18 |
| Patator (FTP/SSH) | 0.9965 | 0.9664 | -0.0300 | 0.18 |
| DoS / Heartbleed | 1.0000 | 0.9928 | -0.0072 | 0.17 |

## S1_log

Seed 0: graph 0.9971 fused 0.9800 Delta -0.0172 cov 115

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9971 | 0.9600 | -0.0371 | 0.15 |
| Botnet | 0.9929 | 0.9953 | +0.0024 | 0.18 |
| WebAttacks | 0.9974 | 0.9872 | -0.0103 | 0.18 |
| Patator (FTP/SSH) | 1.0000 | 0.9788 | -0.0212 | 0.18 |
| DoS / Heartbleed | 0.9982 | 0.9785 | -0.0197 | 0.17 |

## S2_log_v2

Seed 0: graph 0.9989 fused 0.9789 Delta -0.0201 cov 115

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9971 | 0.9629 | -0.0343 | 0.15 |
| Botnet | 0.9976 | 0.9905 | -0.0071 | 0.18 |
| WebAttacks | 1.0000 | 0.9872 | -0.0128 | 0.18 |
| Patator (FTP/SSH) | 1.0000 | 0.9753 | -0.0247 | 0.18 |
| DoS / Heartbleed | 1.0000 | 0.9785 | -0.0215 | 0.17 |

## S3_log_v2_T3

Seed 0: graph 0.9998 fused 0.9908 Delta -0.0089 cov 347

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9986 | 0.9795 | -0.0191 | 0.32 |
| DDoS | 1.0000 | 1.0000 | +0.0000 | 0.32 |
| Botnet | 1.0000 | 0.9951 | -0.0049 | 0.34 |
| WebAttacks | 1.0000 | 0.9944 | -0.0056 | 0.33 |
| Patator (FTP/SSH) | 1.0000 | 0.9889 | -0.0111 | 0.34 |
| DoS / Heartbleed | 1.0000 | 0.9871 | -0.0129 | 0.33 |

## S4_log_v2_T3_2stage

Seed 0: graph 0.9998 fused 0.9909 Delta -0.0089 cov 347

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9986 | 0.9809 | -0.0177 | 0.32 |
| DDoS | 1.0000 | 1.0000 | +0.0000 | 0.32 |
| Botnet | 1.0000 | 0.9963 | -0.0037 | 0.34 |
| WebAttacks | 1.0000 | 0.9929 | -0.0071 | 0.33 |
| Patator (FTP/SSH) | 1.0000 | 0.9880 | -0.0120 | 0.34 |
| DoS / Heartbleed | 1.0000 | 0.9871 | -0.0129 | 0.33 |

