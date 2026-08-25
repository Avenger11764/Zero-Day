# Exp2 — Staged Fused Fixes (window=60s, 40ep)

## S0_baseline

Seed 0: graph 0.9975 fused 0.9935 Delta -0.0039 cov 232

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 1.0000 | 0.9985 | -0.0015 | 0.19 |
| DDoS | 1.0000 | 1.0000 | +0.0000 | 0.17 |
| Botnet | 0.9928 | 0.9949 | +0.0021 | 0.24 |
| Infiltration | 0.9978 | 0.9968 | -0.0011 | 0.23 |
| WebAttacks | 0.9974 | 0.9824 | -0.0150 | 0.23 |
| Patator (FTP/SSH) | 0.9971 | 0.9850 | -0.0121 | 0.24 |
| DoS / Heartbleed | 0.9972 | 0.9972 | +0.0000 | 0.18 |

## S1_log

Seed 0: graph 0.9984 fused 0.9910 Delta -0.0074 cov 232

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 1.0000 | 0.9955 | -0.0045 | 0.19 |
| DDoS | 1.0000 | 0.9979 | -0.0021 | 0.17 |
| Botnet | 0.9932 | 0.9650 | -0.0282 | 0.24 |
| Infiltration | 0.9968 | 0.9871 | -0.0097 | 0.23 |
| WebAttacks | 0.9991 | 0.9965 | -0.0026 | 0.23 |
| Patator (FTP/SSH) | 1.0000 | 0.9964 | -0.0036 | 0.24 |
| DoS / Heartbleed | 1.0000 | 0.9986 | -0.0014 | 0.18 |

## S2_log_v2

Seed 0: graph 0.9981 fused 0.9815 Delta -0.0167 cov 232

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9985 | 0.9985 | +0.0000 | 0.19 |
| DDoS | 0.9979 | 0.9957 | -0.0021 | 0.17 |
| Botnet | 0.9969 | 0.9605 | -0.0364 | 0.24 |
| Infiltration | 0.9946 | 0.9773 | -0.0173 | 0.23 |
| WebAttacks | 0.9991 | 0.9603 | -0.0388 | 0.23 |
| Patator (FTP/SSH) | 1.0000 | 0.9793 | -0.0207 | 0.24 |
| DoS / Heartbleed | 1.0000 | 0.9986 | -0.0014 | 0.18 |

## S3_log_v2_T3

Seed 0: graph 0.9990 fused 0.9892 Delta -0.0098 cov 688

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9992 | 0.9960 | -0.0032 | 0.36 |
| DDoS | 0.9989 | 0.9978 | -0.0011 | 0.34 |
| Botnet | 0.9979 | 0.9764 | -0.0215 | 0.42 |
| Infiltration | 0.9976 | 0.9821 | -0.0155 | 0.41 |
| WebAttacks | 0.9995 | 0.9847 | -0.0148 | 0.41 |
| Patator (FTP/SSH) | 1.0000 | 0.9899 | -0.0101 | 0.40 |
| DoS / Heartbleed | 1.0000 | 0.9978 | -0.0022 | 0.34 |

## S4_log_v2_T3_2stage

Seed 0: graph 0.9990 fused 0.9867 Delta -0.0123 cov 688

| Family | Graph | Fused | Delta | Cover |
|---|---|---|---|---|
| PortScan | 0.9992 | 0.9976 | -0.0016 | 0.36 |
| DDoS | 0.9989 | 0.9978 | -0.0011 | 0.34 |
| Botnet | 0.9979 | 0.9413 | -0.0566 | 0.42 |
| Infiltration | 0.9976 | 0.9875 | -0.0101 | 0.41 |
| WebAttacks | 0.9995 | 0.9914 | -0.0081 | 0.41 |
| Patator (FTP/SSH) | 1.0000 | 0.9920 | -0.0080 | 0.40 |
| DoS / Heartbleed | 1.0000 | 0.9993 | -0.0007 | 0.34 |

