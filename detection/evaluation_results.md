# M5b evaluation — held-out attack families

Trained once on `Monday-WorkingHours.pcap_ISCX.csv` (benign only), 182 graphs, 60 epochs. Every family below was unseen during training.

| Attack family | ROC-AUC | P@100 | R@100 | Best rank | Top feature | Sep |
| --- | --- | --- | --- | --- | --- | --- |
| Patator (FTP/SSH) | **0.9913** | 0.000 | 0.000 | 185 of 34066 | `out_flows` | 30x |
| DoS / Heartbleed | **0.9536** | 0.280 | 0.431 | 2 of 17022 | `out_flows` | 321x |
| WebAttacks | **0.9515** | 0.000 | 0.000 | 433 of 26443 | `bytes_sent` | 18x |
| DDoS | **0.9436** | 0.320 | 0.552 | 1 of 4741 | `bytes_sent` | 557x |
| Botnet | **0.9287** | 0.440 | 0.041 | 8 of 24281 | `bytes_sent` | 73x |
| Infiltration | **0.9282** | 0.200 | 0.161 | 4 of 19718 | `unique_dst_ports` | 72x |
| PortScan | **0.9081** | 0.040 | 0.235 | 1 of 14595 | `out_flows` | 585x |

Mean ROC-AUC across 7 families: **0.9436**