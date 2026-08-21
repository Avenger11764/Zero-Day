# Red-team evaluation — M5b (relational detector)

Benign: `Monday-WorkingHours.pcap_ISCX.csv`, 529,918 flows, 487 graphs. Sweep size 200 hosts.

Detection threshold: 99th percentile of benign host-window scores (`0.000924`). Anything at or below that is inside the false-positive floor and does not count as a catch.

| Technique | Evades at | Cost to the attacker |
| --- | --- | --- |
| slow_scan | `10` | sweep stretched over 10 windows (20 hosts/min) |
| distributed_scan | `8` | needs 8 attacker machines |
| cover_traffic | **never** | detected at every setting tried |
| port_narrowing | **never** | detected at every setting tried |

## Control — was the attack fair to M5a?

M5a stayed at its false-positive floor on **100%** of variants. The attacker's flows are real benign flows with only `src_ip`/`dst_ip`/`dst_port`/`timestamp` rewritten, so M5a is blind to them by construction. That is what makes any M5b detection attributable to structure rather than to odd-looking flows.