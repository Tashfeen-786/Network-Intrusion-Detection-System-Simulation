# Safe Synthetic Detection Scenarios

Scores below are **expected bands**, not guaranteed constants: anomaly baselines and the optional calculated ML probability affect final risk. A rule match requires investigation and is not proof of intent.

| Scenario | Representative input features | Rule | Expected risk/classification | Expected alert |
|---|---|---|---|---|
| A. Normal HTTPS browsing | TCP/443, 40 packets, 30 KB, 5 s, 3 connections, 0 failures | None | 0–20 / NORMAL | None |
| B. Normal DNS query pattern | UDP/53, 2 packets, 240 B, .2 s, 0 SYN | None | 0–20 / NORMAL | None |
| C. Repeated failed connections | 30 connections, 15 failures, TCP/22 | IDS-002 | 61+ / HIGH RISK or above | Repeated Failed Connections |
| D. High connection rate | 200 connections in 2 s | IDS-001 | 61+ / HIGH RISK or above | High Connection Rate |
| E. Multi-port probing-like data | 35 unique destination ports in summarized window | IDS-003 | 61+ / HIGH RISK or above | Multi-Port Probing-Like Pattern |
| F. SYN-heavy statistical pattern | 100 packets, 85 SYNs | IDS-004 | 81+ likely / CRITICAL INVESTIGATION | SYN-Heavy Statistical Pattern |
| G. Abnormally high volume | >5,000,000 bytes per flow | IDS-006 | 61+ / HIGH RISK or above | Abnormally High Traffic Volume |
| H. High DNS query rate | UDP/53, >40 packets/s | IDS-007 | 41+ / SUSPICIOUS or above | High DNS Query Rate; not proof of tunneling |
| I. Generic C2-like metadata | Small periodic flow using an unusual synthetic service port | IDS-005 | 41+ / SUSPICIOUS or above | Unusual Service-Port Activity; not malware attribution |

Additional data-only scenario `UNUSUAL_PORT_ACTIVITY` selects ports such as 4444/65000 and may trigger IDS-005. Every scenario is a dictionary or CSV row. No socket, raw frame, scan, login attempt, or flood is generated.
