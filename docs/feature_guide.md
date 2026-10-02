# Network Feature Guide

| Feature | Calculation / source | Defensive relevance |
|---|---|---|
| `packet_count` | observed synthetic count | Indicates flow activity and supports rate/ratio context. |
| `byte_count` | observed synthetic bytes | Highlights unusually large transfers. |
| `duration` | seconds | Distinguishes sustained and bursty flows. |
| `bytes_per_second` | bytes / max(duration, .001) | Identifies volume bursts. |
| `packets_per_second` | packets / max(duration, .001) | Identifies rapid activity. |
| `average_packet_size` | bytes / max(packets, 1), or 0 when no packets | Adds transfer-shape context. |
| `connection_count` | connections summarized by record | Useful for high-frequency behavior. |
| `failed_connection_count` | failed subset | Repeated failure may justify authentication/firewall review. |
| `failure_ratio` | failures / max(connections, 1) | Normalizes failure evidence. |
| `syn_count` | synthetic TCP SYN statistic | Supports handshake-pattern analysis. |
| `rst_count` | synthetic TCP reset statistic | Adds failed/aborted connection context. |
| `syn_ratio` | SYNs / max(packets, 1) | Separates normal traffic from SYN-heavy statistics. |
| `unique_destination_ports` | distinct ports summarized in window | High diversity may look probing-like. |
| `unique_destination_ips` | distinct destinations summarized in window | Shows fan-out behavior. |
| `connection_rate` | connections / max(duration, .001) | Identifies session bursts independent of duration. |
| `dns_query_rate` | packets/second only for UDP/53, otherwise 0 | Safe metadata proxy for high DNS activity; not proof of tunneling. |

Missing optional counts become zero; diversity defaults to one. IPs must parse, ports must be 0–65535, protocols must be TCP/UDP/ICMP, numbers must be finite/non-negative, failures cannot exceed non-zero connections, and timestamps must be ISO-8601. Zero duration remains stored as evidence but the denominator is clamped for finite rates.
