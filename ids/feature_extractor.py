"""Validation and defensive feature engineering for synthetic network flows."""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from math import isfinite
from typing import Any, Mapping

SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}

class FlowValidationError(ValueError):
    """Raised when a flow cannot safely be analyzed."""


def _number(flow: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = flow.get(key, default)
    if value is None or value == "":
        value = default
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise FlowValidationError(f"{key} must be numeric") from exc
    if not isfinite(result) or result < 0:
        raise FlowValidationError(f"{key} must be a finite non-negative number")
    return result


def validate_flow(flow: Mapping[str, Any]) -> dict[str, Any]:
    """Return a normalized copy or raise a human-readable validation error."""
    if not isinstance(flow, Mapping):
        raise FlowValidationError("flow must be an object")
    result = dict(flow)
    for key in ("source_ip", "destination_ip"):
        try:
            result[key] = str(ip_address(str(flow.get(key, ""))))
        except ValueError as exc:
            raise FlowValidationError(f"{key} is not a valid IP address") from exc
    for key in ("source_port", "destination_port"):
        try:
            port = int(flow.get(key, -1))
        except (TypeError, ValueError) as exc:
            raise FlowValidationError(f"{key} must be an integer") from exc
        if not 0 <= port <= 65535:
            raise FlowValidationError(f"{key} must be between 0 and 65535")
        result[key] = port
    protocol = str(flow.get("protocol", "")).upper()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise FlowValidationError(f"protocol must be one of {sorted(SUPPORTED_PROTOCOLS)}")
    result["protocol"] = protocol
    for key in (
        "packet_count", "byte_count", "duration_seconds", "connection_count",
        "failed_connection_count", "syn_count", "rst_count",
        "unique_destination_ports", "unique_destination_ips",
    ):
        result[key] = _number(flow, key, 1 if key.startswith("unique_") else 0)
    if result["failed_connection_count"] > result["connection_count"] and result["connection_count"] > 0:
        # Keep synthetic data internally consistent without hiding the input issue.
        raise FlowValidationError("failed_connection_count cannot exceed connection_count")
    timestamp = result.get("timestamp")
    if timestamp:
        try:
            datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError as exc:
            raise FlowValidationError("timestamp must be ISO-8601") from exc
    else:
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["flow_id"] = str(result.get("flow_id") or "").strip()
    return result


def extract_network_features(flow: Mapping[str, Any]) -> dict[str, float]:
    """Validate a flow and derive stable rate, ratio, and diversity features."""
    f = validate_flow(flow)
    packets = float(f["packet_count"])
    byte_count = float(f["byte_count"])
    duration = float(f["duration_seconds"])
    connections = float(f["connection_count"])
    failed = float(f["failed_connection_count"])
    syn_count = float(f["syn_count"])
    safe_duration = max(duration, 0.001)
    safe_connections = max(connections, 1.0)
    safe_packets = max(packets, 1.0)
    return {
        "packet_count": packets,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_second": byte_count / safe_duration,
        "packets_per_second": packets / safe_duration,
        "average_packet_size": byte_count / safe_packets if packets else 0.0,
        "connection_count": connections,
        "failed_connection_count": failed,
        "failure_ratio": failed / safe_connections,
        "syn_count": syn_count,
        "rst_count": float(f["rst_count"]),
        "syn_ratio": syn_count / safe_packets,
        "unique_destination_ports": float(f["unique_destination_ports"]),
        "unique_destination_ips": float(f["unique_destination_ips"]),
        "connection_rate": connections / safe_duration,
        # A safe metadata proxy for DNS-rate investigation; it does not inspect payloads or claim tunneling.
        "dns_query_rate": (packets / safe_duration) if f["protocol"] == "UDP" and f["destination_port"] == 53 else 0.0,
    }
