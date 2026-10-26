"""Heuristic rule-based anomaly and threat classification engine for NetWatch.

Evaluates deterministic network attack signatures with configurable thresholds:

- Port scan (port_scan): excessive unique destination ports.

- SYN flood (syn_flood): excessive unacknowledged TCP SYN packets.

- ICMP flood (icmp_flood): excessive ICMP packet volume.

- Bandwidth hog (bandwidth_hog): excessive outbound byte transmission.

Classifies severity as low, medium, or high by magnitude.

Runs independently of ML models, attaching ML confidence score when available.

"""

from __future__ import annotations

import ipaddress

import logging

from typing import Any, Dict, List, Optional

from backend.config import settings

logger = logging.getLogger(__name__)

def is_local_subnet_ip(ip_str: str, subnet_str: Optional[str] = None) -> bool:

    try:

        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback or ip.is_link_local:

            return False

        if ip.version == 6:

            return ip.is_private

        if ip.is_private:
            return True

        if subnet_str:
            net = ipaddress.ip_network(subnet_str, strict=False)
            return ip in net

        return False

    except Exception:

        return False

def classify_window_anomalies(

    row: Dict[str, Any],

    src_ip: Optional[str] = None,

    ml_score: Optional[float] = None,

) -> List[Dict[str, Any]]:

    """Classify per-host window metrics into readable structured threat alerts.

    Args:

        row: Metric row dictionary or feature mapping.

        src_ip: Host IP address.

        ml_score: Optional IsolationForest anomaly score (0.0 - 1.0).

    Returns:

        List of generated threat alert dictionaries.

    """

    host = src_ip or row.get("src_ip") or "unknown_host"

    alerts: List[Dict[str, Any]] = []

    unique_ports = float(row.get("unique_dst_ports") or 0)

    syn_count = float(row.get("syn_count") or 0)

    tcp_count = float(row.get("tcp_count") or 0)

    syn_ratio = float(row.get("syn_ratio") or 0.0)
    if syn_ratio == 0.0 and tcp_count > 0:
        syn_ratio = min(1.0, syn_count / tcp_count)
    elif syn_ratio == 0.0 and syn_count > 0:
        syn_ratio = 1.0

    icmp_count = float(row.get("icmp_count") or 0)

    bytes_out = float(row.get("bytes_out") or 0)

    is_local = is_local_subnet_ip(host, settings.resolved_subnet)

    # 1. Port Scan Detection (monitor local LAN hosts; external CDNs are excluded)

    if is_local and unique_ports >= settings.rule_port_scan_threshold:

        if unique_ports >= settings.rule_port_scan_high_threshold:

            severity = "high"

            default_score = 0.95

        elif unique_ports >= settings.rule_port_scan_threshold * 1.5:

            severity = "medium"

            default_score = 0.80

        else:

            severity = "low"

            default_score = 0.65

        score = round(ml_score if ml_score is not None else default_score, 3)

        alerts.append(

            {

                "alert_type": "port_scan",

                "severity": severity,

                "src_ip": host,

                "score": score,

                "message": f"Port scan detected from {host}: {int(unique_ports)} unique destination ports probed in 5s window",

                "details": {

                    "rule": "port_scan",

                    "unique_dst_ports": int(unique_ports),

                    "threshold": settings.rule_port_scan_threshold,

                    "ml_score": ml_score,

                },

            }

        )

    # 2. SYN Flood Detection (high SYN count / ratio -> "syn_flood")

    # Exclude horizontal port scans where SYNs are scattered across many distinct target ports

    is_port_scan = (unique_ports >= settings.rule_port_scan_threshold)

    if not is_port_scan and syn_count >= settings.rule_syn_flood_count and (syn_ratio >= settings.rule_syn_flood_ratio or syn_count >= settings.rule_syn_flood_high_count):

        if syn_count >= settings.rule_syn_flood_high_count:

            severity = "high"

            default_score = 0.98

        elif syn_count >= settings.rule_syn_flood_count * 1.5:

            severity = "medium"

            default_score = 0.85

        else:

            severity = "low"

            default_score = 0.70

        score = round(ml_score if ml_score is not None else default_score, 3)

        alerts.append(

            {

                "alert_type": "syn_flood",

                "severity": severity,

                "src_ip": host,

                "score": score,

                "message": f"SYN flood detected from {host}: {int(syn_count)} SYN packets without ACK ({syn_ratio * 100.0:.1f}% of TCP traffic)",

                "details": {

                    "rule": "syn_flood",

                    "syn_count": int(syn_count),

                    "syn_ratio": round(syn_ratio, 3),

                    "threshold_count": settings.rule_syn_flood_count,

                    "ml_score": ml_score,

                },

            }

        )

    # 3. ICMP Flood Detection (icmp count spike -> "icmp_flood")

    if icmp_count >= settings.rule_icmp_flood_count:

        if icmp_count >= settings.rule_icmp_flood_high_count:

            severity = "high"

            default_score = 0.95

        elif icmp_count >= settings.rule_icmp_flood_count * 1.8:

            severity = "medium"

            default_score = 0.80

        else:

            severity = "low"

            default_score = 0.65

        score = round(ml_score if ml_score is not None else default_score, 3)

        alerts.append(

            {

                "alert_type": "icmp_flood",

                "severity": severity,

                "src_ip": host,

                "score": score,

                "message": f"ICMP flood detected from {host}: {int(icmp_count)} ICMP packets in 5s window",

                "details": {

                    "rule": "icmp_flood",

                    "icmp_count": int(icmp_count),

                    "threshold": settings.rule_icmp_flood_count,

                    "ml_score": ml_score,

                },

            }

        )

    # 4. Bandwidth Hog Detection (monitor local LAN abuse; external requires massive volumetric flood)

    effective_bw_thresh = settings.rule_bandwidth_hog_bytes if is_local else settings.rule_bandwidth_hog_high_bytes

    if bytes_out >= effective_bw_thresh:

        mb_out = bytes_out / (1024.0 * 1024.0)

        if bytes_out >= settings.rule_bandwidth_hog_high_bytes:

            severity = "high"

            default_score = 0.90

        elif bytes_out >= settings.rule_bandwidth_hog_bytes * 2.0:

            severity = "medium"

            default_score = 0.75

        else:

            severity = "low"

            default_score = 0.60

        score = round(ml_score if ml_score is not None else default_score, 3)

        alerts.append(

            {

                "alert_type": "bandwidth_hog",

                "severity": severity,

                "src_ip": host,

                "score": score,

                "message": f"High bandwidth consumption from {host}: {mb_out:.2f} MB transmitted in 5s window",

                "details": {

                    "rule": "bandwidth_hog",

                    "bytes_out": int(bytes_out),

                    "mb_out": round(mb_out, 2),

                    "threshold_bytes": settings.rule_bandwidth_hog_bytes,

                    "ml_score": ml_score,

                },

            }

        )

    return alerts

