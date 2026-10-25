"""Unit tests for NetWatch heuristic threat detection rules."""

from __future__ import annotations

import pytest

from backend.config import settings
from backend.ml.rules import classify_window_anomalies


def test_clean_window_produces_no_alerts() -> None:
    """Verify standard benign traffic triggers zero threat alerts."""
    benign_row = {
        "src_ip": "192.168.1.105",
        "pps": 15.0,
        "bytes_out": 25000,
        "bytes_in": 120000,
        "syn_count": 2,
        "syn_ratio": 0.05,
        "icmp_count": 0,
        "unique_dst_ports": 3,
        "unique_dst_ips": 2,
    }
    alerts = classify_window_anomalies(benign_row)
    assert len(alerts) == 0


def test_port_scan_detection_and_severity() -> None:
    """Verify port scan rule triggers with proper severity levels."""
    src = "192.168.1.200"

    # 1. Low severity (>= settings.rule_port_scan_threshold, e.g. 15)
    row_low = {"src_ip": src, "unique_dst_ports": settings.rule_port_scan_threshold}
    alerts_low = classify_window_anomalies(row_low)
    assert len(alerts_low) == 1
    assert alerts_low[0]["alert_type"] == "port_scan"
    assert alerts_low[0]["severity"] == "low"
    assert src in alerts_low[0]["message"]

    # 2. Medium severity (>= threshold * 1.5)
    row_med = {
        "src_ip": src,
        "unique_dst_ports": int(settings.rule_port_scan_threshold * 1.6),
    }
    alerts_med = classify_window_anomalies(row_med)
    assert len(alerts_med) == 1
    assert alerts_med[0]["severity"] == "medium"

    # 3. High severity (>= settings.rule_port_scan_high_threshold, e.g. 50)
    row_high = {"src_ip": src, "unique_dst_ports": settings.rule_port_scan_high_threshold + 10}
    alerts_high = classify_window_anomalies(row_high, ml_score=0.99)
    assert len(alerts_high) == 1
    assert alerts_high[0]["severity"] == "high"
    assert alerts_high[0]["score"] == 0.99


def test_syn_flood_detection() -> None:
    """Verify SYN flood triggers on count and ratio criteria."""
    src = "192.168.1.201"

    # High count, high ratio
    row = {
        "src_ip": src,
        "syn_count": settings.rule_syn_flood_high_count + 50,
        "syn_ratio": 0.95,
    }
    alerts = classify_window_anomalies(row)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "syn_flood"
    assert alerts[0]["severity"] == "high"
    assert "SYN flood detected" in alerts[0]["message"]

    # High count but low ratio (< threshold) -> should not trigger syn_flood
    row_low_ratio = {
        "src_ip": src,
        "syn_count": settings.rule_syn_flood_count + 10,
        "syn_ratio": 0.10,  # mostly established traffic
    }
    alerts_low_ratio = classify_window_anomalies(row_low_ratio)
    assert len(alerts_low_ratio) == 0


def test_icmp_flood_detection() -> None:
    """Verify ICMP flood rule triggers on spike in ICMP volume."""
    src = "192.168.1.202"

    row = {
        "src_ip": src,
        "icmp_count": settings.rule_icmp_flood_high_count + 20,
    }
    alerts = classify_window_anomalies(row)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "icmp_flood"
    assert alerts[0]["severity"] == "high"
    assert "ICMP flood detected" in alerts[0]["message"]


def test_bandwidth_hog_detection() -> None:
    """Verify bandwidth hog rule triggers on high outbound byte volume."""
    src = "192.168.1.203"

    # 15 MB outbound in 5s
    bytes_out = 15 * 1024 * 1024
    row = {
        "src_ip": src,
        "bytes_out": bytes_out,
    }
    alerts = classify_window_anomalies(row)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "bandwidth_hog"
    assert "15.00 MB" in alerts[0]["message"]


def test_multi_attack_window() -> None:
    """Verify multiple concurrent attack signatures trigger distinct alerts."""
    src = "192.168.1.250"
    row = {
        "src_ip": src,
        "unique_dst_ports": 100,
        "syn_count": 200,
        "syn_ratio": 0.99,
        "icmp_count": 150,
        "bytes_out": 20 * 1024 * 1024,
    }
    alerts = classify_window_anomalies(row)
    alert_types = {a["alert_type"] for a in alerts}
    assert alert_types == {"port_scan", "syn_flood", "icmp_flood", "bandwidth_hog"}
