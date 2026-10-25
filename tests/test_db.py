"""Unit and integration tests for NetWatch SQLite database engine."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from backend.db import (
    acknowledge_alert,
    cleanup_old_records,
    get_ai_alerts,
    get_connection,
    get_device_inventory,
    get_health_history,
    get_health_status,
    get_max_packet_flow_id,
    get_protocol_distribution,
    get_system_status,
    get_top_talkers,
    get_traffic_timeseries,
    get_unprocessed_packet_flows,
    init_db,
    insert_ai_alerts_batch,
    insert_health_score,
    insert_packet_flows_batch,
    mark_devices_offline,
    save_baseline_metadata,
    toggle_device_known,
    update_probe_metrics,
    upsert_device_inventory_batch,
    upsert_traffic_metrics_batch,
)


@pytest.fixture
def test_db(tmp_path: Path) -> str:
    """Fixture providing a fresh, initialized SQLite database in WAL mode."""
    db_file = str(tmp_path / "test_netwatch.db")
    init_db(db_file)
    return db_file


def test_init_db_and_wal_mode(test_db: str) -> None:
    """Verify tables are created and PRAGMA journal_mode is WAL."""
    conn = get_connection(test_db)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert mode.upper() == "WAL"

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        required = {
            "device_inventory",
            "packet_flows",
            "traffic_metrics",
            "ai_alerts",
            "health_history",
            "baseline_metadata",
        }
        assert required.issubset(tables)
    finally:
        conn.close()


def test_packet_flows_batch_insert_and_unprocessed(test_db: str) -> None:
    """Verify batch inserting packet flows and querying unprocessed records."""
    now = time.time()
    flows = [
        {
            "ts": now - 2.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "1.1.1.1",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "DNS",
            "length": 64,
            "tcp_flags": None,
        },
        {
            "ts": now - 1.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "142.250.190.46",
            "src_port": 49152,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 1420,
            "tcp_flags": "S",
        },
    ]

    inserted = insert_packet_flows_batch(flows, db_path=test_db)
    assert inserted == 2

    max_id = get_max_packet_flow_id(test_db)
    assert max_id == 2

    # Query from id 0
    records = get_unprocessed_packet_flows(last_id=0, limit=10, db_path=test_db)
    assert len(records) == 2
    assert records[0]["protocol"] == "DNS"
    assert records[1]["protocol"] == "TCP"

    # Query from id 1
    records_after_1 = get_unprocessed_packet_flows(last_id=1, limit=10, db_path=test_db)
    assert len(records_after_1) == 1
    assert records_after_1[0]["dst_port"] == 443


def test_traffic_metrics_upsert_and_probe_update(test_db: str) -> None:
    """Verify traffic metrics upserting and probe metrics updating."""
    window_ts = time.time() - 30.0

    # 1. Network-wide aggregate row (src_ip is None)
    net_row = {
        "ts": window_ts,
        "src_ip": None,
        "bytes_out": 50000,
        "bytes_in": 120000,
        "pps": 35.0,
        "tcp_count": 80,
        "udp_count": 20,
        "icmp_count": 0,
        "dns_count": 10,
        "other_count": 0,
        "syn_count": 2,
        "unique_dst_ports": 5,
        "unique_dst_ips": 4,
        "latency_ms": None,
        "loss_pct": None,
    }

    # 2. Per-host row
    host_row = {
        "ts": window_ts,
        "src_ip": "192.168.1.50",
        "bytes_out": 25000,
        "bytes_in": 60000,
        "pps": 15.0,
        "tcp_count": 40,
        "udp_count": 10,
        "icmp_count": 0,
        "dns_count": 5,
        "other_count": 0,
        "syn_count": 1,
        "unique_dst_ports": 3,
        "unique_dst_ips": 2,
        "latency_ms": None,
        "loss_pct": None,
    }

    inserted = upsert_traffic_metrics_batch([net_row, host_row], db_path=test_db)
    assert inserted == 2

    # Probe updates gateway latency and loss on the network-wide row
    updated = update_probe_metrics(
        window_ts=window_ts,
        latency_ms=14.5,
        loss_pct=0.0,
        db_path=test_db,
    )
    assert updated is True

    # Retrieve timeseries
    series = get_traffic_timeseries(minutes=60, db_path=test_db)
    assert len(series) == 1
    assert series[0]["latency_ms"] == 14.5
    assert series[0]["loss_pct"] == 0.0
    assert series[0]["bytes_out"] == 50000


def test_device_inventory_upsert_and_offline(test_db: str) -> None:
    """Verify device inventory upserts, known toggling, and offline transitions."""
    now = time.time()
    devices = [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.10",
            "vendor": "Cisco Systems",
            "hostname": "switch.local",
            "status": "online",
            "is_known": 1,
            "first_seen": now - 100,
            "last_seen": now,
        },
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.20",
            "vendor": "Apple",
            "hostname": "iphone.local",
            "status": "online",
            "is_known": 0,
            "first_seen": now - 500,
            "last_seen": now - 300,  # Old
        },
    ]

    upsert_device_inventory_batch(devices, db_path=test_db)
    inventory = get_device_inventory(db_path=test_db)
    assert len(inventory) == 2

    # Toggle is_known for iPhone
    new_state = toggle_device_known("AA:BB:CC:DD:EE:FF", db_path=test_db)
    assert new_state == 1

    # Toggle again
    new_state = toggle_device_known("AA:BB:CC:DD:EE:FF", db_path=test_db)
    assert new_state == 0

    # Mark offline devices older than now - 100
    offline_count = mark_devices_offline(last_seen_cutoff=now - 100, db_path=test_db)
    assert offline_count == 1

    updated_inv = {d["mac"]: d for d in get_device_inventory(db_path=test_db)}
    assert updated_inv["AA:BB:CC:DD:EE:FF"]["status"] == "offline"
    assert updated_inv["00:11:22:33:44:55"]["status"] == "online"


def test_ai_alerts_insert_and_acknowledge(test_db: str) -> None:
    """Verify threat alerts insertion, querying, and acknowledgment."""
    now = time.time()
    alerts = [
        {
            "ts": now - 10,
            "alert_type": "port_scan",
            "severity": "high",
            "src_ip": "192.168.1.150",
            "message": "Port scan detected: 250 ports probed",
            "score": 0.95,
            "acknowledged": 0,
            "details_json": '{"ports": 250}',
        },
        {
            "ts": now - 5,
            "alert_type": "unknown_device",
            "severity": "medium",
            "src_ip": "192.168.1.188",
            "message": "New unknown device detected",
            "score": 0.50,
            "acknowledged": 0,
            "details_json": '{"vendor": "Unknown"}',
        },
    ]

    inserted = insert_ai_alerts_batch(alerts, db_path=test_db)
    assert inserted == 2

    fetched = get_ai_alerts(limit=10, db_path=test_db)
    assert len(fetched) == 2
    # Newest first
    assert fetched[0]["alert_type"] == "unknown_device"

    # Filter by severity
    high_alerts = get_ai_alerts(severity="high", db_path=test_db)
    assert len(high_alerts) == 1
    assert high_alerts[0]["src_ip"] == "192.168.1.150"

    # Acknowledge high alert
    high_id = high_alerts[0]["id"]
    acked = acknowledge_alert(high_id, db_path=test_db)
    assert acked is True

    # Filter by unacknowledged only
    unacked = get_ai_alerts(acknowledged=False, db_path=test_db)
    assert len(unacked) == 1
    assert unacked[0]["alert_type"] == "unknown_device"


def test_health_history_and_status(test_db: str) -> None:
    """Verify health score insertion and status retrieval."""
    now = time.time()
    insert_health_score(ts=now - 20, score=95.0, db_path=test_db)
    insert_health_score(ts=now - 10, score=72.5, db_path=test_db)

    status = get_health_status(db_path=test_db)
    assert status["score"] == 72.5
    assert status["label"] == "Degraded"

    history = get_health_history(limit=5, db_path=test_db)
    assert len(history) == 2
    assert history[-1]["score"] == 72.5  # newest last (chronological for charts)


def test_system_status_and_top_talkers(test_db: str) -> None:
    """Verify system status metrics and top talkers queries."""
    now = time.time()

    # Insert a device
    upsert_device_inventory_batch(
        [
            {
                "mac": "11:22:33:44:55:66",
                "ip": "192.168.1.75",
                "vendor": "Intel",
                "hostname": "workstation",
                "status": "online",
                "is_known": 1,
                "first_seen": now,
                "last_seen": now,
            }
        ],
        db_path=test_db,
    )

    # Insert a packet flow
    insert_packet_flows_batch(
        [
            {
                "ts": now,
                "src_ip": "192.168.1.75",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 53,
                "protocol": "DNS",
                "length": 128,
                "tcp_flags": None,
            }
        ],
        db_path=test_db,
    )

    # Insert traffic metrics for top talkers
    upsert_traffic_metrics_batch(
        [
            {
                "ts": now,
                "src_ip": "192.168.1.75",
                "bytes_out": 100000,
                "bytes_in": 500000,
                "pps": 50.0,
                "tcp_count": 0,
                "udp_count": 25,
                "icmp_count": 0,
                "dns_count": 25,
                "other_count": 0,
                "syn_count": 0,
                "unique_dst_ports": 1,
                "unique_dst_ips": 1,
                "latency_ms": None,
                "loss_pct": None,
            }
        ],
        db_path=test_db,
    )

    status = get_system_status(test_db)
    assert status["db_size_bytes"] > 0
    assert status["interface"] is not None
    assert status["subnet"] is not None
    assert status["last_packet_time"] is not None

    top_talkers = get_top_talkers(minutes=15, limit=5, db_path=test_db)
    assert len(top_talkers) == 1
    assert top_talkers[0]["ip"] == "192.168.1.75"
    assert top_talkers[0]["bytes_out"] == 100000


def test_cleanup_old_records(test_db: str) -> None:
    """Verify retention cleanup deletes records older than cutoff."""
    old_ts = time.time() - 100000  # ~27 hours ago
    fresh_ts = time.time()

    insert_packet_flows_batch(
        [
            {
                "ts": old_ts,
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.2",
                "src_port": 1,
                "dst_port": 2,
                "protocol": "TCP",
                "length": 60,
                "tcp_flags": None,
            },
            {
                "ts": fresh_ts,
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.2",
                "src_port": 1,
                "dst_port": 2,
                "protocol": "TCP",
                "length": 60,
                "tcp_flags": None,
            },
        ],
        db_path=test_db,
    )

    # Clean records older than 1 hour
    deleted = cleanup_old_records(retention_hours=1.0, db_path=test_db)
    assert deleted["packet_flows"] == 1

    remaining = get_unprocessed_packet_flows(last_id=0, limit=10, db_path=test_db)
    assert len(remaining) == 1
    assert remaining[0]["ts"] == pytest.approx(fresh_ts, abs=1.0)
