"""Integration tests for NetWatch FastAPI REST endpoints."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.config import settings
from backend.db import (
    init_db,
    insert_ai_alerts_batch,
    insert_health_score,
    insert_packet_flows_batch,
    upsert_device_inventory_batch,
    upsert_traffic_metrics_batch,
)


@pytest.fixture
def client_with_test_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """Provide a TestClient connected to an isolated test database with fixture data."""
    test_db = str(tmp_path / "test_api_netwatch.db")
    init_db(test_db)

    # Monkeypatch settings to point to isolated test database
    monkeypatch.setattr(settings, "db_path", test_db)

    now = time.time()

    # Seed test device
    upsert_device_inventory_batch(
        [
            {
                "mac": "00:AA:22:33:44:55",
                "ip": "192.168.1.15",
                "vendor": "NetWatch Test Lab",
                "hostname": "test-host.lan",
                "status": "online",
                "is_known": 0,
                "first_seen": now - 60,
                "last_seen": now,
            }
        ],
        db_path=test_db,
    )

    # Seed packet flows
    insert_packet_flows_batch(
        [
            {
                "ts": now - 5,
                "src_ip": "192.168.1.15",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 53,
                "protocol": "DNS",
                "length": 80,
                "tcp_flags": None,
            },
            {
                "ts": now - 2,
                "src_ip": "192.168.1.15",
                "dst_ip": "1.1.1.1",
                "src_port": 50001,
                "dst_port": 443,
                "protocol": "TCP",
                "length": 1500,
                "tcp_flags": "S",
            },
        ],
        db_path=test_db,
    )

    # Seed traffic metrics (network-wide and host)
    upsert_traffic_metrics_batch(
        [
            {
                "ts": now - 5,
                "src_ip": None,
                "bytes_out": 1580,
                "bytes_in": 3200,
                "pps": 10.0,
                "tcp_count": 1,
                "udp_count": 0,
                "icmp_count": 0,
                "dns_count": 1,
                "other_count": 0,
                "syn_count": 1,
                "unique_dst_ports": 2,
                "unique_dst_ips": 2,
                "latency_ms": 11.2,
                "loss_pct": 0.0,
            },
            {
                "ts": now - 5,
                "src_ip": "192.168.1.15",
                "bytes_out": 1580,
                "bytes_in": 3200,
                "pps": 10.0,
                "tcp_count": 1,
                "udp_count": 0,
                "icmp_count": 0,
                "dns_count": 1,
                "other_count": 0,
                "syn_count": 1,
                "unique_dst_ports": 2,
                "unique_dst_ips": 2,
                "latency_ms": None,
                "loss_pct": None,
            },
        ],
        db_path=test_db,
    )

    # Seed alert
    insert_ai_alerts_batch(
        [
            {
                "ts": now - 2,
                "alert_type": "port_scan",
                "severity": "high",
                "src_ip": "192.168.1.15",
                "message": "Port scan detected from 192.168.1.15",
                "score": 0.95,
                "acknowledged": 0,
                "details_json": '{"ports": 45}',
            }
        ],
        db_path=test_db,
    )

    # Seed health
    insert_health_score(ts=now, score=85.0, db_path=test_db)

    with TestClient(app) as client:
        yield client


def test_api_status(client_with_test_db: TestClient) -> None:
    """Verify /api/status endpoint response structure."""
    res = client_with_test_db.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "capture_running" in data
    assert "interface" in data
    assert "subnet" in data
    assert "db_size_bytes" in data
    assert data["db_size_bytes"] > 0


def test_api_devices(client_with_test_db: TestClient) -> None:
    """Verify /api/devices endpoint returns seeded device."""
    res = client_with_test_db.get("/api/devices")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    device = data[0]
    assert device["mac"] == "00:AA:22:33:44:55"
    assert device["ip"] == "192.168.1.15"
    assert device["vendor"] == "NetWatch Test Lab"
    assert device["is_known"] == 0


def test_api_device_toggle_known(client_with_test_db: TestClient) -> None:
    """Verify /api/devices/{mac}/known toggles known state."""
    # Toggle to known (1)
    res = client_with_test_db.post("/api/devices/00:AA:22:33:44:55/known")
    assert res.status_code == 200
    assert res.json()["is_known"] == 1

    # Toggle to unknown (0)
    res2 = client_with_test_db.post("/api/devices/00:AA:22:33:44:55/known")
    assert res2.status_code == 200
    assert res2.json()["is_known"] == 0

    # Nonexistent device should return 404
    res_404 = client_with_test_db.post("/api/devices/DE:AD:BE:EF:00:00/known")
    assert res_404.status_code == 404


def test_api_traffic(client_with_test_db: TestClient) -> None:
    """Verify /api/traffic returns time series points."""
    res = client_with_test_db.get("/api/traffic?minutes=15")
    assert res.status_code == 200
    data = res.json()
    assert data["minutes"] == 15.0
    assert len(data["points"]) >= 1
    pt = data["points"][0]
    assert "bps_in" in pt
    assert "bps_out" in pt
    assert "latency_ms" in pt


def test_api_protocols(client_with_test_db: TestClient) -> None:
    """Verify /api/protocols returns protocol distribution."""
    res = client_with_test_db.get("/api/protocols?minutes=15")
    assert res.status_code == 200
    data = res.json()
    assert "total_packets" in data
    assert "tcp" in data
    assert "dns" in data
    assert data["total_packets"] >= 1


def test_api_top_talkers(client_with_test_db: TestClient) -> None:
    """Verify /api/top-talkers returns per-host consumption."""
    res = client_with_test_db.get("/api/top-talkers?minutes=15&limit=5")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    host = data[0]
    assert host["ip"] == "192.168.1.15"
    assert host["bytes_out"] == 1580


def test_api_alerts_and_ack(client_with_test_db: TestClient) -> None:
    """Verify /api/alerts and acknowledge endpoint."""
    res = client_with_test_db.get("/api/alerts?limit=10")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert["alert_type"] == "port_scan"
    assert alert["acknowledged"] == 0

    # Acknowledge alert
    alert_id = alert["id"]
    res_ack = client_with_test_db.post(f"/api/alerts/{alert_id}/ack")
    assert res_ack.status_code == 200
    assert res_ack.json()["acknowledged"] is True

    # Acknowledge nonexistent alert should return 404
    res_ack_404 = client_with_test_db.post("/api/alerts/999999/ack")
    assert res_ack_404.status_code == 404


def test_api_health(client_with_test_db: TestClient) -> None:
    """Verify /api/health returns score and history."""
    res = client_with_test_db.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["score"] == 85.0
    assert data["label"] == "Healthy"
    assert isinstance(data["history"], list)


def test_api_forecast(client_with_test_db: TestClient) -> None:
    """Verify /api/forecast returns valid forecast response."""
    res = client_with_test_db.get("/api/forecast")
    assert res.status_code == 200
    data = res.json()
    assert "points" in data
    assert "model_loaded" in data
    assert isinstance(data["points"], list)
