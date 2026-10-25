"""Unit tests for NetWatch network health score computation engine."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from backend.db import get_health_status, init_db, insert_ai_alerts_batch, upsert_traffic_metrics_batch
from backend.ml.health import (
    compute_health_score_from_penalties,
    evaluate_and_record_health,
    get_health_label,
)


def test_health_score_ideal_conditions() -> None:
    """Verify clean, optimal network conditions yield perfect 100.0 score."""
    score, penalties = compute_health_score_from_penalties(
        latency_ms=12.0,
        loss_pct=0.0,
        high_alerts=0,
        medium_alerts=0,
        low_alerts=0,
    )
    assert score == 100.0
    assert penalties["total_penalty"] == 0.0
    assert get_health_label(score) == "Healthy"


def test_alert_penalties_and_capping() -> None:
    """Verify alert severity weighting and 45-point cap."""
    # 1 High alert = 20 pts penalty -> score 80.0
    score1, p1 = compute_health_score_from_penalties(high_alerts=1)
    assert score1 == 80.0
    assert p1["alert_penalty"] == 20.0

    # 1 Medium + 2 Low = 10 + 8 = 18 pts penalty -> score 82.0
    score2, p2 = compute_health_score_from_penalties(medium_alerts=1, low_alerts=2)
    assert score2 == 82.0
    assert p2["alert_penalty"] == 18.0

    # 5 High alerts = 100 pts -> capped at 45.0 pts penalty -> score 55.0
    score3, p3 = compute_health_score_from_penalties(high_alerts=5)
    assert score3 == 55.0
    assert p3["alert_penalty"] == 45.0


def test_packet_loss_penalty_and_capping() -> None:
    """Verify packet loss penalty scaling (1.5x) and 35-point cap."""
    # 10% loss -> 15.0 pts penalty -> score 85.0
    score1, p1 = compute_health_score_from_penalties(loss_pct=10.0)
    assert score1 == 85.0
    assert p1["loss_penalty"] == 15.0

    # 30% loss -> 45.0 pts -> capped at 35.0 pts -> score 65.0
    score2, p2 = compute_health_score_from_penalties(loss_pct=30.0)
    assert score2 == 65.0
    assert p2["loss_penalty"] == 35.0


def test_latency_penalty_and_capping() -> None:
    """Verify latency baseline (20ms), scaling (0.25x), and 20-point cap."""
    # Latency at or below 20ms baseline -> 0 penalty
    score1, p1 = compute_health_score_from_penalties(latency_ms=18.0)
    assert score1 == 100.0
    assert p1["latency_penalty"] == 0.0

    # 60ms latency -> (60 - 20) * 0.25 = 10.0 pts penalty -> score 90.0
    score2, p2 = compute_health_score_from_penalties(latency_ms=60.0)
    assert score2 == 90.0
    assert p2["latency_penalty"] == 10.0

    # 200ms latency -> (200 - 20) * 0.25 = 45 pts -> capped at 20.0 pts -> score 80.0
    score3, p3 = compute_health_score_from_penalties(latency_ms=200.0)
    assert score3 == 80.0
    assert p3["latency_penalty"] == 20.0


def test_worst_case_clamping_to_zero() -> None:
    """Verify total combined maximum penalties clamp to 0.0, Critical."""
    score, penalties = compute_health_score_from_penalties(
        latency_ms=300.0,
        loss_pct=50.0,
        high_alerts=10,
    )
    assert score == 0.0
    assert penalties["total_penalty"] == 100.0
    assert get_health_label(score) == "Critical"


def test_health_labels() -> None:
    """Verify qualitative boundary label classifications."""
    assert get_health_label(100.0) == "Healthy"
    assert get_health_label(80.0) == "Healthy"
    assert get_health_label(79.9) == "Degraded"
    assert get_health_label(50.0) == "Degraded"
    assert get_health_label(49.9) == "Critical"
    assert get_health_label(0.0) == "Critical"


def test_evaluate_and_record_health_integration(tmp_path: Path) -> None:
    """Verify evaluate_and_record_health writes to SQLite table."""
    db_file = str(tmp_path / "health_test.db")
    init_db(db_file)

    now = time.time()
    # 1. Insert network traffic row with latency and loss
    upsert_traffic_metrics_batch(
        [
            {
                "ts": now,
                "src_ip": None,
                "bytes_out": 1000,
                "bytes_in": 1000,
                "pps": 10,
                "latency_ms": 40.0,  # 5.0 penalty
                "loss_pct": 5.0,     # 7.5 penalty
            }
        ],
        db_path=db_file,
    )

    # 2. Insert 1 medium alert
    insert_ai_alerts_batch(
        [
            {
                "ts": now,
                "alert_type": "unknown_device",
                "severity": "medium",
                "src_ip": "192.168.1.55",
                "message": "New device",
                "score": 0.5,
                "acknowledged": 0,
            }
        ],
        db_path=db_file,
    )

    # Evaluate health
    health_result = evaluate_and_record_health(window_ts=now, db_path=db_file)

    # Expected: 100 - (10.0 alert + 7.5 loss + 5.0 latency) = 77.5
    assert health_result["score"] == pytest.approx(77.5, abs=0.5)

    status = get_health_status(db_path=db_file)
    assert status["score"] == pytest.approx(77.5, abs=0.5)
    assert status["label"] == "Degraded"
