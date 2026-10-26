"""Network health score computation and history recording for NetWatch.

Evaluates an objective, continuous 0-100 network health score every window
based on active telemetry and threat levels:

Formula:
-----------------------------------------------------------------------------
Health Score = clamp(100.0 - (Penalty_alerts + Penalty_loss + Penalty_latency), 0.0, 100.0)

1. Penalty_alerts = min(45.0, (20.0 * N_high) + (10.0 * N_medium) + (4.0 * N_low))
   Where N_high, N_medium, N_low represent unacknowledged alerts in the lookback window.

2. Penalty_loss   = min(35.0, 1.5 * loss_pct)
   Scales linearly with active packet loss percentage (e.g. 10% loss = -15.0 pts).

3. Penalty_latency= min(20.0, max(0.0, (latency_ms - 20.0) * 0.25))
   Penalizes round-trip latency exceeding the 20ms baseline threshold.

Score Categorization:
- 80.0 to 100.0 : Healthy
- 50.0 to 79.9  : Degraded
-  0.0 to 49.9  : Critical
-----------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import logging
import math
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.config import settings
from backend.db import get_connection, init_db, insert_health_score

logger = logging.getLogger(__name__)


def compute_health_score_from_penalties(
    latency_ms: Optional[float] = None,
    loss_pct: Optional[float] = None,
    high_alerts: int = 0,
    medium_alerts: int = 0,
    low_alerts: int = 0,
) -> Tuple[float, Dict[str, float]]:
    """Compute mathematical health score clamped to [0.0, 100.0].

    Args:
        latency_ms: Gateway round-trip time in milliseconds.
        loss_pct: Gateway packet loss percentage (0.0 to 100.0).
        high_alerts: Count of unacknowledged high/critical severity alerts.
        medium_alerts: Count of unacknowledged medium/warning severity alerts.
        low_alerts: Count of unacknowledged low/info severity alerts.

    Returns:
        Tuple of (clamped_score, penalties_breakdown_dict).
    """
    # 1. Alert Penalties (Cap: 60.0 pts)
    p_alerts = min(60.0, (25.0 * high_alerts) + (15.0 * medium_alerts) + (5.0 * low_alerts))

    # 2. Packet Loss Penalty (Cap: 35.0 pts)
    effective_loss = max(0.0, float(loss_pct or 0.0))
    p_loss = min(35.0, 1.5 * effective_loss)

    # 3. Latency Penalty (Cap: 20.0 pts; Baseline: 20ms)
    effective_lat = max(0.0, float(latency_ms or 0.0))
    if effective_lat > 20.0:
        p_latency = min(20.0, (effective_lat - 20.0) * 0.25)
    else:
        p_latency = 0.0

    raw_score = 100.0 - (p_alerts + p_loss + p_latency)
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    penalties = {
        "alert_penalty": round(p_alerts, 2),
        "loss_penalty": round(p_loss, 2),
        "latency_penalty": round(p_latency, 2),
        "total_penalty": round(p_alerts + p_loss + p_latency, 2),
    }

    return final_score, penalties


def get_health_label(score: float) -> str:
    """Categorize numerical health score into qualitative label."""
    if score >= 80.0:
        return "Healthy"
    elif score >= 50.0:
        return "Degraded"
    return "Critical"


def evaluate_and_record_health(
    window_ts: Optional[float] = None,
    lookback_minutes: float = 5.0,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate current health metrics, record to health_history, and return summary.

    Args:
        window_ts: Timestamp for the evaluation; defaults to current time.
        lookback_minutes: Lookback window in minutes for active unacknowledged alerts.
        db_path: Optional SQLite database path.

    Returns:
        Summary dict containing score, label, penalties, and database insert ID.
    """
    now = window_ts if window_ts is not None else time.time()
    cutoff_alerts = now - (lookback_minutes * 60.0)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Fetch latest network-wide probe telemetry (latency & loss)
        cursor.execute(
            """
            SELECT latency_ms, loss_pct
            FROM traffic_metrics
            WHERE src_ip IS NULL
            ORDER BY ts DESC
            LIMIT 1
            """
        )
        metric_row = cursor.fetchone()
        latency_ms = float(metric_row["latency_ms"]) if metric_row and metric_row["latency_ms"] is not None else None
        loss_pct = float(metric_row["loss_pct"]) if metric_row and metric_row["loss_pct"] is not None else 0.0

        # 2. Fetch unacknowledged alerts in lookback window by severity
        cursor.execute(
            """
            SELECT severity, COUNT(*) as cnt
            FROM ai_alerts
            WHERE acknowledged = 0 AND ts >= ?
            GROUP BY severity
            """,
            (cutoff_alerts,),
        )
        alert_rows = cursor.fetchall()
        severity_counts = {r["severity"].lower(): int(r["cnt"]) for r in alert_rows}

    finally:
        conn.close()

    high_cnt = severity_counts.get("high", 0) + severity_counts.get("critical", 0)
    med_cnt = severity_counts.get("medium", 0) + severity_counts.get("warning", 0)
    low_cnt = severity_counts.get("low", 0) + severity_counts.get("info", 0)

    score, penalties = compute_health_score_from_penalties(
        latency_ms=latency_ms,
        loss_pct=loss_pct,
        high_alerts=high_cnt,
        medium_alerts=med_cnt,
        low_alerts=low_cnt,
    )
    label = get_health_label(score)

    # Write to health_history table
    row_id = insert_health_score(score=score, ts=now, db_path=db_path)

    summary = {
        "ts": now,
        "score": score,
        "label": label,
        "db_id": row_id,
        "latency_ms": latency_ms,
        "loss_pct": loss_pct,
        "active_alerts": {
            "high": high_cnt,
            "medium": med_cnt,
            "low": low_cnt,
        },
        "penalties": penalties,
    }

    logger.debug(
        "Health score evaluated: %.1f (%s) | latency=%.1fms loss=%.1f%% alerts(H:%d/M:%d/L:%d)",
        score,
        label,
        latency_ms or 0.0,
        loss_pct,
        high_cnt,
        med_cnt,
        low_cnt,
    )
    return summary


def run_health_daemon(
    interval_seconds: Optional[float] = None,
    once: bool = False,
    db_path: Optional[str] = None,
) -> None:
    """Run health evaluation loop periodically every window."""
    interval = interval_seconds or settings.agg_window_seconds
    logger.info("=" * 65)
    logger.info("NetWatch Health Evaluation Service Started")
    logger.info("  Cadence  : %.1f seconds", interval)
    logger.info("=" * 65)

    stop_requested = False

    def _sig_handler(signum: int, frame: Any) -> None:
        nonlocal stop_requested
        logger.info("Termination signal received. Stopping health daemon...")
        stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    while not stop_requested:
        start_t = time.time()
        try:
            summary = evaluate_and_record_health(db_path=db_path)
            logger.info("Network Health: %.1f (%s) [Loss: %.1f%%, Latency: %s ms, Penalty: -%.1f pts]",
                        summary["score"], summary["label"], summary["loss_pct"],
                        f"{summary['latency_ms']:.1f}" if summary["latency_ms"] else "N/A",
                        summary["penalties"]["total_penalty"])
        except Exception as exc:
            logger.error("Health evaluation error: %s", exc)

        if once or stop_requested:
            break

        elapsed = time.time() - start_t
        sleep_time = max(0.5, interval - elapsed)
        sleep_end = time.time() + sleep_time
        while not stop_requested and time.time() < sleep_end:
            time.sleep(0.2)

    logger.info("NetWatch Health Service stopped cleanly.")


def main() -> None:
    """CLI entrypoint for NetWatch health evaluation daemon."""
    parser = argparse.ArgumentParser(description="NetWatch Health Evaluation Service")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Cadence in seconds (default: 5.0s)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Evaluate once, write to health_history, and exit",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    run_health_daemon(
        interval_seconds=args.interval,
        once=args.once,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
