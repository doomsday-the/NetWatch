"""Baseline network traffic recording utility for NetWatch.

Monitors or designates a period of normal network operation as the baseline dataset.
Stores start and end timestamps in the baseline_metadata table and baseline.json,
and prints a detailed statistical summary for training ML models.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
from pathlib import Path
import signal
import sys
import time

# Ensure repository root is on sys.path
REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from typing import Any, Dict, Optional

from backend.config import REPO_ROOT, settings
from backend.db import get_connection, init_db, save_baseline_metadata

logger = logging.getLogger(__name__)


def record_baseline(
    duration_minutes: float = 10.0,
    name: str = "baseline_normal",
    json_path: Optional[str] = None,
    from_history: bool = False,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a baseline observation window for training anomaly detection models.

    Args:
        duration_minutes: Duration in minutes for the baseline window.
        name: Name identifier for the baseline.
        json_path: Path to write the baseline summary JSON file.
        from_history: If True, designates the last N minutes of already-captured data as baseline.
        db_path: Optional custom SQLite database path.

    Returns:
        Dictionary summary of the recorded baseline telemetry.
    """
    init_db(db_path)
    output_json = Path(json_path or (REPO_ROOT / "baseline.json")).resolve()
    target_seconds = duration_minutes * 60.0

    if from_history:
        # Mark recent historical data as baseline
        now = time.time()
        start_ts = now - target_seconds
        end_ts = now
        logger.info("Designating previous %.1f minutes as baseline '%s'...", duration_minutes, name)
    else:
        # Live recording loop
        start_ts = time.time()
        end_ts = start_ts + target_seconds

        logger.info("=" * 65)
        logger.info("Recording Live Network Baseline: '%s'", name)
        logger.info("  Duration  : %.1f minutes (%.0f seconds)", duration_minutes, target_seconds)
        logger.info("  Start Time: %s", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_ts)))
        logger.info("  End Time  : %s", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_ts)))
        logger.info("=" * 65)
        logger.info("Recording in progress... (Press Ctrl+C to conclude early and save)")

        stop_requested = False

        def _sig_handler(signum: int, frame: Any) -> None:
            nonlocal stop_requested
            logger.info("Early conclusion requested via signal (%d)...", signum)
            stop_requested = True

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        last_status = start_ts
        while not stop_requested and time.time() < end_ts:
            time.sleep(1.0)
            now = time.time()
            if now - last_status >= 15.0:
                elapsed = now - start_ts
                remaining = max(0.0, end_ts - now)

                # Query current flow count
                conn = get_connection(db_path)
                try:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM packet_flows WHERE ts >= ?", (start_ts,))
                    pkt_count = c.fetchone()[0]
                finally:
                    conn.close()

                logger.info(
                    "Baseline progress: %.0fs / %.0fs (%.1f%%) | Flows captured: %d",
                    elapsed,
                    target_seconds,
                    (elapsed / target_seconds) * 100.0,
                    pkt_count,
                )
                last_status = now

        end_ts = time.time()

    actual_duration = max(1.0, end_ts - start_ts)

    # Query comprehensive baseline statistics from SQLite
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Packet flow totals
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_flows,
                COALESCE(SUM(length), 0) AS total_bytes,
                COUNT(DISTINCT src_ip) AS unique_src_ips,
                COUNT(DISTINCT dst_ip) AS unique_dst_ips
            FROM packet_flows
            WHERE ts >= ? AND ts <= ?
            """,
            (start_ts, end_ts),
        )
        flow_stats = dict(cursor.fetchone())

        # 2. Metric windows totals
        cursor.execute(
            """
            SELECT
                COUNT(*) AS metric_windows,
                COALESCE(SUM(bytes_out), 0) AS total_bytes_out,
                COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
                COALESCE(AVG(pps), 0.0) AS avg_pps,
                COALESCE(SUM(tcp_count), 0) AS tcp_count,
                COALESCE(SUM(udp_count), 0) AS udp_count,
                COALESCE(SUM(icmp_count), 0) AS icmp_count,
                COALESCE(SUM(dns_count), 0) AS dns_count,
                COALESCE(SUM(other_count), 0) AS other_count,
                COALESCE(SUM(syn_count), 0) AS syn_count,
                COALESCE(AVG(latency_ms), 0.0) AS avg_latency_ms,
                COALESCE(AVG(loss_pct), 0.0) AS avg_loss_pct
            FROM traffic_metrics
            WHERE src_ip IS NULL AND ts >= ? AND ts <= ?
            """,
            (start_ts, end_ts),
        )
        metric_stats = dict(cursor.fetchone())

        # 3. Active distinct devices
        cursor.execute(
            """
            SELECT COUNT(DISTINCT src_ip)
            FROM traffic_metrics
            WHERE src_ip IS NOT NULL AND ts >= ? AND ts <= ?
            """,
            (start_ts, end_ts),
        )
        device_count = cursor.fetchone()[0] or flow_stats["unique_src_ips"]

    finally:
        conn.close()

    total_pkts = int(flow_stats["total_flows"])
    metric_count = int(metric_stats["metric_windows"])

    avg_bps = round(((metric_stats["total_bytes_out"] + metric_stats["total_bytes_in"]) * 8.0) / actual_duration, 2)
    avg_pps = round(metric_stats["avg_pps"], 2)

    summary: Dict[str, Any] = {
        "baseline_name": name,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "duration_seconds": round(actual_duration, 1),
        "packet_count": total_pkts,
        "metric_windows": metric_count,
        "active_devices": device_count,
        "avg_pps": avg_pps,
        "avg_bps": avg_bps,
        "avg_latency_ms": round(metric_stats["avg_latency_ms"], 2),
        "avg_loss_pct": round(metric_stats["avg_loss_pct"], 2),
        "protocols": {
            "tcp": int(metric_stats["tcp_count"]),
            "udp": int(metric_stats["udp_count"]),
            "icmp": int(metric_stats["icmp_count"]),
            "dns": int(metric_stats["dns_count"]),
            "other": int(metric_stats["other_count"]),
            "syn_packets": int(metric_stats["syn_count"]),
        },
        "created_at": time.time(),
    }

    # 4. Save to baseline_metadata table in SQLite
    row_id = save_baseline_metadata(
        start_ts=start_ts,
        end_ts=end_ts,
        name=name,
        packet_count=total_pkts,
        metric_count=metric_count,
        device_count=device_count,
        summary_json=json.dumps(summary, indent=2),
        db_path=db_path,
    )
    summary["db_record_id"] = row_id

    # 5. Save to baseline.json file
    try:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        logger.info("Saved baseline summary file: %s", output_json)
    except Exception as exc:
        logger.error("Failed writing baseline JSON file: %s", exc)

    # 6. Print formatted summary
    print("\n" + "=" * 65)
    print(f"       NETWATCH BASELINE RECORDING SUMMARY ({name})")
    print("=" * 65)
    print(f"  Duration           : {summary['duration_seconds']} seconds ({summary['duration_seconds']/60.0:.1f} minutes)")
    print(f"  Start Timestamp    : {summary['start_ts']:.0f} ({time.strftime('%H:%M:%S', time.localtime(summary['start_ts']))})")
    print(f"  End Timestamp      : {summary['end_ts']:.0f} ({time.strftime('%H:%M:%S', time.localtime(summary['end_ts']))})")
    print(f"  Packet Flows       : {summary['packet_count']:,}")
    print(f"  Metric Windows     : {summary['metric_windows']:,}")
    print(f"  Active Devices     : {summary['active_devices']}")
    print(f"  Average Throughput : {summary['avg_bps']:,} bps")
    print(f"  Average Packet Rate: {summary['avg_pps']} pps")
    print(f"  Average Latency    : {summary['avg_latency_ms']} ms")
    print(f"  Average Loss       : {summary['avg_loss_pct']}%")
    print("  Protocol Breakdown :")
    for proto, cnt in summary["protocols"].items():
        print(f"    - {proto.upper():<12}: {cnt:,}")
    print(f"  Database ID        : #{row_id}")
    print(f"  Output File        : {output_json}")
    print("=" * 65)
    print("Baseline ready for training ML anomaly detection models!\n")

    return summary


def main() -> None:
    """CLI entrypoint for baseline recording script."""
    parser = argparse.ArgumentParser(description="NetWatch Network Baseline Recorder")
    parser.add_argument(
        "--minutes",
        type=float,
        default=10.0,
        help="Recording duration in minutes (default: 10.0)",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=None,
        help="Optional recording duration in seconds (overrides --minutes)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="baseline_normal",
        help="Baseline dataset identifier (default: baseline_normal)",
    )
    parser.add_argument(
        "--from-history",
        action="store_true",
        help="Designate preceding duration from existing captured database traffic as baseline",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        default=None,
        help="Output JSON file path (default: baseline.json in repo root)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()
    duration_min = (args.seconds / 60.0) if args.seconds is not None else args.minutes

    record_baseline(
        duration_minutes=duration_min,
        name=args.name,
        json_path=args.json_file,
        from_history=args.from_history,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
