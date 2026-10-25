"""Database management, schema creation, connection handling, and batch operations for NetWatch.

Enforces:
- SQLite WAL journal mode
- 30-second busy timeout
- Batch inserts (never write once per packet)
- Indexed timestamps and IP addresses
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional, Sequence, Union

from backend.config import settings

logger = logging.getLogger(__name__)

# Complete SQLite DDL schema
SCHEMA_SQL = """
-- 1. Device Inventory
CREATE TABLE IF NOT EXISTS device_inventory (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    vendor TEXT,
    hostname TEXT,
    status TEXT,
    is_known INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen REAL
);

-- 2. Packet Flows
CREATE TABLE IF NOT EXISTS packet_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    tcp_flags TEXT
);

-- 3. Traffic Metrics
-- Note: src_ip IS NULL indicates a network-wide aggregate row
CREATE TABLE IF NOT EXISTS traffic_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NULL,
    bytes_out INTEGER DEFAULT 0,
    bytes_in INTEGER DEFAULT 0,
    pps REAL DEFAULT 0.0,
    tcp_count INTEGER DEFAULT 0,
    udp_count INTEGER DEFAULT 0,
    icmp_count INTEGER DEFAULT 0,
    dns_count INTEGER DEFAULT 0,
    other_count INTEGER DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    unique_dst_ports INTEGER DEFAULT 0,
    unique_dst_ips INTEGER DEFAULT 0,
    latency_ms REAL NULL,
    loss_pct REAL NULL
);

-- 4. AI Alerts
CREATE TABLE IF NOT EXISTS ai_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    message TEXT NOT NULL,
    score REAL NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    details_json TEXT
);

-- 5. Health History
CREATE TABLE IF NOT EXISTS health_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    score REAL NOT NULL
);

-- 6. Baseline Training Metadata
CREATE TABLE IF NOT EXISTS baseline_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    packet_count INTEGER DEFAULT 0,
    metric_count INTEGER DEFAULT 0,
    device_count INTEGER DEFAULT 0,
    created_at REAL NOT NULL,
    summary_json TEXT
);

-- Indexes on Timestamps (unix epoch float)
CREATE INDEX IF NOT EXISTS idx_packet_flows_ts ON packet_flows(ts);
CREATE INDEX IF NOT EXISTS idx_traffic_metrics_ts ON traffic_metrics(ts);
CREATE INDEX IF NOT EXISTS idx_ai_alerts_ts ON ai_alerts(ts);
CREATE INDEX IF NOT EXISTS idx_health_history_ts ON health_history(ts);
CREATE INDEX IF NOT EXISTS idx_device_inventory_last_seen ON device_inventory(last_seen);

-- Indexes on IP columns
CREATE INDEX IF NOT EXISTS idx_device_inventory_ip ON device_inventory(ip);
CREATE INDEX IF NOT EXISTS idx_packet_flows_src_ip ON packet_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_packet_flows_dst_ip ON packet_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_metrics_src_ip ON traffic_metrics(src_ip);
CREATE INDEX IF NOT EXISTS idx_ai_alerts_src_ip ON ai_alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_ai_alerts_ack ON ai_alerts(acknowledged);

-- Unique window constraints to prevent duplicate metric intervals
CREATE UNIQUE INDEX IF NOT EXISTS idx_tm_network ON traffic_metrics(ts) WHERE src_ip IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tm_host ON traffic_metrics(ts, src_ip) WHERE src_ip IS NOT NULL;
"""


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open and configure a SQLite connection in WAL mode with a 30s timeout.

    Args:
        db_path: Optional path to the database file; defaults to settings.db_path.

    Returns:
        Configured sqlite3.Connection with Row factory and WAL enabled.
    """
    target_path = db_path or str(settings.absolute_db_path)
    timeout = settings.db_timeout_seconds

    conn = sqlite3.connect(
        target_path,
        timeout=timeout,
        isolation_level=None,  # Autocommit mode by default; explicit transactions when needed
    )
    conn.row_factory = sqlite3.Row

    # Enforce WAL mode and concurrency pragmas
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)};")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")

    return conn


@contextlib.contextmanager
def get_db_context(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager providing an isolated connection with managed transactions."""
    conn = get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables and indexes.

    Args:
        db_path: Optional path to the database file; defaults to settings.db_path.
    """
    target_path = db_path or str(settings.absolute_db_path)
    logger.info("Initializing NetWatch database at: %s", target_path)

    conn = get_connection(target_path)
    try:
        conn.executescript(SCHEMA_SQL)
        logger.info("Database schema and indexes initialized successfully in WAL mode.")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Batch Insert Helper Functions
# ---------------------------------------------------------------------------

def insert_packet_flows_batch(
    flows: Sequence[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """Insert a batch of packet flows into the database.

    Args:
        flows: Sequence of flow dictionaries.
        db_path: Optional database path override.

    Returns:
        Number of records successfully inserted.
    """
    if not flows:
        return 0

    sql = """
    INSERT INTO packet_flows (
        ts, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags
    ) VALUES (
        :ts, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :length, :tcp_flags
    )
    """
    with get_db_context(db_path) as conn:
        conn.executemany(sql, flows)

    logger.debug("Inserted batch of %d packet flows", len(flows))
    return len(flows)


DEFAULT_METRIC_FIELDS: Dict[str, Any] = {
    "src_ip": None,
    "bytes_out": 0,
    "bytes_in": 0,
    "pps": 0.0,
    "tcp_count": 0,
    "udp_count": 0,
    "icmp_count": 0,
    "dns_count": 0,
    "other_count": 0,
    "syn_count": 0,
    "unique_dst_ports": 0,
    "unique_dst_ips": 0,
    "latency_ms": None,
    "loss_pct": None,
}


def insert_traffic_metrics_batch(
    metrics: Sequence[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """Insert a batch of traffic metrics aggregates into the database.

    Args:
        metrics: Sequence of traffic metrics dictionaries.
        db_path: Optional database path override.

    Returns:
        Number of records successfully inserted.
    """
    if not metrics:
        return 0

    sql = """
    INSERT INTO traffic_metrics (
        ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
        icmp_count, dns_count, other_count, syn_count,
        unique_dst_ports, unique_dst_ips, latency_ms, loss_pct
    ) VALUES (
        :ts, :src_ip, :bytes_out, :bytes_in, :pps, :tcp_count, :udp_count,
        :icmp_count, :dns_count, :other_count, :syn_count,
        :unique_dst_ports, :unique_dst_ips, :latency_ms, :loss_pct
    )
    """
    normalized_metrics = [{**DEFAULT_METRIC_FIELDS, **m} for m in metrics]
    with get_db_context(db_path) as conn:
        conn.executemany(sql, normalized_metrics)

    logger.debug("Inserted batch of %d traffic metrics records", len(metrics))
    return len(metrics)


def upsert_traffic_metrics_batch(
    metrics: Sequence[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """Upsert traffic metrics into the database, handling network-wide and per-host rows.

    Preserves any existing latency_ms and loss_pct on the network-wide row.

    Args:
        metrics: Sequence of metrics dictionaries.
        db_path: Optional database path override.

    Returns:
        Number of processed records.
    """
    if not metrics:
        return 0

    network_sql = """
    INSERT INTO traffic_metrics (
        ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
        icmp_count, dns_count, other_count, syn_count,
        unique_dst_ports, unique_dst_ips, latency_ms, loss_pct
    ) VALUES (
        :ts, NULL, :bytes_out, :bytes_in, :pps, :tcp_count, :udp_count,
        :icmp_count, :dns_count, :other_count, :syn_count,
        :unique_dst_ports, :unique_dst_ips, :latency_ms, :loss_pct
    )
    ON CONFLICT(ts) WHERE src_ip IS NULL DO UPDATE SET
        bytes_out = excluded.bytes_out,
        bytes_in = excluded.bytes_in,
        pps = excluded.pps,
        tcp_count = excluded.tcp_count,
        udp_count = excluded.udp_count,
        icmp_count = excluded.icmp_count,
        dns_count = excluded.dns_count,
        other_count = excluded.other_count,
        syn_count = excluded.syn_count,
        unique_dst_ports = excluded.unique_dst_ports,
        unique_dst_ips = excluded.unique_dst_ips,
        latency_ms = COALESCE(traffic_metrics.latency_ms, excluded.latency_ms),
        loss_pct = COALESCE(traffic_metrics.loss_pct, excluded.loss_pct)
    """

    host_sql = """
    INSERT INTO traffic_metrics (
        ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
        icmp_count, dns_count, other_count, syn_count,
        unique_dst_ports, unique_dst_ips, latency_ms, loss_pct
    ) VALUES (
        :ts, :src_ip, :bytes_out, :bytes_in, :pps, :tcp_count, :udp_count,
        :icmp_count, :dns_count, :other_count, :syn_count,
        :unique_dst_ports, :unique_dst_ips, :latency_ms, :loss_pct
    )
    ON CONFLICT(ts, src_ip) WHERE src_ip IS NOT NULL DO UPDATE SET
        bytes_out = excluded.bytes_out,
        bytes_in = excluded.bytes_in,
        pps = excluded.pps,
        tcp_count = excluded.tcp_count,
        udp_count = excluded.udp_count,
        icmp_count = excluded.icmp_count,
        dns_count = excluded.dns_count,
        other_count = excluded.other_count,
        syn_count = excluded.syn_count,
        unique_dst_ports = excluded.unique_dst_ports,
        unique_dst_ips = excluded.unique_dst_ips
    """

    network_rows = [{**DEFAULT_METRIC_FIELDS, **m} for m in metrics if m.get("src_ip") is None]
    host_rows = [{**DEFAULT_METRIC_FIELDS, **m} for m in metrics if m.get("src_ip") is not None]

    with get_db_context(db_path) as conn:
        if network_rows:
            conn.executemany(network_sql, network_rows)
        if host_rows:
            conn.executemany(host_sql, host_rows)

    logger.debug("Upserted %d traffic metrics records (%d net, %d host)", len(metrics), len(network_rows), len(host_rows))
    return len(metrics)


def update_probe_metrics(
    window_ts: float,
    latency_ms: Optional[float],
    loss_pct: Optional[float],
    db_path: Optional[str] = None,
) -> bool:
    """Write or update rolling latency and loss metrics into the network-wide row for a window.

    Args:
        window_ts: Timestamp aligned to the aggregation window boundary.
        latency_ms: Average ping latency in milliseconds, or None.
        loss_pct: Packet loss percentage (0.0 - 100.0).
        db_path: Optional database path override.

    Returns:
        True upon successful write.
    """
    sql = """
    INSERT INTO traffic_metrics (
        ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
        icmp_count, dns_count, other_count, syn_count,
        unique_dst_ports, unique_dst_ips, latency_ms, loss_pct
    ) VALUES (
        ?, NULL, 0, 0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0, ?, ?
    )
    ON CONFLICT(ts) WHERE src_ip IS NULL DO UPDATE SET
        latency_ms = excluded.latency_ms,
        loss_pct = excluded.loss_pct
    """
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (window_ts, latency_ms, loss_pct))
    return True


def get_unprocessed_packet_flows(
    last_id: int,
    limit: int = 15000,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve new packet flow rows inserted after last_id.

    Args:
        last_id: Last processed primary key ID.
        limit: Maximum rows to read per iteration.
        db_path: Optional database path override.

    Returns:
        List of flow row dictionaries sorted ascending by ID.
    """
    sql = """
    SELECT id, ts, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags
    FROM packet_flows
    WHERE id > ?
    ORDER BY id ASC
    LIMIT ?
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (last_id, limit))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_max_packet_flow_id(db_path: Optional[str] = None) -> int:
    """Retrieve the maximum ID currently present in packet_flows table.

    Args:
        db_path: Optional database path override.

    Returns:
        Highest packet_flow ID or 0 if table is empty.
    """
    sql = "SELECT COALESCE(MAX(id), 0) FROM packet_flows"
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        conn.close()


def upsert_device_inventory_batch(
    devices: Sequence[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """Insert or update device inventory entries keyed by MAC address.

    Args:
        devices: Sequence of device dictionaries.
        db_path: Optional database path override.

    Returns:
        Number of device records upserted.
    """
    if not devices:
        return 0

    sql = """
    INSERT INTO device_inventory (
        mac, ip, vendor, hostname, status, is_known, first_seen, last_seen
    ) VALUES (
        :mac, :ip, :vendor, :hostname, :status,
        COALESCE(:is_known, 0), :first_seen, :last_seen
    )
    ON CONFLICT(mac) DO UPDATE SET
        ip = excluded.ip,
        vendor = COALESCE(excluded.vendor, device_inventory.vendor),
        hostname = COALESCE(excluded.hostname, device_inventory.hostname),
        status = excluded.status,
        last_seen = excluded.last_seen
    """
    with get_db_context(db_path) as conn:
        conn.executemany(sql, devices)

    logger.debug("Upserted %d device inventory records", len(devices))
    return len(devices)


DEFAULT_ALERT_FIELDS: Dict[str, Any] = {
    "src_ip": None,
    "score": 0.0,
    "acknowledged": 0,
    "details_json": None,
}


def insert_ai_alerts_batch(
    alerts: Sequence[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """Insert a batch of AI alerts into the database.

    Args:
        alerts: Sequence of alert dictionaries.
        db_path: Optional database path override.

    Returns:
        Number of alert records inserted.
    """
    if not alerts:
        return 0

    sql = """
    INSERT INTO ai_alerts (
        ts, alert_type, severity, src_ip, message, score, acknowledged, details_json
    ) VALUES (
        :ts, :alert_type, :severity, :src_ip, :message, :score,
        COALESCE(:acknowledged, 0), :details_json
    )
    """
    normalized_alerts = [{**DEFAULT_ALERT_FIELDS, **a} for a in alerts]
    with get_db_context(db_path) as conn:
        conn.executemany(sql, normalized_alerts)

    logger.info("Inserted %d AI alerts", len(alerts))
    return len(alerts)


def insert_health_score(
    score: float,
    ts: Optional[float] = None,
    db_path: Optional[str] = None,
) -> int:
    """Record a health score at the specified or current timestamp.

    Args:
        score: Computed health score (0.0 to 100.0).
        ts: Unix epoch timestamp; defaults to current time.
        db_path: Optional database path override.

    Returns:
        The inserted row ID.
    """
    current_ts = ts if ts is not None else time.time()
    sql = "INSERT INTO health_history (ts, score) VALUES (?, ?)"

    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (current_ts, score))
        row_id = cursor.lastrowid or 0

    logger.debug("Recorded health score %.2f (id=%d)", score, row_id)
    return row_id


# ---------------------------------------------------------------------------
# Common Query Functions
# ---------------------------------------------------------------------------

def get_recent_traffic_metrics(
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    src_ip: Optional[Union[str, None]] = None,
    network_wide_only: bool = False,
    limit: int = 120,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch traffic metrics records matching query filters.

    Args:
        start_ts: Optional start unix epoch timestamp.
        end_ts: Optional end unix epoch timestamp.
        src_ip: Filter for a specific source IP.
        network_wide_only: If True, only return rows where src_ip is NULL.
        limit: Maximum number of rows to return.
        db_path: Optional database path override.

    Returns:
        List of dictionaries with traffic metrics.
    """
    conditions = []
    params: List[Any] = []

    if network_wide_only:
        conditions.append("src_ip IS NULL")
    elif src_ip is not None:
        conditions.append("src_ip = ?")
        params.append(src_ip)

    if start_ts is not None:
        conditions.append("ts >= ?")
        params.append(start_ts)

    if end_ts is not None:
        conditions.append("ts <= ?")
        params.append(end_ts)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT * FROM traffic_metrics
    {where_clause}
    ORDER BY ts DESC
    LIMIT ?
    """
    params.append(limit)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_recent_packet_flows(
    limit: int = 100,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve recent packet flows for inspection.

    Args:
        limit: Maximum flows to return.
        src_ip: Optional source IP filter.
        dst_ip: Optional destination IP filter.
        db_path: Optional database path override.

    Returns:
        List of flow dictionaries.
    """
    conditions = []
    params: List[Any] = []

    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if dst_ip:
        conditions.append("dst_ip = ?")
        params.append(dst_ip)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT * FROM packet_flows
    {where_clause}
    ORDER BY ts DESC
    LIMIT ?
    """
    params.append(limit)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_device_inventory(
    only_active: bool = False,
    active_window_seconds: float = 300.0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all discovered devices in inventory.

    Args:
        only_active: If True, filters devices seen within active_window_seconds.
        active_window_seconds: Time window in seconds to consider a device active.
        db_path: Optional database path override.

    Returns:
        List of device dictionary records.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if only_active:
            cutoff = time.time() - active_window_seconds
            sql = "SELECT * FROM device_inventory WHERE last_seen >= ? ORDER BY last_seen DESC"
            cursor.execute(sql, (cutoff,))
        else:
            sql = "SELECT * FROM device_inventory ORDER BY last_seen DESC"
            cursor.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_device_mac_map(db_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Fetch mapping of MAC addresses to existing device records.

    Args:
        db_path: Optional database path override.

    Returns:
        Dictionary mapping MAC address to device record dict.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT mac, ip, vendor, hostname, status, is_known, first_seen, last_seen FROM device_inventory")
        rows = cursor.fetchall()
        return {row["mac"]: dict(row) for row in rows}
    finally:
        conn.close()


def mark_devices_offline(last_seen_cutoff: float, db_path: Optional[str] = None) -> int:
    """Mark devices that have not been seen since cutoff as offline.

    Args:
        last_seen_cutoff: Unix epoch timestamp cutoff.
        db_path: Optional database path override.

    Returns:
        Number of devices marked offline.
    """
    sql = "UPDATE device_inventory SET status = 'offline' WHERE status = 'online' AND last_seen < ?"
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (last_seen_cutoff,))
        count = cursor.rowcount

    if count > 0:
        logger.info("Marked %d inactive devices as offline (last_seen < %.1f)", count, last_seen_cutoff)
    return count


def get_ai_alerts(
    limit: int = 50,
    acknowledged: Optional[bool] = None,
    severity: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve AI anomaly alerts with filtering options.

    Args:
        limit: Maximum alerts to retrieve.
        acknowledged: Filter by acknowledged status (True/False/None).
        severity: Filter by severity ('warning', 'critical', etc.).
        db_path: Optional database path override.

    Returns:
        List of alert dictionaries.
    """
    conditions = []
    params: List[Any] = []

    if acknowledged is not None:
        conditions.append("acknowledged = ?")
        params.append(1 if acknowledged else 0)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT * FROM ai_alerts
    {where_clause}
    ORDER BY ts DESC
    LIMIT ?
    """
    params.append(limit)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def acknowledge_alert(alert_id: int, db_path: Optional[str] = None) -> bool:
    """Mark an AI alert as acknowledged.

    Args:
        alert_id: Primary key ID of the alert.
        db_path: Optional database path override.

    Returns:
        True if updated, False if alert was not found.
    """
    sql = "UPDATE ai_alerts SET acknowledged = 1 WHERE id = ?"
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(sql, (alert_id,))
        return cursor.rowcount > 0


def save_baseline_metadata(
    start_ts: float,
    end_ts: float,
    name: str = "baseline_normal",
    packet_count: int = 0,
    metric_count: int = 0,
    device_count: int = 0,
    summary_json: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Save baseline time window metadata into SQLite.

    Args:
        start_ts: Unix epoch start of baseline period.
        end_ts: Unix epoch end of baseline period.
        name: Identifier for baseline configuration.
        packet_count: Count of packet flows captured.
        metric_count: Count of metric windows captured.
        device_count: Unique active devices observed.
        summary_json: Optional serialized telemetry details.
        db_path: Optional database path override.

    Returns:
        The inserted row ID.
    """
    sql = """
    INSERT INTO baseline_metadata (
        name, start_ts, end_ts, packet_count, metric_count, device_count, created_at, summary_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            sql,
            (name, start_ts, end_ts, packet_count, metric_count, device_count, time.time(), summary_json),
        )
        row_id = cursor.lastrowid or 0

    logger.info("Saved baseline '%s' (ID %d): %.1f -> %.1f (%d packets)", name, row_id, start_ts, end_ts, packet_count)
    return row_id


def get_latest_baseline(db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve the most recently recorded baseline metadata record.

    Args:
        db_path: Optional database path override.

    Returns:
        Dictionary of baseline metadata or None if no baseline recorded yet.
    """
    sql = "SELECT * FROM baseline_metadata ORDER BY id DESC LIMIT 1"
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def toggle_device_known(mac: str, db_path: Optional[str] = None) -> Optional[int]:
    """Toggle is_known status for a device by MAC address.

    Args:
        mac: Hardware MAC address string.
        db_path: Optional database path override.

    Returns:
        New is_known integer value (0 or 1), or None if device was not found.
    """
    normalized = mac.lower().replace("-", ":")
    fetch_sql = "SELECT is_known FROM device_inventory WHERE LOWER(mac) = ?"
    update_sql = "UPDATE device_inventory SET is_known = ? WHERE LOWER(mac) = ?"

    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(fetch_sql, (normalized,))
        row = cursor.fetchone()
        if not row:
            return None

        current_val = int(row["is_known"]) if row["is_known"] is not None else 0
        new_val = 0 if current_val == 1 else 1
        cursor.execute(update_sql, (new_val, normalized))
        return new_val


def get_system_status(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve operational telemetry about database size, packet capture, and interfaces.

    Args:
        db_path: Optional database path override.

    Returns:
        Dictionary with capture_running, last_packet_time, db_size_bytes, interface, subnet.
    """
    target_path = db_path or str(settings.absolute_db_path)
    db_size = 0
    try:
        if os.path.exists(target_path):
            db_size = os.path.getsize(target_path)
            # Add WAL and SHM file sizes if present
            for ext in ("-wal", "-shm"):
                aux = target_path + ext
                if os.path.exists(aux):
                    db_size += os.path.getsize(aux)
    except Exception as exc:
        logger.debug("Failed computing db size: %s", exc)

    conn = get_connection(db_path)
    last_packet_ts: Optional[float] = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(ts) FROM packet_flows")
        row = cursor.fetchone()
        if row and row[0] is not None:
            last_packet_ts = float(row[0])
    finally:
        conn.close()

    # Consider capture running if packet received within last 15 seconds
    now = time.time()
    capture_running = bool(last_packet_ts and (now - last_packet_ts) <= 15.0)

    return {
        "capture_running": capture_running,
        "last_packet_time": last_packet_ts,
        "db_size_bytes": db_size,
        "interface": settings.resolved_interface,
        "subnet": settings.resolved_subnet,
        "gateway": settings.resolved_gateway,
    }


def get_traffic_timeseries(
    minutes: float = 15.0,
    window_seconds: float = 5.0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve chronological network-wide traffic telemetry for dashboard charts.

    Calculates bps_in and bps_out from byte volumes over each window interval.

    Args:
        minutes: Lookback window in minutes (default: 15).
        window_seconds: Window length in seconds for rate computation (default: 5.0).
        db_path: Optional database path override.

    Returns:
        List of chronological metric dictionaries.
    """
    cutoff = time.time() - (minutes * 60.0)
    w_sec = max(0.1, window_seconds)

    sql = """
    SELECT ts, bytes_out, bytes_in, pps, latency_ms, loss_pct, tcp_count, udp_count, icmp_count, dns_count
    FROM traffic_metrics
    WHERE src_ip IS NULL AND ts >= ?
    ORDER BY ts ASC
    """

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (cutoff,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            b_out = int(r["bytes_out"] or 0)
            b_in = int(r["bytes_in"] or 0)
            bps_out = round((b_out * 8.0) / w_sec, 2)
            bps_in = round((b_in * 8.0) / w_sec, 2)

            result.append(
                {
                    "ts": float(r["ts"]),
                    "bps_out": bps_out,
                    "bps_in": bps_in,
                    "bytes_out": b_out,
                    "bytes_in": b_in,
                    "pps": float(r["pps"] or 0.0),
                    "latency_ms": float(r["latency_ms"]) if r["latency_ms"] is not None else None,
                    "loss_pct": float(r["loss_pct"]) if r["loss_pct"] is not None else None,
                }
            )
        return result
    finally:
        conn.close()


def get_protocol_distribution(
    minutes: float = 5.0,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Calculate aggregated protocol share totals over the specified lookback duration.

    Args:
        minutes: Duration in minutes.
        db_path: Optional database path override.

    Returns:
        Dictionary mapping protocol names to total packet counts.
    """
    cutoff = time.time() - (minutes * 60.0)
    sql = """
    SELECT
        COALESCE(SUM(tcp_count), 0) AS tcp,
        COALESCE(SUM(udp_count), 0) AS udp,
        COALESCE(SUM(icmp_count), 0) AS icmp,
        COALESCE(SUM(dns_count), 0) AS dns,
        COALESCE(SUM(other_count), 0) AS other
    FROM traffic_metrics
    WHERE src_ip IS NULL AND ts >= ?
    """

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (cutoff,))
        row = cursor.fetchone()
        tcp = int(row["tcp"]) if row else 0
        udp = int(row["udp"]) if row else 0
        icmp = int(row["icmp"]) if row else 0
        dns = int(row["dns"]) if row else 0
        other = int(row["other"]) if row else 0
        total = tcp + udp + icmp + dns + other

        return {
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp,
            "dns": dns,
            "other": other,
            "total_packets": total,
            "minutes": minutes,
        }
    finally:
        conn.close()


def get_top_talkers(
    minutes: float = 5.0,
    limit: int = 10,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve top active network hosts ordered by total bandwidth consumed.

    Enriches host metrics with hostname, vendor, and known status from device inventory.

    Args:
        minutes: Lookback duration in minutes.
        limit: Maximum hosts to return.
        db_path: Optional database path override.

    Returns:
        List of host summaries sorted by total bytes descending.
    """
    cutoff = time.time() - (minutes * 60.0)
    sql = """
    SELECT
        tm.src_ip AS ip,
        COALESCE(SUM(tm.bytes_out), 0) AS bytes_out,
        COALESCE(SUM(tm.bytes_in), 0) AS bytes_in,
        COALESCE(SUM(tm.bytes_out + tm.bytes_in), 0) AS total_bytes,
        ROUND(AVG(tm.pps), 2) AS avg_pps,
        MAX(d.hostname) AS hostname,
        MAX(d.vendor) AS vendor,
        MAX(d.status) AS status,
        COALESCE(MAX(d.is_known), 0) AS is_known
    FROM traffic_metrics tm
    LEFT JOIN device_inventory d ON tm.src_ip = d.ip
    WHERE tm.src_ip IS NOT NULL AND tm.ts >= ?
    GROUP BY tm.src_ip
    ORDER BY total_bytes DESC
    LIMIT ?
    """

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (cutoff, limit))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            ip = str(d.get("ip") or "").strip()
            hostname = d.get("hostname")
            vendor = d.get("vendor")

            # Enrich hostname and vendor if not already present in device inventory
            if not hostname or str(hostname).lower() in ("none", "unknown", ""):
                if ip in ("10.173.221.202", getattr(settings, "resolved_gateway", "10.173.221.202")):
                    hostname = "Phone Hotspot (Gateway)"
                    vendor = "Mobile Hotspot Gateway"
                elif ip in ("10.173.221.31", getattr(settings, "resolved_ip", "10.173.221.31")):
                    hostname = "ZEREF (Workstation)"
                    vendor = "Local Workstation (Host)"
                elif ip.startswith("10.173.221."):
                    hostname = f"Subnet Host ({ip})"
                    vendor = "Local Subnet Device"
                elif ":" in ip:  # IPv6 address
                    ip_lower = ip.lower()
                    if ip_lower.startswith("2603:"):
                        hostname = "Microsoft Azure / Teams Cloud"
                        vendor = "Microsoft Corporation"
                    elif ip_lower.startswith("2001:4860:"):
                        hostname = "Google Services / Cloud"
                        vendor = "Google LLC"
                    elif ip_lower.startswith("64:ff9b::"):
                        hostname = "NAT64 Carrier Gateway (CDN)"
                        vendor = "Mobile Cellular ISP"
                    elif ip_lower.startswith("2402:"):
                        hostname = "Cellular ISP Access Node"
                        vendor = "Mobile Network Operator"
                    else:
                        hostname = "External IPv6 Internet Host"
                        vendor = "Public Internet"
                else:  # IPv4 external
                    if ip.startswith(("8.8.", "142.250.", "172.217.")):
                        hostname = "Google Services / 8.8.8.8"
                        vendor = "Google LLC"
                    elif ip.startswith(("1.1.1.", "1.0.0.")):
                        hostname = "Cloudflare DNS / Services"
                        vendor = "Cloudflare, Inc."
                    elif ip.startswith(("20.", "40.", "52.")):
                        hostname = "Microsoft Cloud / Windows Services"
                        vendor = "Microsoft Corporation"
                    else:
                        hostname = f"External Cloud Host ({ip})"
                        vendor = "Public Internet"

            d["hostname"] = hostname
            d["vendor"] = vendor
            d["host"] = ip  # Support both t.host and t.ip
            result.append(d)
        return result
    finally:
        conn.close()


def get_health_status(
    limit: int = 20,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve the latest network health evaluation score, label, and history.

    Args:
        limit: Number of historical score entries to return.
        db_path: Optional database path override.

    Returns:
        Dict with score, label, last_updated, and history list.
    """
    history_list = get_health_history(limit=limit, db_path=db_path)

    latest_score = 100.0
    latest_ts = time.time()

    if history_list:
        latest_entry = history_list[-1]
        latest_score = float(latest_entry.get("score", 100.0))
        latest_ts = float(latest_entry.get("ts", time.time()))

    if latest_score >= 80.0:
        label = "Healthy"
    elif latest_score >= 50.0:
        label = "Degraded"
    else:
        label = "Critical"

    return {
        "score": round(latest_score, 1),
        "label": label,
        "last_updated": latest_ts,
        "history": history_list,
    }


def get_health_history(
    limit: int = 100,
    since_ts: Optional[float] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch health score historical trend data.

    Args:
        limit: Maximum records to return.
        since_ts: Optional timestamp filter for health entries.
        db_path: Optional database path override.

    Returns:
        List of health entries sorted chronologically.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if since_ts is not None:
            sql = "SELECT * FROM health_history WHERE ts >= ? ORDER BY ts ASC LIMIT ?"
            cursor.execute(sql, (since_ts, limit))
        else:
            sql = "SELECT * FROM health_history ORDER BY ts DESC LIMIT ?"
            cursor.execute(sql, (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        # Return in ascending order for time-series charts
        return results if since_ts is not None else list(reversed(results))
    finally:
        conn.close()


def cleanup_old_records(
    retention_hours: Optional[float] = None,
    db_path: Optional[str] = None,
) -> Dict[str, int]:
    """Purge packet flows and traffic metrics older than the retention threshold.

    Args:
        retention_hours: Retention duration in hours (defaults to settings.retention_hours).
        db_path: Optional database path override.

    Returns:
        Dictionary mapping table name to number of deleted rows.
    """
    hours = retention_hours if retention_hours is not None else settings.retention_hours
    cutoff = time.time() - (hours * 3600.0)
    purged: Dict[str, int] = {}

    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM packet_flows WHERE ts < ?", (cutoff,))
        purged["packet_flows"] = cursor.rowcount

        cursor.execute("DELETE FROM traffic_metrics WHERE ts < ?", (cutoff,))
        purged["traffic_metrics"] = cursor.rowcount

        cursor.execute("DELETE FROM health_history WHERE ts < ?", (cutoff,))
        purged["health_history"] = cursor.rowcount

    logger.info("Purged records older than %.1f hours: %s", hours, purged)
    return purged




def reset_database_tables(clear_devices: bool = True, db_path: Optional[str] = None) -> Dict[str, int]:
    """Purge telemetry tables and optionally device inventory to return to a clean slate.

    Args:
        clear_devices: If True, also purges the device_inventory table.
        db_path: Optional SQLite database file path.

    Returns:
        Dictionary mapping table name to number of deleted rows.
    """
    purged: Dict[str, int] = {}
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM packet_flows")
        purged["packet_flows"] = cursor.rowcount

        cursor.execute("DELETE FROM traffic_metrics")
        purged["traffic_metrics"] = cursor.rowcount

        cursor.execute("DELETE FROM health_history")
        purged["health_history"] = cursor.rowcount

        cursor.execute("DELETE FROM ai_alerts")
        purged["ai_alerts"] = cursor.rowcount

        if clear_devices:
            cursor.execute("DELETE FROM device_inventory")
            purged["device_inventory"] = cursor.rowcount

    logger.info("Database reset completed: %s", purged)
    return purged


def baseline_all_devices(db_path: Optional[str] = None) -> int:
    """Mark all currently registered devices as known / trusted.

    Args:
        db_path: Optional SQLite database file path.

    Returns:
        Number of device rows updated.
    """
    with get_db_context(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE device_inventory SET is_known = 1")
        count = cursor.rowcount
    logger.info("Marked %d devices as known baseline", count)
    return count


def main() -> None:
    """CLI entrypoint for database maintenance and initialization."""
    parser = argparse.ArgumentParser(description="NetWatch Database Management Utility")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize the NetWatch database schema and indexes",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Purge records older than retention threshold",
    )

    args = parser.parse_args()

    if args.init:
        init_db(args.db_path)
        print(f"NetWatch database initialized successfully at: {args.db_path or settings.db_path}")
    elif args.cleanup:
        counts = cleanup_old_records(db_path=args.db_path)
        print(f"Cleanup complete. Deleted: {counts}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
