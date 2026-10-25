"""Traffic metrics aggregator for NetWatch.

Periodically reads unaggregated packet flows from SQLite,
computes network-wide and per-host traffic metrics over aligned time windows,
determines LAN upload/download directionality,
upserts records into traffic_metrics,
and performs hourly retention cleanup.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import math
import signal
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.config import settings
from backend.db import (
    cleanup_old_records,
    get_max_packet_flow_id,
    get_unprocessed_packet_flows,
    upsert_traffic_metrics_batch,
)

logger = logging.getLogger(__name__)


def is_syn_packet(tcp_flags: Optional[str]) -> bool:
    """Return True if TCP flags contain SYN without ACK."""
    if not tcp_flags:
        return False
    flags = tcp_flags.upper()
    return "S" in flags and "A" not in flags


class WindowTrafficAccumulator:
    """Aggregates packet flows for a single discrete time window."""

    def __init__(self, window_ts: float, window_seconds: float, lan_subnet: Optional[ipaddress.IPv4Network] = None) -> None:
        self.window_ts = window_ts
        self.window_seconds = window_seconds
        self.lan_subnet = lan_subnet

        # Network-wide counters
        self.net_bytes_out = 0
        self.net_bytes_in = 0
        self.net_packet_count = 0
        self.net_tcp = 0
        self.net_udp = 0
        self.net_icmp = 0
        self.net_dns = 0
        self.net_other = 0
        self.net_syn = 0
        self.net_dst_ports: Set[int] = set()
        self.net_dst_ips: Set[str] = set()

        # Per-host counters: host_ip -> dict
        # We track hosts appearing as either src_ip or dst_ip
        self.host_bytes_out: Dict[str, int] = defaultdict(int)
        self.host_bytes_in: Dict[str, int] = defaultdict(int)
        self.host_packet_count: Dict[str, int] = defaultdict(int)
        self.host_tcp: Dict[str, int] = defaultdict(int)
        self.host_udp: Dict[str, int] = defaultdict(int)
        self.host_icmp: Dict[str, int] = defaultdict(int)
        self.host_dns: Dict[str, int] = defaultdict(int)
        self.host_other: Dict[str, int] = defaultdict(int)
        self.host_syn: Dict[str, int] = defaultdict(int)
        self.host_dst_ports: Dict[str, Set[int]] = defaultdict(set)
        self.host_dst_ips: Dict[str, Set[str]] = defaultdict(set)

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        """Incorporate a single packet flow into window metrics."""
        length = int(pkt.get("length") or 0)
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        protocol = (pkt.get("protocol") or "OTHER").upper()
        flags = pkt.get("tcp_flags") or ""
        syn = is_syn_packet(flags)

        # 1. Network-wide accumulation
        self.net_packet_count += 1
        if protocol == "TCP":
            self.net_tcp += 1
        elif protocol == "UDP":
            self.net_udp += 1
        elif protocol == "ICMP":
            self.net_icmp += 1
        elif protocol == "DNS":
            self.net_dns += 1
        else:
            self.net_other += 1

        if syn:
            self.net_syn += 1

        if dst_port is not None:
            self.net_dst_ports.add(int(dst_port))
        if dst_ip:
            self.net_dst_ips.add(str(dst_ip))

        # Directionality for network-wide totals:
        # Determine whether flow is upload (LAN -> WAN), download (WAN -> LAN), or local LAN
        src_in_lan = False
        dst_in_lan = False

        if self.lan_subnet:
            try:
                if src_ip:
                    src_in_lan = ipaddress.IPv4Address(src_ip) in self.lan_subnet
            except Exception:
                pass
            try:
                if dst_ip:
                    dst_in_lan = ipaddress.IPv4Address(dst_ip) in self.lan_subnet
            except Exception:
                pass

        if src_in_lan and not dst_in_lan:
            # Egress / Upload
            self.net_bytes_out += length
        elif dst_in_lan and not src_in_lan:
            # Ingress / Download
            self.net_bytes_in += length
        else:
            # Both inside LAN or both outside: count as internal traffic
            self.net_bytes_out += length
            self.net_bytes_in += length

        # 2. Per-host accumulation
        if src_ip:
            self.host_bytes_out[src_ip] += length
            self.host_packet_count[src_ip] += 1

            if protocol == "TCP":
                self.host_tcp[src_ip] += 1
            elif protocol == "UDP":
                self.host_udp[src_ip] += 1
            elif protocol == "ICMP":
                self.host_icmp[src_ip] += 1
            elif protocol == "DNS":
                self.host_dns[src_ip] += 1
            else:
                self.host_other[src_ip] += 1

            if syn:
                self.host_syn[src_ip] += 1

            if dst_port is not None:
                self.host_dst_ports[src_ip].add(int(dst_port))
            if dst_ip:
                self.host_dst_ips[src_ip].add(str(dst_ip))

        if dst_ip:
            # bytes_in for destination host
            self.host_bytes_in[dst_ip] += length

    def build_metric_rows(self) -> List[Dict[str, Any]]:
        """Construct database rows for network-wide and per-source-IP metrics."""
        rows: List[Dict[str, Any]] = []
        w_sec = max(0.1, self.window_seconds)

        # Network-wide row (src_ip IS NULL)
        net_pps = round(self.net_packet_count / w_sec, 2)
        rows.append(
            {
                "ts": self.window_ts,
                "src_ip": None,
                "bytes_out": self.net_bytes_out,
                "bytes_in": self.net_bytes_in,
                "pps": net_pps,
                "tcp_count": self.net_tcp,
                "udp_count": self.net_udp,
                "icmp_count": self.net_icmp,
                "dns_count": self.net_dns,
                "other_count": self.net_other,
                "syn_count": self.net_syn,
                "unique_dst_ports": len(self.net_dst_ports),
                "unique_dst_ips": len(self.net_dst_ips),
                "latency_ms": None,
                "loss_pct": None,
            }
        )

        # Per source IP rows
        all_hosts = set(self.host_bytes_out.keys()) | set(self.host_bytes_in.keys())
        for host in all_hosts:
            pkt_cnt = self.host_packet_count[host]
            host_pps = round(pkt_cnt / w_sec, 2)

            rows.append(
                {
                    "ts": self.window_ts,
                    "src_ip": host,
                    "bytes_out": self.host_bytes_out[host],
                    "bytes_in": self.host_bytes_in[host],
                    "pps": host_pps,
                    "tcp_count": self.host_tcp[host],
                    "udp_count": self.host_udp[host],
                    "icmp_count": self.host_icmp[host],
                    "dns_count": self.host_dns[host],
                    "other_count": self.host_other[host],
                    "syn_count": self.host_syn[host],
                    "unique_dst_ports": len(self.host_dst_ports[host]),
                    "unique_dst_ips": len(self.host_dst_ips[host]),
                    "latency_ms": None,
                    "loss_pct": None,
                }
            )

        return rows


class TrafficAggregatorService:
    """Manages periodic window aggregation of packet flows and hourly cleanup."""

    def __init__(self, window_seconds: Optional[float] = None, db_path: Optional[str] = None) -> None:
        self.window_seconds = window_seconds or settings.agg_window_seconds
        self.db_path = db_path
        self.last_processed_id = 0
        self.last_cleanup_time = time.time()
        self.stop_requested = False

        # Parse local LAN subnet for upload/download direction classification
        self.lan_subnet: Optional[ipaddress.IPv4Network] = None
        try:
            resolved_sub = settings.resolved_subnet
            self.lan_subnet = ipaddress.IPv4Network(resolved_sub, strict=False)
            logger.info("Aggregator initialized with LAN subnet: %s", self.lan_subnet)
        except Exception as exc:
            logger.warning("Could not parse LAN subnet (%s): %s", settings.subnet, exc)

    def process_new_flows(self) -> int:
        """Fetch pending packet flows, bucket by aligned window, and upsert traffic_metrics.

        Returns:
            Number of packet flow rows successfully aggregated.
        """
        # Read new flows since last watermark
        # Periodically refresh LAN subnet if network changed
        if not hasattr(self, "_last_subnet_check") or time.time() - self._last_subnet_check >= 15.0:
            self._last_subnet_check = time.time()
            try:
                new_sub = settings.get_network_info(refresh=False).subnet
                if not self.lan_subnet or str(self.lan_subnet) != new_sub:
                    self.lan_subnet = ipaddress.IPv4Network(new_sub, strict=False)
                    logger.info("Aggregator dynamically updated LAN subnet to: %s", self.lan_subnet)
            except Exception:
                pass

        flows = get_unprocessed_packet_flows(
            last_id=self.last_processed_id,
            limit=25000,
            db_path=self.db_path,
        )
        if not flows:
            return 0

        # Bucket packets into discrete aligned windows
        # window_ts = math.floor(ts / window_seconds) * window_seconds
        windows: Dict[float, WindowTrafficAccumulator] = {}

        max_id = self.last_processed_id
        for flow in flows:
            flow_id = flow["id"]
            if flow_id > max_id:
                max_id = flow_id

            flow_ts = float(flow["ts"]) if flow.get("ts") else time.time()
            aligned_ts = math.floor(flow_ts / self.window_seconds) * self.window_seconds

            if aligned_ts not in windows:
                windows[aligned_ts] = WindowTrafficAccumulator(
                    window_ts=aligned_ts,
                    window_seconds=self.window_seconds,
                    lan_subnet=self.lan_subnet,
                )
            windows[aligned_ts].add_packet(flow)

        # Build metric rows for all windows
        metrics_batch: List[Dict[str, Any]] = []
        for accumulator in windows.values():
            metrics_batch.extend(accumulator.build_metric_rows())

        # Upsert into database
        if metrics_batch:
            upsert_traffic_metrics_batch(metrics_batch, db_path=self.db_path)
            logger.debug(
                "Aggregated %d flows across %d windows into %d metrics rows",
                len(flows),
                len(windows),
                len(metrics_batch),
            )

        self.last_processed_id = max_id
        return len(flows)

    def check_retention_cleanup(self) -> None:
        """Execute hourly purge of data exceeding retention threshold."""
        now = time.time()
        # Run cleanup once every hour (3600 seconds)
        if now - self.last_cleanup_time >= 3600.0:
            try:
                deleted_counts = cleanup_old_records(
                    retention_hours=settings.retention_hours,
                    db_path=self.db_path,
                )
                logger.info("Hourly retention cleanup executed: %s", deleted_counts)
            except Exception as exc:
                logger.error("Hourly retention cleanup failed: %s", exc)
            finally:
                self.last_cleanup_time = now

    def run_loop(self, once: bool = False) -> None:
        """Run aggregator worker loop."""
        logger.info("=" * 65)
        logger.info("NetWatch Traffic Aggregator Service Started")
        logger.info("  Window Size : %.1f seconds", self.window_seconds)
        logger.info("  LAN Subnet  : %s", self.lan_subnet)
        logger.info("  Retention   : %.1f hours", settings.retention_hours)
        logger.info("=" * 65)

        # Initialize watermark to current max ID if starting fresh
        if self.last_processed_id == 0:
            self.last_processed_id = 0

        while not self.stop_requested:
            start_t = time.time()
            try:
                processed_count = self.process_new_flows()
                self.check_retention_cleanup()
            except Exception as exc:
                logger.error("Aggregator cycle error: %s", exc, exc_info=True)
                processed_count = 0

            if once or self.stop_requested:
                break

            elapsed = time.time() - start_t
            sleep_time = max(0.5, self.window_seconds - elapsed)

            # Interruptible sleep
            sleep_end = time.time() + sleep_time
            while not self.stop_requested and time.time() < sleep_end:
                time.sleep(0.2)

        logger.info("NetWatch Traffic Aggregator stopped cleanly.")


def main() -> None:
    """CLI entrypoint for NetWatch traffic aggregator."""
    parser = argparse.ArgumentParser(description="NetWatch Traffic Window Aggregator")
    parser.add_argument(
        "--window",
        type=float,
        default=None,
        help="Aggregation window duration in seconds (default: from config 5.0s)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process current pending flows and exit immediately",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    service = TrafficAggregatorService(
        window_seconds=args.window,
        db_path=args.db_path,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d, stopping aggregator...", signum)
        service.stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    service.run_loop(once=args.once)


if __name__ == "__main__":
    main()
