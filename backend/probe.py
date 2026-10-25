"""Active network latency and packet loss probe for NetWatch.

Periodically pings the default gateway without requiring root privileges (system ping),
maintains a rolling 20-probe statistics window (average latency and loss percentage),
and records metrics into the aligned network-wide traffic_metrics table row.
"""

from __future__ import annotations

import argparse
import collections
import logging
import math
import platform
import re
import signal
import subprocess
import sys
import time
from typing import Any, Deque, Dict, Optional, Tuple

from backend.config import settings
from backend.db import update_probe_metrics

logger = logging.getLogger(__name__)


def ping_host_system(host: str, timeout_seconds: float = 1.5) -> Optional[float]:
    """Ping a host using standard OS system utilities without requiring root permissions.

    Works portably across Linux (Ubuntu) and Windows.

    Args:
        host: IP address or hostname to ping.
        timeout_seconds: Response timeout in seconds.

    Returns:
        Round-trip latency in milliseconds, or None if timed out / unreachable.
    """
    is_windows = platform.system().lower() == "windows"

    if is_windows:
        timeout_ms = int(timeout_seconds * 1000)
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        timeout_int = max(1, int(math.ceil(timeout_seconds)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_int), host]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds + 1.0,
        )
        if proc.returncode != 0:
            return None

        output = proc.stdout
        # Match "time=4.2 ms" or "time=4ms" or "time<1ms"
        match = re.search(r"time[=<]\s*([\d\.]+)\s*ms", output, re.IGNORECASE)
        if match:
            return float(match.group(1))
        elif "time<1ms" in output.lower().replace(" ", ""):
            return 0.5

        return None
    except (subprocess.TimeoutExpired, OSError, Exception) as exc:
        logger.debug("System ping to %s failed: %s", host, exc)
        return None


def ping_host_scapy(host: str, timeout_seconds: float = 1.5) -> Optional[float]:
    """Ping host using Scapy ICMP Echo Request (requires raw socket permissions).

    Args:
        host: Target IP address.
        timeout_seconds: Response timeout.

    Returns:
        Round-trip latency in milliseconds, or None.
    """
    try:
        import scapy.all as scapy  # type: ignore

        pkt = scapy.IP(dst=host) / scapy.ICMP()
        start = time.time()
        reply = scapy.sr1(pkt, timeout=timeout_seconds, verbose=0)
        elapsed_ms = (time.time() - start) * 1000.0

        if reply and reply.haslayer(scapy.ICMP):
            icmp_type = reply[scapy.ICMP].type
            if icmp_type == 0:  # Echo Reply
                return round(elapsed_ms, 2)
        return None
    except Exception as exc:
        logger.debug("Scapy ping to %s failed: %s", host, exc)
        return None


class GatewayProbeService:
    """Active probing service maintaining rolling window metrics."""

    def __init__(
        self,
        target_ip: Optional[str] = None,
        interval_seconds: Optional[float] = None,
        window_size: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        use_scapy: bool = False,
        db_path: Optional[str] = None,
    ) -> None:
        self.target_ip = target_ip or settings.resolved_gateway
        self.interval = interval_seconds or settings.probe_interval_seconds
        self.window_size = window_size or settings.probe_window_size
        self.timeout = timeout_seconds or settings.probe_timeout_seconds
        self.use_scapy = use_scapy
        self.db_path = db_path
        self.stop_requested = False

        # Rolling probe outcome history: deque of (latency_ms, is_success)
        self.history: Deque[Tuple[Optional[float], bool]] = collections.deque(maxlen=self.window_size)

        # Fallback if no gateway detected
        if not self.target_ip or self.target_ip in ("0.0.0.0", "127.0.0.1", ""):
            local_ip = settings.resolved_ip
            self.target_ip = local_ip if local_ip != "127.0.0.1" else "8.8.8.8"
            logger.warning(
                "No default gateway found in routing table; falling back to target: %s",
                self.target_ip,
            )

    def probe_once(self) -> Tuple[Optional[float], float]:
        """Perform a single ping probe and update rolling history.

        Returns:
            (avg_latency_ms, loss_pct) computed over the rolling window.
        """
        # Execute ping probe
        if self.use_scapy:
            rtt = ping_host_scapy(self.target_ip, timeout_seconds=self.timeout)
            if rtt is None:
                rtt = ping_host_system(self.target_ip, timeout_seconds=self.timeout)
        else:
            rtt = ping_host_system(self.target_ip, timeout_seconds=self.timeout)

        # Record outcome
        success = rtt is not None
        self.history.append((rtt, success))

        # Track consecutive failures and adapt dynamically
        if not success:
            self._consecutive_fails = getattr(self, "_consecutive_fails", 0) + 1
        else:
            self._consecutive_fails = 0

        # After consecutive timeouts or every 10 probes, check if network/gateway changed
        probe_count = getattr(self, "_probe_count", 0) + 1
        self._probe_count = probe_count

        if self._consecutive_fails >= 3 or (probe_count % 10 == 0):
            try:
                current_gw = settings.get_network_info(refresh=True).gateway
                if current_gw and current_gw != self.target_ip:
                    logger.warning("Gateway change detected: %s -> %s", self.target_ip, current_gw)
                    self.target_ip = current_gw
                    self.history.clear()
                    self._consecutive_fails = 0
                elif self._consecutive_fails >= 5 and self.target_ip != "1.1.1.1":
                    # Gateway may block ICMP ping (common on mobile hotspots); test Internet fallback
                    fallback_rtt = ping_host_system("1.1.1.1", timeout_seconds=1.0)
                    if fallback_rtt is not None:
                        logger.warning("Gateway %s drops ICMP; switching latency probe to 1.1.1.1", self.target_ip)
                        self.target_ip = "1.1.1.1"
                        self.history.clear()
                        self._consecutive_fails = 0
            except Exception as e:
                logger.debug("Gateway re-detection error: %s", e)

        # Calculate rolling statistics
        total = len(self.history)
        failed = sum(1 for _, ok in self.history if not ok)
        loss_pct = round((failed / total) * 100.0, 1)

        valid_latencies = [lat for lat, ok in self.history if ok and lat is not None]
        avg_latency = round(sum(valid_latencies) / len(valid_latencies), 2) if valid_latencies else None

        return avg_latency, loss_pct

    def record_metrics_for_window(self, avg_latency: Optional[float], loss_pct: float) -> float:
        """Write rolling probe metrics into the aligned network-wide traffic_metrics row.

        Args:
            avg_latency: Average round-trip time in milliseconds.
            loss_pct: Packet loss percentage.

        Returns:
            The aligned window timestamp.
        """
        # Aligned window boundary matching aggregator:
        # window_ts = math.floor(ts / agg_window_seconds) * agg_window_seconds
        w_sec = settings.agg_window_seconds
        window_ts = math.floor(time.time() / w_sec) * w_sec

        update_probe_metrics(
            window_ts=window_ts,
            latency_ms=avg_latency,
            loss_pct=loss_pct,
            db_path=self.db_path,
        )
        return window_ts

    def run_loop(self, once: bool = False) -> None:
        """Run active gateway probe loop."""
        logger.info("=" * 65)
        logger.info("NetWatch Gateway Latency & Loss Probe Started")
        logger.info("  Target Host : %s", self.target_ip)
        logger.info("  Interval    : %.1f seconds", self.interval)
        logger.info("  Window Size : %d probes", self.window_size)
        logger.info("  Method      : %s", "Scapy ICMP" if self.use_scapy else "System Ping (non-root)")
        logger.info("=" * 65)

        while not self.stop_requested:
            start_t = time.time()
            try:
                avg_latency, loss_pct = self.probe_once()
                window_ts = self.record_metrics_for_window(avg_latency, loss_pct)

                status_str = f"{avg_latency:.2f} ms" if avg_latency is not None else "TIMEOUT"
                logger.info(
                    "Gateway probe to %s: %s | Rolling Loss: %.1f%% (Window: %d/%d, ts: %.0f)",
                    self.target_ip,
                    status_str,
                    loss_pct,
                    len(self.history),
                    self.window_size,
                    window_ts,
                )
            except Exception as exc:
                logger.error("Error during probe execution: %s", exc, exc_info=True)

            if once or self.stop_requested:
                break

            elapsed = time.time() - start_t
            sleep_time = max(0.5, self.interval - elapsed)

            # Interruptible sleep
            sleep_end = time.time() + sleep_time
            while not self.stop_requested and time.time() < sleep_end:
                time.sleep(0.2)

        logger.info("NetWatch Gateway Probe stopped cleanly.")


def main() -> None:
    """CLI entrypoint for NetWatch gateway probe."""
    parser = argparse.ArgumentParser(description="NetWatch Gateway Latency & Loss Probe")
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Target IP/host to ping (default: auto-detected default gateway)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Probe interval in seconds (default: 5.0s)",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=None,
        help="Rolling statistics window size in probes (default: 20)",
    )
    parser.add_argument(
        "--use-scapy",
        action="store_true",
        help="Use Scapy ICMP packets instead of system ping (requires root)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Perform single probe, record to database, and exit",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    service = GatewayProbeService(
        target_ip=args.target,
        interval_seconds=args.interval,
        window_size=args.window_size,
        use_scapy=args.use_scapy,
        db_path=args.db_path,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d, stopping probe service...", signum)
        service.stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    service.run_loop(once=args.once)


if __name__ == "__main__":
    main()
