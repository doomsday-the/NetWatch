"""Passive packet sniffer for NetWatch.

Captures live network packets using Scapy (AsyncSniffer, store=False),
parses packet flow metadata (IPs, ports, protocols, flags, frame size),
buffers records into a high-throughput thread-safe queue,
and batch-inserts them into SQLite every 1 second.
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.db import insert_packet_flows_batch

logger = logging.getLogger(__name__)


def parse_packet(packet: Any) -> Optional[Dict[str, Any]]:
    """Extract flow metadata from a captured network packet.

    Handles Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, and DNS.

    Args:
        packet: Scapy Packet instance.

    Returns:
        Dictionary formatted for the packet_flows database table,
        or None if the packet contains no extractable network layer.
    """
    try:
        import scapy.all as scapy  # type: ignore

        # Capture timestamp
        ts = float(packet.time) if hasattr(packet, "time") and packet.time else time.time()
        length = len(packet)

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol: str = "OTHER"
        tcp_flags: str = ""

        # Network layer parsing
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
        elif packet.haslayer(scapy.IPv6):
            src_ip = packet[scapy.IPv6].src
            dst_ip = packet[scapy.IPv6].dst
        elif packet.haslayer(scapy.ARP):
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            protocol = "ARP"

        # Transport & Application layer parsing
        if packet.haslayer(scapy.TCP):
            src_port = int(packet[scapy.TCP].sport)
            dst_port = int(packet[scapy.TCP].dport)
            tcp_flags = str(packet[scapy.TCP].flags)
            if src_port == 53 or dst_port == 53 or packet.haslayer(scapy.DNS):
                protocol = "DNS"
            else:
                protocol = "TCP"
        elif packet.haslayer(scapy.UDP):
            src_port = int(packet[scapy.UDP].sport)
            dst_port = int(packet[scapy.UDP].dport)
            if src_port == 53 or dst_port == 53 or packet.haslayer(scapy.DNS):
                protocol = "DNS"
            else:
                protocol = "UDP"
        elif packet.haslayer(scapy.ICMP) or packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply"):
            protocol = "ICMP"

        if not src_ip and not dst_ip and protocol == "OTHER":
            return None

        return {
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
            "tcp_flags": tcp_flags,
        }
    except Exception as exc:
        logger.debug("Packet parsing failed: %s", exc)
        return None


class PacketSnifferService:
    """Manages asynchronous packet sniffing, thread-safe queuing, and batched DB writes."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        promisc: Optional[bool] = None,
        queue_maxsize: Optional[int] = None,
        flush_interval: Optional[float] = None,
        stats_interval: Optional[float] = None,
    ) -> None:
        self.interface = interface or settings.resolved_interface
        self.bpf_filter = bpf_filter if bpf_filter is not None else settings.bpf_filter
        self.promisc = promisc if promisc is not None else settings.promiscuous_mode
        self.queue_maxsize = queue_maxsize or settings.sniffer_queue_maxsize
        self.flush_interval = flush_interval or settings.flush_interval_seconds
        self.stats_interval = stats_interval or settings.stats_interval_seconds

        self.flow_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=self.queue_maxsize)
        self.stop_event = threading.Event()

        # Telemetry & Drop counters
        self.total_captured = 0
        self.total_dropped = 0
        self.total_inserted = 0
        self._window_captured = 0
        self._last_stats_time = time.time()
        self._last_overflow_log_time = 0.0

        # Background threads
        self.writer_thread: Optional[threading.Thread] = None
        self.stats_thread: Optional[threading.Thread] = None
        self.async_sniffer: Optional[Any] = None

    def _packet_callback(self, packet: Any) -> None:
        """Callback invoked by Scapy for every captured packet."""
        flow_record = parse_packet(packet)
        if not flow_record:
            return

        self.total_captured += 1
        self._window_captured += 1

        try:
            # Non-blocking push; drops packet if queue is saturated
            self.flow_queue.put_nowait(flow_record)
        except queue.Full:
            self.total_dropped += 1
            now = time.time()
            if now - self._last_overflow_log_time >= 5.0:
                self._last_overflow_log_time = now
                logger.warning(
                    "Sniffer flow queue is full (%d items)! Total dropped packets so far: %d",
                    self.queue_maxsize,
                    self.total_dropped,
                )

    def _writer_loop(self) -> None:
        """Background worker that flushes queued packet flows to SQLite in batches."""
        logger.debug("Database flow writer thread started")
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()

        while not self.stop_event.is_set() or not self.flow_queue.empty():
            try:
                # Wait for next item with short timeout
                record = self.flow_queue.get(timeout=0.2)
                batch.append(record)
                self.flow_queue.task_done()
            except queue.Empty:
                pass

            now = time.time()
            # Flush batch if batch size reached or flush interval elapsed
            if batch and (len(batch) >= settings.batch_size or (now - last_flush) >= self.flush_interval):
                try:
                    inserted = insert_packet_flows_batch(batch)
                    self.total_inserted += inserted
                except Exception as exc:
                    logger.error("Failed writing packet flow batch to database: %s", exc)
                finally:
                    batch = []
                    last_flush = now

        # Flush any remaining residual records before shutdown
        if batch:
            try:
                inserted = insert_packet_flows_batch(batch)
                self.total_inserted += inserted
            except Exception as exc:
                logger.error("Final residual batch write failed: %s", exc)

        logger.debug("Database flow writer thread stopped")

    def _stats_loop(self) -> None:
        """Periodic telemetry reporter logging packets/second every 10 seconds."""
        while not self.stop_event.is_set():
            time.sleep(1.0)
            now = time.time()
            elapsed = now - self._last_stats_time
            if elapsed >= self.stats_interval:
                pps = self._window_captured / elapsed if elapsed > 0 else 0.0
                q_size = self.flow_queue.qsize()
                logger.info(
                    "Sniffer throughput: %.1f pps | Captured: %d | Stored: %d | Dropped: %d | Queue: %d/%d",
                    pps,
                    self.total_captured,
                    self.total_inserted,
                    self.total_dropped,
                    q_size,
                    self.queue_maxsize,
                )
                self._window_captured = 0
                self._last_stats_time = now

    def start(self) -> None:
        """Initialize and launch packet capture and worker threads."""
        logger.info("=" * 65)
        logger.info("NetWatch Passive Packet Sniffer Starting")
        logger.info("  Interface   : %s", self.interface)
        logger.info("  BPF Filter  : %s", self.bpf_filter or "(none)")
        logger.info("  Promiscuous : %s", self.promisc)
        logger.info("  Batch Flush : %.1fs", self.flush_interval)
        logger.info("  Queue Limit : %d", self.queue_maxsize)
        logger.info("=" * 65)

        # Start writer thread
        self.writer_thread = threading.Thread(target=self._writer_loop, name="NetWatch-DBWriter", daemon=True)
        self.writer_thread.start()

        # Start stats thread
        self.stats_thread = threading.Thread(target=self._stats_loop, name="NetWatch-Stats", daemon=True)
        self.stats_thread.start()

        # Launch Scapy AsyncSniffer
        try:
            import scapy.all as scapy  # type: ignore

            sniffer_kwargs: Dict[str, Any] = {
                "iface": self.interface,
                "prn": self._packet_callback,
                "store": False,
                "promisc": self.promisc,
            }
            if self.bpf_filter:
                sniffer_kwargs["filter"] = self.bpf_filter

            self.async_sniffer = scapy.AsyncSniffer(**sniffer_kwargs)
            self.async_sniffer.start()
            logger.info("Passive packet sniffing actively capturing on '%s'...", self.interface)

        except (PermissionError, OSError) as exc:
            err_str = str(exc).lower()
            if "operation not permitted" in err_str or "permission denied" in err_str or isinstance(exc, PermissionError):
                logger.warning(
                    "Raw packet capture requires superuser/root permissions. "
                    "Automatically falling back to simulated traffic generation."
                )
                sim_thread = threading.Thread(target=run_simulated_capture, args=(self,), daemon=True)
                sim_thread.start()
            else:
                logger.error("OS Network Sniffer Initialization Error: %s", exc)
                self.stop()
                raise

        except RuntimeError as exc:
            err_str = str(exc).lower()
            if "winpcap" in err_str or "libpcap" in err_str:
                logger.warning(
                    "Raw packet capture driver (Npcap/libpcap) not found on this system. "
                    "Automatically falling back to simulated traffic generation so NetWatch can run seamlessly."
                )
                sim_thread = threading.Thread(target=run_simulated_capture, args=(self,), daemon=True)
                sim_thread.start()
            else:
                logger.error("Runtime error initializing sniffer: %s", exc)
                self.stop()
                raise

    def stop(self) -> None:
        """Gracefully terminate sniffer and flush queues."""
        logger.info("Stopping NetWatch sniffer service...")
        self.stop_event.set()

        if self.async_sniffer and hasattr(self.async_sniffer, "running") and self.async_sniffer.running:
            try:
                self.async_sniffer.stop()
            except Exception as exc:
                logger.debug("Error while stopping AsyncSniffer: %s", exc)

        if self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join(timeout=3.0)

        logger.info(
            "Sniffer shutdown complete. Total Captured: %d | Stored: %d | Dropped: %d",
            self.total_captured,
            self.total_inserted,
            self.total_dropped,
        )


def run_simulated_capture(service: PacketSnifferService) -> None:
    """Generate synthetic network packets for testing in development environments."""
    import random
    import scapy.all as scapy  # type: ignore

    logger.info("Starting simulated traffic generation for testing sniffer pipeline...")
    sample_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.55", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
    sample_ports = [80, 443, 53, 22, 8080, 3306, 5432]
    flags_list = ["S", "SA", "PA", "FA", "R", "A"]

    while not service.stop_event.is_set():
        src = random.choice(sample_ips)
        dst = random.choice(sample_ips)
        if src == dst:
            dst = "8.8.4.4"

        proto_choice = random.random()
        if proto_choice < 0.65:
            # TCP
            pkt = scapy.IP(src=src, dst=dst) / scapy.TCP(
                sport=random.randint(1024, 65535),
                dport=random.choice(sample_ports),
                flags=random.choice(flags_list),
            )
        elif proto_choice < 0.85:
            # UDP / DNS
            dport = 53 if random.random() < 0.4 else random.choice(sample_ports)
            pkt = scapy.IP(src=src, dst=dst) / scapy.UDP(sport=random.randint(1024, 65535), dport=dport)
        elif proto_choice < 0.95:
            # ICMP
            pkt = scapy.IP(src=src, dst=dst) / scapy.ICMP()
        else:
            # ARP
            pkt = scapy.ARP(psrc=src, pdst=dst)

        service._packet_callback(pkt)
        time.sleep(random.uniform(0.01, 0.08))


def main() -> None:
    """CLI entrypoint for NetWatch packet sniffer."""
    parser = argparse.ArgumentParser(description="NetWatch Passive Network Packet Sniffer")
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to sniff on (default: auto-detected)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Berkeley Packet Filter (BPF) string (e.g. 'ip or ip6')",
    )
    parser.add_argument(
        "--promisc",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable promiscuous mode (default: True)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run with synthetic packet traffic generator (for testing without raw socket permissions)",
    )

    args = parser.parse_args()

    service = PacketSnifferService(
        interface=args.iface,
        bpf_filter=args.filter,
        promisc=args.promisc,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d, shutting down sniffer...", signum)
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    if args.simulate:
        # Start DB writer and stats
        service.writer_thread = threading.Thread(target=service._writer_loop, name="NetWatch-DBWriter", daemon=True)
        service.writer_thread.start()
        service.stats_thread = threading.Thread(target=service._stats_loop, name="NetWatch-Stats", daemon=True)
        service.stats_thread.start()

        sim_thread = threading.Thread(target=run_simulated_capture, args=(service,), daemon=True)
        sim_thread.start()
        logger.info("Simulated sniffer running. Press Ctrl+C to terminate.")

        try:
            while not service.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            service.stop()
        return

    try:
        service.start()
        while not service.stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Interrupted by user (Ctrl+C)")
    except Exception:
        sys.exit(1)
    finally:
        service.stop()


if __name__ == "__main__":
    main()
