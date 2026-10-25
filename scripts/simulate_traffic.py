"""Realistic network traffic simulator for NetWatch.

Generates and inserts realistic synthetic network telemetry directly into SQLite:
- Simulates normal LAN and WAN traffic across multiple devices.
- Injects targeted network attack anomalies (portscan, synflood, icmpflood, bandwidth).
- Creates realistic device inventory profiles with hardware vendors.
- Generates aligned traffic_metrics, packet_flows, and health_history entries.
Allows testing ML models, REST APIs, and UI dashboards without requiring VMs or root permissions.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import math
import os
from pathlib import Path
import random
import sys
import time

# Ensure repository root is on sys.path
REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from typing import Any, Dict, List, Optional, Set

from backend.aggregator import WindowTrafficAccumulator
from backend.config import settings
from backend.db import (
    get_connection,
    init_db,
    insert_health_score,
    insert_packet_flows_batch,
    upsert_device_inventory_batch,
    upsert_traffic_metrics_batch,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simulated Device Profiles
# ---------------------------------------------------------------------------

DEFAULT_SIM_DEVICES = [
    {
        "mac": "c8:cb:b8:d4:5e:c5",
        "ip": "172.17.48.1",
        "vendor": "Nokia / Alcatel-Lucent",
        "hostname": "gateway.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "a4:42:3b:5e:c8:9c",
        "ip": "172.17.48.6",
        "vendor": "Intel Corporation",
        "hostname": "workstation-arush.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "3c:22:fb:11:22:33",
        "ip": "172.17.48.15",
        "vendor": "Apple",
        "hostname": "macbook-pro.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "30:a7:71:63:db:18",
        "ip": "172.17.48.22",
        "vendor": "Samsung Electronics",
        "hostname": "galaxy-s24.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "b8:27:eb:11:22:33",
        "ip": "172.17.48.50",
        "vendor": "Raspberry Pi Foundation",
        "hostname": "nas-server.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "00:08:02:44:55:66",
        "ip": "172.17.48.75",
        "vendor": "Hewlett Packard",
        "hostname": "office-printer.local",
        "status": "online",
        "is_known": 1,
    },
    {
        "mac": "94:bb:43:7c:79:01",
        "ip": "172.17.48.88",
        "vendor": "Sony Interactive Entertainment",
        "hostname": "playstation-5.local",
        "status": "online",
        "is_known": 1,
    },
]

EXTERNAL_HOSTS = [
    "8.8.8.8",        # Google DNS
    "1.1.1.1",        # Cloudflare DNS
    "142.250.190.46", # Google Web
    "151.101.1.69",   # CDN (Fastly)
    "104.244.42.1",   # Social (X / Twitter)
    "20.112.52.29",   # Microsoft Azure
]


def populate_simulated_devices(db_path: Optional[str] = None) -> None:
    """Insert simulated hardware inventory profiles into device_inventory."""
    now = time.time()
    devices = []
    for d in DEFAULT_SIM_DEVICES:
        dev = dict(d)
        dev["first_seen"] = now - 86400.0  # 1 day ago
        dev["last_seen"] = now
        devices.append(dev)

    upsert_device_inventory_batch(devices, db_path=db_path)
    logger.info("Populated %d realistic device profiles in inventory", len(devices))


# ---------------------------------------------------------------------------
# Traffic Generation Patterns
# ---------------------------------------------------------------------------

def generate_normal_window_packets(
    window_start: float,
    window_end: float,
    lan_ips: List[str],
) -> List[Dict[str, Any]]:
    """Generate typical normal enterprise/home LAN traffic for a 5-second window."""
    packets: List[Dict[str, Any]] = []
    num_packets = random.randint(25, 65)

    for _ in range(num_packets):
        t = random.uniform(window_start, window_end)
        src_lan = random.choice(lan_ips)
        ext_target = random.choice(EXTERNAL_HOSTS)

        rand_proto = random.random()
        if rand_proto < 0.65:
            # HTTPS / HTTP browsing
            sport = random.randint(49152, 65535)
            dport = 443 if random.random() < 0.85 else 80
            length = random.choice([64, 128, 512, 1024, 1460, 1500])

            # Outbound request
            packets.append(
                {
                    "ts": t,
                    "src_ip": src_lan,
                    "dst_ip": ext_target,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": "TCP",
                    "length": length,
                    "tcp_flags": "PA" if random.random() < 0.8 else "S",
                }
            )
            # Inbound response
            if random.random() < 0.9:
                packets.append(
                    {
                        "ts": t + random.uniform(0.005, 0.04),
                        "src_ip": ext_target,
                        "dst_ip": src_lan,
                        "src_port": dport,
                        "dst_port": sport,
                        "protocol": "TCP",
                        "length": random.choice([512, 1460, 1500]),
                        "tcp_flags": "A" if random.random() < 0.8 else "SA",
                    }
                )

        elif rand_proto < 0.85:
            # DNS Resolution
            dns_server = random.choice(["8.8.8.8", "1.1.1.1"])
            sport = random.randint(49152, 65535)
            packets.append(
                {
                    "ts": t,
                    "src_ip": src_lan,
                    "dst_ip": dns_server,
                    "src_port": sport,
                    "dst_port": 53,
                    "protocol": "DNS",
                    "length": random.randint(68, 140),
                    "tcp_flags": "",
                }
            )
            packets.append(
                {
                    "ts": t + random.uniform(0.008, 0.03),
                    "src_ip": dns_server,
                    "dst_ip": src_lan,
                    "src_port": 53,
                    "dst_port": sport,
                    "protocol": "DNS",
                    "length": random.randint(90, 280),
                    "tcp_flags": "",
                }
            )

        elif rand_proto < 0.95:
            # Local LAN file sharing / internal RPC
            other_lan = random.choice([ip for ip in lan_ips if ip != src_lan])
            sport = random.randint(49152, 65535)
            dport = random.choice([445, 8080, 22, 5353])
            packets.append(
                {
                    "ts": t,
                    "src_ip": src_lan,
                    "dst_ip": other_lan,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": "TCP",
                    "length": random.randint(120, 1460),
                    "tcp_flags": "PA",
                }
            )

        else:
            # Gateway ping / ICMP health check
            gw_ip = "172.17.48.1"
            packets.append(
                {
                    "ts": t,
                    "src_ip": src_lan,
                    "dst_ip": gw_ip,
                    "src_port": None,
                    "dst_port": None,
                    "protocol": "ICMP",
                    "length": 64,
                    "tcp_flags": "",
                }
            )

    return packets


def generate_attack_packets(
    attack_type: str,
    window_start: float,
    window_end: float,
    lan_ips: List[str],
) -> List[Dict[str, Any]]:
    """Inject specific anomaly attack signatures into a time window."""
    packets: List[Dict[str, Any]] = []

    if attack_type == "portscan":
        # Port scan anomaly: single host scans hundreds of distinct destination ports
        attacker_ip = "172.17.48.199"
        target_ip = "172.17.48.50"  # Target NAS server
        scan_ports = list(range(20, 180)) + [443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

        for p in scan_ports:
            t = random.uniform(window_start, window_end)
            packets.append(
                {
                    "ts": t,
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(30000, 60000),
                    "dst_port": p,
                    "protocol": "TCP",
                    "length": random.choice([44, 54, 60]),
                    "tcp_flags": "S",  # SYN scan
                }
            )
            # Target replies RST / Closed
            if random.random() < 0.7:
                packets.append(
                    {
                        "ts": t + 0.002,
                        "src_ip": target_ip,
                        "dst_ip": attacker_ip,
                        "src_port": p,
                        "dst_port": random.randint(30000, 60000),
                        "protocol": "TCP",
                        "length": 40,
                        "tcp_flags": "RA",  # RST+ACK
                    }
                )

    elif attack_type == "synflood":
        # SYN flood DoS: massive volume of unacknowledged SYN packets
        attacker_ip = "172.17.48.210"
        target_ip = "172.17.48.6"  # Workstation web server
        target_port = 443

        for _ in range(450):
            t = random.uniform(window_start, window_end)
            packets.append(
                {
                    "ts": t,
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": target_port,
                    "protocol": "TCP",
                    "length": 54,
                    "tcp_flags": "S",  # Pure SYN without ACK
                }
            )

    elif attack_type == "icmpflood":
        # Ping flood / Smurf attack
        attacker_ip = "172.17.48.220"
        target_ip = "172.17.48.1"  # Flood gateway

        for _ in range(500):
            t = random.uniform(window_start, window_end)
            packets.append(
                {
                    "ts": t,
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": None,
                    "dst_port": None,
                    "protocol": "ICMP",
                    "length": 128,
                    "tcp_flags": "",
                }
            )

    elif attack_type == "bandwidth":
        # Volumetric bandwidth surge / exfiltration / high bit-rate stream
        source_ip = "172.17.48.15"  # MacBook
        dest_ip = "142.250.190.46"

        for _ in range(600):
            t = random.uniform(window_start, window_end)
            packets.append(
                {
                    "ts": t,
                    "src_ip": source_ip,
                    "dst_ip": dest_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "length": 1500,  # Max MTU payload
                    "tcp_flags": "PA",
                }
            )

    return packets


# ---------------------------------------------------------------------------
# Simulator Orchestration
# ---------------------------------------------------------------------------

def simulate_traffic(
    minutes: float = 15.0,
    attacks: Optional[List[str]] = None,
    clear_existing: bool = False,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate and write synthetic network traffic into SQLite.

    Args:
        minutes: Total time history to generate ending at current timestamp.
        attacks: List of attack types to inject ('portscan', 'synflood', 'icmpflood', 'bandwidth').
        clear_existing: If True, purges existing packet flows and metrics before generating.
        db_path: Optional SQLite database file path.

    Returns:
        Summary dict containing flow counts, window counts, and injected attacks.
    """
    init_db(db_path)
    if clear_existing:
        conn = get_connection(db_path)
        try:
            conn.execute("DELETE FROM packet_flows")
            conn.execute("DELETE FROM traffic_metrics")
            conn.execute("DELETE FROM health_history")
            conn.execute("DELETE FROM ai_alerts")
            logger.info("Cleared existing database tables")
        finally:
            conn.close()

    populate_simulated_devices(db_path)

    w_sec = settings.agg_window_seconds
    now = time.time()
    total_seconds = minutes * 60.0
    start_time = math.floor((now - total_seconds) / w_sec) * w_sec
    end_time = math.floor(now / w_sec) * w_sec

    num_windows = int((end_time - start_time) / w_sec)
    lan_ips = [d["ip"] for d in DEFAULT_SIM_DEVICES]
    lan_subnet = ipaddress.IPv4Network("172.17.48.0/21")

    # Select attack placement (in the latter half of the simulation timeline)
    attack_schedule: Dict[int, str] = {}
    if attacks:
        valid_attacks = [a.lower().strip() for a in attacks if a.lower().strip() in ("portscan", "synflood", "icmpflood", "bandwidth")]
        if valid_attacks and num_windows > 4:
            # Place attacks in middle to late windows
            attack_start_idx = max(2, int(num_windows * 0.6))
            for i, atk in enumerate(valid_attacks):
                target_idx = attack_start_idx + (i * 3)
                if target_idx < num_windows:
                    attack_schedule[target_idx] = atk

    total_flows_created = 0
    total_metrics_created = 0

    logger.info("=" * 65)
    logger.info("Simulating %.1f minutes of network traffic (%d windows)...", minutes, num_windows)
    if attack_schedule:
        logger.info("Scheduled attack injections: %s", {f"window_{k}": v for k, v in attack_schedule.items()})
    logger.info("=" * 65)

    all_packet_batches: List[Dict[str, Any]] = []
    all_metric_rows: List[Dict[str, Any]] = []

    for w_idx in range(num_windows):
        w_start = start_time + (w_idx * w_sec)
        w_end = w_start + w_sec

        # 1. Normal background traffic
        window_pkts = generate_normal_window_packets(w_start, w_end, lan_ips)

        # 2. Check for attack injection in this window
        attack = attack_schedule.get(w_idx)
        if attack:
            attack_pkts = generate_attack_packets(attack, w_start, w_end, lan_ips)
            window_pkts.extend(attack_pkts)
            logger.info("Injected '%s' attack in window %d (ts=%.0f, %d attack packets)", attack, w_idx, w_start, len(attack_pkts))

        # Sort packets chronologically
        window_pkts.sort(key=lambda p: p["ts"])
        all_packet_batches.extend(window_pkts)
        total_flows_created += len(window_pkts)

        # 3. Accumulate and build metrics for this window
        acc = WindowTrafficAccumulator(window_ts=w_start, window_seconds=w_sec, lan_subnet=lan_subnet)
        for pkt in window_pkts:
            acc.add_packet(pkt)

        metric_rows = acc.build_metric_rows()

        # Set realistic latency and packet loss on the network-wide row
        for r in metric_rows:
            if r["src_ip"] is None:
                if attack == "icmpflood":
                    r["latency_ms"] = round(random.uniform(95.0, 160.0), 2)
                    r["loss_pct"] = round(random.uniform(25.0, 45.0), 1)
                    health_score = random.uniform(35.0, 50.0)
                elif attack in ("synflood", "bandwidth"):
                    r["latency_ms"] = round(random.uniform(25.0, 65.0), 2)
                    r["loss_pct"] = round(random.uniform(5.0, 15.0), 1)
                    health_score = random.uniform(55.0, 70.0)
                else:
                    r["latency_ms"] = round(random.uniform(3.5, 9.5), 2)
                    r["loss_pct"] = 0.0
                    health_score = random.uniform(94.0, 99.5)

                # Record health score history point
                insert_health_score(health_score, ts=w_start, db_path=db_path)

        all_metric_rows.extend(metric_rows)
        total_metrics_created += len(metric_rows)

        # Flush in batches of 1000 to keep memory low
        if len(all_packet_batches) >= 2000:
            insert_packet_flows_batch(all_packet_batches, db_path=db_path)
            all_packet_batches = []

        if len(all_metric_rows) >= 500:
            upsert_traffic_metrics_batch(all_metric_rows, db_path=db_path)
            all_metric_rows = []

    # Final residual flush
    if all_packet_batches:
        insert_packet_flows_batch(all_packet_batches, db_path=db_path)
    if all_metric_rows:
        upsert_traffic_metrics_batch(all_metric_rows, db_path=db_path)

    summary = {
        "minutes": minutes,
        "windows_generated": num_windows,
        "packets_inserted": total_flows_created,
        "metric_rows_upserted": total_metrics_created,
        "attacks_injected": list(attack_schedule.values()),
        "time_range": (start_time, end_time),
    }

    logger.info("=" * 65)
    logger.info("Traffic Simulation Complete!")
    logger.info("  Total Packet Flows  : %d", total_flows_created)
    logger.info("  Traffic Metric Rows : %d", total_metrics_created)
    logger.info("  Attacks Injected    : %s", summary["attacks_injected"] or "None (Normal baseline)")
    logger.info("  Time Span           : %.0f -> %.0f", start_time, end_time)
    logger.info("=" * 65)

    return summary


def main() -> None:
    """CLI entrypoint for traffic simulation script."""
    parser = argparse.ArgumentParser(description="NetWatch Network Traffic Simulator")
    parser.add_argument(
        "--minutes",
        type=float,
        default=15.0,
        help="Minutes of traffic history to generate (default: 15.0)",
    )
    parser.add_argument(
        "--attack",
        nargs="+",
        choices=["portscan", "synflood", "icmpflood", "bandwidth"],
        default=None,
        help="One or more attacks to inject (portscan, synflood, icmpflood, bandwidth)",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Purge existing packet flows, traffic metrics, and alerts before simulating",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    simulate_traffic(
        minutes=args.minutes,
        attacks=args.attack,
        clear_existing=args.clear,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
