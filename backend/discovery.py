"""Network discovery and interface auto-detection for NetWatch.

Provides:
- Interface, IP, subnet, and gateway auto-detection.
- Background ARP sweep process using Scapy (broadcast srp) running every 30s.
- Device inventory upsert with MAC, IP, OUI vendor lookup, reverse DNS, and online/offline tracking.
- Automatic unknown device detection and AI alert generation.
- Initial baseline creation marking first-run devices as known.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from backend.config import settings
from backend.db import (
    get_device_mac_map,
    insert_ai_alerts_batch,
    mark_devices_offline,
    upsert_device_inventory_batch,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network Detection Data Structures & Helpers
# ---------------------------------------------------------------------------

@dataclass
class NetworkInfo:
    """Network details discovered for an interface."""

    interface: str
    ip: str
    netmask: str
    subnet: str
    gateway: Optional[str] = None
    mac: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert network info to a dictionary."""
        return {
            "interface": self.interface,
            "ip": self.ip,
            "netmask": self.netmask,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "mac": self.mac,
        }


def _get_egress_ip() -> Optional[str]:
    """Determine the local IP used for external traffic via a UDP socket test.

    Does not transmit any actual packets over the wire.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception as exc:
        logger.debug("Socket route probe failed: %s", exc)
        return None
    finally:
        s.close()


def _get_linux_default_route() -> Tuple[Optional[str], Optional[str]]:
    """Parse /proc/net/route on Linux systems to find default interface and gateway."""
    route_file = "/proc/net/route"
    if not os.path.exists(route_file):
        return None, None

    try:
        with open(route_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 3:
                iface, dest, gateway_hex = parts[0], parts[1], parts[2]
                if dest == "00000000":  # Default destination
                    gateway_ip = socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))
                    return iface, gateway_ip
    except Exception as exc:
        logger.debug("Failed parsing /proc/net/route: %s", exc)

    return None, None


def _get_scapy_route() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract route via Scapy routing table.

    Returns:
        (interface, local_ip, gateway_ip) or (None, None, None)
    """
    try:
        import scapy.all as scapy  # type: ignore

        route = scapy.conf.route.route("8.8.8.8")
        if route and len(route) >= 3:
            return str(route[0]), str(route[1]), str(route[2])
    except Exception as exc:
        logger.debug("Scapy route lookup failed: %s", exc)

    return None, None, None


def get_default_interface_name() -> str:
    """Auto-detect the name of the active default network interface.

    Returns:
        Interface name (e.g. 'eth0', 'enp3s0', 'Wi-Fi') or 'lo' as fallback.
    """
    # 1. Try Linux /proc/net/route
    linux_iface, _ = _get_linux_default_route()
    if linux_iface:
        return linux_iface

    # 2. Try socket probe + psutil match
    egress_ip = _get_egress_ip()
    if egress_ip:
        for if_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == egress_ip:
                    return if_name

    # 3. Try Scapy route
    scapy_iface, scapy_ip, _ = _get_scapy_route()
    if scapy_iface:
        if scapy_iface in psutil.net_if_addrs():
            return scapy_iface
        if scapy_ip:
            for if_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == scapy_ip:
                        return if_name

    # 4. Fallback: First active up interface with an IPv4 address
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for if_name, stat in stats.items():
        if stat.isup and if_name in addrs:
            for addr in addrs[if_name]:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return if_name

    return "lo"


def detect_network_info(
    interface_name: Optional[str] = None,
    subnet_override: Optional[str] = None,
    gateway_override: Optional[str] = None,
) -> NetworkInfo:
    """Detect complete network details for an interface.

    Args:
        interface_name: Target interface or None/'auto' to auto-detect.
        subnet_override: Optional manual subnet CIDR override.
        gateway_override: Optional manual gateway IP override.

    Returns:
        NetworkInfo object containing interface, ip, netmask, subnet, gateway, mac.
    """
    if not interface_name or interface_name.lower() == "auto":
        target_iface = get_default_interface_name()
    else:
        target_iface = interface_name

    all_addrs = psutil.net_if_addrs()
    target_addrs = all_addrs.get(target_iface)

    resolved_iface = target_iface
    if not target_addrs:
        egress_ip = _get_egress_ip()
        for if_name, addrs in all_addrs.items():
            if any(a.family == socket.AF_INET and a.address == egress_ip for a in addrs):
                resolved_iface = if_name
                target_addrs = addrs
                break

    ip: str = "127.0.0.1"
    netmask: str = "255.0.0.0"
    mac: Optional[str] = None

    if target_addrs:
        for addr in target_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if addr.netmask:
                    netmask = addr.netmask
            elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                mac = addr.address
            elif addr.family.name in ("AF_LINK", "AF_PACKET"):
                mac = addr.address

    # Calculate CIDR subnet
    if subnet_override and subnet_override.lower() != "auto":
        subnet = subnet_override
    else:
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            subnet = str(network)
        except Exception as exc:
            logger.warning("Failed calculating subnet for %s/%s: %s", ip, netmask, exc)
            subnet = f"{ip}/24"

    # Detect Gateway
    gateway: Optional[str] = None
    if gateway_override and gateway_override.lower() != "auto":
        gateway = gateway_override
    else:
        _, linux_gw = _get_linux_default_route()
        if linux_gw:
            gateway = linux_gw
        else:
            _, _, scapy_gw = _get_scapy_route()
            if scapy_gw and scapy_gw != "0.0.0.0":
                gateway = scapy_gw

    info = NetworkInfo(
        interface=resolved_iface,
        ip=ip,
        netmask=netmask,
        subnet=subnet,
        gateway=gateway,
        mac=normalize_mac(mac) if mac else None,
    )
    logger.debug("Detected network parameters: %s", info.to_dict())
    return info


# ---------------------------------------------------------------------------
# MAC & OUI Vendor Utilities
# ---------------------------------------------------------------------------

_OUI_CACHE: Optional[Dict[str, str]] = None


def normalize_mac(mac: Optional[str]) -> str:
    """Normalize MAC address to standard lowercase colon-delimited format.

    Args:
        mac: Raw MAC address string.

    Returns:
        Formatted MAC string (e.g. '00:11:22:33:44:55') or empty string if invalid.
    """
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    if len(cleaned) != 12:
        return mac.lower().replace("-", ":")
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def load_oui_table(csv_path: Optional[str] = None) -> Dict[str, str]:
    """Load local MAC OUI prefix table from CSV file.

    Args:
        csv_path: Path to the oui.csv file; defaults to settings.oui_file_path.

    Returns:
        Dictionary mapping 6-hex uppercase prefix to vendor name.
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None and not csv_path:
        return _OUI_CACHE

    target_path = Path(csv_path or settings.oui_file_path).resolve()
    table: Dict[str, str] = {}

    if not target_path.exists():
        logger.warning("OUI database file not found at %s. Vendor lookup will return 'Unknown'.", target_path)
        _OUI_CACHE = table
        return table

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    raw_prefix = row[0].strip()
                    vendor = row[1].strip()
                    cleaned_prefix = re.sub(r"[^0-9A-Fa-f]", "", raw_prefix).upper()
                    if len(cleaned_prefix) == 6:
                        table[cleaned_prefix] = vendor
        logger.debug("Loaded %d vendor entries from OUI database at %s", len(table), target_path)
    except Exception as exc:
        logger.error("Failed loading OUI CSV from %s: %s", target_path, exc)

    if not csv_path:
        _OUI_CACHE = table
    return table


def lookup_vendor(mac: str, oui_table: Optional[Dict[str, str]] = None) -> str:
    """Identify the hardware vendor for a MAC address using the local OUI table.

    Args:
        mac: Hardware MAC address string.
        oui_table: Preloaded OUI dictionary; if None, uses default cached table.

    Returns:
        Vendor name or 'Unknown'.
    """
    if not mac:
        return "Unknown"

    table = oui_table if oui_table is not None else load_oui_table()
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(cleaned) < 6:
        return "Unknown"

    prefix = cleaned[:6]
    return table.get(prefix, "Unknown")


# ---------------------------------------------------------------------------
# Reverse DNS Resolution
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str, timeout: Optional[float] = None) -> Optional[str]:
    """Perform reverse DNS lookup for an IP with a strict timeout.

    Args:
        ip: Target IPv4 address.
        timeout: Timeout in seconds; defaults to settings.dns_timeout_seconds.

    Returns:
        Resolved hostname string, or None if lookup timed out or failed.
    """
    effective_timeout = timeout if timeout is not None else settings.dns_timeout_seconds

    def _lookup() -> Optional[str]:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=effective_timeout)
        except Exception:
            return None


def batch_resolve_hostnames(ips: List[str], timeout: Optional[float] = None) -> Dict[str, Optional[str]]:
    """Concurrently resolve hostnames for a list of IP addresses.

    Args:
        ips: List of IP strings.
        timeout: Per-resolution timeout in seconds.

    Returns:
        Mapping of IP address to resolved hostname or None.
    """
    effective_timeout = timeout if timeout is not None else settings.dns_timeout_seconds
    results: Dict[str, Optional[str]] = {}

    if not ips:
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 12)) as executor:
        future_to_ip = {executor.submit(resolve_hostname, ip, effective_timeout): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = None

    return results


# ---------------------------------------------------------------------------
# ARP Subnet Sweeping (Scapy + System Fallback)
# ---------------------------------------------------------------------------

def _parse_system_arp_cache(subnet_cidr: str) -> List[Tuple[str, str]]:
    """Extract known IP and MAC entries from system ARP cache as a fallback.

    Args:
        subnet_cidr: Target subnet CIDR string.

    Returns:
        List of (ip, mac) tuples residing on the target subnet.
    """
    try:
        target_net = ipaddress.IPv4Network(subnet_cidr, strict=False)
    except Exception:
        target_net = None

    discovered: List[Tuple[str, str]] = []

    # 1. Check Linux /proc/net/arp
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip_str, flags, mac_str = parts[0], parts[2], parts[3]
                    if flags != "0x0" and mac_str != "00:00:00:00:00:00":
                        if not target_net or ipaddress.IPv4Address(ip_str) in target_net:
                            discovered.append((ip_str, normalize_mac(mac_str)))
            if discovered:
                return discovered
        except Exception as exc:
            logger.debug("Failed reading /proc/net/arp: %s", exc)

    # 2. Check cross-platform 'arp -a' command
    try:
        import subprocess

        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            # Matches IP followed by MAC
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})",
                line,
            )
            if match:
                ip_str = match.group(1)
                mac_str = normalize_mac(match.group(2))
                # Skip broadcast and multicast MACs
                if mac_str and not mac_str.startswith("ff:ff:ff") and not mac_str.startswith("01:00:5e"):
                    if not target_net or ipaddress.IPv4Address(ip_str) in target_net:
                        discovered.append((ip_str, mac_str))
    except Exception as exc:
        logger.debug("System arp -a execution failed: %s", exc)

    return discovered


def arp_sweep_scapy(
    subnet: str,
    interface: Optional[str] = None,
    timeout: Optional[float] = None,
) -> List[Tuple[str, str]]:
    """Perform a broadcast ARP sweep of a subnet using Scapy.

    Args:
        subnet: CIDR notation of target subnet (e.g. '192.168.1.0/24').
        interface: Interface to transmit on; None defaults to Scapy default.
        timeout: ARP response wait timeout in seconds.

    Returns:
        List of (ip, mac) tuples for all responding devices.
    """
    effective_timeout = timeout if timeout is not None else settings.arp_timeout_seconds
    responders: List[Tuple[str, str]] = []

    try:
        import scapy.all as scapy  # type: ignore

        # Construct broadcast Ethernet frame encapsulating ARP request
        arp_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)

        srp_kwargs: Dict[str, Any] = {
            "timeout": effective_timeout,
            "verbose": 0,
            "retry": 1,
        }
        if interface and interface.lower() != "auto":
            srp_kwargs["iface"] = interface

        logger.debug("Broadcasting Scapy ARP sweep on %s (subnet: %s)...", interface or "default", subnet)
        ans, _ = scapy.srp(arp_packet, **srp_kwargs)

        for sent, received in ans:
            if received.haslayer(scapy.ARP):
                resp_ip = received[scapy.ARP].psrc
                resp_mac = normalize_mac(received[scapy.ARP].hwsrc or received[scapy.Ether].src)
                if resp_ip and resp_mac:
                    responders.append((resp_ip, resp_mac))

        logger.debug("Scapy ARP sweep received %d responses", len(responders))
        return responders

    except (RuntimeError, PermissionError, OSError) as exc:
        logger.warning(
            "Scapy raw layer-2 packet operations unavailable (%s). Falling back to OS ARP table discovery.",
            exc,
        )
        return _parse_system_arp_cache(subnet)
    except Exception as exc:
        logger.error("Unexpected error during Scapy ARP sweep: %s", exc)
        return _parse_system_arp_cache(subnet)


# ---------------------------------------------------------------------------
# Discovery Sweep Cycle & State Management
# ---------------------------------------------------------------------------

def run_discovery_sweep(
    net_info: Optional[NetworkInfo] = None,
    oui_table: Optional[Dict[str, str]] = None,
    force_no_baseline: bool = False,
) -> Dict[str, Any]:
    """Execute a single complete discovery sweep across the local network.

    1. Discovers network parameters (interface, subnet, local IP, gateway).
    2. Broadcasts ARP sweep to locate active hosts.
    3. Resolves hostnames via reverse DNS.
    4. Looks up hardware vendors from MAC OUI.
    5. Upserts discovered devices into device_inventory (status='online').
    6. Triggers ai_alerts for newly detected unknown MAC addresses.
    7. Marks hosts not seen for 2 sweeps as offline.

    Args:
        net_info: Optional pre-detected NetworkInfo object.
        oui_table: Optional preloaded OUI vendor dictionary.
        force_no_baseline: If True, disables initial baseline marking.

    Returns:
        Summary dict containing counts of active, new, and offline devices.
    """
    now = time.time()
    network = net_info or settings.get_network_info(refresh=False)
    oui = oui_table if oui_table is not None else load_oui_table()

    logger.info(
        "Starting discovery sweep on interface '%s' (Subnet: %s, Local IP: %s)",
        network.interface,
        network.subnet,
        network.ip,
    )

    # 1. Perform ARP sweep
    discovered_pairs = arp_sweep_scapy(
        subnet=network.subnet,
        interface=network.interface,
        timeout=settings.arp_timeout_seconds,
    )

    # Ensure local machine is present in discovered inventory
    if network.ip and network.mac:
        if not any(pair[0] == network.ip or pair[1] == network.mac for pair in discovered_pairs):
            discovered_pairs.append((network.ip, network.mac))

    # De-duplicate by MAC address (preserving latest IP)
    unique_devices: Dict[str, str] = {}  # mac -> ip
    for ip_str, mac_str in discovered_pairs:
        if mac_str:
            unique_devices[mac_str] = ip_str

    logger.info("ARP sweep located %d active responders", len(unique_devices))

    # 2. Reverse DNS resolution
    ips_to_resolve = list(unique_devices.values())
    hostnames = batch_resolve_hostnames(ips_to_resolve, timeout=settings.dns_timeout_seconds)

    # 3. Query existing device inventory
    existing_devices = get_device_mac_map()
    is_first_run = (len(existing_devices) == 0) and settings.baseline_initial_devices and not force_no_baseline

    devices_to_upsert: List[Dict[str, Any]] = []
    alerts_to_insert: List[Dict[str, Any]] = []

    new_device_count = 0

    for mac, ip in unique_devices.items():
        vendor = lookup_vendor(mac, oui)
        hostname = hostnames.get(ip)

        # Intelligent classification for local workstation and mobile hotspot gateway
        is_gw = (ip == network.gateway) or (ip == getattr(settings, "resolved_gateway", None))
        is_local = (ip == network.ip) or (mac == network.mac)

        # Check if MAC has locally administered / randomized bit set (common on mobile phones/hotspots)
        cleaned_mac = re.sub(r"[^0-9A-Fa-f]", "", mac)
        is_private_mac = False
        if len(cleaned_mac) >= 2:
            try:
                first_byte = int(cleaned_mac[:2], 16)
                if (first_byte & 0x02) != 0:
                    is_private_mac = True
            except Exception:
                pass

        if is_local:
            if not hostname or str(hostname).lower() in ("none", "unknown"):
                hostname = socket.gethostname() or "Local Host"
            if vendor in ("Unknown", None, ""):
                vendor = "Local Workstation (Host)"
        elif is_gw:
            if not hostname or str(hostname).lower() in ("none", "unknown"):
                hostname = "Phone Hotspot (Gateway)"
            if vendor in ("Unknown", None, ""):
                vendor = "Mobile Hotspot Gateway"
        elif is_private_mac:
            if not hostname or str(hostname).lower() in ("none", "unknown"):
                hostname = f"Mobile Device ({ip})"
            if vendor in ("Unknown", None, ""):
                vendor = "Mobile Device (Private MAC)"
        else:
            if not hostname or str(hostname).lower() in ("none", "unknown"):
                hostname = f"Connected Device ({ip})"
            if vendor in ("Unknown", None, ""):
                vendor = "Network Client Device"

        if mac in existing_devices:
            # Existing device: preserve baseline is_known flag and first_seen timestamp
            existing_record = existing_devices[mac]
            is_known = existing_record.get("is_known", 0)
            first_seen = existing_record.get("first_seen", now)
        else:
            # Brand new MAC detected
            new_device_count += 1
            first_seen = now

            if is_first_run:
                # First run marks all initial devices as known baseline
                is_known = 1
                logger.info("Baseline device established: %s (%s, %s)", ip, mac, vendor)
            else:
                # Newly appeared device outside of baseline
                is_known = 0
                alert_msg = f"New unknown device detected: IP {ip}, MAC {mac}, Vendor: {vendor}"
                logger.warning("AI Alert Triggered: %s", alert_msg)

                alerts_to_insert.append(
                    {
                        "ts": now,
                        "alert_type": "unknown_device",
                        "severity": "medium",
                        "src_ip": ip,
                        "message": alert_msg,
                        "score": settings.warning_threshold,
                        "acknowledged": 0,
                        "details_json": json.dumps(
                            {
                                "mac": mac,
                                "ip": ip,
                                "vendor": vendor,
                                "hostname": hostname,
                                "first_seen": first_seen,
                            }
                        ),
                    }
                )

        devices_to_upsert.append(
            {
                "mac": mac,
                "ip": ip,
                "vendor": vendor,
                "hostname": hostname,
                "status": "online",
                "is_known": is_known,
                "first_seen": first_seen,
                "last_seen": now,
            }
        )

    # 4. Batch upsert device inventory
    if devices_to_upsert:
        upsert_device_inventory_batch(devices_to_upsert)

    # 5. Insert alerts for unknown devices
    if alerts_to_insert:
        insert_ai_alerts_batch(alerts_to_insert)

    # 6. Mark devices not seen for 2 sweeps as offline
    # A device is offline if last_seen < now - (threshold * interval)
    offline_cutoff = now - (settings.offline_threshold_sweeps * settings.discovery_interval_seconds)
    marked_offline = mark_devices_offline(offline_cutoff)

    summary = {
        "timestamp": now,
        "responders": len(unique_devices),
        "new_devices": new_device_count,
        "alerts_created": len(alerts_to_insert),
        "marked_offline": marked_offline,
        "is_first_run_baseline": is_first_run,
    }
    logger.info(
        "Discovery sweep finished: %d online, %d new, %d alerts, %d marked offline",
        summary["responders"],
        summary["new_devices"],
        summary["alerts_created"],
        summary["marked_offline"],
    )
    return summary


# ---------------------------------------------------------------------------
# Background Process Execution Loop
# ---------------------------------------------------------------------------

_RUNNING = True


def _handle_shutdown_signal(signum: int, frame: Any) -> None:
    """Handle graceful termination on SIGINT and SIGTERM."""
    global _RUNNING
    logger.info("Received termination signal (%d). Shutting down NetWatch discovery service...", signum)
    _RUNNING = False


def run_discovery_loop(
    interval_seconds: Optional[float] = None,
    once: bool = False,
    force_no_baseline: bool = False,
) -> None:
    """Run discovery sweeps periodically as a standalone background service.

    Args:
        interval_seconds: Loop pause duration in seconds; defaults to settings.discovery_interval_seconds.
        once: If True, execute a single sweep and return immediately.
        force_no_baseline: If True, disable initial baseline creation.
    """
    global _RUNNING
    signal.signal(signal.SIGINT, _handle_shutdown_signal)
    signal.signal(signal.SIGTERM, _handle_shutdown_signal)

    interval = interval_seconds if interval_seconds is not None else settings.discovery_interval_seconds
    oui_table = load_oui_table()
    net_info = settings.get_network_info()

    logger.info("=" * 65)
    logger.info("NetWatch Network Discovery Service Started")
    logger.info("  Interface : %s", net_info.interface)
    logger.info("  Subnet    : %s", net_info.subnet)
    logger.info("  Interval  : %.1f seconds", interval)
    logger.info("  Offline   : %d missed sweeps", settings.offline_threshold_sweeps)
    logger.info("=" * 65)

    while _RUNNING:
        sweep_start = time.time()
        try:
            current_net = settings.get_network_info(refresh=True)
            if current_net.subnet != net_info.subnet or current_net.interface != net_info.interface:
                logger.warning(
                    "Network change detected in discovery: %s (%s) -> %s (%s)",
                    net_info.subnet, net_info.interface, current_net.subnet, current_net.interface
                )
                net_info = current_net
            run_discovery_sweep(net_info=net_info, oui_table=oui_table, force_no_baseline=force_no_baseline)
        except Exception as exc:
            logger.error("Error encountered during discovery sweep: %s", exc, exc_info=True)

        if once or not _RUNNING:
            break

        # Calculate remaining sleep time to maintain precise cadence
        elapsed = time.time() - sweep_start
        sleep_time = max(1.0, interval - elapsed)

        # Interruptible sleep in small chunks
        sleep_end = time.time() + sleep_time
        while _RUNNING and time.time() < sleep_end:
            time.sleep(0.5)

    logger.info("NetWatch Discovery Service exited cleanly.")


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entrypoint for running network discovery."""
    parser = argparse.ArgumentParser(description="NetWatch Network Device Discovery Service")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Perform a single discovery sweep and exit",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Override discovery interval in seconds (default: 30s)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Do not treat initial sweep as known baseline (mark all new devices as unknown)",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Print auto-detected network parameters and exit without sweeping",
    )

    args = parser.parse_args()

    if args.inspect:
        detected = detect_network_info()
        print("=== NetWatch Network Auto-Detection ===")
        for key, value in detected.to_dict().items():
            print(f"  {key:<12}: {value}")
        return

    run_discovery_loop(
        interval_seconds=args.interval,
        once=args.once,
        force_no_baseline=args.no_baseline,
    )


if __name__ == "__main__":
    main()
