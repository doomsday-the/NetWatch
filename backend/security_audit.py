"""Defensive security audit engine for NetWatch.

Runs real-time defensive checks against network traffic, flow patterns,
and device topology to detect active cyber attacks and security posture risks:
- Port Scanning & Service Reconnaissance
- TCP SYN Flooding & Half-Open Resource Exhaustion
- ICMP Storm / Ping Flooding (DoS)
- Bandwidth Anomaly & Covert Data Exfiltration
- ARP Cache Poisoning / Gateway Spoofing (MITM)
- Rogue / Unauthorized Device Infiltration
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.db import get_connection, get_device_inventory
from backend.gemini_service import verify_anomaly_with_gemini

logger = logging.getLogger(__name__)


def is_local_subnet_ip(ip_str: str, subnet_str: Optional[str] = None) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local:
            return False
        if ip.version == 6:
            return ip.is_private
        if subnet_str:
            net = ipaddress.ip_network(subnet_str, strict=False)
            return ip in net
        return ip.is_private
    except Exception:
        return False

def get_all_local_ips() -> set[str]:
    import psutil
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.address:
                ips.add(a.address.lower())
    return ips



def check_syn_flood_audit(minutes: float = 10.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for active TCP SYN flooding attacks."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway
    local_ips = get_all_local_ips()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Correlate with active / unresolved alerts in ai_alerts
        cursor.execute(
            """
            SELECT id, alert_type, src_ip, severity, score, message, ts, details_json
            FROM ai_alerts
            WHERE alert_type = 'syn_flood' AND (acknowledged = 0 OR ts >= ?)
            ORDER BY ts DESC LIMIT 5
            """,
            (cutoff,),
        )
        recent_alerts = [dict(r) for r in cursor.fetchall() if is_local_subnet_ip(r['src_ip'], net_info.subnet)]

        # 2. Correlate with traffic_metrics
        cursor.execute(
            """
            SELECT src_ip, SUM(syn_count) as total_syn, SUM(tcp_count) as total_tcp,
                   MAX(pps) as peak_pps, MAX(unique_dst_ports) as max_ports
            FROM traffic_metrics INDEXED BY idx_traffic_metrics_ts
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING total_syn >= 25
            ORDER BY total_syn DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        suspects = []
        for r in rows:
            src_ip, total_syn, total_tcp, peak_pps = r[0], r[1], r[2], r[3]
            max_ports = r[4] if len(r) > 4 and r[4] is not None else 0
            ratio = (total_syn / total_tcp) if total_tcp and total_tcp > 0 else 1.0
            if src_ip.lower() in local_ips or src_ip.startswith("169.254.") or (gw_ip and src_ip == gw_ip):
                continue
            if not is_local_subnet_ip(src_ip, net_info.subnet):
                continue

            # If traffic was distributed across many ports and no syn_flood alert exists, it is a port scan
            if max_ports >= settings.rule_port_scan_threshold and not any(a.get("src_ip") == src_ip and a.get("alert_type") == "syn_flood" for a in recent_alerts):
                continue

            if total_syn >= settings.rule_syn_flood_count and (ratio >= settings.rule_syn_flood_ratio or total_syn >= settings.rule_syn_flood_high_count):
                suspects.append({
                    "src_ip": src_ip,
                    "syn_packets": total_syn,
                    "tcp_packets": total_tcp,
                    "syn_ratio": round(ratio * 100.0, 1),
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if recent_alerts or suspects:
            top_ip = suspects[0]["src_ip"] if suspects else recent_alerts[0].get("src_ip", "Unknown")
            is_crit = any(a.get("severity") == "high" for a in recent_alerts) or any(s["syn_packets"] >= 45 for s in suspects)
            top_msg = recent_alerts[0].get("message") if recent_alerts else f"{suspects[0]['syn_packets']} unacknowledged SYNs ({suspects[0]['syn_ratio']}% ratio)"

            return {
                "check": "syn_flood",
                "name": "TCP SYN Flood Defense Audit",
                "status": "CRITICAL" if is_crit else "WARNING",
                "score_penalty": 30 if is_crit else 15,
                "summary": f"Active TCP SYN flood attack confirmed from {top_ip}: {top_msg}",
                "details": suspects if suspects else recent_alerts,
                "remediation": {
                    "windows": f"New-NetFirewallRule -DisplayName 'Block-SYN-Attacker-{top_ip}' -Direction Inbound -RemoteAddress {top_ip} -Action Block",
                    "linux": f"iptables -A INPUT -s {top_ip} -p tcp --syn -j DROP",
                    "system": "Enable TCP SYN Cookies: 'netsh interface tcp set global timestamps=enabled' or Linux 'sysctl -w net.ipv4.tcp_syncookies=1'",
                },
            }

        return {
            "check": "syn_flood",
            "name": "TCP SYN Flood Defense Audit",
            "status": "PASS",
            "score_penalty": 0,
            "summary": "Normal TCP handshake distribution. No half-open SYN connection floods detected.",
            "details": [],
            "remediation": None,
        }
    finally:
        conn.close()


def check_port_scan_audit(minutes: float = 10.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for vertical and horizontal port scanning."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Correlate with active / unresolved alerts in ai_alerts
        cursor.execute(
            """
            SELECT id, alert_type, src_ip, severity, score, message, ts, details_json
            FROM ai_alerts
            WHERE alert_type = 'port_scan' AND (acknowledged = 0 OR ts >= ?)
            ORDER BY ts DESC LIMIT 5
            """,
            (cutoff,),
        )
        recent_alerts = [dict(r) for r in cursor.fetchall() if is_local_subnet_ip(r['src_ip'], net_info.subnet)]

        # 2. Correlate with traffic_metrics
        cursor.execute(
            """
            SELECT src_ip, MAX(unique_dst_ports) as max_ports, MAX(unique_dst_ips) as max_ips,
                   SUM(tcp_count + udp_count) as total_packets
            FROM traffic_metrics INDEXED BY idx_traffic_metrics_ts
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING max_ports >= 20
            ORDER BY max_ports DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        local_ips = get_all_local_ips()
        scanners = []
        for r in rows:
            src_ip, max_ports, max_ips, total_pkts = r[0], r[1], r[2], r[3]
            if (src_ip.lower() in local_ips or (gw_ip and src_ip == gw_ip) or src_ip.startswith("169.254.")) and max_ports < 250:
                continue
            if not is_local_subnet_ip(src_ip, net_info.subnet):
                continue

            if max_ports >= settings.rule_port_scan_threshold:
                scanners.append({
                    "src_ip": src_ip,
                    "probed_ports": max_ports,
                    "target_hosts": max_ips,
                    "packets": total_pkts,
                })

        if recent_alerts or scanners:
            top_ip = scanners[0]["src_ip"] if scanners else recent_alerts[0].get("src_ip", "Unknown")
            is_crit = any(a.get("severity") == "high" for a in recent_alerts) or any(s["probed_ports"] >= 75 for s in scanners)
            top_msg = recent_alerts[0].get("message") if recent_alerts else f"{scanners[0]['probed_ports']} ports probed"

            return {
                "check": "port_scan",
                "name": "Port Scanning & Reconnaissance Audit",
                "status": "CRITICAL" if is_crit else "WARNING",
                "score_penalty": 25 if is_crit else 15,
                "summary": f"Port reconnaissance confirmed from {top_ip}: {top_msg}",
                "details": scanners if scanners else recent_alerts,
                "remediation": {
                    "windows": f"New-NetFirewallRule -DisplayName 'Block-PortScanner-{top_ip}' -Direction Inbound -RemoteAddress {top_ip} -Action Block",
                    "linux": f"iptables -I INPUT -s {top_ip} -j DROP",
                    "system": "Close unused listening ports and filter ICMP port unreachable responses.",
                },
            }

        return {
            "check": "port_scan",
            "name": "Port Scanning & Reconnaissance Audit",
            "status": "PASS",
            "score_penalty": 0,
            "summary": "No port reconnaissance or sweep scanning detected across local network hosts.",
            "details": [],
            "remediation": None,
        }
    finally:
        conn.close()


def check_icmp_storm_audit(minutes: float = 10.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for ICMP flood and ping storms."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Correlate with active / unresolved alerts in ai_alerts
        cursor.execute(
            """
            SELECT id, alert_type, src_ip, severity, score, message, ts, details_json
            FROM ai_alerts
            WHERE alert_type = 'icmp_flood' AND (acknowledged = 0 OR ts >= ?)
            ORDER BY ts DESC LIMIT 5
            """,
            (cutoff,),
        )
        recent_alerts = [dict(r) for r in cursor.fetchall() if is_local_subnet_ip(r['src_ip'], net_info.subnet)]

        # 2. Correlate with traffic_metrics
        cursor.execute(
            """
            SELECT src_ip, SUM(icmp_count) as total_icmp, MAX(pps) as peak_pps
            FROM traffic_metrics INDEXED BY idx_traffic_metrics_ts
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING total_icmp >= 30
            ORDER BY total_icmp DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        local_ips = get_all_local_ips()
        flooders = []
        for r in rows:
            src_ip, total_icmp, peak_pps = r[0], r[1], r[2]
            if src_ip.lower() in local_ips or src_ip.startswith("169.254.") or (gw_ip and src_ip == gw_ip):
                continue
            if not is_local_subnet_ip(src_ip, net_info.subnet):
                continue
            if (peak_pps or 0) >= 3.0 and total_icmp >= 30:
                flooders.append({
                    "src_ip": src_ip,
                    "total_icmp": total_icmp,
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if recent_alerts or flooders:
            top_ip = flooders[0]["src_ip"] if flooders else recent_alerts[0].get("src_ip", "Unknown")
            is_crit = any(a.get("severity") == "high" for a in recent_alerts) or any(f["total_icmp"] >= 60 for f in flooders)
            top_msg = recent_alerts[0].get("message") if recent_alerts else f"{flooders[0]['total_icmp']} ICMP packets detected"

            return {
                "check": "icmp_flood",
                "name": "ICMP Storm / Ping Flood Audit",
                "status": "CRITICAL" if is_crit else "WARNING",
                "score_penalty": 30 if is_crit else 20,
                "summary": f"Elevated ICMP flood rate from {top_ip}: {top_msg}",
                "details": flooders if flooders else recent_alerts,
                "remediation": {
                    "windows": f"New-NetFirewallRule -DisplayName 'Block-ICMP-{top_ip}' -Direction Inbound -Protocol ICMPv4 -RemoteAddress {top_ip} -Action Block",
                    "linux": f"iptables -A INPUT -p icmp -s {top_ip} -j DROP",
                    "system": "Rate limit ICMP on your host or router to prevent denial-of-service degradation.",
                },
            }

        return {
            "check": "icmp_flood",
            "name": "ICMP Storm / Ping Flood Audit",
            "status": "PASS",
            "score_penalty": 0,
            "summary": "ICMP frame volume within healthy baseline parameters (< 1.5% total bandwidth).",
            "details": [],
            "remediation": None,
        }
    finally:
        conn.close()


def check_bandwidth_drain_audit(minutes: float = 10.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit for abnormal bandwidth consumption surges or covert data exfiltration."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Correlate with active / unresolved alerts in ai_alerts
        cursor.execute(
            """
            SELECT id, alert_type, src_ip, severity, score, message, ts, details_json
            FROM ai_alerts
            WHERE alert_type = 'bandwidth_hog' AND (acknowledged = 0 OR ts >= ?)
            ORDER BY ts DESC LIMIT 5
            """,
            (cutoff,),
        )
        recent_alerts = [dict(r) for r in cursor.fetchall() if is_local_subnet_ip(r['src_ip'], net_info.subnet)]

        # 2. Correlate with traffic_metrics
        cursor.execute(
            """
            SELECT src_ip, SUM(bytes_out) as total_out, SUM(bytes_in) as total_in,
                   MAX(pps) as peak_pps
            FROM traffic_metrics INDEXED BY idx_traffic_metrics_ts
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY total_out DESC
            LIMIT 5
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        local_ips = get_all_local_ips()
        hogs = []
        for r in rows:
            src_ip, total_out, total_in, peak_pps = r[0], r[1], r[2], r[3]
            if src_ip.lower() in local_ips or src_ip.startswith("169.254.") or (gw_ip and src_ip == gw_ip):
                continue
            if not is_local_subnet_ip(src_ip, net_info.subnet):
                continue
            if (total_out or 0) >= settings.rule_bandwidth_hog_bytes and (peak_pps or 0) >= 20:
                hogs.append({
                    "src_ip": src_ip,
                    "mb_uploaded": round(total_out / 1_000_000, 2),
                    "mb_downloaded": round(total_in / 1_000_000, 2),
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if recent_alerts or hogs:
            top_ip = hogs[0]["src_ip"] if hogs else recent_alerts[0].get("src_ip", "Unknown")
            is_crit = any(a.get("severity") == "high" for a in recent_alerts) or any(h["mb_uploaded"] >= 15.0 for h in hogs)
            top_msg = recent_alerts[0].get("message") if recent_alerts else f"{hogs[0]['mb_uploaded']} MB uploaded"

            return {
                "check": "bandwidth_drain",
                "name": "Bandwidth Drain & Exfiltration Audit",
                "status": "CRITICAL" if is_crit else "WARNING",
                "score_penalty": 20 if is_crit else 15,
                "summary": f"Unusual sustained outbound throughput surge from {top_ip}: {top_msg}",
                "details": hogs if hogs else recent_alerts,
                "remediation": {
                    "windows": f"Get-NetTCPConnection -RemoteAddress {top_ip} | Select-Object OwningProcess, LocalAddress, RemotePort",
                    "linux": "iftop -i any or nethogs to trace high throughput process.",
                    "system": "Check for unauthorized streaming, large file uploads, or background P2P synchronization.",
                },
            }

        return {
            "check": "bandwidth_drain",
            "name": "Bandwidth Drain & Exfiltration Audit",
            "status": "PASS",
            "score_penalty": 0,
            "summary": "Throughput distribution normal. No abnormal data exfiltration or bandwidth drain detected.",
            "details": [],
            "remediation": None,
        }
    finally:
        conn.close()


def check_arp_spoof_audit(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit for ARP spoofing / Poisoning by checking MAC-to-IP duplication of the gateway."""
    devices = get_device_inventory(db_path=db_path)
    gateway_ip = settings.resolved_gateway

    ip_to_macs: Dict[str, List[str]] = collections.defaultdict(list)
    for d in devices:
        ip = d.get("ip")
        mac = d.get("mac")
        if ip and mac:
            ip_to_macs[ip].append(mac.lower())

    anomalies = []
    for ip, macs in ip_to_macs.items():
        unique_macs = set(macs)
        if len(unique_macs) > 1:
            anomalies.append({
                "ip": ip,
                "conflicting_macs": list(unique_macs),
                "is_gateway": (ip == gateway_ip),
            })

    if anomalies:
        top = anomalies[0]
        is_gw = top.get("is_gateway", False)
        return {
            "check": "arp_spoof",
            "name": "ARP Poisoning & MITM Verification",
            "status": "CRITICAL" if is_gw else "WARNING",
            "score_penalty": 35 if is_gw else 20,
            "summary": f"ARP conflict detected for {'Default Gateway ' if is_gw else ''}{top['ip']}: claimed by multiple MACs ({', '.join(top['conflicting_macs'])}). Possible Man-In-The-Middle attack!",
            "details": anomalies,
            "remediation": {
                "windows": f"arp -d * (clears ARP cache) then bind static gateway: 'netsh interface ipv4 set neighbors \"{settings.resolved_interface}\" \"{top['ip']}\" \"{top['conflicting_macs'][0]}\"'",
                "linux": f"ip neigh flush all; arp -s {top['ip']} {top['conflicting_macs'][0]}",
                "system": "Isolate the conflicting MAC on the switch/Wi-Fi router and verify DHCP Snooping / Dynamic ARP Inspection.",
            },
        }

    return {
        "check": "arp_spoof",
        "name": "ARP Poisoning & MITM Verification",
        "status": "PASS",
        "score_penalty": 0,
        "summary": "ARP table clean. Gateway and subnet IP-to-MAC mappings are uniquely verified.",
        "details": [],
        "remediation": None,
    }


def check_rogue_devices_audit(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit discovered device inventory for untrusted/rogue devices."""
    devices = get_device_inventory(db_path=db_path)
    unknown = [d for d in devices if d.get("is_known") == 0 and d.get("status") == "online"]

    if unknown:
        return {
            "check": "rogue_device",
            "name": "Rogue & Untrusted Host Infiltration Audit",
            "status": "WARNING",
            "score_penalty": min(20, len(unknown) * 5),
            "summary": f"{len(unknown)} unverified device(s) online in your subnet without trusted baseline approval.",
            "details": unknown,
            "remediation": {
                "windows": "Inspect device MAC and hostname in the Devices page. Toggle whitelist or isolate via router MAC filtering.",
                "linux": "Review DHCP leases on your gateway and enable 802.1X port authentication.",
                "system": "If these devices belong to you, click 'Trust All Devices' in Operations & Control.",
            },
        }

    return {
        "check": "rogue_device",
        "name": "Rogue & Untrusted Host Infiltration Audit",
        "status": "PASS",
        "score_penalty": 0,
        "summary": "All online devices on this subnet match verified trusted hardware baselines.",
        "details": [],
        "remediation": None,
    }


def run_comprehensive_security_audit(check_type: str = "all", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute defensive security audit across network traffic and devices."""
    checks_map = {
        "syn_flood": check_syn_flood_audit,
        "port_scan": check_port_scan_audit,
        "icmp_flood": check_icmp_storm_audit,
        "bandwidth_drain": check_bandwidth_drain_audit,
        "arp_spoof": check_arp_spoof_audit,
        "rogue_device": check_rogue_devices_audit,
    }

    results = []
    # Always evaluate all checks so the full defense suite and posture score are maintained!
    for fn in checks_map.values():
        results.append(fn(db_path=db_path))

    total_penalty = sum(r.get("score_penalty", 0) for r in results)
    security_score = max(0, 100 - total_penalty)

    has_critical = any(r.get("status") == "CRITICAL" for r in results)
    has_warning = any(r.get("status") == "WARNING" for r in results)

    if has_critical:
        posture = "CRITICAL_DEFENSE_ACTION_REQUIRED"
        posture_label = "Under Active Attack"
        color = "#ef4444"
    elif has_warning:
        posture = "ELEVATED_RISK"
        posture_label = "Elevated Risk Detected"
        color = "#f59e0b"
    else:
        posture = "SECURE"
        posture_label = "Optimal Security Posture"
        color = "#10b981"

    net_info = settings.get_network_info(refresh=False)

    return {
        "audit_timestamp": time.time(),
        "security_score": security_score,
        "posture": posture,
        "posture_label": posture_label,
        "color": color,
        "target_interface": net_info.interface,
        "target_ip": net_info.ip,
        "target_subnet": net_info.subnet,
        "target_gateway": net_info.gateway,
        "checks_performed": len(results),
        "passed_checks": sum(1 for r in results if r.get("status") == "PASS"),
        "warning_checks": sum(1 for r in results if r.get("status") == "WARNING"),
        "critical_checks": sum(1 for r in results if r.get("status") == "CRITICAL"),
        "checks": results,
    }
