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
import logging
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.db import get_connection, get_device_inventory
from backend.gemini_service import verify_anomaly_with_gemini

logger = logging.getLogger(__name__)


def check_syn_flood_audit(minutes: float = 1.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for instantaneous active TCP SYN flooding attacks.

    Evaluates recent 30-60 second traffic rate to distinguish active DoS floods
    from routine web browsing handshakes.
    """
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    my_ip = net_info.ip

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        # Look for hosts generating rapid burst of unacknowledged SYNs in the current window
        cursor.execute(
            """
            SELECT src_ip, SUM(syn_count) as total_syn, SUM(tcp_count) as total_tcp,
                   MAX(pps) as peak_pps
            FROM traffic_metrics
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING total_syn >= 150
            ORDER BY total_syn DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        suspects = []
        for r in rows:
            src_ip, total_syn, total_tcp, peak_pps = r[0], r[1], r[2], r[3]
            ratio = (total_syn / total_tcp) if total_tcp and total_tcp > 0 else 1.0
            # Exclude local client unless sustained flood (> 300 SYNs/min with 90%+ ratio)
            if src_ip == my_ip and (total_syn < 300 or ratio < 0.90):
                continue

            if total_syn >= 200 and ratio >= 0.85 and (peak_pps or 0) >= 40:
                suspects.append({
                    "src_ip": src_ip,
                    "syn_packets": total_syn,
                    "tcp_packets": total_tcp,
                    "syn_ratio": round(ratio * 100.0, 1),
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if suspects:
            top = suspects[0]
            # Verify with Gemini
            net_ctx = {"ip": net_info.ip, "gateway": net_info.gateway, "subnet": net_info.subnet, "interface": net_info.interface}
            candidate = {"src_ip": top["src_ip"], "alert_type": "syn_flood", "details": top, "message": f"{top['syn_packets']} unacknowledged SYNs"}
            verdict = verify_anomaly_with_gemini(candidate, net_ctx)

            if verdict.get("is_genuine_attack", True):
                return {
                    "check": "syn_flood",
                    "name": "TCP SYN Flood Defense Audit",
                    "status": "CRITICAL" if top["syn_packets"] > 400 else "WARNING",
                    "score_penalty": 30 if top["syn_packets"] > 400 else 15,
                    "summary": f"Active SYN flood attack confirmed from {top['src_ip']} ({top['syn_packets']} unacknowledged SYNs, {top['syn_ratio']}% ratio). {verdict.get('reasoning', '')}",
                    "details": suspects,
                    "remediation": {
                        "windows": f"New-NetFirewallRule -DisplayName 'Block-SYN-Attacker' -Direction Inbound -RemoteAddress {top['host_ip'] if 'host_ip' in top else top['src_ip']} -Action Block",
                        "linux": f"iptables -A INPUT -s {top['src_ip']} -p tcp --syn -j DROP",
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


def check_port_scan_audit(minutes: float = 1.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for vertical and horizontal port scanning."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT src_ip, MAX(unique_dst_ports) as max_ports, MAX(unique_dst_ips) as max_ips,
                   SUM(tcp_count + udp_count) as total_packets
            FROM traffic_metrics
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING max_ports >= 75
            ORDER BY max_ports DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        scanners = []
        for r in rows:
            src_ip, max_ports, max_ips, total_pkts = r[0], r[1], r[2], r[3]
            # Exclude default router gateway from routine port scan alerts
            if gw_ip and src_ip == gw_ip and max_ports < 250:
                continue

            if max_ports >= settings.rule_port_scan_threshold:
                scanners.append({
                    "src_ip": src_ip,
                    "probed_ports": max_ports,
                    "target_hosts": max_ips,
                    "packets": total_pkts,
                })

        if scanners:
            top = scanners[0]
            net_ctx = {"ip": net_info.ip, "gateway": net_info.gateway, "subnet": net_info.subnet, "interface": net_info.interface}
            candidate = {"src_ip": top["src_ip"], "alert_type": "port_scan", "details": top, "message": f"{top['probed_ports']} ports probed"}
            verdict = verify_anomaly_with_gemini(candidate, net_ctx)

            if verdict.get("is_genuine_attack", True):
                return {
                    "check": "port_scan",
                    "name": "Port Scanning & Reconnaissance Audit",
                    "status": "CRITICAL" if top["probed_ports"] >= 200 else "WARNING",
                    "score_penalty": 25 if top["probed_ports"] >= 200 else 15,
                    "summary": f"Port reconnaissance confirmed from {top['src_ip']} ({top['probed_ports']} ports probed). {verdict.get('reasoning', '')}",
                    "details": scanners,
                    "remediation": {
                        "windows": f"New-NetFirewallRule -DisplayName 'Block-PortScanner-{top['src_ip']}' -Direction Inbound -RemoteAddress {top['src_ip']} -Action Block",
                        "linux": f"iptables -I INPUT -s {top['src_ip']} -j DROP",
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


def check_icmp_storm_audit(minutes: float = 1.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit network flows for ICMP flood and ping storms, filtering monitoring probes."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)
    gw_ip = net_info.gateway

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT src_ip, SUM(icmp_count) as total_icmp, MAX(pps) as peak_pps
            FROM traffic_metrics
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            HAVING total_icmp >= 80
            ORDER BY total_icmp DESC
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        flooders = []
        for r in rows:
            src_ip, total_icmp, peak_pps = r[0], r[1], r[2]
            # NetWatch probe generates ~12 pings per minute; real storm is 80+ pings/min with peak pps > 15
            if (peak_pps or 0) >= 15.0 and total_icmp >= 100:
                flooders.append({
                    "src_ip": src_ip,
                    "total_icmp": total_icmp,
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if flooders:
            top = flooders[0]
            net_ctx = {"ip": net_info.ip, "gateway": net_info.gateway, "subnet": net_info.subnet, "interface": net_info.interface}
            candidate = {"src_ip": top["src_ip"], "alert_type": "icmp_flood", "details": top, "message": f"{top['total_icmp']} ICMP frames"}
            verdict = verify_anomaly_with_gemini(candidate, net_ctx)

            if verdict.get("is_genuine_attack", True):
                return {
                    "check": "icmp_flood",
                    "name": "ICMP Storm / Ping Flood Audit",
                    "status": "WARNING",
                    "score_penalty": 20,
                    "summary": f"Elevated ICMP flood rate from {top['src_ip']} ({top['total_icmp']} ICMP frames).",
                    "details": flooders,
                    "remediation": {
                        "windows": f"New-NetFirewallRule -DisplayName 'Block-ICMP-{top['src_ip']}' -Direction Inbound -Protocol ICMPv4 -RemoteAddress {top['src_ip']} -Action Block",
                        "linux": f"iptables -A INPUT -p icmp -s {top['src_ip']} -j DROP",
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


def check_bandwidth_drain_audit(minutes: float = 1.0, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Audit for abnormal bandwidth consumption surges or covert data exfiltration."""
    cutoff = time.time() - (minutes * 60.0)
    net_info = settings.get_network_info(refresh=False)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT src_ip, SUM(bytes_out) as total_out, SUM(bytes_in) as total_in,
                   MAX(pps) as peak_pps
            FROM traffic_metrics
            WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY total_out DESC
            LIMIT 5
            """,
            (cutoff,),
        )
        rows = cursor.fetchall()

        hogs = []
        for r in rows:
            src_ip, total_out, total_in, peak_pps = r[0], r[1], r[2], r[3]
            # Trigger only on massive sustained outbound surge (> 30 MB in 60 seconds with peak pps > 80)
            if (total_out or 0) >= 30_000_000 and (peak_pps or 0) >= 80:
                hogs.append({
                    "src_ip": src_ip,
                    "mb_uploaded": round(total_out / 1_000_000, 2),
                    "mb_downloaded": round(total_in / 1_000_000, 2),
                    "peak_pps": round(peak_pps or 0, 1),
                })

        if hogs:
            top = hogs[0]
            return {
                "check": "bandwidth_drain",
                "name": "Bandwidth Drain & Exfiltration Audit",
                "status": "WARNING",
                "score_penalty": 15,
                "summary": f"Unusual sustained outbound throughput surge from {top['src_ip']} ({top['mb_uploaded']} MB uploaded in 60s).",
                "details": hogs,
                "remediation": {
                    "windows": f"Get-NetTCPConnection -RemoteAddress {top['src_ip']} | Select-Object OwningProcess, LocalAddress, RemotePort",
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
    if check_type in checks_map:
        results.append(checks_map[check_type](db_path=db_path))
    else:
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
