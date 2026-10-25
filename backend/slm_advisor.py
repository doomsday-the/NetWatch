"""Security Language Model (SLM) Advisor & Incident Response Engine for NetWatch.

Powered directly by Google Gemini Generative AI models (gemini-3.5-flash, gemini-3.1-flash-lite).
Provides real-time incident analysis, anomaly reasoning, and multi-platform remediation playbooks.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.db import get_ai_alerts, get_device_inventory
from backend.gemini_service import call_gemini, chat_with_gemini

logger = logging.getLogger(__name__)


def analyze_anomaly_with_slm(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Generate intelligent security incident analysis using Gemini AI."""
    net_info = settings.get_network_info(refresh=False)
    alert_type = alert.get("alert_type", "anomaly").lower()
    src_ip = alert.get("src_ip", "0.0.0.0")
    severity = alert.get("severity", "medium").upper()
    score = alert.get("score", 0.7)
    message = alert.get("message", "")

    sys_instruction = (
        "You are an elite Tier-3 Incident Response Lead. "
        "Analyze the provided network anomaly and formulate an incident response playbook. "
        "Return STRICT JSON only without markdown code fences:\n"
        "{\n"
        '  "threat_title": "Short descriptive attack or anomaly name",\n'
        '  "mitre_technique": "Txxxx - Technique Name",\n'
        '  "tactical_assessment": "1-2 paragraphs detailing the threat mechanism and blast radius",\n'
        '  "business_impact": "Direct operational or data security impact",\n'
        '  "incident_playbook": {\n'
        '    "immediate_actions": ["Step 1", "Step 2", "Step 3"],\n'
        '    "firewall_commands": {\n'
        '      "windows_powershell": "PowerShell command to block or inspect the IP",\n'
        '      "linux_iptables": "iptables command to block the IP"\n'
        '    },\n'
        '    "permanent_hardening": ["Hardening step 1", "Hardening step 2"]\n'
        '  },\n'
        '  "curated_summary": "1-2 sentence executive briefing"\n'
        "}"
    )

    prompt = (
        f"Incident Telemetry:\n"
        f"- Target IP: {src_ip}\n"
        f"- Alert Type: {alert_type}\n"
        f"- Severity: {severity} (Confidence: {round(score * 100, 1)}%)\n"
        f"- Description: {message}\n"
        f"- Details: {alert.get('details_json', '{}')}\n\n"
        f"Host Environment:\n"
        f"- Local Machine: {net_info.ip} on {net_info.interface}\n"
        f"- Gateway: {net_info.gateway} (Subnet: {net_info.subnet})\n\n"
        f"Analyze this incident and generate remediation playbooks."
    )

    raw_json = call_gemini(prompt, system_instruction=sys_instruction, timeout=12.0)
    if raw_json:
        try:
            clean = re.sub(r"^```json\s*|\s*```$", "", raw_json.strip(), flags=re.MULTILINE)
            parsed = json.loads(clean)
            parsed["anomaly_id"] = alert.get("id")
            parsed["source_ip"] = src_ip
            parsed["severity"] = severity
            parsed["confidence_score"] = round(score * 100, 1)
            return parsed
        except Exception as e:
            logger.debug("Failed parsing Gemini anomaly analysis JSON: %s", e)

    # Fallback knowledge base if offline
    return {
        "anomaly_id": alert.get("id"),
        "threat_title": f"{alert_type.replace('_', ' ').title()} Alert",
        "severity": severity,
        "confidence_score": round(score * 100, 1),
        "source_ip": src_ip,
        "mitre_technique": "T1046 - Network Discovery / T1498 - Denial of Service",
        "tactical_assessment": message or "Anomalous traffic signature flagged by detection pipeline.",
        "business_impact": "Potential network degradation or service probing.",
        "incident_playbook": {
            "immediate_actions": [
                f"Verify if host {src_ip} belongs to authorized personnel.",
                f"Inspect active connections using netstat or Get-NetTCPConnection.",
                "Enforce network firewall rule if suspicious.",
            ],
            "firewall_commands": {
                "windows_powershell": f"New-NetFirewallRule -DisplayName 'Block-Threat-{src_ip}' -Direction Inbound -RemoteAddress {src_ip} -Action Block",
                "linux_iptables": f"sudo iptables -I INPUT -s {src_ip} -j DROP",
            },
            "permanent_hardening": [
                "Segment subnet and restrict unnecessary external ports.",
                "Enable host OS connection logging.",
            ],
        },
        "curated_summary": f"Incident from {src_ip} flagged with severity {severity}. Recommended action is to inspect and block.",
    }


def chat_with_slm(user_message: str) -> Dict[str, Any]:
    """Conversational security copilot powered by Google Gemini AI."""
    net_info = settings.get_network_info(refresh=False)
    devices = get_device_inventory()
    alerts = get_ai_alerts(limit=5, acknowledged=False)

    online_dev_count = sum(1 for d in devices if d.get("status") == "online")
    active_alerts_count = len(alerts)

    net_ctx = {
        "interface": net_info.interface,
        "ip": net_info.ip,
        "subnet": net_info.subnet,
        "gateway": net_info.gateway or "Auto",
        "active_alerts": active_alerts_count,
        "devices_online": online_dev_count,
    }

    reply_text = chat_with_gemini(user_message, net_ctx)

    return {
        "reply": reply_text,
        "timestamp": time.time(),
        "context": net_ctx,
    }
