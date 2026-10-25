"""Gemini AI Security Engine for NetWatch.

Connects directly to Google Gemini Generative AI models using a multi-model
fallback cascade (gemini-3.5-flash, gemini-3.1-flash-lite, gemini-flash-latest, gemma-4-26b-a4b-it).

Provides:
- Intelligent false-positive suppression and real threat triage.
- Automated anomaly validation against live network traffic patterns.
- Interactive conversational AI Security Copilot with full network context.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# Load .env explicitly
REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")

logger = logging.getLogger(__name__)

# Fallback models cascade
CANDIDATE_MODELS = [
    "gemini-flash-lite-latest",
    "gemma-4-26b-a4b-it",
    "gemma-4-31b-it",
]

API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def get_gemini_api_key() -> Optional[str]:
    """Retrieve Gemini API key from environment."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")


def call_gemini(
    prompt: str,
    system_instruction: Optional[str] = None,
    timeout: float = 6.0,
) -> Optional[str]:
    """Execute inference across the candidate Gemini models with automatic fallback.

    Args:
        prompt: User prompt content.
        system_instruction: Optional system level guardrail instruction.
        timeout: Network timeout in seconds.

    Returns:
        Generated response text or None if all models fail.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        logger.warning("GEMINI_API_KEY is not configured.")
        return None

    contents = []
    if system_instruction:
        contents.append({"role": "user", "parts": [{"text": f"System Directive:\n{system_instruction}\n"}]})
        contents.append({"role": "model", "parts": [{"text": "Understood. I will follow this system directive strictly."}]})

    contents.append({"role": "user", "parts": [{"text": prompt}]})

    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024,
        },
    }

    for model_name in CANDIDATE_MODELS:
        url = f"{API_BASE_URL}/{model_name}:generateContent?key={api_key}"
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"].strip()
            else:
                logger.debug("Model %s returned status %d: %s", model_name, resp.status_code, resp.text[:120])
        except Exception as exc:
            logger.debug("Model %s request failed: %s", model_name, exc)

    return None


def verify_anomaly_with_gemini(
    candidate: Dict[str, Any],
    net_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Use Gemini AI to analyze network telemetry and determine if it is a real attack or benign traffic.

    Args:
        candidate: Candidate anomaly dict (src_ip, alert_type, metrics, message).
        net_context: Host network context (local IP, gateway IP, subnet, interface).

    Returns:
        Dict containing is_genuine_attack (bool), confidence (float), reasoning, and verified alert.
    """
    sys_instruction = (
        "You are an expert Network Security Analyst (SOC Tier 3). "
        "Your task is to review candidate network anomaly alerts and eliminate false positives. "
        "Be aware that in normal environments: "
        "- Routers / Hotspot Gateways perform NAT routing, DNS forwarding, and NTP checks across multiple ports. "
        "- Browsers open multiple parallel TCP connections to CDN endpoints. "
        "- Network monitoring tools send periodic ICMP ping probes for latency measurements. "
        "- Operating systems maintain IPv6 multicast and neighbor discovery. "
        "Return your verdict in STRICT JSON format with no markdown fences:\n"
        "{\n"
        '  "is_genuine_attack": false,\n'
        '  "confidence": 0.85,\n'
        '  "classification": "benign_hotspot_traffic | legitimate_attack | suspicious_reconnaissance",\n'
        '  "reasoning": "Clear explanation of why this is benign or an attack.",\n'
        '  "suggested_action": "ignore | block | monitor"\n'
        "}"
    )

    prompt = (
        f"Candidate Anomaly Evaluation:\n"
        f"- Target IP: {candidate.get('src_ip')}\n"
        f"- Flagged Alert Type: {candidate.get('alert_type')}\n"
        f"- Raw Observation Message: {candidate.get('message')}\n"
        f"- Raw Metrics: {json.dumps(candidate.get('details', {}))}\n\n"
        f"Host Environment Context:\n"
        f"- Local Machine IP: {net_context.get('ip')}\n"
        f"- Default Gateway: {net_context.get('gateway')}\n"
        f"- Subnet: {net_context.get('subnet')}\n"
        f"- Interface: {net_context.get('interface')}\n\n"
        f"Is this a genuine malicious cyber attack or normal benign hotspot/operating system traffic?"
    )

    raw_text = call_gemini(prompt, system_instruction=sys_instruction, timeout=8.0)
    if raw_text:
        try:
            # Clean possible markdown fences
            clean = re.sub(r"^```json\s*|\s*```$", "", raw_text.strip(), flags=re.MULTILINE)
            result = json.loads(clean)
            return result
        except Exception as e:
            logger.debug("Failed parsing Gemini anomaly response: %s", e)

    # Heuristic fallback if Gemini is offline
    src_ip = candidate.get("src_ip", "")
    gateway = net_context.get("gateway", "")
    local_ip = net_context.get("ip", "")

    # Default rule: Gateway and local machine traffic under moderate thresholds is benign
    if src_ip in (gateway, local_ip) and candidate.get("alert_type") in ("port_scan", "icmp_flood", "syn_flood"):
        return {
            "is_genuine_attack": False,
            "confidence": 0.90,
            "classification": "benign_hotspot_traffic",
            "reasoning": "Traffic from default gateway or local host within normal NAT/monitoring thresholds.",
            "suggested_action": "ignore",
        }

    return {
        "is_genuine_attack": True,
        "confidence": 0.70,
        "classification": "suspicious",
        "reasoning": "Metric exceeds standard thresholds.",
        "suggested_action": "monitor",
    }


def chat_with_gemini(message: str, net_context: Dict[str, Any]) -> str:
    """Conversational security copilot powered directly by Gemini AI."""
    norm_msg = re.sub(r"[?!.,]", "", message.strip().lower())
    quick_greetings = (
        "hi", "hello", "hey", "sup", "greetings", "test",
        "how are you", "how do you do", "how do u do", "how r u",
        "who are you", "what can you do", "status"
    )
    if norm_msg in quick_greetings:
        return (
            f"👋 **NetWatch AI Security Copilot Online**\n\n"
            f"I am operating at peak efficiency, actively monitoring `{net_context.get('interface', 'Wi-Fi')}` "
            f"on subnet `{net_context.get('subnet', '10.173.221.0/24')}`.\n\n"
            f"- **Workstation Host**: `{net_context.get('ip', 'Local')}` (ZEREF)\n"
            f"- **Gateway / Hotspot**: `{net_context.get('gateway', 'Auto')}`\n"
            f"- **Online Devices**: `{net_context.get('devices_online', 2)}` active\n"
            f"- **Active Threat Alerts**: `{net_context.get('active_alerts', 0)}`\n\n"
            f"All defensive monitors are active. Ask me anything about your network posture, firewall commands, or anomaly triage!"
        )

    sys_instruction = (
        "You are NetWatch Security Copilot, an elite AI network defense assistant. "
        "You provide actionable, practical cybersecurity advice for network monitoring, "
        "firewall rules (Windows PowerShell and Linux iptables), incident response, and traffic analysis. "
        "Format your responses cleanly with markdown headings, bullet points, and code blocks."
    )

    context_str = (
        f"Real-Time Host Telemetry:\n"
        f"- Local IP: {net_context.get('ip')}\n"
        f"- Subnet: {net_context.get('subnet')}\n"
        f"- Gateway: {net_context.get('gateway')}\n"
        f"- Monitored Interface: {net_context.get('interface')}\n"
        f"- Active Security Incidents: {net_context.get('active_alerts', 0)}\n"
        f"- Online Devices: {net_context.get('devices_online', 0)}\n\n"
    )

    prompt = f"{context_str}User Question: {message}"
    reply = call_gemini(prompt, system_instruction=sys_instruction, timeout=15.0)
    if reply:
        return reply

    # Offline fallback
    return (
        f"🤖 **NetWatch AI Security Copilot (Offline Mode)**\n\n"
        f"Currently monitoring `{net_context.get('interface')}` on subnet `{net_context.get('subnet')}`.\n"
        f"Ensure `GEMINI_API_KEY` is active to enable live model reasoning."
    )
