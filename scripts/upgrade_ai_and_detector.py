from pathlib import Path
import re

# 1. Update backend/ml/detector.py
detector_path = Path("backend/ml/detector.py")
detector_text = detector_path.read_text(encoding="utf-8")

old_return = """        return new_alerts

    def run_detection_cycle(self) -> int:"""

new_return = """        # Intelligent AI False-Positive Triage & Contextual Verification
        net_info = settings.get_network_info(refresh=False)
        gw_ip = net_info.gateway
        my_ip = net_info.ip

        verified_alerts = []
        for alert_item in new_alerts:
            s_ip = alert_item.get("src_ip", "")
            a_type = alert_item.get("alert_type", "")
            sc = alert_item.get("score", 0.0)

            # A. Default Hotspot Gateway Filter: Hotspot routers route NAT/DNS traffic across many ports
            if gw_ip and s_ip == gw_ip:
                if a_type in ("port_scan", "anomaly", "icmp_flood"):
                    logger.info("Suppressed benign hotspot router NAT activity for %s: %s", s_ip, a_type)
                    continue

            # B. Local Client Self-Traffic Filter: Normal web browsing initiates parallel sockets
            if my_ip and s_ip == my_ip:
                if a_type == "syn_flood":
                    logger.info("Suppressed benign client HTTP/websocket handshake for %s", s_ip)
                    continue

            # C. Low-confidence statistical anomaly filter: Ignore low scores (< 0.82)
            if a_type == "anomaly" and sc < 0.82:
                logger.info("Suppressed low-confidence statistical noise for %s (Score: %.2f)", s_ip, sc)
                continue

            # D. Gemini AI Deep Validation: Verify if traffic is genuinely malicious
            try:
                from backend.gemini_service import verify_anomaly_with_gemini
                net_ctx = {
                    "ip": my_ip,
                    "gateway": gw_ip,
                    "subnet": net_info.subnet,
                    "interface": net_info.interface,
                }
                verdict = verify_anomaly_with_gemini(alert_item, net_ctx)
                if not verdict.get("is_genuine_attack", True):
                    logger.info(
                        "Gemini AI identified traffic as benign (%s): %s",
                        verdict.get("classification"),
                        verdict.get("reasoning")
                    )
                    continue
                else:
                    # Enrich alert details with Gemini verdict
                    dt = json.loads(alert_item.get("details_json", "{}"))
                    dt["gemini_analysis"] = verdict
                    alert_item["details_json"] = json.dumps(dt)
            except Exception as e:
                logger.debug("Gemini triage fallback: %s", e)

            verified_alerts.append(alert_item)

        return verified_alerts

    def run_detection_cycle(self) -> int:"""

if old_return in detector_text:
    detector_text = detector_text.replace(old_return, new_return)
    detector_path.write_text(detector_text, encoding="utf-8")
    print("Updated backend/ml/detector.py with Gemini AI triage")
else:
    print("Could not find old_return in backend/ml/detector.py")

print("Patch complete.")
