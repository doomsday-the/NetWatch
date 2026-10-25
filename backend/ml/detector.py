"""Real-time machine learning and heuristic anomaly detector for NetWatch.

Runs as a background daemon:
- Scores per-host traffic metrics using the trained IsolationForest pipeline.
- Runs heuristic threat detection rules (port_scan, syn_flood, icmp_flood, bandwidth_hog)
  independently of ML models, attaching ML scores when available.
- Falls back to rules-only mode if no trained model exists.
- Enforces a 30-second cooldown per IP and alert type to merge repeats and eliminate spam.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
import pandas as pd

from backend.config import settings
from backend.db import get_connection, init_db, insert_ai_alerts_batch
from backend.ml.features import FEATURE_COLUMNS, extract_features_with_metadata
from backend.ml.rules import classify_window_anomalies

logger = logging.getLogger(__name__)


def decision_to_anomaly_score(decision_value: float) -> float:
    """Convert IsolationForest decision function score to a 0.0-1.0 anomaly confidence score."""
    score = 0.5 - (decision_value * 2.5)
    return float(np.clip(score, 0.0, 1.0))


class AnomalyDetectorService:
    """Real-time network traffic anomaly scoring and alert generation service."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        window_seconds: Optional[float] = None,
        cooldown_seconds: Optional[float] = None,
        rules_only: bool = False,
        db_path: Optional[str] = None,
    ) -> None:
        self.model_path = Path(model_path or settings.model_path).resolve()
        self.window_seconds = window_seconds or settings.agg_window_seconds
        self.cooldown_seconds = cooldown_seconds or settings.alert_cooldown_seconds
        self.rules_only = rules_only
        self.db_path = db_path

        self.last_evaluated_id = 0
        self.stop_requested = False

        # Alert spam suppression: (src_ip, alert_type) -> last_alert_timestamp
        self.last_alert_time: Dict[Tuple[str, str], float] = {}
        self.repeat_counts: Dict[Tuple[str, str], int] = {}

        # Model artifact state
        self.pipeline: Optional[Any] = None
        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load trained IsolationForest pipeline from disk."""
        if self.rules_only:
            logger.info("Running in explicit rules-only mode per configuration")
            self.pipeline = None
            return

        if not self.model_path.exists():
            logger.warning(
                "No trained ML model found at '%s'. Running in rules-only detection mode.",
                self.model_path,
            )
            self.pipeline = None
            return

        try:
            artifact = joblib.load(self.model_path)
            self.pipeline = artifact.get("pipeline", artifact)
            logger.info("Loaded IsolationForest anomaly detector model from: %s", self.model_path)
        except Exception as exc:
            logger.error("Failed loading model from %s: %s. Falling back to rules-only mode.", self.model_path, exc)
            self.pipeline = None

    def fetch_unscored_metrics(self) -> List[Dict[str, Any]]:
        """Fetch newly aggregated per-host traffic metrics since last watermark."""
        sql = """
        SELECT id, ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
               icmp_count, dns_count, other_count, syn_count, unique_dst_ports, unique_dst_ips
        FROM traffic_metrics
        WHERE src_ip IS NOT NULL AND id > ?
        ORDER BY id ASC
        LIMIT 1000
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(sql, (self.last_evaluated_id,))
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def evaluate_batch(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate a batch of per-host metric rows using ML and heuristic rules.

        Returns:
            List of generated alerts respecting 30s cooldown per (src_ip, alert_type).
        """
        if not rows:
            return []

        now = time.time()
        new_alerts: List[Dict[str, Any]] = []

        # Extract features
        features_df, meta_df = extract_features_with_metadata(rows)

        # 1. Machine Learning Inference (IsolationForest)
        ml_anomalies: Dict[int, Tuple[float, float, bool]] = {}  # row_idx -> (score, decision_val, is_outlier)
        if self.pipeline is not None and not features_df.empty:
            try:
                decisions = self.pipeline.decision_function(features_df)
                predictions = self.pipeline.predict(features_df)

                for idx in range(len(rows)):
                    df_val = float(decisions[idx])
                    is_outlier = int(predictions[idx]) == -1
                    score = decision_to_anomaly_score(df_val)
                    ml_anomalies[idx] = (score, df_val, is_outlier)
            except Exception as exc:
                logger.error("ML model evaluation error: %s", exc)

        # 2. Process each row
        for idx, row in enumerate(rows):
            src_ip = row["src_ip"]
            row_id = row["id"]
            if row_id > self.last_evaluated_id:
                self.last_evaluated_id = row_id

            feature_dict = features_df.iloc[idx].to_dict()

            ml_tuple = ml_anomalies.get(idx)
            ml_score = ml_tuple[0] if ml_tuple else None
            ml_outlier = ml_tuple[2] if ml_tuple else False

            # A. Heuristic Rule Classification (Runs independently of ML model)
            rule_alerts = classify_window_anomalies(
                feature_dict,
                src_ip=src_ip,
                ml_score=ml_score,
            )

            matched_rule = False
            for rule_alert in rule_alerts:
                matched_rule = True
                alert_type = rule_alert["alert_type"]
                cooldown_key = (src_ip, alert_type)
                last_time = self.last_alert_time.get(cooldown_key, 0.0)

                if now - last_time < self.cooldown_seconds:
                    # Merge repeated alert within cooldown
                    self.repeat_counts[cooldown_key] = self.repeat_counts.get(cooldown_key, 0) + 1
                    continue

                self.last_alert_time[cooldown_key] = now
                repeat_count = self.repeat_counts.pop(cooldown_key, 0)

                details = dict(rule_alert.get("details", {}))
                details.update(
                    {
                        "metric_id": row_id,
                        "feature_values": feature_dict,
                        "repeat_count": repeat_count,
                    }
                )

                new_alerts.append(
                    {
                        "ts": float(row.get("ts") or now),
                        "alert_type": alert_type,
                        "severity": rule_alert["severity"],
                        "src_ip": src_ip,
                        "message": rule_alert["message"],
                        "score": round(float(rule_alert["score"]), 3),
                        "acknowledged": 0,
                        "details_json": json.dumps(details),
                    }
                )

            # B. Statistical ML Anomaly Alert (if ML flagged an outlier and no specific rule caught it)
            if ml_tuple and (ml_outlier or ml_score >= settings.anomaly_threshold) and not matched_rule:
                alert_type = "anomaly"
                cooldown_key = (src_ip, alert_type)
                last_time = self.last_alert_time.get(cooldown_key, 0.0)

                if now - last_time < self.cooldown_seconds:
                    self.repeat_counts[cooldown_key] = self.repeat_counts.get(cooldown_key, 0) + 1
                    continue

                self.last_alert_time[cooldown_key] = now
                repeat_count = self.repeat_counts.pop(cooldown_key, 0)

                if ml_score >= settings.critical_threshold:
                    severity = "high"
                elif ml_score >= settings.anomaly_threshold:
                    severity = "medium"
                else:
                    severity = "low"

                msg = f"Statistical traffic anomaly detected on {src_ip} (Score: {ml_score:.2f}) [PPS: {feature_dict.get('pps', 0):.1f}, Ports: {int(feature_dict.get('unique_dst_ports', 0))}]"
                details = {
                    "detector": "IsolationForest",
                    "anomaly_score": round(ml_score, 4),
                    "decision_score": round(ml_tuple[1], 4),
                    "metric_id": row_id,
                    "feature_values": feature_dict,
                    "repeat_count": repeat_count,
                }

                new_alerts.append(
                    {
                        "ts": float(row.get("ts") or now),
                        "alert_type": alert_type,
                        "severity": severity,
                        "src_ip": src_ip,
                        "message": msg,
                        "score": round(ml_score, 3),
                        "acknowledged": 0,
                        "details_json": json.dumps(details),
                    }
                )

        # Intelligent AI False-Positive Triage & Contextual Verification
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

    def run_detection_cycle(self) -> int:
        """Execute one detection cycle across unexamined metrics."""
        rows = self.fetch_unscored_metrics()
        if not rows:
            return 0

        alerts = self.evaluate_batch(rows)
        if alerts:
            insert_ai_alerts_batch(alerts, db_path=self.db_path)
            logger.info("Detector generated %d new threat alerts", len(alerts))

        return len(rows)

    def run_loop(self, once: bool = False) -> None:
        """Run anomaly detector in periodic loop."""
        mode_str = "IsolationForest ML + Rules" if self.pipeline is not None else "Heuristic Rules-Only"
        logger.info("=" * 65)
        logger.info("NetWatch Anomaly Detector Service Started")
        logger.info("  Mode        : %s", mode_str)
        logger.info("  Cadence     : %.1f seconds", self.window_seconds)
        logger.info("  Cooldown    : %.1f seconds", self.cooldown_seconds)
        logger.info("  Threshold   : %.2f (Warning), %.2f (Critical)", settings.anomaly_threshold, settings.critical_threshold)
        logger.info("=" * 65)

        if self.last_evaluated_id == 0:
            conn = get_connection(self.db_path)
            try:
                c = conn.cursor()
                c.execute("SELECT COALESCE(MAX(id), 0) FROM traffic_metrics WHERE src_ip IS NOT NULL")
                row = c.fetchone()
                self.last_evaluated_id = max(0, (row[0] or 0) - 100)
            finally:
                conn.close()

        while not self.stop_requested:
            start_t = time.time()
            try:
                processed = self.run_detection_cycle()
            except Exception as exc:
                logger.error("Error during detector cycle: %s", exc, exc_info=True)
                processed = 0

            if once or self.stop_requested:
                break

            elapsed = time.time() - start_t
            sleep_time = max(0.5, self.window_seconds - elapsed)

            sleep_end = time.time() + sleep_time
            while not self.stop_requested and time.time() < sleep_end:
                time.sleep(0.2)

        logger.info("NetWatch Anomaly Detector stopped cleanly.")


def main() -> None:
    """CLI entrypoint for NetWatch anomaly detector."""
    parser = argparse.ArgumentParser(description="NetWatch Real-time Anomaly Detector")
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Custom path to model.joblib",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=None,
        help="Loop evaluation interval in seconds (default: 5.0s)",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=None,
        help="Alert cooldown duration per IP and type (default: 30s)",
    )
    parser.add_argument(
        "--rules-only",
        action="store_true",
        help="Force heuristic rules-only mode without loading ML model",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Evaluate pending metrics and exit immediately",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    service = AnomalyDetectorService(
        model_path=args.model_path,
        window_seconds=args.window,
        cooldown_seconds=args.cooldown,
        rules_only=args.rules_only,
        db_path=args.db_path,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d, stopping detector...", signum)
        service.stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    service.run_loop(once=args.once)


if __name__ == "__main__":
    main()
