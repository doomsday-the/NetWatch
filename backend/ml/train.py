"""Model training utility for NetWatch anomaly detection.

Loads per-host baseline traffic features from SQLite,
evaluates data sufficiency,
fits an IsolationForest pipeline with StandardScaler,
prints dataset statistics,
and serializes the trained model to model.joblib.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.config import REPO_ROOT, settings
from backend.db import get_connection, get_latest_baseline, init_db
from backend.ml.features import FEATURE_COLUMNS, extract_features

logger = logging.getLogger(__name__)


def load_baseline_training_data(
    db_path: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Tuple[Optional[float], Optional[float]], str]:
    """Load per-host traffic metrics from the recorded baseline period.

    Checks:
    1. Latest baseline record in the SQLite baseline_metadata table.
    2. baseline.json file in repository root.
    3. Fallback to all per-host rows in traffic_metrics if no baseline metadata is found.

    Returns:
        (rows, (start_ts, end_ts), source_description)
    """
    init_db(db_path)
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    source_desc = "all traffic_metrics"

    # 1. Check database metadata
    meta = get_latest_baseline(db_path=db_path)
    if meta:
        start_ts = float(meta["start_ts"])
        end_ts = float(meta["end_ts"])
        source_desc = f"SQLite baseline_metadata #{meta['id']} ('{meta.get('name', 'default')}')"

    # 2. Check baseline.json if no DB record
    if start_ts is None:
        json_file = REPO_ROOT / "baseline.json"
        if json_file.exists():
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    start_ts = float(data["start_ts"])
                    end_ts = float(data["end_ts"])
                    source_desc = f"baseline.json ({data.get('baseline_name', 'default')})"
            except Exception as exc:
                logger.debug("Failed reading baseline.json: %s", exc)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if start_ts is not None and end_ts is not None:
            sql = """
            SELECT id, ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
                   icmp_count, dns_count, other_count, syn_count, unique_dst_ports, unique_dst_ips
            FROM traffic_metrics
            WHERE src_ip IS NOT NULL AND ts >= ? AND ts <= ?
            ORDER BY ts ASC
            """
            cursor.execute(sql, (start_ts, end_ts))
        else:
            sql = """
            SELECT id, ts, src_ip, bytes_out, bytes_in, pps, tcp_count, udp_count,
                   icmp_count, dns_count, other_count, syn_count, unique_dst_ports, unique_dst_ips
            FROM traffic_metrics
            WHERE src_ip IS NOT NULL
            ORDER BY ts ASC
            """
            cursor.execute(sql)

        rows = [dict(r) for r in cursor.fetchall()]
        return rows, (start_ts, end_ts), source_desc
    finally:
        conn.close()


def train_model(
    contamination: Optional[float] = None,
    min_samples: Optional[int] = None,
    output_path: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Any:
    """Train and serialize IsolationForest anomaly detection pipeline.

    Args:
        contamination: Expected anomaly contamination rate (default: 0.02).
        min_samples: Minimum training instances required (default: 20).
        output_path: Output file path for model.joblib.
        db_path: Optional custom SQLite database path.

    Returns:
        Trained sklearn Pipeline.
    """
    contam = contamination if contamination is not None else settings.model_contamination
    threshold_samples = min_samples if min_samples is not None else settings.min_training_samples
    target_path = Path(output_path or settings.model_path).resolve()

    logger.info("Loading baseline training data...")
    raw_rows, (start_ts, end_ts), source_desc = load_baseline_training_data(db_path=db_path)

    # Validate sample size
    if len(raw_rows) < threshold_samples:
        err_msg = (
            f"\n{'='*70}\n"
            f"REFUSING TO TRAIN: Insufficient training samples.\n"
            f"Found only {len(raw_rows)} per-host metric windows from {source_desc}.\n"
            f"A minimum of {threshold_samples} samples is required to build a reliable model.\n\n"
            f"To collect baseline data:\n"
            f"  1. Record live baseline:\n"
            f"     python scripts/record_baseline.py --minutes 10\n"
            f"  2. Or simulate realistic baseline traffic:\n"
            f"     python scripts/simulate_traffic.py --minutes 15\n"
            f"{'='*70}"
        )
        logger.error(err_msg)
        print(err_msg)
        sys.exit(1)

    logger.info("Extracted %d samples from %s", len(raw_rows), source_desc)

    # Extract canonical feature matrix
    X = extract_features(raw_rows)

    # Build Pipeline: StandardScaler + IsolationForest
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    contamination=contam,
                    random_state=42,
                    n_estimators=100,
                    max_samples="auto",
                    n_jobs=-1,
                ),
            ),
        ]
    )

    logger.info("Fitting IsolationForest (contamination=%.4f, samples=%d)...", contam, len(X))
    pipeline.fit(X)

    # Calculate statistics on training dataset
    predictions = pipeline.predict(X)
    inliers = int(np.sum(predictions == 1))
    outliers = int(np.sum(predictions == -1))
    decision_scores = pipeline.decision_function(X)

    stats_summary = {
        "samples": len(X),
        "inliers": inliers,
        "outliers": outliers,
        "outlier_pct": round((outliers / len(X)) * 100.0, 2),
        "decision_mean": round(float(np.mean(decision_scores)), 4),
        "decision_std": round(float(np.std(decision_scores)), 4),
        "features": {},
    }

    for col in FEATURE_COLUMNS:
        stats_summary["features"][col] = {
            "mean": round(float(X[col].mean()), 2),
            "std": round(float(X[col].std()), 2),
            "max": round(float(X[col].max()), 2),
        }

    # Save model artifact with metadata
    target_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": pipeline,
        "feature_columns": FEATURE_COLUMNS,
        "contamination": contam,
        "sample_count": len(X),
        "trained_at": time.time(),
        "baseline_source": source_desc,
        "baseline_range": (start_ts, end_ts),
        "stats": stats_summary,
    }
    joblib.dump(artifact, target_path)
    logger.info("Saved trained model artifact to: %s", target_path)

    # Print summary table
    print("\n" + "=" * 65)
    print("       NETWATCH ISOLATION FOREST MODEL TRAINING SUMMARY")
    print("=" * 65)
    print(f"  Baseline Source    : {source_desc}")
    print(f"  Training Instances : {len(X):,}")
    print(f"  Contamination Rate : {contam:.4f} ({contam * 100:.2f}%)")
    print(f"  Fitted Inliers     : {inliers:,} ({inliers / len(X) * 100:.1f}%)")
    print(f"  Fitted Outliers    : {outliers:,} ({outliers / len(X) * 100:.1f}%)")
    print(f"  Decision Score Mean: {stats_summary['decision_mean']} (std: {stats_summary['decision_std']})")
    print("  Feature Distribution (Mean / Std / Max):")
    for col, st in stats_summary["features"].items():
        print(f"    - {col:<18}: {st['mean']:>10.2f} (std: {st['std']:>9.2f}, max: {st['max']:>10.2f})")
    print(f"  Model Saved To     : {target_path}")
    print("=" * 65)
    print("Model ready for real-time inference by backend.ml.detector!\n")

    return pipeline


def main() -> None:
    """CLI entrypoint for training IsolationForest anomaly detector."""
    parser = argparse.ArgumentParser(description="NetWatch Anomaly Detection Model Training")
    parser.add_argument(
        "--contamination",
        type=float,
        default=None,
        help="Expected proportion of anomalies in baseline dataset (default: from config 0.02)",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=None,
        help="Minimum sample count required to proceed with training (default: 20)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save model.joblib (default: backend/ml/model.joblib)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional custom SQLite database path",
    )

    args = parser.parse_args()

    train_model(
        contamination=args.contamination,
        min_samples=args.min_samples,
        output_path=args.output,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
