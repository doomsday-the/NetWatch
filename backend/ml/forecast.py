"""Bandwidth forecasting using autoregressive lag feature regression for NetWatch.

Extracts the last ~30 minutes of network-wide throughput,
constructs autoregressive lag features (lag_1, lag_2, lag_3, rolling_mean),
fits a scikit-learn LinearRegression model,
and autoregressively projects bandwidth demands over the upcoming 5 minutes
with expanding confidence intervals.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression

from backend.config import settings
from backend.db import get_connection

logger = logging.getLogger(__name__)


def build_lag_features(
    series: np.ndarray,
    num_lags: int = 3,
) -> Tuple[np.ndarray, np.ndarray]:
    """Construct autoregressive feature matrix and target vector from a 1D time series.

    Features for time t: [series[t-1], series[t-2], series[t-3], rolling_mean(t-3:t)]
    Target for time t  : series[t]

    Args:
        series: 1D numpy array of historical bandwidth observations.
        num_lags: Number of lag steps to include as predictors.

    Returns:
        (X, y) feature matrix and target vector.
    """
    n = len(series)
    if n <= num_lags:
        return np.empty((0, num_lags + 1)), np.empty((0,))

    X_list = []
    y_list = []

    for i in range(num_lags, n):
        lags = [series[i - j] for j in range(1, num_lags + 1)]
        rolling_mean = float(np.mean(lags))
        features = lags + [rolling_mean]

        X_list.append(features)
        y_list.append(series[i])

    return np.array(X_list, dtype=np.float64), np.array(y_list, dtype=np.float64)


def generate_bandwidth_forecast(
    horizon_minutes: float = 5.0,
    lookback_minutes: float = 30.0,
    window_seconds: float = 5.0,
    num_lags: int = 3,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fit autoregressive lag regression on recent network bps and predict future bandwidth.

    Args:
        horizon_minutes: Duration into the future to forecast (default: 5.0 min).
        lookback_minutes: Historical data duration to train regression (default: 30.0 min).
        window_seconds: Window duration step in seconds (default: 5.0s).
        num_lags: Number of autoregressive lags (default: 3).
        db_path: Optional SQLite database path override.

    Returns:
        List of dicts containing ts, predicted_bps, confidence_lower_bps, confidence_upper_bps.
        Returns empty list if fewer than 15 historical data points exist.
    """
    cutoff = time.time() - (lookback_minutes * 60.0)
    sql = """
    SELECT ts, bytes_out, bytes_in
    FROM traffic_metrics
    WHERE src_ip IS NULL AND ts >= ?
    ORDER BY ts ASC
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (cutoff,))
        rows = cursor.fetchall()
    finally:
        conn.close()

    # Minimum threshold: require at least 15 points (~75s) to construct meaningful lag features
    if len(rows) < 15:
        logger.debug("Insufficient traffic metrics to forecast (%d points, min 15 required)", len(rows))
        return []

    # Calculate throughput series (bps)
    w_sec = max(0.1, window_seconds)
    timestamps: List[float] = []
    bps_values: List[float] = []

    for r in rows:
        ts = float(r["ts"])
        b_out = int(r["bytes_out"] or 0)
        b_in = int(r["bytes_in"] or 0)
        bps = ((b_out + b_in) * 8.0) / w_sec
        timestamps.append(ts)
        bps_values.append(bps)

    y_series = np.array(bps_values, dtype=np.float64)

    # 1. Build lag feature matrix
    X_train, y_train = build_lag_features(y_series, num_lags=num_lags)
    if len(X_train) < 10:
        return []

    # 2. Fit LinearRegression model
    model = LinearRegression()
    model.fit(X_train, y_train)

    # 3. Residual standard error for confidence cone
    fitted = model.predict(X_train)
    residuals = y_train - fitted
    std_err = float(np.std(residuals)) if len(residuals) > 1 else 1000.0

    # 4. Multi-step autoregressive roll-forward projection
    num_steps = int((horizon_minutes * 60.0) / w_sec)
    last_ts = timestamps[-1]

    forecast_results: List[Dict[str, Any]] = []
    recent_history = list(y_series[-num_lags:])

    # Dampening factor to stabilize long-range multi-step autoregressive predictions
    global_mean = float(np.mean(y_train))

    for step in range(1, num_steps + 1):
        future_ts = last_ts + (step * w_sec)

        # Prepare lag feature vector: [y_t-1, y_t-2, y_t-3, rolling_mean]
        lags = [recent_history[-j] for j in range(1, num_lags + 1)]
        feat_vector = np.array(lags + [float(np.mean(lags))], dtype=np.float64).reshape(1, -1)

        pred_raw = float(model.predict(feat_vector)[0])
        # Reversion toward baseline mean as horizon grows
        blend_weight = max(0.4, 1.0 - (0.01 * step))
        pred_bps = max(0.0, (pred_raw * blend_weight) + (global_mean * (1.0 - blend_weight)))

        # Update sliding history with new prediction
        recent_history.append(pred_bps)

        # Confidence cone: uncertainty expands with forecast distance
        uncertainty = 1.96 * std_err * math.sqrt(1.0 + (0.04 * step))
        lower_bps = max(0.0, pred_bps - uncertainty)
        upper_bps = pred_bps + uncertainty

        forecast_results.append(
            {
                "ts": float(future_ts),
                "predicted_bps": float(round(pred_bps, 2)),
                "confidence_lower_bps": float(round(lower_bps, 2)),
                "confidence_upper_bps": float(round(upper_bps, 2)),
            }
        )

    logger.debug("Generated %d forecast steps for horizon %.1f min", len(forecast_results), horizon_minutes)
    return forecast_results
