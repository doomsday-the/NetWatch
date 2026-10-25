"""Feature engineering for NetWatch machine learning anomaly detection.

Extracts normalized statistical feature vectors from per-source-IP traffic_metrics rows:
- pps (packets per second)
- bytes_out (bytes transmitted)
- bytes_in (bytes received)
- syn_count (TCP SYN packets without ACK)
- icmp_count (ICMP packet volume)
- unique_dst_ports (distinct target ports)
- unique_dst_ips (distinct target IPs)
- syn_ratio (ratio of SYN packets to total TCP volume)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Sequence, Tuple, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Complete list of canonical feature names used by IsolationForest and ML detectors
FEATURE_COLUMNS: List[str] = [
    "pps",
    "bytes_out",
    "bytes_in",
    "syn_count",
    "icmp_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "syn_ratio",
]


def extract_features(
    data: Union[pd.DataFrame, Sequence[Dict[str, Any]]],
) -> pd.DataFrame:
    """Extract and validate numeric feature DataFrame from per-IP traffic metrics.

    Args:
        data: DataFrame or sequence of dicts containing traffic_metrics columns.

    Returns:
        DataFrame containing exactly the canonical FEATURE_COLUMNS, with missing
        values replaced by 0.0 and cast to float64.
    """
    if isinstance(data, pd.DataFrame):
        df = data.copy()
    elif isinstance(data, (list, tuple)):
        if not data:
            return pd.DataFrame(columns=FEATURE_COLUMNS, dtype=np.float64)
        df = pd.DataFrame(list(data))
    else:
        raise TypeError(f"Expected DataFrame or Sequence of dicts, got {type(data)}")

    if df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS, dtype=np.float64)

    # Ensure required raw metric columns exist with default 0
    raw_dependencies = [
        "pps",
        "bytes_out",
        "bytes_in",
        "syn_count",
        "icmp_count",
        "tcp_count",
        "unique_dst_ports",
        "unique_dst_ips",
    ]
    for col in raw_dependencies:
        if col not in df.columns:
            df[col] = 0.0

    # Fill NaNs with zeros
    df = df.fillna(0.0)

    # Calculate syn_ratio: syn_count / max(tcp_count, 1)
    tcp_col = pd.to_numeric(df["tcp_count"], errors="coerce").fillna(0.0).values
    syn_col = pd.to_numeric(df["syn_count"], errors="coerce").fillna(0.0).values

    with np.errstate(divide="ignore", invalid="ignore"):
        syn_ratio = np.where(
            tcp_col > 0,
            syn_col / tcp_col,
            np.where(syn_col > 0, 1.0, 0.0),
        )
        syn_ratio = np.clip(np.nan_to_num(syn_ratio, nan=0.0, posinf=1.0, neginf=0.0), 0.0, 1.0)

    df["syn_ratio"] = syn_ratio

    # Select only the model feature columns and convert to float64
    features_df = df[FEATURE_COLUMNS].astype(np.float64).fillna(0.0)
    return features_df


def extract_features_with_metadata(
    data: Sequence[Dict[str, Any]],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Extract feature matrix alongside metadata (id, ts, src_ip).

    Args:
        data: Sequence of row dictionaries from traffic_metrics.

    Returns:
        Tuple of (features_df, metadata_df).
    """
    if not data:
        return (
            pd.DataFrame(columns=FEATURE_COLUMNS, dtype=np.float64),
            pd.DataFrame(columns=["id", "ts", "src_ip"]),
        )

    df = pd.DataFrame(list(data))
    meta_cols = [c for c in ["id", "ts", "src_ip"] if c in df.columns]
    meta_df = df[meta_cols].copy()
    features_df = extract_features(df)

    return features_df, meta_df
