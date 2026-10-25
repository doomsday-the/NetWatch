"""Unit tests for NetWatch feature engineering module."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from backend.ml.features import (
    FEATURE_COLUMNS,
    extract_features,
    extract_features_with_metadata,
)


def test_feature_columns_definition() -> None:
    """Verify canonical feature column list is complete and properly ordered."""
    assert "pps" in FEATURE_COLUMNS
    assert "bytes_out" in FEATURE_COLUMNS
    assert "bytes_in" in FEATURE_COLUMNS
    assert "syn_count" in FEATURE_COLUMNS
    assert "icmp_count" in FEATURE_COLUMNS
    assert "unique_dst_ports" in FEATURE_COLUMNS
    assert "unique_dst_ips" in FEATURE_COLUMNS
    assert "syn_ratio" in FEATURE_COLUMNS
    assert len(FEATURE_COLUMNS) == 8


def test_extract_features_empty_input() -> None:
    """Verify handling of empty lists and empty DataFrames."""
    empty_df = extract_features([])
    assert isinstance(empty_df, pd.DataFrame)
    assert list(empty_df.columns) == FEATURE_COLUMNS
    assert len(empty_df) == 0

    empty_df2 = extract_features(pd.DataFrame())
    assert isinstance(empty_df2, pd.DataFrame)
    assert list(empty_df2.columns) == FEATURE_COLUMNS
    assert len(empty_df2) == 0


def test_extract_features_missing_columns() -> None:
    """Verify missing metrics are imputed with zero without errors."""
    partial_data = [
        {"pps": 12.0, "bytes_out": 4096},
        {"bytes_in": 8192, "syn_count": 5},
    ]
    df = extract_features(partial_data)
    assert len(df) == 2
    assert list(df.columns) == FEATURE_COLUMNS

    # Check defaults
    assert df.loc[0, "bytes_in"] == 0.0
    assert df.loc[0, "syn_count"] == 0.0
    assert df.loc[1, "pps"] == 0.0


def test_syn_ratio_calculation() -> None:
    """Verify syn_ratio computation edge cases: division by zero, clamping."""
    sample_data = [
        # Normal ratio: 10 / 50 = 0.20
        {"syn_count": 10, "tcp_count": 50},
        # Zero TCP but positive SYN: should clamp to 1.0
        {"syn_count": 5, "tcp_count": 0},
        # Both zero: should be 0.0
        {"syn_count": 0, "tcp_count": 0},
        # SYN greater than TCP (anomalous counter edge case): clamp to 1.0
        {"syn_count": 100, "tcp_count": 50},
    ]

    features = extract_features(sample_data)
    assert features.loc[0, "syn_ratio"] == pytest.approx(0.20, abs=1e-4)
    assert features.loc[1, "syn_ratio"] == 1.0
    assert features.loc[2, "syn_ratio"] == 0.0
    assert features.loc[3, "syn_ratio"] == 1.0


def test_extract_features_with_metadata() -> None:
    """Verify feature matrix and metadata DataFrame split correctly."""
    records = [
        {
            "ts": 1700000000.0,
            "src_ip": "192.168.1.10",
            "pps": 20.0,
            "bytes_out": 15000,
            "bytes_in": 30000,
            "syn_count": 2,
            "icmp_count": 0,
            "tcp_count": 20,
            "unique_dst_ports": 4,
            "unique_dst_ips": 3,
        },
        {
            "ts": 1700000005.0,
            "src_ip": "192.168.1.20",
            "pps": 5.0,
            "bytes_out": 2000,
            "bytes_in": 4000,
            "syn_count": 0,
            "icmp_count": 1,
            "tcp_count": 5,
            "unique_dst_ports": 1,
            "unique_dst_ips": 1,
        },
    ]

    features_df, meta_df = extract_features_with_metadata(records)
    assert len(features_df) == 2
    assert len(meta_df) == 2
    assert list(features_df.columns) == FEATURE_COLUMNS
    assert list(meta_df.columns) == ["ts", "src_ip"]
    assert meta_df.loc[0, "src_ip"] == "192.168.1.10"
    assert meta_df.loc[1, "src_ip"] == "192.168.1.20"
