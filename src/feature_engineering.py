"""
feature_engineering.py

Feature engineering pipeline for network traffic analysis.
"""

from __future__ import annotations

import pandas as pd
import numpy as np
from loguru import logger


class FeatureEngineer:
    """
    Generates advanced features from raw network traffic data.
    """

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Apply feature engineering.

        Args:
            X (pd.DataFrame): Raw features.

        Returns:
            pd.DataFrame: Engineered features.
        """
        logger.info("Starting feature engineering")

        df = X.copy()

        # Statistical features
        df["byte_ratio"] = df["src_bytes"] / (df["dst_bytes"] + 1)
        df["packets_per_duration"] = df["packet_count"] / (df["duration"] + 0.01)
        df["bytes_per_packet"] = (df["src_bytes"] + df["dst_bytes"]) / (df["packet_count"] + 1)

        # Flag ratios
        df["syn_ack_ratio"] = df["syn_flag_count"] / (df["ack_flag_count"] + 1)
        df["rst_rate"] = df["rst_flag_count"] / (df["packet_count"] + 1)
        df["fin_rate"] = df["fin_flag_count"] / (df["packet_count"] + 1)

        # Protocol dominance
        df["tcp_udp_ratio"] = df["protocol_tcp"] / (df["protocol_udp"] + 1)

        # Temporal & flow behavior
        df["flow_intensity"] = df["flow_bytes_per_sec"] * df["flow_packets_per_sec"]
        df["traffic_density"] = df["packet_count"] / (df["duration"] + 1)

        # Anomaly indicators
        df["high_packet_rate"] = (df["flow_packets_per_sec"] > 100).astype(int)
        df["suspicious_login"] = (df["failed_logins"] > 5).astype(int)
        df["large_payload"] = (df["dst_bytes"] > 1e6).astype(int)

        # Entropy-like approximations
        df["flag_entropy"] = (
            df["syn_flag_count"]
            + df["ack_flag_count"]
            + df["rst_flag_count"]
            + df["fin_flag_count"]
        ) / (df["packet_count"] + 1)

        logger.info("Feature engineering completed")

        return df
