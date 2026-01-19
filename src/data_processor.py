"""
data_processor.py

Synthetic network traffic generator and preprocessing pipeline
inspired by CICIDS2017 dataset characteristics.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from typing import Tuple
from loguru import logger


class DataProcessor:
    """
    Handles synthetic data generation and preprocessing
    for AI-based Network Intrusion Detection.
    """

    ATTACK_TYPES = [
        "BENIGN",
        "DDoS",
        "PortScan",
        "BruteForce",
        "Malware",
    ]

    def __init__(self, random_state: int = 42) -> None:
        self.random_state = random_state
        np.random.seed(self.random_state)

    def generate_synthetic_data(self, n_samples: int = 10000) -> pd.DataFrame:
        """
        Generate CICIDS-style synthetic network traffic.

        Args:
            n_samples (int): Number of samples.

        Returns:
            pd.DataFrame: Generated dataset.
        """
        logger.info("Generating synthetic network traffic data")

        labels = np.random.choice(
            self.ATTACK_TYPES,
            size=n_samples,
            p=[0.55, 0.15, 0.12, 0.10, 0.08],
        )

        data = {
            "duration": np.random.exponential(scale=2.0, size=n_samples),
            "src_bytes": np.random.lognormal(mean=7, sigma=2, size=n_samples),
            "dst_bytes": np.random.lognormal(mean=6, sigma=2, size=n_samples),
            "packet_count": np.random.poisson(lam=20, size=n_samples),
            "flow_packets_per_sec": np.random.gamma(shape=2.0, scale=10.0, size=n_samples),
            "flow_bytes_per_sec": np.random.gamma(shape=2.0, scale=500.0, size=n_samples),
            "syn_flag_count": np.random.poisson(lam=2, size=n_samples),
            "ack_flag_count": np.random.poisson(lam=10, size=n_samples),
            "rst_flag_count": np.random.binomial(1, 0.1, size=n_samples),
            "fin_flag_count": np.random.binomial(1, 0.3, size=n_samples),
            "urg_flag_count": np.random.binomial(1, 0.05, size=n_samples),
            "protocol_tcp": np.random.binomial(1, 0.65, size=n_samples),
            "protocol_udp": np.random.binomial(1, 0.30, size=n_samples),
            "protocol_icmp": np.random.binomial(1, 0.05, size=n_samples),
            "failed_logins": np.random.poisson(lam=0.5, size=n_samples),
            "label": labels,
        }

        df = pd.DataFrame(data)

        df = self._inject_attack_patterns(df)
        logger.info("Synthetic data generation completed")

        return df

    def _inject_attack_patterns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Inject attack-specific behavior into traffic.

        Args:
            df (pd.DataFrame): Raw traffic data.

        Returns:
            pd.DataFrame: Modified traffic data.
        """
        logger.debug("Injecting attack-specific patterns")

        ddos_mask = df["label"] == "DDoS"
        df.loc[ddos_mask, "packet_count"] *= 10
        df.loc[ddos_mask, "flow_packets_per_sec"] *= 5

        scan_mask = df["label"] == "PortScan"
        df.loc[scan_mask, "duration"] *= 0.1
        df.loc[scan_mask, "syn_flag_count"] += 5

        brute_mask = df["label"] == "BruteForce"
        df.loc[brute_mask, "failed_logins"] += 10

        malware_mask = df["label"] == "Malware"
        df.loc[malware_mask, "dst_bytes"] *= 4
        df.loc[malware_mask, "urg_flag_count"] += 1

        return df

    def split_features_labels(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Split features and labels.

        Args:
            df (pd.DataFrame): Dataset.

        Returns:
            Tuple[pd.DataFrame, pd.Series]: X, y
        """
        X = df.drop(columns=["label"])
        y = df["label"]
        return X, y
