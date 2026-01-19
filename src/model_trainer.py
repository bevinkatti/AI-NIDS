"""
model_trainer.py

Model training, evaluation, and persistence for AI-NIDS.
"""

from __future__ import annotations

import joblib
import pandas as pd
from pathlib import Path
from typing import Dict, Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score
from loguru import logger


class ModelTrainer:
    """
    Handles Random Forest training and evaluation.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.model = RandomForestClassifier(
            n_estimators=config["ml"]["n_estimators"],
            max_depth=config["ml"]["max_depth"],
            random_state=config["ml"]["random_state"],
            n_jobs=-1,
        )
        self.feature_names: list[str] | None = None

    def train(
        self, X: pd.DataFrame, y: pd.Series
    ) -> Dict[str, Any]:
        """
        Train and evaluate the model.
        """
        logger.info("Starting model training")

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=self.config["ml"]["test_size"],
            random_state=self.config["ml"]["random_state"],
            stratify=y,
        )

        self.model.fit(X_train, y_train)

        # ✅ STORE FEATURE ORDER USED DURING TRAINING
        self.feature_names = list(X.columns)

        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5)

        metrics = {
            "accuracy": accuracy,
            "cv_mean": cv_scores.mean(),
            "cv_std": cv_scores.std(),
            "report": classification_report(y_test, y_pred, output_dict=True),
        }

        logger.info(f"Model accuracy: {accuracy:.4f}")
        return metrics

    def save_model(self, path: Path) -> None:
        """
        Save trained model along with feature schema.
        """
        if self.feature_names is None:
            raise RuntimeError(
                "Feature names not set. Train the model before saving."
            )

        path.parent.mkdir(parents=True, exist_ok=True)

        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
            },
            path,
        )

        logger.info(f"Model and feature schema saved at {path}")
