"""
database.py

PostgreSQL database integration using SQLAlchemy with
connection pooling, repository pattern, and graceful fallback.
"""

from __future__ import annotations
import os
import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
)
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from loguru import logger

from src.utils import get_env_variable


Base = declarative_base()


# =========================
# ORM MODELS
# =========================

class Detection(Base):
    """
    Stores each intrusion detection event.
    """

    __tablename__ = "detections"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String(64))
    destination_ip = Column(String(64))
    prediction = Column(String(50), index=True)
    confidence = Column(Float)
    threat_level = Column(String(20))
    features = Column(JSON)


class ModelVersionRepository:
    """
    Repository for ML model version tracking.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def register(
        self, version: str, accuracy: float, metadata: Dict[str, Any]
    ) -> None:
        """
        Register a trained model version.
        """
        if not self.db.enabled:
            return

        session = self.db.get_session()
        if session is None:
            return

        try:
            model = ModelVersion(
                version=version,
                accuracy=accuracy,
                model_metadata=metadata,
            )
            session.add(model)
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            logger.error(f"Failed to register model version: {exc}")
        finally:
            session.close()


# =========================
# DATABASE MANAGER
# =========================

class DatabaseManager:
    """
    Manages database engine, sessions, and health checks.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.engine = None
        self.SessionLocal = None
        self.enabled = config["database"]["enabled"]
        self.fallback = config["database"]["fallback_to_memory"]

        if self.enabled:
            self._initialize_engine()

    def _initialize_engine(self) -> None:
        """
        Initialize SQLAlchemy engine with connection pooling.
        """
        try:
            password = get_env_variable(
                self.config["database"]["password_env"], ""
            )

            host = os.getenv("DB_HOST", self.config["database"]["host"])
            port = os.getenv("DB_PORT", self.config["database"]["port"])
            name = os.getenv("DB_NAME", self.config["database"]["name"])
            user = os.getenv("DB_USER", self.config["database"]["user"])

            db_url = (
                f"postgresql+psycopg2://"
                f"{user}:{password}@"
                f"{host}:{port}/"
                f"{name}"
            )


            self.engine = create_engine(
                db_url,
                pool_size=self.config["database"]["pool_size"],
                max_overflow=self.config["database"]["max_overflow"],
                pool_pre_ping=True,
            )

            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
            )

            Base.metadata.create_all(self.engine)
            logger.info("Database connection established")

        except OperationalError as exc:
            logger.error(f"Database unavailable: {exc}")
            if not self.fallback:
                raise
            logger.warning("Falling back to in-memory mode")
            self.enabled = False

    def get_session(self) -> Optional[Session]:
        """
        Create a new database session.

        Returns:
            Optional[Session]: SQLAlchemy session or None if disabled.
        """
        if not self.enabled or self.SessionLocal is None:
            return None
        return self.SessionLocal()

    def test_connection(self) -> bool:
        """
        Test database connectivity.

        Returns:
            bool: True if connection is healthy.
        """
        try:
            if not self.engine:
                return False
            with self.engine.connect():
                return True
        except SQLAlchemyError:
            return False


# =========================
# REPOSITORIES
# =========================

class DetectionRepository:
    """
    Repository for Detection persistence.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._memory_store: List[Dict[str, Any]] = []

    def save(
        self,
        source_ip: str,
        destination_ip: str,
        prediction: str,
        confidence: float,
        threat_level: str,
        features: Dict[str, Any],
    ) -> None:
        """
        Save a detection event.
        """
        if not self.db.enabled:
            self._memory_store.append(
                {
                    "timestamp": datetime.datetime.utcnow(),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "prediction": prediction,
                    "confidence": confidence,
                    "threat_level": threat_level,
                    "features": features,
                }
            )
            return

        session = self.db.get_session()
        if session is None:
            return

        try:
            detection = Detection(
                source_ip=source_ip,
                destination_ip=destination_ip,
                prediction=prediction,
                confidence=confidence,
                threat_level=threat_level,
                features=features,
            )
            session.add(detection)
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            logger.error(f"Failed to save detection: {exc}")
        finally:
            session.close()

    def list_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent detections.
        """
        if not self.db.enabled:
            return self._memory_store[-limit:]

        session = self.db.get_session()
        if session is None:
            return []

        try:
            records = (
                session.query(Detection)
                .order_by(Detection.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "timestamp": r.timestamp,
                    "source_ip": r.source_ip,
                    "destination_ip": r.destination_ip,
                    "prediction": r.prediction,
                    "confidence": r.confidence,
                    "threat_level": r.threat_level,
                }
                for r in records
            ]
        finally:
            session.close()


class ModelVersionRepository:
    """
    Repository for ML model version tracking.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def register(
        self, version: str, accuracy: float, metadata: Dict[str, Any]
    ) -> None:
        """
        Register a trained model version.
        """
        if not self.db.enabled:
            return

        session = self.db.get_session()
        if session is None:
            return

        try:
            model = ModelVersion(
                version=version,
                accuracy=accuracy,
                metadata=metadata,
            )
            session.add(model)
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            logger.error(f"Failed to register model version: {exc}")
        finally:
            session.close()
