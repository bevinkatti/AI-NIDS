"""
utils.py

Core utilities for configuration management, logging, and helpers.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

import yaml
from loguru import logger


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"


def load_config() -> Dict[str, Any]:
    """
    Load YAML configuration file.

    Returns:
        Dict[str, Any]: Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If config file is missing.
        yaml.YAMLError: If config file is invalid.
    """
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Config file not found at {CONFIG_PATH}")

    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    return config


def setup_logging(config: Dict[str, Any]) -> None:
    """
    Configure Loguru logging.

    Args:
        config (Dict[str, Any]): Application configuration.
    """
    logger.remove()

    log_level = config["logging"]["level"]
    log_file = config["logging"]["log_file"]

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        sys.stdout,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
               "<level>{message}</level>",
    )

    logger.add(
        log_file,
        level=log_level,
        rotation=config["logging"]["rotation"],
        retention=config["logging"]["retention"],
        encoding="utf-8",
    )

    logger.info("Logging initialized successfully")


def get_env_variable(name: str, default: str | None = None) -> str:
    """
    Safely fetch environment variables.

    Args:
        name (str): Environment variable name.
        default (str | None): Default value if not found.

    Returns:
        str: Environment variable value.

    Raises:
        EnvironmentError: If variable not found and no default provided.
    """
    value = os.getenv(name, default)
    if value is None:
        raise EnvironmentError(f"Required environment variable '{name}' not set")
    return value


def ensure_directories() -> None:
    """
    Ensure required project directories exist.
    """
    required_dirs = [
        BASE_DIR / "logs",
        BASE_DIR / "models",
        BASE_DIR / "assets" / "images" / "screenshots",
    ]

    for directory in required_dirs:
        directory.mkdir(parents=True, exist_ok=True)

    logger.debug("Required directories verified")


def initialize_app() -> Dict[str, Any]:
    """
    Initialize application environment.

    Returns:
        Dict[str, Any]: Loaded configuration.
    """
    config = load_config()
    setup_logging(config)
    ensure_directories()

    logger.info("Application initialized successfully")
    return config
