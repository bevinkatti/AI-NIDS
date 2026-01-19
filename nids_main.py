"""
nids_main.py

Main Streamlit application for AI-Powered Network Intrusion Detection System.
"""

from __future__ import annotations

import joblib
import random
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px

from src.utils import initialize_app
from src.data_processor import DataProcessor
from src.feature_engineering import FeatureEngineer
from src.database import DatabaseManager, DetectionRepository
#monitoring
from prometheus_client import Counter, start_http_server, REGISTRY


# =========================
# APP INITIALIZATION
# =========================

# Prometheus-safe counter initialization (handles Streamlit reruns)
try:
    DETECTION_COUNTER = Counter(
        "nids_detections_total",
        "Total number of intrusion detections",
    )
except ValueError:
    # Counter already exists in Prometheus registry
    DETECTION_COUNTER = REGISTRY._names_to_collectors["nids_detections_total"]


config = initialize_app()
# Start Prometheus metrics server (runs in background)
try:
    start_http_server(8000)
except OSError:
    # Ignore if Streamlit reloads and port is already in use
    pass


st.set_page_config(
    page_title="AI-NIDS Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load custom CSS
css_path = Path("assets/css/style.css")
if css_path.exists():
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# =========================
# LOAD MODEL & PIPELINES
# =========================

MODEL_PATH = Path("models/nids_model.pkl")

if not MODEL_PATH.exists():
    st.error("❌ Trained model not found. Please train the model first.")
    st.stop()


#this is correct
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
TRAIN_FEATURES = bundle["feature_names"]


feature_engineer = FeatureEngineer()
data_processor = DataProcessor()

db_manager = DatabaseManager(config)
detection_repo = DetectionRepository(db_manager)

# =========================
# HELPER FUNCTIONS
# =========================

def classify_packet(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform intrusion detection on a single packet.

    Args:
        features (Dict[str, Any]): Raw packet features.

    Returns:
        Dict[str, Any]: Prediction result.
    """
    df = pd.DataFrame([features])
    X_fe = feature_engineer.transform(df)
    X_fe = X_fe.reindex(columns=TRAIN_FEATURES, fill_value=0) #new line
    probabilities = model.predict_proba(X_fe)[0]  #thisss

    classes = model.classes_

    idx = int(np.argmax(probabilities))
    prediction = classes[idx]
    confidence = float(probabilities[idx])

    threat_map = {
        "BENIGN": "Safe",
        "PortScan": "Medium",
        "BruteForce": "High",
        "Malware": "High",
        "DDoS": "Critical",
    }

    return {
        "prediction": prediction,
        "confidence": confidence,
        "threat_level": threat_map.get(prediction, "Unknown"),
    }


def random_packet() -> Dict[str, Any]:
    """
    Generate a random packet for quick testing.
    """
    df = data_processor.generate_synthetic_data(1)
    return df.drop(columns=["label"]).iloc[0].to_dict()


# =========================
# SIDEBAR
# =========================

st.sidebar.title("AI-NIDS Control Panel")
st.sidebar.markdown("Production-grade Network Intrusion Detection")

db_status = "Connected" if db_manager.enabled else "In-Memory Mode"
st.sidebar.info(f"Database Status: **{db_status}**")

# =========================
# MAIN TABS
# =========================

tabs = st.tabs(
    [
        "📊 Overview",
        "🛡 Live Detection",
        "📈 Feature Analysis",
        "🕒 Detection History",
    ]
)

# =========================
# TAB 1: OVERVIEW
# =========================

with tabs[0]:
    st.title("AI-Powered Network Intrusion Detection System")

    st.markdown(
        """
        **Key Capabilities**
        - Random Forest ML model (95%+ accuracy)
        - CICIDS-style traffic analysis
        - 27+ engineered features
        - Real-time detection with confidence scoring
        - Persistent storage with graceful fallback
        """
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Model Type", "Random Forest")
    col2.metric("Attack Types", "5")
    col3.metric("Features", "27+")

# =========================
# TAB 2: LIVE DETECTION
# =========================

with tabs[1]:
    st.header("Live Intrusion Detection")

    with st.expander("🔍 Manual Packet Input", expanded=True):
        packet = {}

        cols = st.columns(4)
        packet["duration"] = cols[0].number_input("Duration", 0.0, 100.0, 1.0)
        packet["src_bytes"] = cols[1].number_input("Source Bytes", 0.0, 1e7, 500.0)
        packet["dst_bytes"] = cols[2].number_input("Destination Bytes", 0.0, 1e7, 300.0)
        packet["packet_count"] = cols[3].number_input("Packet Count", 1, 10000, 20)

        cols = st.columns(4)
        packet["flow_packets_per_sec"] = cols[0].number_input("Packets/sec", 0.0, 1000.0, 10.0)
        packet["flow_bytes_per_sec"] = cols[1].number_input("Bytes/sec", 0.0, 1e6, 500.0)
        packet["syn_flag_count"] = cols[2].number_input("SYN Count", 0, 100, 2)
        packet["ack_flag_count"] = cols[3].number_input("ACK Count", 0, 100, 10)

        cols = st.columns(4)
        packet["rst_flag_count"] = cols[0].number_input("RST Count", 0, 10, 0)
        packet["fin_flag_count"] = cols[1].number_input("FIN Count", 0, 10, 1)
        packet["urg_flag_count"] = cols[2].number_input("URG Count", 0, 10, 0)
        packet["failed_logins"] = cols[3].number_input("Failed Logins", 0, 50, 0)

        cols = st.columns(3)
        packet["protocol_tcp"] = cols[0].selectbox("TCP", [0, 1], index=1)
        packet["protocol_udp"] = cols[1].selectbox("UDP", [0, 1], index=0)
        packet["protocol_icmp"] = cols[2].selectbox("ICMP", [0, 1], index=0)

    col1, col2 = st.columns(2)

    if col1.button("🚨 Detect Threat"):
        with st.spinner("Analyzing packet..."):
            result = classify_packet(packet)
        DETECTION_COUNTER.inc()

        detection_repo.save(
            source_ip="manual",
            destination_ip="manual",
            prediction=result["prediction"],
            confidence=result["confidence"],
            threat_level=result["threat_level"],
            features=packet,
        )

        st.success("Detection completed")

        st.metric("Prediction", result["prediction"])
        st.metric("Threat Level", result["threat_level"])
        st.metric("Confidence", f"{result['confidence']:.2%}")

    if col2.button("⚡ Quick Test (Random Packet)"):
        packet = random_packet()
        result = classify_packet(packet)

        st.info("Random packet tested")
        st.metric("Prediction", result["prediction"])
        st.metric("Threat Level", result["threat_level"])
        st.metric("Confidence", f"{result['confidence']:.2%}")

# =========================
# TAB 3: FEATURE ANALYSIS
# =========================

with tabs[2]:
    st.header("Feature Distribution Analysis")

    df = data_processor.generate_synthetic_data(1000)
    feature = st.selectbox("Select Feature", df.columns.drop("label"))

    fig = px.histogram(df, x=feature, color="label", barmode="overlay")
    st.plotly_chart(fig, use_container_width=True)

# =========================
# TAB 4: HISTORY
# =========================

with tabs[3]:
    st.header("Detection History")

    records = detection_repo.list_recent(limit=100)

    if not records:
        st.info("No detection records available")
    else:
        history_df = pd.DataFrame(records)
        st.dataframe(history_df, use_container_width=True)

        csv = history_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download History CSV",
            csv,
            file_name="detection_history.csv",
            mime="text/csv",
        )

    if st.button("🗑 Clear Detection History"):
            detection_repo.clear_all()
            st.success("Detection history cleared")
            st.rerun()

