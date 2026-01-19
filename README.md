# 🔐 AI-Powered Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)  
![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue)
![Prometheus](https://img.shields.io/badge/Monitoring-Prometheus-orange)  

A **AI-powered Network Intrusion Detection System (AI-NIDS)** built as part of a **VOIS** internship project.  
The system performs **real-time intrusion detection**, supports **multiple attack types**, provides a **professional dashboard**, and is fully **Dockerized with monitoring support**
---

## 🚀 Key Features
### 🔍 Machine Learning

- Random Forest classifier with **95%+ accuracy**
- Detects multiple attack types:
  - DDoS
  - Port Scan
  - Brute Force
  - Malware
  - Benign traffic
- **27+ engineered features** (statistical, protocol-based, temporal)
- Confidence scores & threat level mapping

### ⚙️ System Capabilities
- Real-time packet analysis
- Manual packet input & quick test generation
- Feature alignment to avoid training-inference mismatch
- Graceful fallback when database is unavailable

### 📊 UI / UX
- Modern **Streamlit dashboard**
- Multiple tabs:
  - Overview
  - Live Detection
  - Feature Analysis
  - Detection History
- Professional dark theme with custom CSS
- Export detection history as CSV

### 🗄 Database
- PostgreSQL with SQLAlchemy ORM
- Detection history persistence
- In-memory fallback mode if DB is offline

### 📦 DevOps & Monitoring
- Fully Dockerized (multi-container setup)
- Docker Compose orchestration
- Prometheus monitoring with custom metrics

---

## 🏗 Architecture Overview
User ─▶ Streamlit UI ─▶ Feature Engineering ─▶ ML Model

## 🧪 Tech Stack

| Category | Tools |
|--------|------|
| Language | Python 3.11 |
| ML | scikit-learn |
| UI | Streamlit, Plotly |
| Database | PostgreSQL, SQLAlchemy |
| DevOps | Docker, Docker Compose |
| Monitoring | Prometheus |
| Logging | Loguru |

---

## ⚙️ Installation & Setup

### 🔹 Prerequisites
- Docker & Docker Compose
- Git

---

### 🔹 Run with Docker (Recommended)

```bash
docker compose up -d --build
``` 
Access:  
App → http://localhost:8501  

🔹 Local Run (Without Docker)
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run nids_main.py
```
---
### 📊 Monitoring
Prometheus collects metrics from the application.  
grafana has visual data monitoring

Prometheus → http://localhost:9090  
Grafana → http://localhost:3000  

---
### 🧠Learning

-End-to-end ML system design  
-Feature engineering for network security data  
-Handling ML inference consistency  
-Dockerizing production ML systems  
-Monitoring Streamlit applications with Prometheus  
-Graceful failure handling in real systems.

---
### 📌 Future Enhancements

Live packet capture (pcap / scapy)  
FastAPI REST endpoint   
Model retraining pipeline  
Alerting system for critical threats

---
### 👤 Author
Abhishek (VOIS Intern) -
AI / ML | CyberSecurity | MLOps