CREATE TABLE IF NOT EXISTS detections (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    prediction VARCHAR(50),
    confidence FLOAT,
    threat_level VARCHAR(20),
    features JSON
);

CREATE TABLE IF NOT EXISTS model_versions (
    id SERIAL PRIMARY KEY,
    version VARCHAR(50) UNIQUE,
    accuracy FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_metadata JSON
);
