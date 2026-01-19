from src.utils import initialize_app
from src.database import DatabaseManager, DetectionRepository

config = initialize_app()

db = DatabaseManager(config)
repo = DetectionRepository(db)

repo.save(
    source_ip="192.168.1.10",
    destination_ip="10.0.0.5",
    prediction="DDoS",
    confidence=0.97,
    threat_level="Critical",
    features={"packet_rate": 1200},
)

print(repo.list_recent())
