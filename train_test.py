from src.utils import initialize_app
from src.data_processor import DataProcessor
from src.feature_engineering import FeatureEngineer
from src.model_trainer import ModelTrainer
from pathlib import Path

config = initialize_app()

dp = DataProcessor()
df = dp.generate_synthetic_data(8000)
X, y = dp.split_features_labels(df)

fe = FeatureEngineer()
X_fe = fe.transform(X)

trainer = ModelTrainer(config)
metrics = trainer.train(X_fe, y)

trainer.save_model(Path("models/nids_model.pkl"))

print("Accuracy:", metrics["accuracy"])
