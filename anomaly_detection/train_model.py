"""
Model Trainer
Random Forest — 5 features matching backend MLModel.predict()
"""
import pickle
import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from generate_data import generate_training_data

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logger import log_info

# ── 5 features — exactly matching backend MLModel.predict() ──
FEATURES = [
    "requests_per_minute",
    "failed_attempts",
    "data_accessed_mb",
    "unique_endpoints",
    "login_time_seconds"
]

LABELS = {
    0: "Normal",
    1: "Brute_Force",
    2: "Data_Exfiltration",
    3: "API_Flooding",
    4: "Privilege_Escalation"
}


def train():
    print("=" * 50)
    print("   ANOMALY DETECTION MODEL TRAINING")
    print("=" * 50)

    df = generate_training_data()

    X = df[FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train.values)
    X_test_scaled  = scaler.transform(X_test.values)

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train_scaled, y_train)

    y_pred   = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.1f}%")
    print(classification_report(y_test, y_pred, target_names=list(LABELS.values())))

    os.makedirs("model", exist_ok=True)
    with open("model/detector.pkl", "wb") as f: pickle.dump(model, f)
    with open("model/scaler.pkl", "wb") as f:  pickle.dump(scaler, f)

    print("Model saved  : anomaly_detection/model/detector.pkl")
    print("Scaler saved : anomaly_detection/model/scaler.pkl")
    print("\n✅ Training Complete!")

    return model, scaler


if __name__ == "__main__":
    train()