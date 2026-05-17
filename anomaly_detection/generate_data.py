"""
Training Data Generator
5 features — matches backend MLModel.predict() exactly
"""
import pandas as pd
import numpy as np
import os


def generate_training_data():
    print("Generating training data...")
    np.random.seed(42)
    records = []

    # 400 Normal
    for _ in range(400):
        records.append({
            "requests_per_minute": np.random.uniform(1, 10),
            "failed_attempts":     np.random.randint(0, 2),
            "data_accessed_mb":    np.random.uniform(0.1, 5.0),
            "unique_endpoints":    np.random.randint(1, 5),
            "login_time_seconds":  np.random.uniform(0.5, 3.0),
            "label": 0
        })

    # 100 Brute Force — high failed_attempts, fast login
    for _ in range(100):
        records.append({
            "requests_per_minute": np.random.uniform(30, 200),
            "failed_attempts":     np.random.randint(8, 20),
            "data_accessed_mb":    np.random.uniform(0.1, 2.0),
            "unique_endpoints":    np.random.randint(1, 3),
            "login_time_seconds":  np.random.uniform(0.01, 0.1),
            "label": 1
        })

    # 100 Data Exfiltration — very high data_accessed_mb
    for _ in range(100):
        records.append({
            "requests_per_minute": np.random.uniform(5, 30),
            "failed_attempts":     np.random.randint(0, 2),
            "data_accessed_mb":    np.random.uniform(100.0, 500.0),
            "unique_endpoints":    np.random.randint(4, 15),
            "login_time_seconds":  np.random.uniform(0.05, 0.5),
            "label": 2
        })

    # 100 API Flooding — very high requests_per_minute
    for _ in range(100):
        records.append({
            "requests_per_minute": np.random.uniform(100, 300),
            "failed_attempts":     np.random.randint(0, 3),
            "data_accessed_mb":    np.random.uniform(1.0, 10.0),
            "unique_endpoints":    np.random.randint(1, 4),
            "login_time_seconds":  np.random.uniform(0.01, 0.05),
            "label": 3
        })

    # 100 Privilege Escalation — high unique_endpoints
    for _ in range(100):
        records.append({
            "requests_per_minute": np.random.uniform(10, 50),
            "failed_attempts":     np.random.randint(0, 3),
            "data_accessed_mb":    np.random.uniform(5.0, 30.0),
            "unique_endpoints":    np.random.randint(8, 20),
            "login_time_seconds":  np.random.uniform(0.05, 0.3),
            "label": 4
        })

    df = pd.DataFrame(records)
    os.makedirs("model", exist_ok=True)
    df.to_csv("model/training_data.csv", index=False)
    print(f"Training data saved — {len(df)} records")
    print(f"Labels: {df['label'].value_counts().sort_index().to_dict()}")
    return df


if __name__ == "__main__":
    generate_training_data()