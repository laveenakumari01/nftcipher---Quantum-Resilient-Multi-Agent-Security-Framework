"""
Anomaly Detector
ML Model + Rule Based fallback
Used by Sentinel Agent
LLM + ML both work together
"""
import pickle
import os
import time
from logger import log_info, log_threat, log_error

FEATURES = [
    "request_count",
    "failed_attempts",
    "data_size", 
    "unique_actions",
    "time_window",
    "repeated_action",
    "unusual_hour"
]

LABELS = {
    0: "Normal",
    1: "Brute_Force",
    2: "Data_Exfiltration",
    3: "API_Flooding",
    4: "Privilege_Escalation"
}

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "model", "detector.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "model", "scaler.pkl")


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_loaded = False
        self._load_model()

    def _load_model(self):
        """Load trained model from this project"""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                self.model_loaded = True
                log_info("Anomaly Detection model loaded successfully")
            else:
                log_info("Model not found — run train_model.py first — using rule-based")
        except Exception as e:
            log_error(f"Model load error: {e}")

    def extract_features(self, agent_data: dict) -> list:
        return [
            agent_data.get("request_count", 0),
            agent_data.get("failed_attempts", 0),
            agent_data.get("data_size", 0),
            agent_data.get("unique_actions", 1),
            agent_data.get("time_window", 60),
            1 if agent_data.get("repeated_action") else 0,
            1 if agent_data.get("unusual_hour") else 0,
        ]

    def detect(self, agent_id: str, agent_data: dict) -> dict:
        features = self.extract_features(agent_data)

        if self.model_loaded:
            try:
                import numpy as np
                features_array = np.array(features).reshape(1, -1)
                features_scaled = self.scaler.transform(features_array)
            
                prediction = self.model.predict(features_scaled)[0]
                probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Risk score — anomaly probability
                is_anomaly = prediction != 0
                risk_score = float(probabilities[prediction])

                attack_type = LABELS.get(int(prediction), "Unknown")

                log_info(f"ML Detection: [{agent_id}] → {attack_type} | Risk: {risk_score:.2f}")
                return self._build_result(agent_id, is_anomaly, attack_type, risk_score, "ML_MODEL")

            except Exception as e:
                log_error(f"ML error: {e} — using rules")

        return self._rule_based(agent_id, agent_data)

    def _rule_based(self, agent_id: str, agent_data: dict) -> dict:
        """Rule-based fallback"""
        rc = agent_data.get("request_count", 0)
        fa = agent_data.get("failed_attempts", 0)
        ds = agent_data.get("data_size", 0)
        ua = agent_data.get("unique_actions", 1)

        if fa >= 3:
            return self._build_result(agent_id, True, "Brute_Force", min(0.5 + fa * 0.1, 1.0), "RULE")
        elif rc > 50:
            return self._build_result(agent_id, True, "API_Flooding", min(0.4 + rc * 0.01, 1.0), "RULE")
        elif ds > 10000:
            return self._build_result(agent_id, True, "Data_Exfiltration", min(0.6, 1.0), "RULE")
        elif ua > 8:
            return self._build_result(agent_id, True, "Privilege_Escalation", 0.7, "RULE")

        return self._build_result(agent_id, False, "Normal", 0.1, "RULE")

    def _build_result(self, agent_id, is_anomaly, attack_type, risk_score, method):
        risk_level = (
            "HIGH" if risk_score >= 0.9 else
            "MEDIUM" if risk_score >= 0.6 else
            "LOW" if risk_score >= 0.3 else
            "SAFE"
        )
        if is_anomaly:
            log_threat(f"[{agent_id}] {attack_type} | Risk: {risk_score:.2f} | {risk_level}")
        return {
            "agent_id": agent_id,
            "is_anomaly": is_anomaly,
            "attack_type": attack_type,
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "detection_method": method,
            "timestamp": time.time()
        }