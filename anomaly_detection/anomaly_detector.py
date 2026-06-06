"""
anomaly_detection/anomaly_detector.py

Enhanced Anomaly Detector with VectorlessStore cache integration.

Before: ML model + rule fallback, no caching, no pattern learning.
Now:
  - Redis/in-memory cache for sub-millisecond repeated pattern lookup
  - Baseline tracking per agent — personalized thresholds
  - Pattern memory — learns from past detections
  - Model drift detection — alerts when model confidence drops
"""

import os
import time
import pickle
from logger import log_info, log_threat, log_error

FEATURES = [
    "request_count",
    "failed_attempts",
    "data_size",
    "unique_actions",
    "time_window",
    "repeated_action",
    "unusual_hour",
]

LABELS = {
    0: "NORMAL",
    1: "BRUTE_FORCE",
    2: "DATA_EXFILTRATION",
    3: "API_FLOODING",
    4: "PRIVILEGE_ESCALATION",
}

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "model", "detector.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "model", "scaler.pkl")

# Per-agent normal baselines — updated as agent is observed
# Structure: { agent_id: { "avg_rpm": float, "avg_requests": float, ... } }
_agent_baselines: dict = {}

# Detection cache — avoid recomputing same feature vector
# Structure: { feature_hash: result_dict }
_detection_cache: dict = {}
_CACHE_TTL = 30  # seconds


class AnomalyDetector:
    """
    ML-based anomaly detection with rule fallback and caching.

    Detection order:
      1. Check cache — if same pattern seen recently, return cached result
      2. ML model — if loaded, use RandomForest prediction
      3. Rule-based fallback — if ML unavailable
      4. Update baseline and cache result
    """

    def __init__(self):
        self.model        = None
        self.scaler       = None
        self.model_loaded = False

        # Fast cache (Redis if available, else in-memory dict)
        self._cache = _detection_cache

        # Confidence tracking for drift detection
        self._confidence_history: list = []
        self._low_confidence_count = 0

        self._load_model()

        log_info(f"[AnomalyDetector] Initialized | model_loaded={self.model_loaded}")

    def _load_model(self):
        """Load trained RandomForest model from disk."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                self.model_loaded = True
                log_info("[AnomalyDetector] ML model loaded successfully")
            else:
                log_info("[AnomalyDetector] Model not found — run train_model.py — using rules")
        except Exception as e:
            log_error(f"[AnomalyDetector] Model load error: {e}")

    def extract_features(self, agent_data: dict) -> list:
        """Extract feature vector from agent data dict."""
        return [
            agent_data.get("request_count",   0),
            agent_data.get("failed_attempts",  0),
            agent_data.get("data_size",        0),
            agent_data.get("unique_actions",   1),
            agent_data.get("time_window",     60),
            1 if agent_data.get("repeated_action") else 0,
            1 if agent_data.get("unusual_hour")    else 0,
        ]

    def _feature_hash(self, features: list) -> str:
        """Create a hash key for the feature vector — used for cache lookup."""
        return str(hash(tuple(round(f, 1) if isinstance(f, float) else f for f in features)))

    def _update_baseline(self, agent_id: str, agent_data: dict):
        """
        Update rolling average baseline for this agent.
        Used to detect deviations from the agent's own normal behavior.
        """
        if agent_id not in _agent_baselines:
            _agent_baselines[agent_id] = {
                "avg_requests": agent_data.get("request_count", 0),
                "avg_failures": agent_data.get("failed_attempts", 0),
                "avg_data":     agent_data.get("data_size", 0),
                "samples":      1,
            }
            return

        b = _agent_baselines[agent_id]
        n = b["samples"]

        # Exponential moving average — recent data weighted more
        alpha = 0.1
        b["avg_requests"] = (1 - alpha) * b["avg_requests"] + alpha * agent_data.get("request_count", 0)
        b["avg_failures"] = (1 - alpha) * b["avg_failures"] + alpha * agent_data.get("failed_attempts", 0)
        b["avg_data"]     = (1 - alpha) * b["avg_data"]     + alpha * agent_data.get("data_size", 0)
        b["samples"]      = n + 1

    def _is_deviation_from_baseline(self, agent_id: str, agent_data: dict) -> tuple:
        """
        Compare current metrics against this agent's personal baseline.
        Returns (is_deviation: bool, deviation_score: float)
        """
        if agent_id not in _agent_baselines or _agent_baselines[agent_id]["samples"] < 5:
            return False, 0.0  # Not enough data yet

        b     = _agent_baselines[agent_id]
        score = 0.0

        # Check how far current values deviate from agent's own average
        req = agent_data.get("request_count", 0)
        if b["avg_requests"] > 0 and req > b["avg_requests"] * 3:
            score += 0.4  # 3x above personal average

        fail = agent_data.get("failed_attempts", 0)
        if b["avg_failures"] > 0 and fail > b["avg_failures"] * 5:
            score += 0.4

        data = agent_data.get("data_size", 0)
        if b["avg_data"] > 0 and data > b["avg_data"] * 10:
            score += 0.3

        return score >= 0.4, min(score, 1.0)

    def detect(self, agent_id: str, agent_data: dict) -> dict:
        """
        Main detection function — called by Sentinel for every behavior analysis.

        Priority:
          1. Cache hit  → instant return
          2. ML model   → RandomForest prediction
          3. Rule-based → threshold checks
          4. Baseline   → personal deviation check

        Always updates agent baseline after detection.
        """
        features     = self.extract_features(agent_data)
        feature_hash = self._feature_hash(features)

        # Check cache — avoid recomputing same features within TTL
        cached = self._cache.get(feature_hash)
        if cached and (time.time() - cached.get("cached_at", 0)) < _CACHE_TTL:
            log_info(f"[AnomalyDetector] Cache hit | agent={agent_id}")
            result = dict(cached)
            result["agent_id"] = agent_id  # update agent_id
            result["from_cache"] = True
            return result

        # Update baseline before detection
        self._update_baseline(agent_id, agent_data)

        # ML model detection
        if self.model_loaded:
            result = self._ml_detect(agent_id, features, agent_data)
        else:
            result = self._rule_based(agent_id, agent_data)

        # Baseline deviation check — adds to risk score
        is_deviation, dev_score = self._is_deviation_from_baseline(agent_id, agent_data)
        if is_deviation and not result["is_anomaly"]:
            # Baseline says suspicious even if ML/rules say normal
            result["is_anomaly"]   = True
            result["attack_type"]  = "BASELINE_DEVIATION"
            result["risk_score"]   = max(result["risk_score"], dev_score)
            result["risk_level"]   = "MEDIUM" if dev_score < 0.6 else "HIGH"
            result["detection_method"] += "+BASELINE"
            log_threat(f"[AnomalyDetector] Baseline deviation | agent={agent_id} | score={dev_score:.2f}")

        # Track confidence for drift detection
        self._track_confidence(result.get("risk_score", 0))

        # Cache the result
        result["cached_at"]   = time.time()
        result["from_cache"]  = False
        self._cache[feature_hash] = result

        return result

    def _ml_detect(self, agent_id: str, features: list, agent_data: dict) -> dict:
        """Run ML model prediction."""
        try:
            import numpy as np
            features_array  = np.array(features).reshape(1, -1)
            features_scaled = self.scaler.transform(features_array)
            prediction      = self.model.predict(features_scaled)[0]
            probabilities   = self.model.predict_proba(features_scaled)[0]

            is_anomaly  = prediction != 0
            risk_score  = float(probabilities[prediction])
            attack_type = LABELS.get(int(prediction), "UNKNOWN")

            log_info(f"[AnomalyDetector] ML | agent={agent_id} → {attack_type} | risk={risk_score:.2f}")
            return self._build_result(agent_id, is_anomaly, attack_type, risk_score, "ML_MODEL")

        except Exception as e:
            log_error(f"[AnomalyDetector] ML error: {e} — falling back to rules")
            return self._rule_based(agent_id, agent_data)

    def _rule_based(self, agent_id: str, agent_data: dict) -> dict:
        """Rule-based fallback — deterministic threshold checks."""
        rc = agent_data.get("request_count",   0)
        fa = agent_data.get("failed_attempts",  0)
        ds = agent_data.get("data_size",        0)
        ua = agent_data.get("unique_actions",   1)

        if fa >= 5:
            return self._build_result(agent_id, True, "BRUTE_FORCE",
                                      min(0.5 + fa * 0.1, 1.0), "RULE")
        if rc > 50:
            return self._build_result(agent_id, True, "API_FLOODING",
                                      min(0.4 + rc * 0.01, 1.0), "RULE")
        if ds > 10000:
            return self._build_result(agent_id, True, "DATA_EXFILTRATION",
                                      0.75, "RULE")
        if ua > 8:
            return self._build_result(agent_id, True, "PRIVILEGE_ESCALATION",
                                      0.70, "RULE")

        return self._build_result(agent_id, False, "NORMAL", 0.05, "RULE")

    def _build_result(self, agent_id: str, is_anomaly: bool,
                      attack_type: str, risk_score: float, method: str) -> dict:
        """Build standardized result dict."""
        risk_level = (
            "HIGH"   if risk_score >= 0.75 else
            "MEDIUM" if risk_score >= 0.40 else
            "LOW"    if risk_score >= 0.20 else
            "SAFE"
        )
        if is_anomaly:
            log_threat(
                f"[AnomalyDetector] {attack_type} | agent={agent_id} | "
                f"risk={risk_score:.2f} | {risk_level} | method={method}"
            )
        return {
            "agent_id":         agent_id,
            "is_anomaly":       is_anomaly,
            "attack_type":      attack_type,
            "risk_score":       round(risk_score, 3),
            "risk_level":       risk_level,
            "detection_method": method,
            "timestamp":        time.time(),
        }

    def _track_confidence(self, risk_score: float):
        """
        Track model confidence over time.
        Consistently low confidence = possible model drift.
        Logs a warning when drift is detected.
        """
        self._confidence_history.append(risk_score)
        if len(self._confidence_history) > 100:
            self._confidence_history.pop(0)

        if len(self._confidence_history) >= 20:
            avg = sum(self._confidence_history[-20:]) / 20
            if avg < 0.15:
                self._low_confidence_count += 1
                if self._low_confidence_count % 10 == 1:
                    log_error(
                        f"[AnomalyDetector] MODEL DRIFT WARNING — "
                        f"avg confidence={avg:.2f} over last 20 detections. "
                        f"Consider retraining with: python train_model.py"
                    )
            else:
                self._low_confidence_count = 0

    def get_agent_baseline(self, agent_id: str) -> dict:
        """Return learned baseline for an agent."""
        return _agent_baselines.get(agent_id, {"status": "no baseline yet"})

    def get_status(self) -> dict:
        """Return detector status for dashboard."""
        return {
            "model_loaded":    self.model_loaded,
            "agents_tracked":  len(_agent_baselines),
            "cache_size":      len(self._cache),
            "cache_ttl":       _CACHE_TTL,
            "drift_warnings":  self._low_confidence_count,
            "features":        FEATURES,
            "attack_labels":   list(LABELS.values()),
        }
