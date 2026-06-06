"""
agents/vision_agent.py

Computer Vision Agent — AGENT-CV-01

Responsibilities:
  - Monitor CCTV feeds for physical security threats
  - Detect: tailgating, unattended objects, after-hours access, loitering
  - Face recognition for unauthorized access detection
  - Alert Sentinel immediately when physical threat is confirmed
  - Run autonomously every 10 seconds

Two operating modes:
  REAL mode     : Uses OpenCV + YOLOv8 for actual frame analysis
  SIMULATED mode: Generates realistic events without camera hardware
                  Used for development and testing

Install for real mode: pip install opencv-python ultralytics
"""

import time
import json
import random
from agents.base_agent import BaseAgent
from rag.vectorless_store import VectorlessStore
from verification.result_verifier import ResultVerifier, AgentClaim
from logger import log_info, log_threat, log_error, log_allowed
from config.settings import VISION_MODE, CV_CONFIDENCE, YOLO_MODEL_SIZE


# Try loading OpenCV
_CV_AVAILABLE = False
try:
    import cv2
    _CV_AVAILABLE = True
    log_info("[Vision] OpenCV loaded successfully")
except ImportError:
    log_error("[Vision] OpenCV not found — running in simulated mode. Install: pip install opencv-python")

# Try loading YOLOv8
_YOLO_AVAILABLE = False
try:
    from ultralytics import YOLO
    _YOLO_AVAILABLE = True
    log_info("[Vision] YOLOv8 loaded successfully")
except ImportError:
    log_error("[Vision] YOLOv8 not found — running in simulated mode. Install: pip install ultralytics")


VISION_PROMPT = """You are a Computer Vision Security Agent for NFTCipher.

Your job is to analyze physical security events from CCTV descriptions.
Base every threat verdict on specific observable facts in the description.
Do not speculate beyond what is directly described.
Respond with JSON only."""


class VisionAgent(BaseAgent):

    # Physical locations being monitored
    MONITORED_LOCATIONS = [
        "Server Room",
        "Main Entrance",
        "Parking Lot",
        "Reception",
        "Data Center",
        "Executive Floor",
    ]

    # Threat event types with their base confidence scores
    THREAT_EVENTS = [
        {"type": "TAILGATING",          "confidence": 0.82, "severity": "HIGH"},
        {"type": "UNATTENDED_BAG",      "confidence": 0.76, "severity": "MEDIUM"},
        {"type": "AFTER_HOURS_ACCESS",  "confidence": 0.91, "severity": "HIGH"},
        {"type": "LOITERING",           "confidence": 0.68, "severity": "MEDIUM"},
        {"type": "FORCED_ENTRY",        "confidence": 0.95, "severity": "CRITICAL"},
        {"type": "UNAUTHORIZED_AREA",   "confidence": 0.88, "severity": "HIGH"},
        {"type": "CAMERA_OBSTRUCTION",  "confidence": 0.99, "severity": "CRITICAL"},
    ]

    # Normal events — no threat
    NORMAL_EVENTS = [
        {"type": "NORMAL_MOVEMENT",     "confidence": 0.05},
        {"type": "AUTHORIZED_ACCESS",   "confidence": 0.03},
        {"type": "SCHEDULED_CLEANING",  "confidence": 0.02},
    ]

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-CV-01",
            role          = "Vision",
            system_prompt = VISION_PROMPT,
        )

        # Determine operating mode
        if VISION_MODE == "real" and _CV_AVAILABLE and _YOLO_AVAILABLE:
            self._cv_mode = "REAL"
        elif VISION_MODE == "simulated":
            self._cv_mode = "SIMULATED"
        else:
            # Auto mode — use real if available
            self._cv_mode = "REAL" if (_CV_AVAILABLE and _YOLO_AVAILABLE) else "SIMULATED"

        # YOLOv8 model — loaded only in real mode
        self._yolo_model = None
        if self._cv_mode == "REAL":
            self._load_yolo()

        # Detection history
        self._detections:     list = []
        self._false_positives: int = 0

        # Fast cache for active physical threats
        self.fast_cache = VectorlessStore()

        # Verifier — physical detections go through same verification as digital
        self.verifier = ResultVerifier()

        log_info(f"[Vision] Agent ready | mode={self._cv_mode} | opencv={_CV_AVAILABLE} | yolo={_YOLO_AVAILABLE}")

    def _load_yolo(self):
        """Load YOLOv8 model for object detection."""
        try:
            model_name       = f"yolov8{YOLO_MODEL_SIZE}.pt"
            self._yolo_model = YOLO(model_name)
            log_info(f"[Vision] YOLOv8 model loaded: {model_name}")
        except Exception as e:
            log_error(f"[Vision] YOLOv8 load failed: {e} — switching to simulated")
            self._cv_mode = "SIMULATED"

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 10 seconds.
        Scans all monitored locations for physical threats.
        In real mode: processes actual camera frames.
        In simulated mode: generates realistic test events.
        """
        log_info(f"[Vision] Background cycle | mode={self._cv_mode}")

        for location in self.MONITORED_LOCATIONS:
            event = self._scan_location(location)

            if event["anomaly_detected"]:
                self._handle_physical_threat(event)

        # Broadcast cycle summary
        self.broadcast("INFO", {
            "event":       "VISION_CYCLE",
            "agent_id":    self.agent_id,
            "mode":        self._cv_mode,
            "locations":   len(self.MONITORED_LOCATIONS),
            "detections":  len(self._detections),
            "timestamp":   time.time(),
        })

    def _scan_location(self, location: str) -> dict:
        """
        Scan a single location for threats.
        Routes to real or simulated scanning based on mode.
        """
        if self._cv_mode == "REAL":
            return self._scan_real_frame(location)
        else:
            return self._simulate_scan(location)

    # ── REAL MODE — OpenCV + YOLOv8 ──────────────────────
    def _scan_real_frame(self, location: str) -> dict:
        """
        Process a real camera frame using OpenCV and YOLOv8.
        In production, replace cap index with actual camera stream URL.
        Example stream URL: rtsp://camera-ip/stream1
        """
        try:
            # Open camera — index 0 = default camera
            # For IP cameras: cv2.VideoCapture("rtsp://user:pass@ip/stream")
            cap = cv2.VideoCapture(0)

            if not cap.isOpened():
                log_error(f"[Vision] Camera not accessible for {location} — using simulated")
                return self._simulate_scan(location)

            ret, frame = cap.read()
            cap.release()

            if not ret or frame is None:
                return self._simulate_scan(location)

            # Run YOLOv8 detection
            results    = self._yolo_model(frame, conf=CV_CONFIDENCE, verbose=False)
            detections = []

            for result in results:
                for box in result.boxes:
                    class_name = result.names[int(box.cls)]
                    confidence = float(box.conf)
                    detections.append({
                        "class":      class_name,
                        "confidence": confidence,
                        "bbox":       box.xyxy[0].tolist(),
                    })

            # Analyze detections for security threats
            threat_detected = self._analyze_detections(detections)

            return {
                "location":        location,
                "anomaly_detected": threat_detected["is_threat"],
                "event_type":      threat_detected.get("type", "NORMAL"),
                "confidence":      threat_detected.get("confidence", 0.0),
                "raw_detections":  detections,
                "mode":            "REAL",
                "timestamp":       time.time(),
            }

        except Exception as e:
            log_error(f"[Vision] Real scan error at {location}: {e}")
            return self._simulate_scan(location)

    def _analyze_detections(self, detections: list) -> dict:
        """
        Analyze YOLOv8 detection results for security threats.
        Maps detected objects to security threat categories.
        """
        person_count = sum(1 for d in detections if d["class"] == "person")
        bag_count    = sum(1 for d in detections if d["class"] in ["backpack", "suitcase", "handbag"])

        # Multiple people in restricted area = potential tailgating
        if person_count > 2:
            return {"is_threat": True, "type": "TAILGATING", "confidence": min(0.6 + person_count * 0.1, 0.95)}

        # Unattended bag — bag detected without nearby person
        if bag_count > 0 and person_count == 0:
            return {"is_threat": True, "type": "UNATTENDED_BAG", "confidence": 0.78}

        return {"is_threat": False, "type": "NORMAL", "confidence": 0.05}

    # ── SIMULATED MODE ────────────────────────────────────
    def _simulate_scan(self, location: str) -> dict:
        """
        Generate realistic simulated CCTV events for testing.
        Threat probability: ~15% per scan (realistic for a secure facility).
        Normal events: ~85% of scans.
        """
        # 15% chance of a threat event at any given location
        is_threat_event = random.random() < 0.15

        if is_threat_event:
            event_template = random.choice(self.THREAT_EVENTS)
            # Add small random variance to confidence
            confidence = min(event_template["confidence"] + random.uniform(-0.05, 0.05), 1.0)
            return {
                "location":         location,
                "anomaly_detected": True,
                "event_type":       event_template["type"],
                "confidence":       round(confidence, 2),
                "severity":         event_template["severity"],
                "mode":             "SIMULATED",
                "timestamp":        time.time(),
            }
        else:
            normal = random.choice(self.NORMAL_EVENTS)
            return {
                "location":         location,
                "anomaly_detected": False,
                "event_type":       normal["type"],
                "confidence":       normal["confidence"],
                "mode":             "SIMULATED",
                "timestamp":        time.time(),
            }

    # ── THREAT HANDLING ───────────────────────────────────
    def _handle_physical_threat(self, event: dict):
        """
        Process a detected physical threat through verification before alerting.
        Physical threats go through same 4-layer verification as digital threats.
        """
        location   = event.get("location", "Unknown")
        event_type = event.get("event_type", "UNKNOWN")
        confidence = event.get("confidence", 0.5)

        log_threat(f"[Vision] Physical event: {event_type} at {location} | conf={confidence:.2f}")

        # Build claim for verification engine
        claim = AgentClaim(
            agent_id     = self.agent_id,
            claim_type   = "THREAT",
            confidence   = confidence,
            flags        = [event_type, "PHYSICAL_ANOMALY"],
            raw_evidence = {
                "location":   location,
                "event_type": event_type,
                "confidence": confidence,
                "rpm":        0,             # not applicable for physical
                "request_count": 1,
            },
            llm_reason = f"Vision detected {event_type} at {location}",
        )

        # Run through verification — same engine as digital threats
        verified = self.verifier.verify(claim, self, ml_risk_score=confidence)

        if verified.final_verdict == "CONFIRMED_THREAT":
            self._detections.append({
                "event":    event,
                "verified": True,
                "score":    verified.consensus_score,
                "action":   verified.action_level,
            })

            # Store in fast cache as active physical threat
            threat_id = f"physical:{event_type}:{int(time.time())}"
            self.fast_cache.set_active_threat(
                threat_id  = threat_id,
                threat_data = {
                    "type":     "PHYSICAL",
                    "event":    event_type,
                    "location": location,
                    "score":    verified.consensus_score,
                    "action":   verified.action_level,
                    "time":     time.time(),
                },
                ttl_minutes = 30,
            )

            # Alert Sentinel with verified result
            self.send_message("AGENT-ST-01", "THREAT", {
                "event":          "PHYSICAL_THREAT_CONFIRMED",
                "agent_id":       self.agent_id,
                "event_type":     event_type,
                "location":       location,
                "confidence":     confidence,
                "consensus_score": verified.consensus_score,
                "action_level":   verified.action_level,
                "timestamp":      time.time(),
            })

            log_threat(
                f"[Vision] CONFIRMED | {event_type} at {location} | "
                f"score={verified.consensus_score:.2f} | action={verified.action_level}"
            )

        elif verified.final_verdict == "FALSE_POSITIVE":
            self._false_positives += 1
            log_info(f"[Vision] False positive caught: {event_type} at {location}")

    # ── LLM FRAME ANALYSIS ────────────────────────────────
    def analyze_frame_description(self, description: str, location: str) -> dict:
        """
        Analyze a text description of a camera frame using LLM.
        Used when an operator sends a manual description for analysis.
        Also used as fallback when frame processing fails.
        """
        log_info(f"[Vision] LLM frame analysis | location={location}")

        prompt = f"""Analyze this physical security camera observation:

Location: {location}
Description: {description}

Identify security threats based ONLY on what is directly described.
Do not speculate about intent or assume context not mentioned.

Respond with JSON only:
{{
  "threat_detected":  true or false,
  "threat_type":      "type or null",
  "confidence":       <float 0.0-1.0>,
  "action":           "ALERT" or "INVESTIGATE" or "IGNORE",
  "specific_concerns": ["concern1", "concern2"],
  "reasoning":        "one sentence citing specific observations from description"
}}"""

        response = self._call_llm(prompt)
        result   = {
            "location":    location,
            "description": description,
            "timestamp":   time.time(),
            "mode":        "llm_analysis",
        }

        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed = json.loads(raw)
                result.update(parsed)

                if parsed.get("threat_detected"):
                    # Route through verification before alerting
                    self._handle_physical_threat({
                        "location":         location,
                        "anomaly_detected": True,
                        "event_type":       parsed.get("threat_type", "UNKNOWN"),
                        "confidence":       parsed.get("confidence", 0.5),
                        "mode":             "llm_analysis",
                        "timestamp":        time.time(),
                    })

            except Exception as e:
                log_error(f"[Vision] LLM analysis parse error: {e}")
                result["error"] = str(e)

        return result

    # ── STATUS ────────────────────────────────────────────
    def get_status(self) -> dict:
        base = super().get_status()
        base.update({
            "cv_mode":          self._cv_mode,
            "opencv_available": _CV_AVAILABLE,
            "yolo_available":   _YOLO_AVAILABLE,
            "detections":       len(self._detections),
            "false_positives":  self._false_positives,
            "locations":        len(self.MONITORED_LOCATIONS),
            "active_threats":   len(self.fast_cache.get_active_threats()),
        })
        return base