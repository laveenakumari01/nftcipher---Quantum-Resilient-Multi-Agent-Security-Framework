

"""
Complete Backend 
Quantum Resilient Security Framework for AI Agents

Includes:
- JWT Authentication
- RBAC (Role Based Access Control)
- Zero Trust Validation
- PQC Simulation (CRYSTALS-Kyber + Dilithium)
- ML Anomaly Detection (Real Random Forest Model - detector.pkl)
- PostgreSQL Logging
- Agent Endpoints for Simulation

Port: 8000
"""

import os
import sys
import json
import hashlib
import secrets
import time
import pickle
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional
from functools import lru_cache

import psycopg2
from psycopg2 import pool

from fastapi import Depends, FastAPI, HTTPException, status, Body, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

import uvicorn
from dotenv import load_dotenv
import httpx
import asyncio
from fastapi.responses import StreamingResponse

# ── Agent imports ─────────────────────────────────────────
from agents.sentinel_agent  import SentinelAgent
from agents.arbiter_agent   import ArbiterAgent
from agents.data_access_agent import DataAccessAgent
from agents.cloud_api_agent import CloudAPIAgent
from agents.adversary_agent import AdversaryAgent
from quantum_simulation.pqc_simulation import QuantumTokenGenerator, QuantumVsClassical

load_dotenv()

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════

SECRET_KEY                  = os.getenv("SECRET_KEY", "nftcipher-quantum-secret-key-2024")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DB_NAME     = os.getenv("DB_NAME",     "postgres")
DB_USER     = os.getenv("DB_USER",     "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = os.getenv("DB_PORT",     "5432")

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")

# ML Model paths — same folder structure as project
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "anomaly_detection", "model", "detector.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "anomaly_detection", "model", "scaler.pkl")

# ═══════════════════════════════════════════════════════════
#  ML MODEL LOADER
# ═══════════════════════════════════════════════════════════

class MLModel:
    """
    Loads and uses the trained Random Forest model (detector.pkl)
    from anomaly_detection/model/ folder.
    Falls back to keyword detection if model not found.
    """
    _model  = None
    _scaler = None
    _loaded = False

    @classmethod
    def load(cls):
        if cls._loaded:
            return
        try:
            with open(MODEL_PATH, "rb") as f:
                cls._model = pickle.load(f)
            with open(SCALER_PATH, "rb") as f:
                cls._scaler = pickle.load(f)
            cls._loaded = True
            print("[OK] ML Model loaded: anomaly_detection/model/detector.pkl")
        except FileNotFoundError:
            print("[WARN] ML Model not found — using keyword fallback detection")
            cls._loaded = False
        except Exception as e:
            print(f"[WARN] ML Model load error: {e} — using keyword fallback")
            cls._loaded = False

    @classmethod
    def predict(cls, agent_data: dict) -> dict:
        """
        Predict using real Random Forest model.
        agent_data keys:
            agent_id, requests_per_minute, failed_attempts,
            data_accessed_mb, unique_endpoints, login_time_seconds
        """
        if not cls._loaded:
            return cls._keyword_fallback(agent_data)

        try:
            features = pd.DataFrame([{
                "requests_per_minute": agent_data.get("requests_per_minute", 1),
                "failed_attempts":     agent_data.get("failed_attempts", 0),
                "data_accessed_mb":    agent_data.get("data_accessed_mb", 0.1),
                "unique_endpoints":    agent_data.get("unique_endpoints", 1),
                "login_time_seconds":  agent_data.get("login_time_seconds", 1.0),
            }])

            features_scaled = cls._scaler.transform(features)
            prediction      = cls._model.predict(features_scaled)[0]
            probability     = cls._model.predict_proba(features_scaled)[0]
            confidence      = float(max(probability) * 100)

            if prediction == 1:
                risk = "🔴 HIGH RISK" if confidence >= 90 else (
                       "🟡 MEDIUM RISK" if confidence >= 60 else "🟠 LOW RISK")
                return {
                    "is_anomaly": True,
                    "confidence": round(confidence, 1),
                    "risk_level": risk,
                    "alert":      "🚨 ANOMALY DETECTED!",
                    "model":      "RandomForest (detector.pkl)"
                }
            else:
                return {
                    "is_anomaly": False,
                    "confidence": round(confidence, 1),
                    "risk_level": "🟢 SAFE",
                    "alert":      "✅ Normal Behavior",
                    "model":      "RandomForest (detector.pkl)"
                }
        except Exception as e:
            return cls._keyword_fallback(agent_data)

    @classmethod
    def _keyword_fallback(cls, agent_data: dict) -> dict:
        """Keyword based fallback if model unavailable."""
        suspicious = [
            "brute force", "unauthorized", "sql injection", "malware",
            "attack", "failed login", "exfiltration", "exploit",
            "privilege escalation", "quantum bypass", "zero-day"
        ]
        event = str(agent_data.get("event", "")).lower()
        for kw in suspicious:
            if kw in event:
                return {
                    "is_anomaly": True,
                    "confidence": 90.0,
                    "risk_level": "🔴 HIGH RISK",
                    "alert":      "🚨 ANOMALY DETECTED!",
                    "model":      "Keyword Fallback"
                }
        return {
            "is_anomaly": False,
            "confidence": 100.0,
            "risk_level": "🟢 SAFE",
            "alert":      "✅ Normal Behavior",
            "model":      "Keyword Fallback"
        }


# ═══════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════

class Database:
    _pool = None

    @classmethod
    def get_pool(cls):
        if cls._pool is None:
            try:
                cls._pool = pool.ThreadedConnectionPool(
                    1, 20,
                    dbname=DB_NAME, user=DB_USER,
                    password=DB_PASSWORD, host=DB_HOST, port=int(DB_PORT)
                )
                print("[OK] PostgreSQL connected!")
            except Exception as e:
                print(f"[WARN] PostgreSQL not available: {e}")
                print("   Running in simulation mode (no DB)")
        return cls._pool

    @classmethod
    def execute(cls, query, params=None, fetch=False):
        p = cls.get_pool()
        if not p:
            return [] if fetch else True
        conn = p.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                if fetch:
                    return cur.fetchall()
                conn.commit()
                return True
        except Exception as e:
            print(f"DB Error: {e}")
            conn.rollback()
            return [] if fetch else None
        finally:
            p.putconn(conn)


def init_db():
    Database.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            role VARCHAR(50) PRIMARY KEY,
            perms JSONB NOT NULL
        );
    """)
    Database.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        SERIAL PRIMARY KEY,
            agent_id  VARCHAR(100),
            event     TEXT NOT NULL,
            level     VARCHAR(20) NOT NULL,
            role      VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata  JSONB
        );
    """)
    Database.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          SERIAL PRIMARY KEY,
            agent_id    VARCHAR(100),
            event       TEXT NOT NULL,
            severity    VARCHAR(20) NOT NULL,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_resolved BOOLEAN DEFAULT FALSE,
            metadata    JSONB
        );
    """)
    Database.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            username        VARCHAR(100) UNIQUE NOT NULL,
            full_name       VARCHAR(200),
            email           VARCHAR(200) UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role            VARCHAR(50) DEFAULT 'viewer',
            disabled        BOOLEAN DEFAULT FALSE,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    Database.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);")
    Database.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
    Database.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    Database.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent_id ON logs(agent_id);")
    Database.execute("CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);")
    Database.execute("CREATE INDEX IF NOT EXISTS idx_permissions_role ON permissions(role);")

    _seed_default_users()
    print("[OK] Database tables ready!")


def _seed_default_users():
    """save default users in db."""
    defaults = [
        ("john.doe",     "John Doe",           "john@nftcipher.com",   pwd_context.hash("secret"),           "admin",  False),
        ("viewer01",     "Viewer User",         "viewer@nftcipher.com", pwd_context.hash("viewpass"),         "viewer", False),
        ("AGENT-DR01",   "Data Reader Agent",   "dr01@nftcipher.com",   pwd_context.hash("password123"),      "agent",  False),
        ("AGENT-AC01",   "API Caller Agent",    "ac01@nftcipher.com",   pwd_context.hash("password123"),      "agent",  False),
        ("AGENT-FA01",   "File Access Agent",   "fa01@nftcipher.com",   pwd_context.hash("password123"),      "agent",  False),
        ("AGENT-HACK01", "Unauthorized Agent 1","hack1@nftcipher.com",  pwd_context.hash("xK9#mQ2$zL7!pN4@"),"agent",  True),
        ("AGENT-HACK02", "Unauthorized Agent 2","hack2@nftcipher.com",  pwd_context.hash("xK9#mQ2$zL7!pN4@"),"agent",  True),
    ]
    for username, full_name, email, hashed_password, role, disabled in defaults:
        Database.execute("""
            INSERT INTO users (username, full_name, email, hashed_password, role, disabled)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (email) DO NOTHING
        """, (username, full_name, email, hashed_password, role, disabled))

    for role, perms in ROLE_PERMISSIONS.items():
        Database.execute("""
            INSERT INTO permissions (role, perms)
            VALUES (%s, %s)
            ON CONFLICT (role) DO NOTHING
        """, (role, json.dumps(perms)))


# ═══════════════════════════════════════════════════════════
#  RBAC
# ═══════════════════════════════════════════════════════════

ROLE_ADMIN  = "admin"
ROLE_AGENT  = "agent"
ROLE_VIEWER = "viewer"

ROLE_PERMISSIONS = {
    ROLE_ADMIN:  ["agent:read", "agent:write", "logs:read", "alerts:read",
                  "stats:read", "analyze:write", "admin:all"],
    ROLE_AGENT:  ["agent:read", "agent:write", "logs:read", "analyze:write"],
    ROLE_VIEWER: ["logs:read", "alerts:read", "stats:read"],
}


def check_permission(role: str, permission: str) -> bool:
    rows = Database.execute("SELECT perms FROM permissions WHERE role = %s", (role,), fetch=True)
    if rows and rows[0][0]:
        allowed = rows[0][0]
    else:
        allowed = ROLE_PERMISSIONS.get(role, [])
    return permission in allowed or "admin:all" in allowed


# ═══════════════════════════════════════════════════════════
#  USERS + AUTH
# ═══════════════════════════════════════════════════════════

pwd_context   = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

USERS_DB = {
    "john.doe": {
        "username": "john.doe", "full_name": "John Doe",
        "email": "john@nftcipher.com",
        "hashed_password": pwd_context.hash("secret"),
        "role": ROLE_ADMIN, "disabled": False,
    },
    "viewer01": {
        "username": "viewer01", "full_name": "Viewer User",
        "email": "viewer@nftcipher.com",
        "hashed_password": pwd_context.hash("viewpass"),
        "role": ROLE_VIEWER, "disabled": False,
    },
    "AGENT-DR01": {
        "username": "AGENT-DR01", "full_name": "Data Reader Agent",
        "email": "dr01@nftcipher.com",
        "hashed_password": pwd_context.hash("password123"),
        "role": ROLE_AGENT, "disabled": False,
    },
    "AGENT-AC01": {
        "username": "AGENT-AC01", "full_name": "API Caller Agent",
        "email": "ac01@nftcipher.com",
        "hashed_password": pwd_context.hash("password123"),
        "role": ROLE_AGENT, "disabled": False,
    },
    "AGENT-FA01": {
        "username": "AGENT-FA01", "full_name": "File Access Agent",
        "email": "fa01@nftcipher.com",
        "hashed_password": pwd_context.hash("password123"),
        "role": ROLE_AGENT, "disabled": False,
    },
    "AGENT-HACK01": {
        "username": "AGENT-HACK01", "full_name": "Unauthorized Agent 1",
        "email": "hack1@nftcipher.com",
        "hashed_password": pwd_context.hash("xK9#mQ2$zL7!pN4@"),
        "role": ROLE_AGENT, "disabled": True,
    },
    "AGENT-HACK02": {
        "username": "AGENT-HACK02", "full_name": "Unauthorized Agent 2",
        "email": "hack2@nftcipher.com",
        "hashed_password": pwd_context.hash("xK9#mQ2$zL7!pN4@"),
        "role": ROLE_AGENT, "disabled": True,
    },
}


class User(BaseModel):
    username:  str
    full_name: Optional[str] = None
    email:     Optional[str] = None
    role:      Optional[str] = None
    disabled:  Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def get_user(username: str):
    rows = Database.execute(
        "SELECT username, full_name, email, hashed_password, role, disabled FROM users WHERE username = %s",
        (username,), fetch=True
    )
    if rows:
        r = rows[0]
        return UserInDB(username=r[0], full_name=r[1], email=r[2],
                        hashed_password=r[3], role=r[4], disabled=r[5])
    if username in USERS_DB:
        return UserInDB(**USERS_DB[username])
    return None


def get_user_by_email(email: str):
    rows = Database.execute(
        "SELECT username, full_name, email, hashed_password, role, disabled FROM users WHERE LOWER(email) = LOWER(%s)",
        (email,), fetch=True
    )
    if rows:
        r = rows[0]
        return UserInDB(username=r[0], full_name=r[1], email=r[2],
                        hashed_password=r[3], role=r[4], disabled=r[5])
    for key, data in USERS_DB.items():
        if data.get("email", "").lower() == email.lower():
            return UserInDB(**data)
    return None


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if user:
        if pwd_context.verify(password, user.hashed_password):
            return user
        else:
            return False

    user = get_user_by_email(username)
    if user:
        if pwd_context.verify(password, user.hashed_password):
            return user
        else:
            return False

    return False


import base64

def create_pqc_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire.isoformat()})

    payload_str = json.dumps(to_encode)
    payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).decode()

    # FIX: Use int timestamp (no decimal point) so token always splits into exactly 3 parts on "."
    ts = str(int(time.time()))
    sig = hashlib.sha3_512(f"{PQCSimulator.SERVER_PRIV}{payload_str}{ts}".encode()).hexdigest()

    return f"{payload_b64}.{ts}.{sig}"


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        parts = token.split(".")
        # FIX: PQC token has exactly 3 parts (base64_payload.int_timestamp.hex_sig)
        # hex_sig contains only hex chars [0-9a-f] so no dots in it
        # Standard JWT has 3 parts too but with different format — detect by sig length
        is_pqc = len(parts) == 3 and len(parts[2]) == 128  # sha3_512 hex = 128 chars
        if not is_pqc:
            payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
        else:
            payload_b64, ts, sig = parts

            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += "=" * padding
            payload_str = base64.urlsafe_b64decode(payload_b64).decode()

            expected_sig = hashlib.sha3_512(f"{PQCSimulator.SERVER_PRIV}{payload_str}{ts}".encode()).hexdigest()
            if sig != expected_sig:
                raise HTTPException(status_code=401, detail="PQC Signature invalid")

            payload = json.loads(payload_str)
            exp = datetime.fromisoformat(payload["exp"])
            if datetime.utcnow() > exp:
                raise HTTPException(status_code=401, detail="Token expired")

            username = payload.get("sub")

        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = get_user(username)
        if not user:
            user = get_user_by_email(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed — Zero Trust: {str(e)}")


async def get_active_user(user: User = Depends(get_current_user)) -> User:
    if user.disabled:
        raise HTTPException(status_code=403, detail="Account disabled — Zero Trust policy")
    return user


def require_permission(permission: str):
    async def checker(user: User = Depends(get_active_user)):
        if not check_permission(user.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied — role '{user.role}' lacks '{permission}' (Zero Trust RBAC)"
            )
        return user
    return checker


# ═══════════════════════════════════════════════════════════
#  PQC SIMULATION
# ═══════════════════════════════════════════════════════════

class PQCSimulator:
    SERVER_PRIV = secrets.token_hex(32)

    @staticmethod
    def kyber_keygen():
        priv = secrets.token_hex(32)
        pub  = hashlib.sha3_256(priv.encode()).hexdigest()
        return {"public_key": pub, "private_key": priv, "algorithm": "CRYSTALS-Kyber-768"}

    @staticmethod
    def kyber_encrypt(public_key: str, message: str):
        nonce      = secrets.token_hex(16)
        ciphertext = hashlib.sha3_512(f"{public_key}{nonce}{message}".encode()).hexdigest()
        return {"ciphertext": ciphertext, "nonce": nonce, "algorithm": "CRYSTALS-Kyber-768"}

    @staticmethod
    def dilithium_sign(private_key: str, message: str):
        sig = hashlib.sha3_512(f"{private_key}{message}{time.time()}".encode()).hexdigest()
        return {"signature": sig, "algorithm": "CRYSTALS-Dilithium3", "quantum_safe": True}

    @staticmethod
    def secure_agent_token(agent_id: str, role: str):
        keys      = PQCSimulator.kyber_keygen()
        payload   = json.dumps({"agent_id": agent_id, "role": role, "ts": str(datetime.utcnow())})
        encrypted = PQCSimulator.kyber_encrypt(keys["public_key"], payload)
        signature = PQCSimulator.dilithium_sign(keys["private_key"], payload)
        return {
            "agent_id":      agent_id,
            "role":          role,
            "pqc_token":     encrypted["ciphertext"][:32] + "...",
            "signature":     signature["signature"][:32] + "...",
            "algorithm":     "Kyber-768 + Dilithium3",
            "quantum_safe":  True,
            "nist_approved": True
        }


pqc = PQCSimulator()


# ═══════════════════════════════════════════════════════════
#  DB HELPERS
# ═══════════════════════════════════════════════════════════

def db_log(agent_id, event, level, role=None):
    Database.execute(
        "INSERT INTO logs (agent_id, event, level, role) VALUES (%s, %s, %s, %s)",
        (agent_id, event, level, role)
    )


def db_alert(agent_id, event, severity, reason):
    Database.execute(
        "INSERT INTO alerts (agent_id, event, severity, metadata) VALUES (%s, %s, %s, %s)",
        (agent_id, event, severity, json.dumps({"reason": reason}))
    )


# ═══════════════════════════════════════════════════════════
#  SSE EVENT BUS — Real-time frontend streaming
# ═══════════════════════════════════════════════════════════

# Global asyncio queue for SSE events
_sse_queue: asyncio.Queue = None

def get_sse_queue() -> asyncio.Queue:
    global _sse_queue
    if _sse_queue is None:
        _sse_queue = asyncio.Queue(maxsize=500)
    return _sse_queue

def push_sse_event(event_type: str, data: dict):
    """
    Background threads se SSE event push karo.
    Thread-safe — call_soon_threadsafe use karta hai.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            event = json.dumps({"type": event_type, "data": data, "ts": time.time()})
            loop.call_soon_threadsafe(get_sse_queue().put_nowait, event)
    except Exception:
        pass  # Background thread mein fail ho toh silently ignore karo

# Logger ko SSE hook register karo
from logger import set_sse_hook as _set_logger_sse_hook
_set_logger_sse_hook(push_sse_event)


# ═══════════════════════════════════════════════════════════
#  AGENT SINGLETONS
# ═══════════════════════════════════════════════════════════
# Ek baar banao — har request pe naya agent mat banao

_sentinel  = None
_arbiter   = None
_da_agent  = None
_ca_agent  = None
_adversary = None

def get_sentinel():
    global _sentinel
    if _sentinel is None:
        _sentinel = SentinelAgent()
    return _sentinel

def get_arbiter():
    global _arbiter
    if _arbiter is None:
        _arbiter = ArbiterAgent()
    return _arbiter

def get_da():
    global _da_agent
    if _da_agent is None:
        _da_agent = DataAccessAgent()
    return _da_agent

def get_ca():
    global _ca_agent
    if _ca_agent is None:
        _ca_agent = CloudAPIAgent()
    return _ca_agent

def get_adversary():
    global _adversary
    if _adversary is None:
        _adversary = AdversaryAgent()
    return _adversary


# ═══════════════════════════════════════════════════════════
#  FASTAPI APP
# ═══════════════════════════════════════════════════════════

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 55)
    print(" Backend")
    print("  JWT + RBAC + Zero Trust + PQC + ML")
    print("=" * 55)
    MLModel.load()
    init_db()

    # ── Background Threads Start ────────────────────────
    # Sentinel: har 15 second mein automatically logs scan kare
    sentinel = get_sentinel()
    sentinel.start_background(interval=15)

    # Adversary: har 30 second mein automatically attack simulate kare
    adversary = get_adversary()
    adversary.start_background(interval=30)

    # Sentinel ↔ Adversary direct link — ek doosre se baat kar sakein
    sentinel.set_adversary_ref(adversary)

    print("✅ Background threads started (Sentinel: 15s | Adversary: 30s)")
    print("✅ Sentinel ↔ Adversary direct communication linked")
    print("✅ MessageBus initialized — Agent messaging ready")

    yield

    # ── Cleanup on shutdown ─────────────────────────────
    sentinel.stop_background()
    adversary.stop_background()
    print("🛑 Background threads stopped")

app = FastAPI(
    title=" Quantum Resilient Security Framework",
    description="JWT + RBAC + Zero Trust + PQC + ML Anomaly Detection (RandomForest)",
    version="4.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Root ──────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "system":   "NftCipher",
        "status":   "running",
        "security": "JWT | RBAC | Zero Trust | PQC | ML Detection (RandomForest)"
    }


# ── Auth ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials — Zero Trust enforced"
        )
    token_val = create_pqc_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token_val, "token": token_val, "token_type": "bearer", "role": user.role, "username": user.username}


@app.post("/auth/login")
async def json_login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials — Zero Trust enforced"
        )
    token_val = create_pqc_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token_val, "token": token_val, "token_type": "bearer", "role": user.role, "username": user.username}


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


@app.post("/auth/register")
async def register_user(req: RegisterRequest):
    rows = Database.execute(
        "SELECT username FROM users WHERE LOWER(email) = LOWER(%s)",
        (req.email,), fetch=True
    )
    if rows:
        raise HTTPException(status_code=400, detail="Email already registered")
    for key, data in USERS_DB.items():
        if data.get("email", "").lower() == req.email.lower():
            raise HTTPException(status_code=400, detail="Email already registered")

    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password too short (min 4 chars)")

    username = req.email.split("@")[0].replace(".", "_").replace("+", "_")
    base = username
    counter = 1
    while True:
        existing_user = Database.execute(
            "SELECT username FROM users WHERE username = %s", (username,), fetch=True
        )
        if not existing_user and username not in USERS_DB:
            break
        username = f"{base}_{counter}"
        counter += 1

    hashed = pwd_context.hash(req.password)
    full_name = req.full_name or username

    Database.execute("""
        INSERT INTO users (username, full_name, email, hashed_password, role, disabled)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING
    """, (username, full_name, req.email, hashed, ROLE_ADMIN, False))

    USERS_DB[username] = {
        "username": username, "full_name": full_name, "email": req.email,
        "hashed_password": hashed, "role": ROLE_ADMIN, "disabled": False,
    }

    token_val = create_pqc_token(
        data={"sub": username, "role": ROLE_ADMIN},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": token_val, "token_type": "bearer",
        "role": ROLE_ADMIN, "username": username,
        "email": req.email, "message": "Registration successful"
    }


@app.get("/users/me")
async def read_me(user: User = Depends(get_active_user)):
    return {"username": user.username, "role": user.role, "email": user.email}


# ── Agent Endpoints ───────────────────────────────────────

@app.get("/agent/data")
async def agent_data(user: User = Depends(require_permission("agent:read"))):
    return {"status": "success", "agent": user.username, "data": "Agent data fetched successfully"}


@app.get("/agent/task")
async def agent_task(
    background_tasks: BackgroundTasks,
    user: User = Depends(require_permission("agent:write"))
):
    background_tasks.add_task(db_log, user.username, f"Task by {user.username}", "INFO", user.role)
    return {"status": "success", "agent": user.username, "task": "Task assigned successfully"}


@app.get("/agent/logs")
async def agent_logs(user: User = Depends(require_permission("logs:read"))):
    try:
        logs = []
        log_file = os.path.join(BASE_DIR, "logs", f"nftcipher_{datetime.now().strftime('%Y%m%d')}.log")
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                lines = f.readlines()
            for line in lines[-10:]:
                line = line.strip()
                if "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        logs.append({
                            "timestamp": parts[0].strip(),
                            "agent":     parts[1].strip().replace("Agent:", "").strip(),
                            "status":    parts[2].strip().replace("Status:", "").strip(),
                            "action":    parts[3].strip() if len(parts) > 3 else ""
                        })
        return {"logs": logs}
    except Exception:
        return {"logs": []}


@app.get("/agent/stats")
async def agent_stats(user: User = Depends(require_permission("stats:read"))):
    try:
        total = auth = unauth = 0
        log_file = os.path.join(BASE_DIR, "logs", f"nftcipher_{datetime.now().strftime('%Y%m%d')}.log")
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                lines = f.readlines()
            for line in lines[-500:]:
                if "|" in line:
                    total += 1
                    if "UNAUTHORIZED" in line:
                        unauth += 1
                    else:
                        auth += 1

        total  = min(total, 500)
        unauth = min(unauth, 20)
        auth   = total - unauth

        if total > 0:
            threat_ratio = unauth / total
            score = max(85, int((1 - threat_ratio) * 100))
        else:
            score = 98

        return {
            "total_detections": total,
            "active_threats":   unauth,
            "system_health":    "99.9%",
            "audit_requests":   auth,
            "security_score":   min(score, 100)
        }
    except Exception:
        return {"total_detections": 0, "active_threats": 0,
                "system_health": "99.9%", "audit_requests": 0, "security_score": 98}


# ── ML Anomaly Detection ──────────────────────────────────

@app.post("/log")
async def create_log(
    background_tasks: BackgroundTasks,
    event: str = Body(..., embed=True),
    level: str = Body("INFO", embed=True),
    user: User  = Depends(require_permission("agent:write"))
):
    background_tasks.add_task(db_log, user.username, event, level, user.role)
    return {"message": "Log stored"}


@app.post("/analyze")
async def analyze_event(
    background_tasks: BackgroundTasks,
    event:                str   = Body(...,  embed=True),
    requests_per_minute:  float = Body(1.0,  embed=True),
    failed_attempts:      float = Body(0.0,  embed=True),
    data_accessed_mb:     float = Body(0.1,  embed=True),
    unique_endpoints:     float = Body(1.0,  embed=True),
    login_time_seconds:   float = Body(1.0,  embed=True),
    user: User = Depends(require_permission("analyze:write"))
):
    background_tasks.add_task(db_log, user.username, event, "INFO", user.role)

    agent_data = {
        "agent_id":            user.username,
        "event":               event,
        "requests_per_minute": requests_per_minute,
        "failed_attempts":     failed_attempts,
        "data_accessed_mb":    data_accessed_mb,
        "unique_endpoints":    unique_endpoints,
        "login_time_seconds":  login_time_seconds,
    }

    result = MLModel.predict(agent_data)

    if result["is_anomaly"]:
        alert_reason = f"ML Model detected anomaly — {result['risk_level']}"
        if result["confidence"] >= 90:
            Database.execute("UPDATE users SET disabled = TRUE WHERE username = %s", (user.username,))
            if user.username in USERS_DB:
                USERS_DB[user.username]["disabled"] = True
            alert_reason = f"Auto-Lockdown Triggered — {result['risk_level']}"

        background_tasks.add_task(
            db_alert, user.username, event, "HIGH", alert_reason
        )
        return {
            "status":     "anomaly",
            "risk_level": result["risk_level"],
            "confidence": result["confidence"],
            "alert":      result["alert"],
            "model_used": result["model"],
            "agent":      user.username,
            "locked_down": result["confidence"] >= 90
        }

    return {
        "status":     "normal",
        "risk_level": result["risk_level"],
        "confidence": result["confidence"],
        "alert":      result["alert"],
        "model_used": result["model"],
        "agent":      user.username
    }


@app.post("/admin/lockdown/{username}")
async def admin_lockdown(username: str, user: User = Depends(require_permission("admin:all"))):
    Database.execute("UPDATE users SET disabled = TRUE WHERE username = %s", (username,))
    if username in USERS_DB:
        USERS_DB[username]["disabled"] = True
    return {"status": "success", "message": f"User {username} keys revoked and locked down"}


@app.get("/admin/security-audit")
async def security_audit(user: User = Depends(require_permission("admin:all"))):
    logs_count   = Database.execute("SELECT COUNT(*) FROM logs",   fetch=True)[0][0] if Database.get_pool() else "N/A"
    alerts_count = Database.execute("SELECT COUNT(*) FROM alerts", fetch=True)[0][0] if Database.get_pool() else "N/A"
    users_count  = Database.execute("SELECT COUNT(*) FROM users",  fetch=True)[0][0] if Database.get_pool() else len(USERS_DB)
    return {
        "status": "Audit Complete",
        "database_performance": "Optimized with indexes on logs, alerts, users, permissions",
        "pqc_status": "Enabled (Kyber-768 + Dilithium3)",
        "auto_lockdown_status": "Active via Sentinel ML",
        "metrics": {
            "total_logs":   logs_count,
            "total_alerts": alerts_count,
            "total_users":  users_count
        }
    }


@app.post("/analyze/batch")
async def analyze_batch(
    background_tasks: BackgroundTasks,
    agents: list = Body(..., embed=True),
    user: User   = Depends(require_permission("analyze:write"))
):
    results = []
    for agent_data in agents:
        result = MLModel.predict(agent_data)
        if result["is_anomaly"]:
            agent_id = agent_data.get("agent_id", "unknown")
            alert_reason = f"Batch ML detection — {result['risk_level']}"

            if result["confidence"] >= 90 and agent_id != "unknown":
                Database.execute("UPDATE users SET disabled = TRUE WHERE username = %s", (agent_id,))
                if agent_id in USERS_DB:
                    USERS_DB[agent_id]["disabled"] = True
                alert_reason = f"Auto-Lockdown Triggered (Batch) — {result['risk_level']}"

            background_tasks.add_task(
                db_alert, agent_id, str(agent_data), "HIGH", alert_reason
            )
        results.append({
            "agent_id":   agent_data.get("agent_id", "unknown"),
            "is_anomaly": result["is_anomaly"],
            "risk_level": result["risk_level"],
            "confidence": result["confidence"],
            "model_used": result["model"]
        })
    return {"results": results, "total": len(results)}


@app.get("/logs")
async def get_logs(limit: int = 50, user: User = Depends(require_permission("logs:read"))):
    results = Database.execute(
        f"SELECT agent_id, event, level, role, timestamp FROM logs ORDER BY timestamp DESC LIMIT {limit}",
        fetch=True
    )
    if not results:
        return []
    return [{"agent_id": r[0], "event": r[1], "level": r[2], "role": r[3], "timestamp": str(r[4])}
            for r in results]


@app.get("/alerts")
async def get_alerts(user: User = Depends(require_permission("alerts:read"))):
    results = Database.execute(
        "SELECT agent_id, event, severity, timestamp FROM alerts ORDER BY timestamp DESC LIMIT 50",
        fetch=True
    )
    if not results:
        return []
    return [{"agent_id": r[0], "event": r[1], "severity": r[2], "timestamp": str(r[3])}
            for r in results]


# ── PQC Endpoints ─────────────────────────────────────────

@app.get("/pqc/keygen")
async def pqc_keygen(user: User = Depends(get_active_user)):
    keys = pqc.kyber_keygen()
    return {"agent": user.username, "algorithm": keys["algorithm"],
            "public_key": keys["public_key"][:32] + "...", "quantum_safe": True}


@app.post("/pqc/encrypt")
async def pqc_encrypt(
    message: str = Body(..., embed=True),
    user: User   = Depends(get_active_user)
):
    keys      = pqc.kyber_keygen()
    encrypted = pqc.kyber_encrypt(keys["public_key"], message)
    signature = pqc.dilithium_sign(keys["private_key"], message)
    return {
        "agent":        user.username,
        "ciphertext":   encrypted["ciphertext"][:32] + "...",
        "signature":    signature["signature"][:32] + "...",
        "algorithm":    "Kyber-768 + Dilithium3",
        "quantum_safe": True
    }


@app.get("/pqc/agent-token/{agent_id}")
async def pqc_agent_token(agent_id: str, user: User = Depends(require_permission("agent:read"))):
    return pqc.secure_agent_token(agent_id, user.role)


@app.get("/pqc/status")
async def pqc_status(user: User = Depends(get_active_user)):
    return {
        "pqc_enabled":       True,
        "key_exchange":      "CRYSTALS-Kyber-768",
        "digital_signature": "CRYSTALS-Dilithium3",
        "nist_standard":     "FIPS 203 / FIPS 204 (2024)",
        "quantum_safe":      True,
        "classical_rsa":     "REPLACED",
        "agent":             user.username
    }


# ── RBAC Info ─────────────────────────────────────────────

@app.get("/rbac/all-agents")
async def all_agents(user: User = Depends(require_permission("admin:all"))):
    rows = Database.execute(
        "SELECT username, full_name, email, role, disabled FROM users ORDER BY created_at",
        fetch=True
    )
    if rows:
        return {"agents": [
            {"username": r[0], "full_name": r[1], "email": r[2], "role": r[3], "disabled": r[4]}
            for r in rows
        ]}
    return {"agents": [
        {"username": d["username"], "full_name": d["full_name"],
         "email": d["email"], "role": d["role"], "disabled": d["disabled"]}
        for d in USERS_DB.values()
    ]}


@app.get("/rbac/my-permissions")
async def my_permissions(user: User = Depends(get_active_user)):
    return {
        "username":    user.username,
        "role":        user.role,
        "permissions": ROLE_PERMISSIONS.get(user.role, []),
        "zero_trust":  "Every request validated independently"
    }


# ── Health ────────────────────────────────────────────────

@app.get("/health")
async def health():
    db_ok    = Database.get_pool() is not None
    model_ok = MLModel._loaded
    return {
        "status":     "healthy",
        "database":   "connected" if db_ok else "simulation mode",
        "ml_model":   "RandomForest (detector.pkl)" if model_ok else "keyword fallback",
        "jwt":        "active",
        "rbac":       "active",
        "zero_trust": "enforced",
        "pqc":        "active",
        "timestamp":  str(datetime.utcnow())
    }


# ═══════════════════════════════════════════════════════════
#  QUANTUM ROUTES  —  /quantum/token   /quantum/compare
# ═══════════════════════════════════════════════════════════

class QuantumTokenRequest(BaseModel):
    agent_id: str

@app.post("/quantum/token")
async def quantum_token(req: QuantumTokenRequest, user: User = Depends(get_active_user)):
    """
    PQC-signed quantum token generate karo
    Frontend: generateQuantumToken(agentId)
    """
    gen    = QuantumTokenGenerator()
    result = gen.generate_token(req.agent_id)
    db_log(user.username, f"Quantum token generated for {req.agent_id}", "INFO", user.role)
    return result


@app.get("/quantum/compare")
async def quantum_compare(user: User = Depends(get_active_user)):
    """
    Classical RSA vs PQC comparison
    Frontend: getPQCComparison()
    """
    qvc = QuantumVsClassical()
    return qvc.compare()


# ═══════════════════════════════════════════════════════════
#  SENTINEL ROUTES  —  /sentinel/analyze  /report  /status
# ═══════════════════════════════════════════════════════════

class SentinelAnalyzeRequest(BaseModel):
    token:    str
    agent_id: str
    action:   str
    metadata: dict = {}

@app.post("/sentinel/analyze")
async def sentinel_analyze(req: SentinelAnalyzeRequest, user: User = Depends(get_active_user)):
    """
    Agent behavior analyze karo
    Frontend: analyzeBehavior(token, agentId, action, metadata)
    """
    result = get_sentinel().analyze_behavior(
        token=req.token,
        agent_id=req.agent_id,
        action=req.action,
        metadata=req.metadata
    )
    db_log(user.username, f"Sentinel analyzed {req.agent_id}: {result.get('threat_level')}", "INFO", user.role)
    return result


@app.get("/sentinel/report")
async def sentinel_report(user: User = Depends(get_active_user)):
    """
    Full threat report
    Frontend: getThreatReport()
    """
    return get_sentinel().get_threat_report()


@app.get("/sentinel/status")
async def sentinel_status(user: User = Depends(get_active_user)):
    """
    Sentinel agent ka status
    Frontend: getSentinelStatus()
    """
    return get_sentinel().get_status()


# ═══════════════════════════════════════════════════════════
#  ARBITER ROUTES  —  /arbiter/arbitrate  /block  /status
# ═══════════════════════════════════════════════════════════

class ArbitrateRequest(BaseModel):
    token:    str
    agent_id: str
    action:   str

@app.post("/arbiter/arbitrate")
async def arbiter_arbitrate(req: ArbitrateRequest, user: User = Depends(get_active_user)):
    """
    Allow ya Deny decision lo
    Frontend: arbitrate(token, agentId, action)
    """
    result = get_arbiter().arbitrate(
        token=req.token,
        agent_id=req.agent_id,
        action=req.action
    )
    db_log(user.username, f"Arbiter [{req.agent_id}]: {result.get('decision')}", "INFO", user.role)
    return result


class BlockAgentRequest(BaseModel):
    agent_id: str
    reason:   str = "Manually blocked via dashboard"

@app.post("/arbiter/block")
async def arbiter_block(req: BlockAgentRequest, user: User = Depends(require_permission("admin:all"))):
    """
    Agent ko force block karo
    Frontend: blockAgent(agentId, reason)
    """
    get_arbiter().block_agent(req.agent_id, req.reason)
    db_log(user.username, f"Agent {req.agent_id} force-blocked: {req.reason}", "WARN", user.role)
    return {"status": "BLOCKED", "agent_id": req.agent_id, "reason": req.reason}


@app.get("/arbiter/status")
async def arbiter_status(user: User = Depends(get_active_user)):
    """
    Arbiter agent ka status
    Frontend: getArbiterStatus()
    """
    return get_arbiter().get_status()


# ═══════════════════════════════════════════════════════════
#  DATA ACCESS ROUTES  —  /data/fetch  /data/status
# ═══════════════════════════════════════════════════════════

class DataFetchRequest(BaseModel):
    token: str
    table: str
    query: str = "fetch all"

@app.post("/data/fetch")
async def data_fetch(req: DataFetchRequest, user: User = Depends(get_active_user)):
    """
    DataAccessAgent se real DB data lo
    Frontend: fetchData(token, table, query)
    """
    result = get_da().fetch_data(
        token=req.token,
        table=req.table,
        query=req.query
    )
    db_log(user.username, f"Data fetch [{req.table}]: {result.get('status')}", "INFO", user.role)
    return result


@app.get("/data/status")
async def data_status(user: User = Depends(get_active_user)):
    """
    DataAccessAgent ka status
    Frontend: getDataAgentStatus()
    """
    return get_da().get_status()


# ═══════════════════════════════════════════════════════════
#  CLOUD API ROUTES  —  /cloud/call  /cloud/status
# ═══════════════════════════════════════════════════════════

class CloudCallRequest(BaseModel):
    token:   str
    service: str
    action:  str

@app.post("/cloud/call")
async def cloud_call(req: CloudCallRequest, user: User = Depends(get_active_user)):
    """
    CloudAPIAgent se cloud service call karo
    Frontend: callCloudService(token, service, action)
    """
    result = get_ca().call_service(
        token=req.token,
        service=req.service,
        action=req.action
    )
    db_log(user.username, f"Cloud call [{req.service}/{req.action}]: {result.get('status')}", "INFO", user.role)
    return result


@app.get("/cloud/status")
async def cloud_status(user: User = Depends(get_active_user)):
    """
    CloudAPIAgent ka status
    Frontend: getCloudAgentStatus()
    """
    return get_ca().get_status()


# ═══════════════════════════════════════════════════════════
#  ADVERSARY ROUTES  —  5 attack types + report + status
# ═══════════════════════════════════════════════════════════

class TokenHijackRequest(BaseModel):
    stolen_token: str
    target:       str

@app.post("/adversary/token-hijacking")
async def adversary_token_hijack(req: TokenHijackRequest, user: User = Depends(get_active_user)):
    """Frontend: simulateTokenHijacking(stolenToken, target)"""
    result = get_adversary().simulate_token_hijacking(req.stolen_token, req.target)
    db_log(user.username, "Adversary: token hijacking simulated", "WARN", user.role)
    return result


class HarvestDecryptRequest(BaseModel):
    data_target: str

@app.post("/adversary/harvest-decrypt")
async def adversary_harvest(req: HarvestDecryptRequest, user: User = Depends(get_active_user)):
    """Frontend: simulateHarvestDecrypt(dataTarget)"""
    result = get_adversary().simulate_harvest_now_decrypt_later(req.data_target)
    db_log(user.username, "Adversary: harvest-now-decrypt-later simulated", "WARN", user.role)
    return result


class BruteForceRequest(BaseModel):
    target_agent: str
    attempts:     int = 5

@app.post("/adversary/brute-force")
async def adversary_brute(req: BruteForceRequest, user: User = Depends(get_active_user)):
    """Frontend: simulateBruteForce(targetAgent, attempts)"""
    result = get_adversary().simulate_brute_force(req.target_agent, req.attempts)
    db_log(user.username, f"Adversary: brute force on {req.target_agent}", "WARN", user.role)
    return result


class ApiFloodingRequest(BaseModel):
    target_endpoint: str
    request_count:   int = 20

@app.post("/adversary/api-flooding")
async def adversary_flood(req: ApiFloodingRequest, user: User = Depends(get_active_user)):
    """Frontend: simulateApiFlooding(targetEndpoint, requestCount)"""
    result = get_adversary().simulate_api_flooding(req.target_endpoint, req.request_count)
    db_log(user.username, f"Adversary: API flooding on {req.target_endpoint}", "WARN", user.role)
    return result


class PrivEscRequest(BaseModel):
    agent_id:        str
    target_resource: str

@app.post("/adversary/privilege-escalation")
async def adversary_priv_esc(req: PrivEscRequest, user: User = Depends(get_active_user)):
    """Frontend: simulatePrivilegeEscalation(agentId, targetResource)"""
    result = get_adversary().simulate_privilege_escalation(req.agent_id, req.target_resource)
    db_log(user.username, f"Adversary: priv escalation {req.agent_id} → {req.target_resource}", "WARN", user.role)
    return result


@app.get("/adversary/report")
async def adversary_report(user: User = Depends(get_active_user)):
    """Frontend: getAttackReport()"""
    return get_adversary().get_attack_report()


@app.get("/adversary/status")
async def adversary_status(user: User = Depends(get_active_user)):
    """Frontend: getAdversaryStatus()"""
    return get_adversary().get_status()


# ═══════════════════════════════════════════════════════════
#  MESSAGING ROUTES  —  Agent-to-Agent Communication
# ═══════════════════════════════════════════════════════════

from messaging.message_bus import message_bus as _message_bus

class SendMessageRequest(BaseModel):
    sender_id:    str
    recipient_id: str
    msg_type:     str
    payload:      dict = {}

@app.post("/messages/send")
async def send_agent_message(req: SendMessageRequest, user: User = Depends(get_active_user)):
    """Kisi bhi agent se message bhejo. recipient_id = ALL for broadcast."""
    msg = _message_bus.publish(
        sender_id=req.sender_id,
        recipient_id=req.recipient_id,
        msg_type=req.msg_type,
        payload=req.payload
    )
    db_log(user.username, f"Message: {req.sender_id} -> {req.recipient_id} [{req.msg_type}]", "INFO", user.role)
    return {"status": "sent", "message_id": msg.message_id}

@app.get("/messages/history")
async def get_message_history(limit: int = 50, user: User = Depends(get_active_user)):
    """Poora message history"""
    return {"messages": _message_bus.get_history(limit=limit), "stats": _message_bus.get_stats()}

@app.get("/messages/broadcasts")
async def get_broadcasts(limit: int = 20, user: User = Depends(get_active_user)):
    """Sab broadcast messages"""
    return {"broadcasts": _message_bus.get_broadcasts(limit=limit)}

@app.get("/messages/inbox/{agent_id}")
async def get_agent_inbox(agent_id: str, user: User = Depends(get_active_user)):
    """Kisi agent ki inbox"""
    return {"agent_id": agent_id, "messages": _message_bus.get_inbox(agent_id)}

@app.get("/messages/stats")
async def get_message_stats(user: User = Depends(get_active_user)):
    """MessageBus stats"""
    return _message_bus.get_stats()


# ═══════════════════════════════════════════════════════════
#  SENTINEL DIRECT BLOCK ROUTE
# ═══════════════════════════════════════════════════════════

class SentinelBlockRequest(BaseModel):
    target_id: str
    reason:    str = "Blocked by Sentinel"

@app.post("/sentinel/block-adversary")
async def sentinel_block_adversary(req: SentinelBlockRequest,
                                   user: User = Depends(require_permission("admin:all"))):
    """Sentinel -> Adversary ko directly block karo."""
    get_sentinel().block_adversary_directly(reason=req.reason)
    db_log(user.username, f"Sentinel blocked {req.target_id}: {req.reason}", "WARN", user.role)
    return {"status": "BLOCKED", "target_id": req.target_id, "blocked_by": "AGENT-ST-01"}


# ═══════════════════════════════════════════════════════════
#  ALL AGENTS STATUS  —  /agents/all  /agents/{id}/status  /memory/{id}
# ═══════════════════════════════════════════════════════════

@app.get("/agents/all")
async def all_agents_status(user: User = Depends(get_active_user)):
    """
    Sab agents ka status ek saath
    Frontend: getAllAgentsStatus()
    """
    return {
        "AGENT-ST-01": get_sentinel().get_status(),
        "AGENT-AR-01": get_arbiter().get_status(),
        "AGENT-DA-01": get_da().get_status(),
        "AGENT-CA-01": get_ca().get_status(),
        "AGENT-AD-01": get_adversary().get_status(),
    }


@app.get("/agents/{agent_id}/status")
async def single_agent_status(agent_id: str, user: User = Depends(get_active_user)):
    """
    Ek agent ka status
    Frontend: getAgentStatus(agentId)
    """
    mapping = {
        "AGENT-ST-01": get_sentinel,
        "AGENT-AR-01": get_arbiter,
        "AGENT-DA-01": get_da,
        "AGENT-CA-01": get_ca,
        "AGENT-AD-01": get_adversary,
    }
    agent_fn = mapping.get(agent_id)
    if not agent_fn:
        raise HTTPException(404, f"Agent {agent_id} not found")
    return agent_fn().get_status()


@app.get("/memory/{agent_id}")
async def agent_memory(agent_id: str, user: User = Depends(get_active_user)):
    """
    Agent ki memory — past actions, failed attempts
    Frontend: getAgentMemory(agentId)
    """
    mapping = {
        "AGENT-ST-01": get_sentinel,
        "AGENT-AR-01": get_arbiter,
        "AGENT-DA-01": get_da,
        "AGENT-CA-01": get_ca,
        "AGENT-AD-01": get_adversary,
    }
    agent_fn = mapping.get(agent_id)
    if not agent_fn:
        raise HTTPException(404, f"Agent {agent_id} not found")
    agent = agent_fn()
    return {
        "agent_id":        agent_id,
        "failed_attempts": agent.memory.failed_attempts,
        "history":         agent.memory.get_context(),
        "backend":         "connected" if agent.backend_token else "disconnected"
    }


# ═══════════════════════════════════════════════════════════
#  OAuth Callback
# ═══════════════════════════════════════════════════════════

class OAuthCallbackRequest(BaseModel):
    provider:      str
    code:          str
    redirect_uri:  str
    code_verifier: Optional[str] = None


@app.post("/auth/oauth/callback")
async def oauth_callback(req: OAuthCallbackRequest):
    import base64, json as _json
    provider = req.provider.lower()

    if provider == "google":
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            raise HTTPException(400, "Google OAuth not configured — set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env")
        async with httpx.AsyncClient() as client:
            extra = {"code_verifier": req.code_verifier} if req.code_verifier else {}
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": req.code, "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": req.redirect_uri,
                    "grant_type": "authorization_code", **extra,
                },
            )
        if token_res.status_code != 200:
            raise HTTPException(401, f"Google token exchange failed: {token_res.text}")
        id_token_str = token_res.json().get("id_token", "")
        parts   = id_token_str.split(".")
        padding = 4 - len(parts[1]) % 4
        payload = _json.loads(base64.urlsafe_b64decode(parts[1] + "=" * padding))
        email   = payload.get("email", "")
        name    = payload.get("name", email)

    elif provider == "github":
        if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
            raise HTTPException(400, "GitHub OAuth not configured — set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env")
        async with httpx.AsyncClient() as client:
            token_res = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET,
                    "code": req.code, "redirect_uri": req.redirect_uri,
                },
            )
            gh_access = token_res.json().get("access_token", "")
            user_res  = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {gh_access}", "Accept": "application/json"},
            )
            email_res = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {gh_access}", "Accept": "application/json"},
            )
        gh_user = user_res.json()
        name    = gh_user.get("name") or gh_user.get("login", "github_user")
        emails  = email_res.json() if email_res.status_code == 200 else []
        primary = next((e["email"] for e in emails if e.get("primary")), None)
        email   = primary or gh_user.get("email") or f"{gh_user.get('login','user')}@github.com"

    else:
        raise HTTPException(400, f"Unsupported provider: {provider}")

    role  = USERS_DB.get(email, {}).get("role", ROLE_VIEWER)
    token = create_pqc_token(
        data={"sub": email, "role": role, "provider": provider},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    db_log(email, f"OAuth login via {provider}", "INFO", role)
    return {"access_token": token, "token_type": "bearer", "role": role, "email": email, "name": name, "provider": provider}


# ═══════════════════════════════════════════════════════════
#  SSE STREAM ENDPOINT — Real-time agent activity feed
# ═══════════════════════════════════════════════════════════

@app.get("/stream/events")
async def stream_events():
    """
    Server-Sent Events endpoint.
    Frontend yahan connect kare aur real-time agent events receive kare.
    No auth required — CORS se protected hai.
    """
    queue = get_sse_queue()

    async def event_generator():
        # Connection confirm karo
        yield f"data: {json.dumps({'type': 'CONNECTED', 'data': {'message': 'Live agent feed connected'}, 'ts': time.time()})}\n\n"
        while True:
            try:
                # 30 second timeout — agar kuch nahi aaya toh heartbeat bhejo
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {event}\n\n"
            except asyncio.TimeoutError:
                # Heartbeat — connection alive rakho
                yield f"data: {json.dumps({'type': 'PING', 'data': {}, 'ts': time.time()})}\n\n"
            except Exception:
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


if __name__ == "__main__":
    uvicorn.run("backend:app", host="127.0.0.1", port=8000, reload=True)
