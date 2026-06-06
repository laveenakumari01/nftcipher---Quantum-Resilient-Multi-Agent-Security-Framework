"""
database.py
===========

Shared Database class — single connection pool for the entire application.

pg_rag_store.py and threat_intelligence.py both import from here:
    from database import Database

backend.py also imports from here so everyone shares the same pool.

Why a separate file instead of keeping it in backend.py:
  - pg_rag_store and threat_intelligence are loaded BEFORE backend finishes
    initialising (they are imported at the top of backend.py).
  - If they imported Database from backend, Python would hit a circular import
    error (backend → pg_rag_store → backend).
  - Moving Database here breaks the cycle: everyone imports from database,
    nobody imports from backend except the entry point (uvicorn).
"""

import os
import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv

load_dotenv()

DB_NAME     = os.getenv("DB_NAME",     "postgres")
DB_USER     = os.getenv("DB_USER",     "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = os.getenv("DB_PORT",     "5432")


class Database:
    _pool = None

    @classmethod
    def get_pool(cls):
        if cls._pool is None:
            try:
                cls._pool = pool.ThreadedConnectionPool(
                    1, 20,
                    dbname   = DB_NAME,
                    user     = DB_USER,
                    password = DB_PASSWORD,
                    host     = DB_HOST,
                    port     = int(DB_PORT),
                )
                print("[OK] PostgreSQL connected! (database.py pool)")
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