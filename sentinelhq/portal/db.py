"""
SentinelHQ — shared PostgreSQL connection pool.
All services import this module.
"""

import os
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.pool
import psycopg2.extras

log = logging.getLogger(__name__)

DATABASE_URL = os.environ["DATABASE_URL"]

_pool = None


def get_pool():
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            dsn=DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        log.info("PostgreSQL connection pool created")
    return _pool


@contextmanager
def get_db():
    pool = get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def fetchone(sql: str, params=None):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def fetchall(sql: str, params=None):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def execute(sql: str, params=None):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount


def execute_returning(sql: str, params=None):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()
