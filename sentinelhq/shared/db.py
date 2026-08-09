"""SentinelHQ PostgreSQL connection pool with retry logic."""

import os
import time
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.pool
import psycopg2.extras

log = logging.getLogger(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL', '')

_pool = None


def get_pool():
    """Get or create PostgreSQL connection pool."""
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL environment variable not set")
        min_conn = int(os.environ.get('DB_MIN_CONN', '2'))
        max_conn = int(os.environ.get('DB_MAX_CONN', '10'))
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            dsn=DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        log.info("PostgreSQL connection pool created (min=%d, max=%d)", min_conn, max_conn)
    return _pool


def _reset_pool():
    """Destroy pool — called when postgres restarted or connections went stale."""
    global _pool
    if _pool is not None:
        try:
            _pool.closeall()
        except Exception:
            pass
        _pool = None
    log.warning("DB pool reset — will reconnect on next use")


def get_db(max_retries: int = 5, initial_backoff: float = 1.0):
    """
    Get a healthy DB connection, resetting stale pool automatically.
    Returns raw psycopg2 connection — caller must call putconn() when done.
    """
    backoff = initial_backoff
    for attempt in range(max_retries + 1):
        try:
            conn = get_pool().getconn()
            # Detect stale connection (postgres restarted while pool was alive)
            if conn.closed != 0:
                try:
                    get_pool().putconn(conn, close=True)
                except Exception:
                    pass
                raise psycopg2.OperationalError("stale connection in pool")
            if attempt > 0:
                log.debug("Got DB connection after %d retries", attempt)
            return conn
        except (psycopg2.OperationalError, psycopg2.InterfaceError,
                psycopg2.pool.PoolError) as e:
            if attempt >= max_retries:
                log.error("Cannot get DB connection after %d attempts: %s", max_retries, e)
                raise
            wait = min(backoff * (2 ** attempt), 30)
            log.warning("DB connection error, resetting pool (attempt %d/%d, retry in %.1fs): %s",
                        attempt + 1, max_retries, wait, e)
            _reset_pool()
            time.sleep(wait)
    raise psycopg2.OperationalError("Failed to connect after retries")


@contextmanager
def get_db_context(max_retries: int = 3):
    """
    Context manager for safe database connection handling.

    Usage:
        with get_db_context() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT ...")
    """
    conn = get_db(max_retries=max_retries)
    try:
        yield conn
        conn.commit()
    except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
        # Connection dropped mid-operation — reset pool so next caller reconnects
        log.warning("DB connection lost during operation, resetting pool: %s", e)
        _reset_pool()
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    except Exception as e:
        log.error("Database operation failed", exc_info=True)
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        # Return to pool only if connection and pool are still alive
        try:
            if _pool is not None and conn.closed == 0:
                _pool.putconn(conn)
        except Exception:
            pass


def fetchone(sql: str, params=None):
    """Execute query and fetch single row."""
    with get_db_context() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()


def fetchall(sql: str, params=None):
    """Execute query and fetch all rows."""
    with get_db_context() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()


def execute(sql: str, params=None) -> int:
    """Execute insert/update/delete query. Returns rowcount."""
    with get_db_context() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.rowcount


def execute_returning(sql: str, params=None):
    """Execute query with RETURNING clause."""
    with get_db_context() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()


def lift_decompression_limit(cur):
    """Allow unlimited compressed-chunk decompression for the CURRENT transaction.

    Call BEFORE a large DELETE/UPDATE on the `alerts` TimescaleDB hypertable.
    The default cap (timescaledb.max_tuples_decompressed_per_dml_transaction =
    100000) aborts such DML with 'tuple decompression limit exceeded'.
    SET LOCAL resets on commit; the global config stays untouched.
    Must be called inside an open get_db_context() transaction, on its cursor.
    """
    cur.execute("SET LOCAL timescaledb.max_tuples_decompressed_per_dml_transaction = 0")


def close_pool():
    """Close all connections in pool (cleanup on shutdown)."""
    _reset_pool()
    log.info("Connection pool closed")
