"""
db.py — Postgres connection pool and query helpers.

All database access in the application goes through this module.
Nothing else imports psycopg2 directly — only db.py does.

Usage:
    from db import fetchone, fetchall, execute, execute_returning

    row  = fetchone("SELECT * FROM users WHERE operator_id = %s", (op_id,))
    rows = fetchall("SELECT * FROM scans WHERE user_id = %s", (user_id,))
    execute("UPDATE users SET status = %s WHERE id = %s", ("active", uid))
    row  = execute_returning("INSERT INTO scans ... RETURNING id", (...))
"""

import os
import logging
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor   # rows come back as dicts, not tuples
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  CONNECTION POOL
#  minconn=2  — always keep 2 connections ready
#  maxconn=10 — never open more than 10 simultaneous connections
#  Adjust maxconn based on how many concurrent requests you expect.
# ─────────────────────────────────────────────────────────────
_pool: pool.ThreadedConnectionPool | None = None


def init_pool() -> None:
    """
    Create the connection pool. Called once at server startup (from main.py).
    Raises if Postgres is unreachable so the server fails fast on misconfiguration.
    """
    global _pool
    try:
        _pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 5432)),
            dbname=os.getenv("DB_NAME", "packetpulse"),
            user=os.getenv("DB_USER", "pp_user"),
            password=os.getenv("DB_PASSWORD", ""),
            connect_timeout=5,
        )
        log.info("Database pool initialised (min=2, max=10)")
    except psycopg2.OperationalError as e:
        log.critical("Could not connect to Postgres: %s", e)
        raise


def close_pool() -> None:
    """Close all connections in the pool. Called at server shutdown."""
    global _pool
    if _pool:
        _pool.closeall()
        log.info("Database pool closed")


# ─────────────────────────────────────────────────────────────
#  CONTEXT MANAGER — borrows and returns a connection safely
# ─────────────────────────────────────────────────────────────
@contextmanager
def _get_conn():
    """
    Borrow a connection from the pool for the duration of the with-block.
    Commits on success, rolls back on any exception, always returns the
    connection to the pool regardless of outcome.
    """
    if _pool is None:
        raise RuntimeError("Database pool is not initialised. Call init_pool() first.")

    conn = _pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


# ─────────────────────────────────────────────────────────────
#  PUBLIC QUERY HELPERS
#  All four functions accept:
#    sql    — parameterised SQL string, e.g. "SELECT ... WHERE id = %s"
#    params — tuple of values to bind, e.g. (user_id,)
#             Always use %s placeholders — never format strings directly
#             into SQL. This prevents SQL injection by design.
# ─────────────────────────────────────────────────────────────

def fetchone(sql: str, params: tuple = ()) -> dict | None:
    """
    Run a SELECT and return the first matching row as a dict,
    or None if no rows matched.

    Example:
        user = fetchone("SELECT * FROM users WHERE operator_id = %s", (op_id,))
        if user:
            print(user["email"])
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None


def fetchall(sql: str, params: tuple = ()) -> list[dict]:
    """
    Run a SELECT and return all matching rows as a list of dicts.
    Returns an empty list if no rows matched.

    Example:
        scans = fetchall(
            "SELECT * FROM scans WHERE user_id = %s ORDER BY started_at DESC",
            (user_id,)
        )
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def execute(sql: str, params: tuple = ()) -> int:
    """
    Run an INSERT, UPDATE, or DELETE. Returns the number of rows affected.
    Commits automatically on success, rolls back on error.

    Example:
        rows_updated = execute(
            "UPDATE users SET status = %s WHERE id = %s",
            ("active", user_id)
        )
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount


def execute_returning(sql: str, params: tuple = ()) -> dict | None:
    """
    Run an INSERT or UPDATE with a RETURNING clause and return the
    first returned row as a dict.

    Example:
        scan = execute_returning(
            "INSERT INTO scans (user_id, subnet, ...) VALUES (%s, %s, ...) RETURNING *",
            (user_id, subnet, ...)
        )
        scan_id = scan["id"]
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None


def call_function(sql: str, params: tuple = ()):
    """
    Call a stored Postgres function that returns a scalar value.
    Used for the helper functions defined in init.sql:
        is_account_locked(), record_failed_login(), clear_failed_logins()

    Example:
        locked = call_function(
            "SELECT is_account_locked(%s)", (operator_id,)
        )  # returns True or False
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row[0] if row else None