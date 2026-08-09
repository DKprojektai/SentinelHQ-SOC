"""Brute force — read/unblock only (bot doesn't record attempts)."""
from db import get_db


def unblock_ip(ip: str, actor: str) -> bool:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE blocked_ips
                SET unblocked_at=NOW(), unblocked_by=%s
                WHERE ip=%s AND unblocked_at IS NULL AND blocked_until > NOW()
            """, (actor, ip))
            affected = cur.rowcount > 0
        if affected:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM login_attempts WHERE ip=%s", (ip,))
        return affected


def get_blocked_list() -> list:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ip, blocked_at, blocked_until, reason, source, unblocked_at
                FROM blocked_ips ORDER BY blocked_at DESC LIMIT 50
            """)
            return [dict(r) for r in cur.fetchall()]
