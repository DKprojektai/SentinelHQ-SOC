"""
Brute force protection — shared login attempt tracking via PostgreSQL.
"""
import os
import logging
import requests
from datetime import datetime, timezone, timedelta
from db import get_db

log = logging.getLogger(__name__)

MAX_ATTEMPTS       = 5
WINDOW_MIN         = 15
BLOCK_MIN          = 30
ACCOUNT_MAX_FAILS  = 10   # Bandymų skaičius iš VISŲ IP prieš užrakinant paskyrą
SCAN_MAX_ERRORS    = 5    # 4xx klaidų skaičius prieš užblokuojant skenerį
SCAN_WINDOW_MIN    = 10   # Laiko langas skenerio aptikimui

# ── Telegram notification ─────────────────────────────────────────────────────

def _local_now():
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo(os.environ.get("TZ", "Europe/Vilnius"))).strftime("%Y-%m-%d %H:%M")

_BF_TR = {
    "lt": {
        "blocked_ip":   "🚨 <b>IP užblokuotas</b>",
        "source":       "Šaltinis",
        "user":         "Vartotojas",
        "blocked_for":  "Blokuota",
        "min30":        "30 min.",
        "hr24":         "24 val.",
        "acc_locked":   "🔒 <b>Paskyra užrakinta</b>",
        "acc_fails":    "Nesėkmingi bandymai",
        "acc_diff_ips": "iš skirtingų IP",
        "acc_manual":   "🔑 Atrakinti galima tik rankiniu būdu",
        "scan_blocked": "🤖 <b>Skeneris užblokuotas</b>",
        "errors":       "Klaidos",
        "unblock_btn":  "🔓 Atblokuoti IP",
        "unlock_btn":   "🔓 Atrakinti paskyrą",
    },
    "en": {
        "blocked_ip":   "🚨 <b>IP blocked</b>",
        "source":       "Source",
        "user":         "User",
        "blocked_for":  "Blocked for",
        "min30":        "30 min.",
        "hr24":         "24 hours",
        "acc_locked":   "🔒 <b>Account locked</b>",
        "acc_fails":    "Failed attempts",
        "acc_diff_ips": "from different IPs",
        "acc_manual":   "🔑 Can only be unlocked manually",
        "scan_blocked": "🤖 <b>Scanner blocked</b>",
        "errors":       "Errors",
        "unblock_btn":  "🔓 Unblock IP",
        "unlock_btn":   "🔓 Unlock account",
    },
}

def _get_bot_lang() -> str:
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM collector_state WHERE key='bot_lang'")
                row = cur.fetchone()
                return row["value"] if row and row["value"] in _BF_TR else "lt"
    except Exception:
        return "lt"

def _tr(key: str) -> str:
    return _BF_TR[_get_bot_lang()].get(key, key)


def _notify_ip_blocked(ip: str, source: str, username: str = None):
    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    text = (
        f"{_tr('blocked_ip')}\n──────────────\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 {_tr('source')}: <b>{source}</b>\n"
        f"👤 {_tr('user')}: <code>{username or '?'}</code>\n"
        f"⏱ {_tr('blocked_for')}: {BLOCK_MIN} {_tr('min30')}\n"
        f"⏰ {_local_now()}"
    )
    keyboard = {"inline_keyboard": [[{"text": _tr("unblock_btn"), "callback_data": f"unblock_ip:{ip}"}]]}
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard},
                      timeout=10)
    except Exception as e:
        log.warning("Telegram notify error: %s", e)


def _notify_account_locked(username: str, source: str, fail_count: int):
    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    text = (
        f"{_tr('acc_locked')}\n──────────────\n"
        f"👤 {_tr('user')}: <code>{username}</code>\n"
        f"📍 {_tr('source')}: <b>{source}</b>\n"
        f"⚠️ {_tr('acc_fails')}: <b>{fail_count}</b> {_tr('acc_diff_ips')}\n"
        f"{_tr('acc_manual')}\n"
        f"⏰ {_local_now()}"
    )
    keyboard = {"inline_keyboard": [[{"text": _tr("unlock_btn"), "callback_data": f"unlock_account:admin:{username}"}]]}
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard},
                      timeout=10)
    except Exception as e:
        log.warning("Telegram notify error: %s", e)


def _notify_scan_blocked(ip: str, source: str, count: int, status: int):
    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return
    text = (
        f"{_tr('scan_blocked')}\n──────────────\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 {_tr('source')}: <b>{source}</b>\n"
        f"⚠️ {_tr('errors')}: <b>{count}x HTTP {status}</b>\n"
        f"⏱ {_tr('blocked_for')}: {_tr('hr24')}\n"
        f"⏰ {_local_now()}"
    )
    keyboard = {"inline_keyboard": [[{"text": _tr("unblock_btn"), "callback_data": f"unblock_ip:{ip}"}]]}
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "reply_markup": keyboard},
                      timeout=10)
    except Exception as e:
        log.warning("Telegram notify error: %s", e)


# ── IP blokavimas ─────────────────────────────────────────────────────────────

def is_blocked(ip: str, source: str = None) -> bool:
    """Jei source=None — tikrina visus admin šaltinius."""
    sources = [source] if source else ["admin", "admin_mfa", "admin_scan"]
    placeholders = ",".join(["%s"] * len(sources))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT 1 FROM blocked_ips
                WHERE ip=%s AND source IN ({placeholders}) AND blocked_until > NOW() AND unblocked_at IS NULL
            """, [ip] + sources)
            return cur.fetchone() is not None


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


# ── Paskyros užrakinimas ──────────────────────────────────────────────────────

def is_account_locked(username: str) -> bool:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT locked_at FROM admin_users WHERE username=%s AND locked_at IS NOT NULL", (username,))
            return cur.fetchone() is not None


def unlock_account(username: str, actor: str) -> bool:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE admin_users SET locked_at=NULL, lock_reason=NULL
                WHERE username=%s AND locked_at IS NOT NULL
            """, (username,))
            affected = cur.rowcount > 0
        if affected:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM login_attempts WHERE email=%s", (username,))
            log.info("Account unlocked: %s by %s", username, actor)
        return affected


def get_locked_accounts() -> list:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username AS account, locked_at, lock_reason, 'admin' AS source
                FROM admin_users WHERE locked_at IS NOT NULL
                ORDER BY locked_at DESC
            """)
            return [dict(r) for r in cur.fetchall()]


# ── Bandymų registravimas ─────────────────────────────────────────────────────

def record_attempt(ip: str, username: str, success: bool, source: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO login_attempts(ip, email, success, source)
                VALUES(%s, %s, %s, %s)
            """, (ip, username, success, source))

        if success:
            return

        # --- IP blokavimas ---
        with conn.cursor() as cur:
            cur.execute("""
                SELECT GREATEST(
                    COALESCE(MAX(CASE WHEN unblocked_at IS NOT NULL THEN unblocked_at END), '1970-01-01'),
                    COALESCE(MAX(CASE WHEN unblocked_at IS NULL THEN blocked_until END), '1970-01-01')
                ) AS reset_at
                FROM blocked_ips WHERE ip=%s AND source=%s
            """, (ip, source))
            reset_at = cur.fetchone()["reset_at"]

        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS c FROM login_attempts
                WHERE ip=%s AND source=%s AND success=false
                  AND attempted_at >= NOW() - INTERVAL '%s minutes'
                  AND attempted_at > %s
            """, (ip, source, WINDOW_MIN, reset_at or '1970-01-01'))
            ip_count = cur.fetchone()["c"]

        if ip_count >= MAX_ATTEMPTS and not is_blocked(ip, source):
            blocked_until = datetime.now(timezone.utc) + timedelta(minutes=BLOCK_MIN)
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO blocked_ips(ip, source, blocked_until, reason)
                    VALUES(%s, %s, %s, %s)
                    ON CONFLICT(ip, source) DO UPDATE
                        SET blocked_at=NOW(), blocked_until=EXCLUDED.blocked_until,
                            reason=EXCLUDED.reason, unblocked_at=NULL, unblocked_by=NULL
                """, (ip, source, blocked_until, f"{ip_count} failed attempts in {WINDOW_MIN} min"))
            log.warning("IP blocked: %s (%s attempts, source=%s)", ip, ip_count, source)
            _notify_ip_blocked(ip, source, username)

        # --- Paskyros užrakinimas (iš visų IP) ---
        if username and not is_account_locked(username):
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) AS c FROM login_attempts
                    WHERE email=%s AND success=false
                      AND source IN ('admin','admin_mfa')
                      AND attempted_at >= NOW() - INTERVAL '24 hours'
                """, (username,))
                acc_count = cur.fetchone()["c"]

            if acc_count >= ACCOUNT_MAX_FAILS:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE admin_users SET locked_at=NOW(), lock_reason=%s
                        WHERE username=%s
                    """, (f"{acc_count} failed attempts from multiple IPs", username))
                log.warning("Account locked: %s (%s attempts)", username, acc_count)
                _notify_account_locked(username, source, acc_count)


# ── Skenerių blokavimas (4xx) ────────────────────────────────────────────────

def _is_scan_blocked(ip: str, scan_source: str) -> bool:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1 FROM blocked_ips
                WHERE ip=%s AND source=%s AND blocked_until > NOW() AND unblocked_at IS NULL
            """, (ip, scan_source))
            return cur.fetchone() is not None


def record_http_error(ip: str, path: str, status: int, source: str):
    """Registruoja 4xx klaidą ir užblokuoja IP jei viršytas limitas."""
    scan_source = f"{source}_scan"

    # Jei jau užblokuotas (bet kuriuo būdu) — nerašome toliau
    if _is_scan_blocked(ip, scan_source) or is_blocked(ip):
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO http_errors(ip, path, status_code, source)
                VALUES(%s, %s, %s, %s)
            """, (ip, path[:200], status, source))

        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS c FROM http_errors
                WHERE ip=%s AND source=%s
                  AND occurred_at >= NOW() - INTERVAL '%s minutes'
            """, (ip, source, SCAN_WINDOW_MIN))
            count = cur.fetchone()["c"]

        if count >= SCAN_MAX_ERRORS:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO blocked_ips(ip, source, blocked_until, reason)
                    VALUES(%s, %s, NOW() + INTERVAL '24 hours', %s)
                    ON CONFLICT(ip, source) DO NOTHING
                """, (ip, scan_source, f"{count} HTTP {status} errors in {SCAN_WINDOW_MIN} min"))
                inserted = cur.rowcount > 0
            if inserted:
                log.warning("Scanner blocked: %s (%s errors, source=%s)", ip, count, source)
                _notify_scan_blocked(ip, scan_source, count, status)


# ── Sąrašai ───────────────────────────────────────────────────────────────────

def get_blocked_list() -> list:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ip, blocked_at, blocked_until, reason, source,
                       unblocked_at, unblocked_by
                FROM blocked_ips
                ORDER BY blocked_at DESC
                LIMIT 100
            """)
            return [dict(r) for r in cur.fetchall()]
