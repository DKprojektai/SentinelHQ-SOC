"""
Wazuh Noise Reducer - Analyzer
Rule ID range: 122000-122999 (free block confirmed)
"""

import os
import sqlite3
import json
import time
import logging
from datetime import datetime, timezone, timedelta

import schedule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [analyzer] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DB_PATH                = os.environ.get("DB_PATH", "/data/alerts.db")
ANALYZE_INTERVAL       = int(os.environ.get("ANALYZE_INTERVAL_SECONDS", 600))
NOISE_THRESHOLD_HOURLY = int(os.environ.get("NOISE_THRESHOLD_HOURLY", 20))
NOISE_WINDOW_HOURS     = int(os.environ.get("NOISE_WINDOW_HOURS", 72))
MIN_OCCURRENCES        = int(os.environ.get("MIN_OCCURRENCES", 10))
NOISE_SCORE_CUTOFF     = 60

RULE_ID_START = int(os.environ.get("RULE_ID_START", 122000))
RULE_ID_MAX   = int(os.environ.get("RULE_ID_MAX",   122999))


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_tables(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS noise_candidates (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint      TEXT UNIQUE,
            rule_id          TEXT,
            rule_desc        TEXT,
            agent_id         TEXT,
            agent_name       TEXT,
            location         TEXT,
            occurrence_count INTEGER,
            hourly_rate      REAL,
            noise_score      INTEGER,
            first_seen       TEXT,
            last_seen        TEXT,
            status           TEXT DEFAULT 'pending',
            reviewed_at      TEXT,
            notes            TEXT,
            updated_at       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_nc_status ON noise_candidates(status);
        CREATE INDEX IF NOT EXISTS idx_nc_score  ON noise_candidates(noise_score DESC);

        CREATE TABLE IF NOT EXISTS suppression_rules (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            wazuh_rule_id INTEGER UNIQUE,
            fingerprint   TEXT UNIQUE,
            rule_id       TEXT,
            agent_name    TEXT,
            location      TEXT,
            rule_desc     TEXT,
            noise_score   INTEGER,
            created_at    TEXT,
            approved_at   TEXT,
            status        TEXT DEFAULT 'draft',
            wazuh_xml     TEXT
        );

        CREATE TABLE IF NOT EXISTS rule_id_counter (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            next INTEGER NOT NULL
        );
    """)
    conn.execute(
        "INSERT OR IGNORE INTO rule_id_counter(id, next) VALUES(1, ?)",
        (RULE_ID_START,)
    )


def next_rule_id(conn) -> int:
    row = conn.execute("SELECT next FROM rule_id_counter WHERE id=1").fetchone()
    current = row["next"]
    if current > RULE_ID_MAX:
        raise RuntimeError(
            f"Rule ID range {RULE_ID_START}-{RULE_ID_MAX} exhausted. "
            f"Increase RULE_ID_MAX in .env"
        )
    conn.execute("UPDATE rule_id_counter SET next=? WHERE id=1", (current + 1,))
    return current


def score_fingerprint(fp_data: dict) -> int:
    count       = fp_data["count"]
    level       = fp_data["rule_level"]
    agent_count = fp_data.get("agent_count", 1)
    hourly_rate = count / max(NOISE_WINDOW_HOURS, 1)

    freq_score   = min(int((hourly_rate / NOISE_THRESHOLD_HOURLY) * 40), 40)
    rep_score    = min(int((count / max(count + 1, 1)) * 30), 30)
    spread_score = min((agent_count - 1) * 5, 15)

    if level >= 12:
        penalty = 40
    elif level >= 10:
        penalty = 25
    elif level >= 7:
        penalty = 10
    else:
        penalty = 0

    return max(0, min(freq_score + rep_score + spread_score - penalty, 100))


def build_xml(wazuh_rule_id: int, c: dict) -> str:
    lines = [
        f'<!-- noise-reducer | score={c["noise_score"]} | original={c["rule_id"]} -->',
        f'<rule id="{wazuh_rule_id}" level="0">',
        f'  <if_sid>{c["rule_id"]}</if_sid>',
    ]
    if c.get("agent_name"):
        lines.append(f'  <match>{c["agent_name"]}</match>')
    if c.get("location"):
        lines.append(f'  <location>{c["location"]}</location>')
    lines += [
        f'  <description>SUPPRESSED (noise): {(c["rule_desc"] or "")[:80]}</description>',
        f'  <options>no_log</options>',
        f'</rule>',
    ]
    return "\n".join(lines)


def generate_draft_rules(conn):
    """Create draft XML for high-score candidates that don't have a rule yet."""
    candidates = conn.execute("""
        SELECT nc.* FROM noise_candidates nc
        LEFT JOIN suppression_rules sr ON sr.fingerprint = nc.fingerprint
        WHERE nc.noise_score >= ? AND sr.id IS NULL
        ORDER BY nc.noise_score DESC
    """, (NOISE_SCORE_CUTOFF,)).fetchall()

    for c in candidates:
        c = dict(c)
        try:
            wid = next_rule_id(conn)
        except RuntimeError as e:
            log.error("%s", e)
            break

        xml = build_xml(wid, c)
        conn.execute("""
            INSERT OR IGNORE INTO suppression_rules
            (wazuh_rule_id, fingerprint, rule_id, agent_name, location,
             rule_desc, noise_score, created_at, status, wazuh_xml)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            wid, c["fingerprint"], c["rule_id"],
            c["agent_name"], c["location"], c["rule_desc"],
            c["noise_score"],
            datetime.now(timezone.utc).isoformat(),
            "draft", xml,
        ))
        log.info("Draft rule created: ID=%d for rule_id=%s score=%d",
                 wid, c["rule_id"], c["noise_score"])


def run_analysis():
    log.info("Starting analysis cycle (window=%dh)", NOISE_WINDOW_HOURS)
    since = (
        datetime.now(timezone.utc) - timedelta(hours=NOISE_WINDOW_HOURS)
    ).isoformat()

    with get_db() as conn:
        ensure_tables(conn)

        rows = conn.execute("""
            SELECT
                fingerprint,
                rule_id,
                MAX(rule_level)          AS rule_level,
                MAX(rule_desc)           AS rule_desc,
                agent_id,
                MAX(agent_name)          AS agent_name,
                location,
                COUNT(*)                 AS cnt,
                MIN(collected_at)        AS first_seen,
                MAX(collected_at)        AS last_seen,
                COUNT(DISTINCT agent_id) AS agent_count
            FROM alerts
            WHERE collected_at >= ?
            GROUP BY fingerprint
            HAVING cnt >= ?
            ORDER BY cnt DESC
        """, (since, MIN_OCCURRENCES)).fetchall()

        log.info("Fingerprint groups to evaluate: %d", len(rows))

        new_c = updated = 0
        for row in rows:
            r     = dict(row)
            score = score_fingerprint({
                "count":       r["cnt"],
                "rule_level":  r["rule_level"],
                "agent_count": r["agent_count"],
            })
            hourly = round(r["cnt"] / NOISE_WINDOW_HOURS, 2)
            now    = datetime.now(timezone.utc).isoformat()

            existing = conn.execute(
                "SELECT id, status FROM noise_candidates WHERE fingerprint=?",
                (r["fingerprint"],)
            ).fetchone()

            if existing:
                if existing["status"] == "pending":
                    conn.execute("""
                        UPDATE noise_candidates
                        SET occurrence_count=?, hourly_rate=?, noise_score=?,
                            last_seen=?, updated_at=?
                        WHERE fingerprint=?
                    """, (r["cnt"], hourly, score, r["last_seen"], now, r["fingerprint"]))
                    updated += 1
            else:
                conn.execute("""
                    INSERT INTO noise_candidates
                    (fingerprint, rule_id, rule_desc, agent_id, agent_name,
                     location, occurrence_count, hourly_rate, noise_score,
                     first_seen, last_seen, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    r["fingerprint"], r["rule_id"], r["rule_desc"],
                    r["agent_id"], r["agent_name"], r["location"],
                    r["cnt"], hourly, score,
                    r["first_seen"], r["last_seen"], now,
                ))
                new_c += 1

        generate_draft_rules(conn)
        log.info("Analysis done. New candidates: %d, Updated: %d", new_c, updated)


if __name__ == "__main__":
    log.info("Wazuh Noise Reducer - Analyzer starting")
    log.info("Rule ID range: %d-%d", RULE_ID_START, RULE_ID_MAX)
    log.info("Window: %dh | Threshold: %d/h | Min occurrences: %d",
             NOISE_WINDOW_HOURS, NOISE_THRESHOLD_HOURLY, MIN_OCCURRENCES)

    time.sleep(5)
    run_analysis()

    schedule.every(ANALYZE_INTERVAL).seconds.do(run_analysis)
    while True:
        schedule.run_pending()
        time.sleep(15)
