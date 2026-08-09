"""
Wazuh Noise Reducer - Collector (OpenSearch edition)
Pulls alerts from wazuh-alerts-* index in OpenSearch/Wazuh Indexer.
"""

import os
import sqlite3
import json
import time
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
import schedule
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [collector] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
OPENSEARCH_URL   = os.environ.get("OPENSEARCH_URL", "https://wazuh.indexer:9200").rstrip("/")
OPENSEARCH_USER  = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS  = os.environ.get("OPENSEARCH_PASS", "SecretPassword")
OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX", "wazuh-alerts-*")
VERIFY_SSL       = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"
COLLECT_INTERVAL = int(os.environ.get("COLLECT_INTERVAL_SECONDS", 120))
DB_PATH          = os.environ.get("DB_PATH", "/data/alerts.db")
PAGE_SIZE        = 500


# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                wazuh_id     TEXT UNIQUE,
                fingerprint  TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                alert_ts     TEXT,
                rule_id      TEXT,
                rule_level   INTEGER,
                rule_desc    TEXT,
                agent_id     TEXT,
                agent_name   TEXT,
                agent_ip     TEXT,
                location     TEXT,
                full_log     TEXT,
                raw_json     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_fingerprint ON alerts(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_rule_id     ON alerts(rule_id);
            CREATE INDEX IF NOT EXISTS idx_agent_id    ON alerts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_collected   ON alerts(collected_at);

            CREATE TABLE IF NOT EXISTS collector_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)
    log.info("Database initialised at %s", DB_PATH)


# ── OpenSearch client ─────────────────────────────────────────────────────────
class OpenSearchClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.auth = (OPENSEARCH_USER, OPENSEARCH_PASS)
        self.session.verify = VERIFY_SSL
        self.session.headers.update({"Content-Type": "application/json"})

    def search(self, index: str, body: dict) -> dict:
        url = f"{OPENSEARCH_URL}/{index}/_search"
        r = self.session.post(url, json=body, timeout=30)
        r.raise_for_status()
        return r.json()

    def ping(self) -> bool:
        try:
            r = self.session.get(f"{OPENSEARCH_URL}/_cluster/health", timeout=10)
            return r.ok
        except Exception:
            return False


# ── Fingerprint ───────────────────────────────────────────────────────────────
def make_fingerprint(rule_id: str, agent_id: str, location: str) -> str:
    raw = f"{rule_id}|{agent_id}|{location}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Alert extraction ──────────────────────────────────────────────────────────
def extract_alert(hit: dict) -> dict:
    """Flatten OpenSearch hit into a normalised alert dict."""
    src = hit.get("_source", {})
    rule   = src.get("rule", {})
    agent  = src.get("agent", {})
    return {
        "id":        hit.get("_id", ""),
        "timestamp": src.get("timestamp", ""),
        "rule_id":   str(rule.get("id", "unknown")),
        "rule_level":int(rule.get("level", 0)),
        "rule_desc": rule.get("description", ""),
        "agent_id":  str(agent.get("id", "000")),
        "agent_name":agent.get("name", ""),
        "agent_ip":  agent.get("ip", ""),
        "location":  src.get("location", ""),
        "full_log":  src.get("full_log", src.get("message", "")),
        "raw":       src,
    }


# ── State ─────────────────────────────────────────────────────────────────────
def get_last_timestamp(conn: sqlite3.Connection) -> Optional[str]:
    row = conn.execute(
        "SELECT value FROM collector_state WHERE key='last_ts'"
    ).fetchone()
    return row["value"] if row else None


def set_last_timestamp(conn: sqlite3.Connection, ts: str):
    conn.execute(
        "INSERT OR REPLACE INTO collector_state(key,value) VALUES('last_ts',?)", (ts,)
    )


# ── Ingest ────────────────────────────────────────────────────────────────────
def ingest_alert(conn: sqlite3.Connection, a: dict) -> bool:
    fp  = make_fingerprint(a["rule_id"], a["agent_id"], a["location"])
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """INSERT OR IGNORE INTO alerts
               (wazuh_id, fingerprint, collected_at, alert_ts,
                rule_id, rule_level, rule_desc,
                agent_id, agent_name, agent_ip,
                location, full_log, raw_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                a["id"], fp, now, a["timestamp"],
                a["rule_id"], a["rule_level"], a["rule_desc"],
                a["agent_id"], a["agent_name"], a["agent_ip"],
                a["location"], a["full_log"],
                json.dumps(a["raw"]),
            ),
        )
        return conn.execute("SELECT changes()").fetchone()[0] > 0
    except sqlite3.Error as e:
        log.warning("Insert error %s: %s", a["id"], e)
        return False


# ── Collection cycle ──────────────────────────────────────────────────────────
def collect():
    log.info("Starting collection cycle")
    client = OpenSearchClient()

    if not client.ping():
        log.error("Cannot reach OpenSearch at %s — will retry next cycle", OPENSEARCH_URL)
        return

    with get_db() as conn:
        last_ts  = get_last_timestamp(conn)
        since    = last_ts or (
            datetime.now(timezone.utc) - timedelta(hours=72)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        log.info("Fetching alerts since %s", since)

        total_new  = 0
        newest_ts  = last_ts
        from_      = 0

        while True:
            body = {
                "from": from_,
                "size": PAGE_SIZE,
                "sort": [{"timestamp": {"order": "asc"}}],
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"timestamp": {"gt": since}}}
                        ]
                    }
                },
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "agent.ip",
                    "location", "full_log", "message",
                ],
            }

            try:
                resp  = client.search(OPENSEARCH_INDEX, body)
                hits  = resp.get("hits", {})
                items = hits.get("hits", [])
                total = hits.get("total", {})
                total_count = total.get("value", 0) if isinstance(total, dict) else total
            except Exception as e:
                log.error("Search error at from=%d: %s", from_, e)
                break

            if not items:
                break

            for hit in items:
                a = extract_alert(hit)
                if ingest_alert(conn, a):
                    total_new += 1
                ts = a["timestamp"]
                if ts and (newest_ts is None or ts > newest_ts):
                    newest_ts = ts

            from_ += len(items)
            if from_ >= total_count or len(items) < PAGE_SIZE:
                break

        if newest_ts and newest_ts != last_ts:
            set_last_timestamp(conn, newest_ts)

        log.info("Collection done. New alerts: %d", total_new)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("Wazuh Noise Reducer - Collector (OpenSearch) starting")
    log.info("OpenSearch: %s | Index: %s | Interval: %ds",
             OPENSEARCH_URL, OPENSEARCH_INDEX, COLLECT_INTERVAL)

    init_db()
    collect()

    schedule.every(COLLECT_INTERVAL).seconds.do(collect)
    while True:
        schedule.run_pending()
        time.sleep(10)
