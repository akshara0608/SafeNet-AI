"""
SafeNet-AI Threat Store

Records every analyzed URL in a local SQLite database and builds
threat intelligence from those scans:
1. Risk level distribution
2. Detection signal frequency
3. Most flagged domains
4. Recent high-risk scans
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse


DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "safenet.db"
)

HIGH_RISK_LEVELS = ("High", "Critical")


# ============================================================
# DETECTION SIGNALS
# ============================================================
# Each signal: (key, label, description, test on a stored scan)

SIGNALS = [
    ("ip_host", "IP address host",
     "Raw IP used instead of a domain name",
     lambda s, f: f.get("has_ip_address", 0) == 1),

    ("suspicious_tld", "Suspicious TLD",
     "Domain ends in a TLD common in phishing (.xyz, .top, .tk ...)",
     lambda s, f: f.get("has_suspicious_tld", 0) == 1),

    ("phishing_keywords", "Phishing keywords",
     "URL contains words like login, verify, account, wallet",
     lambda s, f: f.get("has_suspicious_keyword", 0) == 1),

    ("shortener", "URL shortener",
     "Real destination hidden behind a link shortener",
     lambda s, f: f.get("is_shortened_url", 0) == 1),

    ("at_in_authority", "@ in host part",
     "Text before @ can disguise the real host",
     lambda s, f: f.get("has_at_symbol_in_authority", 0) == 1),

    ("deep_subdomains", "Deep subdomains",
     "Three or more subdomain levels",
     lambda s, f: f.get("subdomain_depth", 0) >= 3),

    ("custom_port", "Non-standard port",
     "Explicit port number in the URL",
     lambda s, f: f.get("has_port", 0) == 1),

    ("no_https", "No HTTPS",
     "Connection is not encrypted",
     lambda s, f: not s["https"]),
]


# ============================================================
# DATABASE
# ============================================================

def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                classification TEXT NOT NULL,
                phishing_probability REAL NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                https INTEGER NOT NULL,
                indicators TEXT NOT NULL,
                features TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )


def get_setting(key, default=None):
    with _connect() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()

    return json.loads(row["value"]) if row else default


def set_setting(key, value):
    with _connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value))
        )


def _host_of(url):
    parsed = urlparse(url if "://" in url else "https://" + url)
    return (parsed.hostname or url).lower()


def record_scan(result):
    """
    Store one result from analyze_url.analyze().
    """

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                url, host, classification, phishing_probability,
                risk_score, risk_level, https, indicators,
                features, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                _host_of(result["url"]),
                result["classification"],
                result["phishing_probability"],
                result["risk_score"],
                result["risk_level"],
                int(result["https"]),
                json.dumps(result["indicators"]),
                json.dumps(result["features"]),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
        )


def clear_scans():
    """
    Delete every stored scan. Returns how many were removed.
    """

    with _connect() as conn:
        return conn.execute("DELETE FROM scans").rowcount


# ============================================================
# THREAT INTELLIGENCE SUMMARY
# ============================================================

def list_scans(days=None):
    """
    Return stored scans, newest first.
    days: only scans from the last N days (None = all).
    """

    query = "SELECT * FROM scans"
    params = ()

    if days:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        query += " WHERE scanned_at >= ?"
        params = (since.isoformat(timespec="seconds"),)

    with _connect() as conn:
        rows = conn.execute(query + " ORDER BY id DESC", params).fetchall()

    return [
        {
            "url": r["url"],
            "host": r["host"],
            "classification": r["classification"],
            "phishing_probability": r["phishing_probability"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "https": bool(r["https"]),
            "indicators": json.loads(r["indicators"]),
            "features": json.loads(r["features"]),
            "scanned_at": r["scanned_at"],
        }
        for r in rows
    ]


def threat_summary(recent_limit=10, days=None):
    scans = list_scans(days)

    high_risk = [s for s in scans if s["risk_level"] in HIGH_RISK_LEVELS]

    # --------------------------------------------------------
    # Risk level distribution
    # --------------------------------------------------------

    levels = {level: 0 for level in ("Low", "Medium", "High", "Critical")}

    for s in scans:
        levels[s["risk_level"]] = levels.get(s["risk_level"], 0) + 1

    # --------------------------------------------------------
    # Detection signals: hits across all scans and high-risk scans
    # --------------------------------------------------------

    signals = []

    for key, label, description, test in SIGNALS:
        hits = [s for s in scans if test(s, s["features"])]

        if not hits:
            continue

        signals.append({
            "key": key,
            "label": label,
            "description": description,
            "count": len(hits),
            "high_risk_count": sum(
                s["risk_level"] in HIGH_RISK_LEVELS for s in hits
            ),
        })

    signals.sort(key=lambda x: (x["high_risk_count"], x["count"]), reverse=True)

    # --------------------------------------------------------
    # Most flagged domains (High / Critical only)
    # --------------------------------------------------------

    domains = {}

    for s in high_risk:
        d = domains.setdefault(s["host"], {
            "host": s["host"],
            "count": 0,
            "max_risk_score": 0.0,
            "last_seen": s["scanned_at"],
        })
        d["count"] += 1
        d["max_risk_score"] = max(d["max_risk_score"], s["risk_score"])

    top_domains = sorted(
        domains.values(),
        key=lambda d: (d["count"], d["max_risk_score"]),
        reverse=True
    )[:10]

    return {
        "total_scans": len(scans),
        "high_risk_scans": len(high_risk),
        "phishing_scans": sum(s["classification"] == "Phishing" for s in scans),
        "avg_risk_score": round(
            sum(s["risk_score"] for s in scans) / len(scans), 2
        ) if scans else 0.0,
        "levels": levels,
        "signals": signals,
        "top_domains": top_domains,
        "recent_high_risk": [
            {k: s[k] for k in (
                "url", "host", "risk_score", "risk_level",
                "phishing_probability", "scanned_at"
            )}
            for s in high_risk[:recent_limit]
        ],
    }
