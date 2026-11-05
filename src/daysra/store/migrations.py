from __future__ import annotations

import sqlite3

MIGRATION_V1 = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scope_hash TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('complete', 'partial', 'failed', 'cancelled')),
    tool_versions TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    first_seen_run TEXT NOT NULL REFERENCES runs(run_id),
    last_seen_run TEXT NOT NULL REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS host_obs (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    host_id TEXT NOT NULL REFERENCES hosts(id),
    hostname TEXT NOT NULL,
    ips TEXT NOT NULL DEFAULT '[]',
    sources TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (run_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
CREATE INDEX IF NOT EXISTS idx_host_obs_run ON host_obs(run_id);
CREATE INDEX IF NOT EXISTS idx_host_obs_host ON host_obs(host_id);
"""

MIGRATION_V2 = """
CREATE TABLE IF NOT EXISTS http_obs (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    host_id TEXT NOT NULL REFERENCES hosts(id),
    hostname TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    tech TEXT NOT NULL DEFAULT '[]',
    content_length INTEGER,
    tls_issuer TEXT,
    PRIMARY KEY (run_id, url)
);

CREATE INDEX IF NOT EXISTS idx_http_obs_run ON http_obs(run_id);
CREATE INDEX IF NOT EXISTS idx_http_obs_host ON http_obs(host_id);
CREATE INDEX IF NOT EXISTS idx_http_obs_status ON http_obs(status_code);
"""

MIGRATION_V3 = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    template_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    cve TEXT NOT NULL DEFAULT '[]',
    matched_at TEXT NOT NULL,
    first_seen_run TEXT NOT NULL REFERENCES runs(run_id),
    last_seen_run TEXT NOT NULL REFERENCES runs(run_id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS finding_obs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    finding_id TEXT NOT NULL REFERENCES findings(id),
    evidence TEXT,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_hostname ON findings(hostname);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_template ON findings(template_id);
CREATE INDEX IF NOT EXISTS idx_finding_obs_run ON finding_obs(run_id);
CREATE INDEX IF NOT EXISTS idx_finding_obs_finding ON finding_obs(finding_id);
"""

MIGRATIONS: list[str] = [
    MIGRATION_V1,
    MIGRATION_V2,
    MIGRATION_V3,
]


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply any pending schema migrations using PRAGMA user_version atomically inside transactions."""
    cur = conn.cursor()
    cur.execute("PRAGMA user_version;")
    row = cur.fetchone()
    current_version = int(row[0]) if row else 0

    old_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        for target_version, sql in enumerate(MIGRATIONS, start=1):
            if current_version < target_version:
                conn.execute("BEGIN IMMEDIATE;")
                try:
                    for raw_stmt in sql.split(";"):
                        stmt = raw_stmt.strip()
                        if stmt:
                            conn.execute(stmt)
                    conn.execute(f"PRAGMA user_version = {target_version};")
                    conn.execute("COMMIT;")
                    current_version = target_version
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
    finally:
        conn.isolation_level = old_isolation

    return current_version


__all__ = [
    "MIGRATIONS",
    "MIGRATION_V1",
    "MIGRATION_V2",
    "MIGRATION_V3",
    "apply_migrations",
]
