from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from daysra.store.migrations import apply_migrations

SENSITIVE_PARAM_KEYWORDS: tuple[str, ...] = (
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "auth",
    "session",
    "sid",
    "jwt",
    "signature",
    "sig",
)

DB_FILE_MODE = 0o600
DB_DIR_MODE = 0o700


def _restrict_db_permissions(path: Path) -> None:
    """Enforce owner-only permissions on the database and any WAL/SHM sidecars."""
    sidecars = (
        path,
        path.with_name(f"{path.name}-wal"),
        path.with_name(f"{path.name}-shm"),
    )
    for candidate in sidecars:
        try:
            candidate.chmod(DB_FILE_MODE)
        except FileNotFoundError:
            continue


def _ensure_private_parent(path: Path) -> None:
    """Create missing parent directories with 0700 without touching existing ones."""
    missing: list[Path] = []
    current = path.parent
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=DB_DIR_MODE)
        except FileExistsError:
            # Another process created it concurrently; never alter its mode.
            if not directory.is_dir():
                raise
            continue
        directory.chmod(DB_DIR_MODE)


def sanitize_matched_at(raw_url: str) -> str:
    """Sanitize matched-at URL: remove userinfo (user:pass@), strip fragment,

    and redact query parameter values whose name contains sensitive keywords.
    """
    if not raw_url or not raw_url.strip():
        return ""
    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        return raw_url

    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    query = parts.query
    if query:
        params = parse_qsl(query, keep_blank_values=True)
        sanitized_params = []
        for k, v in params:
            k_lower = k.lower()
            if any(kw in k_lower for kw in SENSITIVE_PARAM_KEYWORDS):
                sanitized_params.append((k, "REDACTED"))
            else:
                sanitized_params.append((k, v))
        query = urlencode(sanitized_params)

    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def get_db_path(custom_path: Path | str | None = None) -> Path:
    """Resolve database path following XDG spec or DAYSRA_HOME override."""
    if custom_path is not None:
        p = Path(custom_path)
    elif "DAYSRA_HOME" in os.environ and os.environ["DAYSRA_HOME"].strip():
        p = Path(os.environ["DAYSRA_HOME"]) / "daysra.db"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if (xdg and xdg.strip()) else (Path.home() / ".local" / "share")
        p = base / "daysra" / "daysra.db"

    _ensure_private_parent(p)
    return p


def host_id(hostname: str) -> str:
    """Generate stable SHA-256 hex digest for a normalized hostname per Design Freeze 6.2."""
    return hashlib.sha256(hostname.strip().lower().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    target: str
    scope_hash: str | None
    started_at: str
    finished_at: str | None
    status: str
    tool_versions: dict[str, str]


@dataclass(frozen=True)
class HostRecord:
    id: str
    hostname: str
    first_seen_run: str
    last_seen_run: str


@dataclass(frozen=True)
class HostObsRecord:
    run_id: str
    host_id: str
    hostname: str
    ips: list[str]
    sources: list[str]


@dataclass(frozen=True)
class HttpObsRecord:
    run_id: str
    host_id: str
    hostname: str
    url: str
    status_code: int | None
    title: str | None
    tech: list[str]
    content_length: int | None
    tls_issuer: str | None


@dataclass(frozen=True)
class FindingRecord:
    id: str
    hostname: str
    template_id: str
    name: str
    severity: str
    cve: list[str]
    matched_at: str
    first_seen_run: str
    last_seen_run: str
    first_seen: str
    last_seen: str
    status: str = "open"


@dataclass(frozen=True)
class FindingObsRecord:
    id: int
    run_id: str
    finding_id: str
    evidence: str | None
    tool: str
    tool_version: str
    observed_at: str


class Database:
    """Manages SQLite connection, migrations, and queries. Python is the sole writer."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = get_db_path(path)
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        try:
            # Tighten the database file before enabling WAL so SQLite creates
            # the -wal/-shm sidecars with owner-only permissions too.
            _restrict_db_permissions(self.path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            _restrict_db_permissions(self.path)
        except Exception:
            conn.close()
            raise
        return conn

    def _init_db(self) -> None:
        conn = self.connect()
        try:
            apply_migrations(conn)
        finally:
            _restrict_db_permissions(self.path)
            conn.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self.connect()
        try:
            with conn:
                yield conn
        finally:
            _restrict_db_permissions(self.path)
            conn.close()

    def get_user_version(self) -> int:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def upsert_run(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        target: str,
        started_at: str,
        status: str = "partial",
        tool_versions: dict[str, str] | None = None,
        scope_hash: str | None = None,
    ) -> None:
        cur = conn.cursor()
        cur.execute("SELECT tool_versions FROM runs WHERE run_id = ?", (run_id,))
        row = cur.fetchone()
        merged_tools: dict[str, str] = {}
        if row:
            raw_tools = row["tool_versions"] if isinstance(row, dict) else row[0]
            if raw_tools:
                try:
                    parsed = json.loads(raw_tools)
                    if isinstance(parsed, dict):
                        merged_tools.update(parsed)
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
        if tool_versions:
            merged_tools.update(tool_versions)
        tools_json = json.dumps(merged_tools, sort_keys=True)
        cur.execute(
            """
            INSERT INTO runs (run_id, target, scope_hash, started_at, status, tool_versions)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                target = CASE WHEN excluded.target != '' THEN excluded.target ELSE runs.target END,
                scope_hash = COALESCE(excluded.scope_hash, runs.scope_hash),
                tool_versions = excluded.tool_versions
            """,
            (run_id, target, scope_hash, started_at, status, tools_json),
        )

    def finish_run(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        status: str,
        finished_at: str | None = None,
    ) -> None:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE runs
            SET
                status = CASE
                    WHEN status IN ('cancelled', 'failed') THEN status
                    ELSE ?
                END,
                finished_at = CASE
                    WHEN status IN ('cancelled', 'failed') THEN finished_at
                    ELSE COALESCE(?, finished_at)
                END
            WHERE run_id = ?
            """,
            (status, finished_at, run_id),
        )

    def upsert_host(
        self,
        conn: sqlite3.Connection,
        hostname: str,
        run_id: str,
    ) -> str:
        hid = host_id(hostname)
        norm_host = hostname.strip().lower()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO hosts (id, hostname, first_seen_run, last_seen_run)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_run = excluded.last_seen_run
            """,
            (hid, norm_host, run_id, run_id),
        )
        return hid

    def upsert_host_obs(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        hostname: str,
        ips: list[str] | None = None,
        sources: list[str] | None = None,
    ) -> str:
        hid = host_id(hostname)
        norm_host = hostname.strip().lower()
        new_ips = sorted({x.strip() for x in (ips or []) if x and x.strip()})
        new_sources = sorted({x.strip() for x in (sources or []) if x and x.strip()})

        cur = conn.cursor()
        cur.execute(
            "SELECT ips, sources FROM host_obs WHERE run_id = ? AND host_id = ?",
            (run_id, hid),
        )
        existing = cur.fetchone()
        if existing:
            merged_ips = sorted(set(json.loads(existing["ips"])) | set(new_ips))
            merged_sources = sorted(set(json.loads(existing["sources"])) | set(new_sources))
            cur.execute(
                """
                UPDATE host_obs
                SET ips = ?, sources = ?
                WHERE run_id = ? AND host_id = ?
                """,
                (json.dumps(merged_ips), json.dumps(merged_sources), run_id, hid),
            )
        else:
            cur.execute(
                """
                INSERT INTO host_obs (run_id, host_id, hostname, ips, sources)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, hid, norm_host, json.dumps(new_ips), json.dumps(new_sources)),
            )

        return hid

    def upsert_http_obs(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        hostname: str,
        url: str,
        status_code: int | None = None,
        title: str | None = None,
        tech: list[str] | None = None,
        content_length: int | None = None,
        tls_issuer: str | None = None,
    ) -> str:
        hid = host_id(hostname)
        norm_host = hostname.strip().lower()
        norm_url = url.strip()
        new_tech = sorted({x.strip() for x in (tech or []) if x and x.strip()})

        cur = conn.cursor()
        cur.execute(
            "SELECT tech, title, status_code, content_length, tls_issuer FROM http_obs WHERE run_id = ? AND url = ?",
            (run_id, norm_url),
        )
        existing = cur.fetchone()
        if existing:
            merged_tech = sorted(set(json.loads(existing["tech"])) | set(new_tech))
            cur.execute(
                """
                UPDATE http_obs
                SET host_id = ?,
                    hostname = ?,
                    status_code = COALESCE(?, status_code),
                    title = CASE WHEN ? IS NOT NULL AND ? != '' THEN ? ELSE title END,
                    tech = ?,
                    content_length = COALESCE(?, content_length),
                    tls_issuer = COALESCE(?, tls_issuer)
                WHERE run_id = ? AND url = ?
                """,
                (
                    hid,
                    norm_host,
                    status_code,
                    title,
                    title,
                    title,
                    json.dumps(merged_tech),
                    content_length,
                    tls_issuer,
                    run_id,
                    norm_url,
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO http_obs (run_id, host_id, hostname, url, status_code, title, tech, content_length, tls_issuer)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    hid,
                    norm_host,
                    norm_url,
                    status_code,
                    title,
                    json.dumps(new_tech),
                    content_length,
                    tls_issuer,
                ),
            )

        return hid

    def upsert_finding(
        self,
        conn: sqlite3.Connection,
        finding_id: str,
        hostname: str,
        template_id: str,
        name: str,
        severity: str,
        matched_at: str,
        run_id: str,
        observed_at: str,
        cve: list[str] | None = None,
        status: str = "open",
    ) -> str:
        norm_host = hostname.strip().lower()
        norm_matched_at = sanitize_matched_at(matched_at)
        new_cve = sorted({c.strip() for c in (cve or []) if c and c.strip()})
        cur = conn.cursor()
        cur.execute(
            "SELECT cve FROM findings WHERE id = ?",
            (finding_id,),
        )
        existing = cur.fetchone()
        if existing:
            raw_cves = json.loads(existing["cve"]) if existing["cve"] else []
            merged_cve = sorted(set(raw_cves) | set(new_cve))
            cur.execute(
                """
                UPDATE findings
                SET hostname = ?,
                    template_id = ?,
                    name = ?,
                    severity = ?,
                    cve = ?,
                    matched_at = ?,
                    last_seen_run = ?,
                    last_seen = ?,
                    status = ?
                WHERE id = ?
                """,
                (
                    norm_host,
                    template_id,
                    name,
                    severity,
                    json.dumps(merged_cve),
                    norm_matched_at,
                    run_id,
                    observed_at,
                    status,
                    finding_id,
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO findings (
                    id, hostname, template_id, name, severity, cve,
                    matched_at, first_seen_run, last_seen_run, first_seen, last_seen, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    norm_host,
                    template_id,
                    name,
                    severity,
                    json.dumps(new_cve),
                    norm_matched_at,
                    run_id,
                    run_id,
                    observed_at,
                    observed_at,
                    status,
                ),
            )
        return finding_id

    def insert_finding_obs(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        finding_id: str,
        evidence: str | None,
        tool: str,
        tool_version: str,
        observed_at: str,
    ) -> int:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO finding_obs (run_id, finding_id, evidence, tool, tool_version, observed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, finding_id, evidence, tool, tool_version, observed_at),
        )
        return int(cur.lastrowid or 0)

    def get_run(self, run_id: str) -> RunRecord | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT run_id, target, scope_hash, started_at, finished_at, status, tool_versions FROM runs WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return RunRecord(
                run_id=row["run_id"],
                target=row["target"],
                scope_hash=row["scope_hash"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                status=row["status"],
                tool_versions=json.loads(row["tool_versions"]),
            )
        finally:
            conn.close()

    def get_latest_run(self) -> RunRecord | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT run_id, target, scope_hash, started_at, finished_at, status, tool_versions FROM runs ORDER BY started_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                return None
            return RunRecord(
                run_id=row["run_id"],
                target=row["target"],
                scope_hash=row["scope_hash"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                status=row["status"],
                tool_versions=json.loads(row["tool_versions"]),
            )
        finally:
            conn.close()

    def get_hosts_for_run(self, run_id: str) -> list[HostObsRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT run_id, host_id, hostname, ips, sources FROM host_obs WHERE run_id = ? ORDER BY hostname ASC",
                (run_id,),
            )
            rows = cur.fetchall()
            return [
                HostObsRecord(
                    run_id=r["run_id"],
                    host_id=r["host_id"],
                    hostname=r["hostname"],
                    ips=json.loads(r["ips"]),
                    sources=json.loads(r["sources"]),
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_all_hosts(self) -> list[HostRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, hostname, first_seen_run, last_seen_run FROM hosts ORDER BY hostname ASC"
            )
            rows = cur.fetchall()
            return [
                HostRecord(
                    id=r["id"],
                    hostname=r["hostname"],
                    first_seen_run=r["first_seen_run"],
                    last_seen_run=r["last_seen_run"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_http_obs_for_run(self, run_id: str) -> list[HttpObsRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT run_id, host_id, hostname, url, status_code, title, tech, content_length, tls_issuer
                FROM http_obs
                WHERE run_id = ?
                ORDER BY hostname ASC, url ASC
                """,
                (run_id,),
            )
            rows = cur.fetchall()
            return [
                HttpObsRecord(
                    run_id=r["run_id"],
                    host_id=r["host_id"],
                    hostname=r["hostname"],
                    url=r["url"],
                    status_code=r["status_code"],
                    title=r["title"],
                    tech=json.loads(r["tech"]),
                    content_length=r["content_length"],
                    tls_issuer=r["tls_issuer"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_all_http_obs(self) -> list[HttpObsRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT run_id, host_id, hostname, url, status_code, title, tech, content_length, tls_issuer
                FROM http_obs
                ORDER BY hostname ASC, url ASC
                """
            )
            rows = cur.fetchall()
            return [
                HttpObsRecord(
                    run_id=r["run_id"],
                    host_id=r["host_id"],
                    hostname=r["hostname"],
                    url=r["url"],
                    status_code=r["status_code"],
                    title=r["title"],
                    tech=json.loads(r["tech"]),
                    content_length=r["content_length"],
                    tls_issuer=r["tls_issuer"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_finding(self, finding_id: str) -> FindingRecord | None:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, hostname, template_id, name, severity, cve,
                       matched_at, first_seen_run, last_seen_run, first_seen, last_seen, status
                FROM findings
                WHERE id = ?
                """,
                (finding_id,),
            )
            r = cur.fetchone()
            if not r:
                return None
            return FindingRecord(
                id=r["id"],
                hostname=r["hostname"],
                template_id=r["template_id"],
                name=r["name"],
                severity=r["severity"],
                cve=json.loads(r["cve"]),
                matched_at=r["matched_at"],
                first_seen_run=r["first_seen_run"],
                last_seen_run=r["last_seen_run"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                status=r["status"],
            )
        finally:
            conn.close()

    def get_findings_for_run(self, run_id: str) -> list[FindingRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT f.id, f.hostname, f.template_id, f.name, f.severity, f.cve,
                                f.matched_at, f.first_seen_run, f.last_seen_run, f.first_seen, f.last_seen, f.status
                FROM findings f
                JOIN finding_obs fo ON f.id = fo.finding_id
                WHERE fo.run_id = ?
                ORDER BY CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6 END, f.name ASC, f.id ASC
                """,
                (run_id,),
            )
            rows = cur.fetchall()
            return [
                FindingRecord(
                    id=r["id"],
                    hostname=r["hostname"],
                    template_id=r["template_id"],
                    name=r["name"],
                    severity=r["severity"],
                    cve=json.loads(r["cve"]),
                    matched_at=r["matched_at"],
                    first_seen_run=r["first_seen_run"],
                    last_seen_run=r["last_seen_run"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    status=r["status"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_all_findings(self) -> list[FindingRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, hostname, template_id, name, severity, cve,
                       matched_at, first_seen_run, last_seen_run, first_seen, last_seen, status
                FROM findings
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6 END, name ASC, id ASC
                """
            )
            rows = cur.fetchall()
            return [
                FindingRecord(
                    id=r["id"],
                    hostname=r["hostname"],
                    template_id=r["template_id"],
                    name=r["name"],
                    severity=r["severity"],
                    cve=json.loads(r["cve"]),
                    matched_at=r["matched_at"],
                    first_seen_run=r["first_seen_run"],
                    last_seen_run=r["last_seen_run"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    status=r["status"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_finding_obs_for_run(self, run_id: str) -> list[FindingObsRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, run_id, finding_id, evidence, tool, tool_version, observed_at
                FROM finding_obs
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            )
            rows = cur.fetchall()
            return [
                FindingObsRecord(
                    id=r["id"],
                    run_id=r["run_id"],
                    finding_id=r["finding_id"],
                    evidence=r["evidence"],
                    tool=r["tool"],
                    tool_version=r["tool_version"],
                    observed_at=r["observed_at"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_finding_obs_for_finding(self, finding_id: str) -> list[FindingObsRecord]:
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, run_id, finding_id, evidence, tool, tool_version, observed_at
                FROM finding_obs
                WHERE finding_id = ?
                ORDER BY observed_at DESC, id DESC
                """,
                (finding_id,),
            )
            rows = cur.fetchall()
            return [
                FindingObsRecord(
                    id=r["id"],
                    run_id=r["run_id"],
                    finding_id=r["finding_id"],
                    evidence=r["evidence"],
                    tool=r["tool"],
                    tool_version=r["tool_version"],
                    observed_at=r["observed_at"],
                )
                for r in rows
            ]
        finally:
            conn.close()


__all__ = [
    "Database",
    "FindingObsRecord",
    "FindingRecord",
    "HostObsRecord",
    "HostRecord",
    "HttpObsRecord",
    "RunRecord",
    "get_db_path",
    "host_id",
    "sanitize_matched_at",
]
