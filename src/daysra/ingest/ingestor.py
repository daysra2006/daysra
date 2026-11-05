from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from daysra.core.contracts import Event, validate_event
from daysra.store.db import Database, sanitize_matched_at


@dataclass(frozen=True)
class IngestResult:
    run_id: str
    target: str
    status: str
    hosts_count: int
    warnings_count: int
    events_count: int
    http_count: int = 0
    findings_count: int = 0


class Ingestor:
    """Reads JSONL event lines, validates them with Pydantic, and upserts into SQLite in a single transaction per run."""

    def __init__(
        self,
        db: Database,
        run_id: str | None = None,
        on_event: Callable[[Event], None] | None = None,
    ) -> None:
        self.db = db
        self.run_id = run_id
        self.on_event = on_event

    def ingest_lines(self, lines: Iterable[str]) -> IngestResult:
        target = ""
        status = "partial"
        hosts_seen = 0
        http_seen = 0
        findings_seen = 0
        warnings_seen = 0
        events_seen = 0
        active_run_id = self.run_id
        run_started = False

        with self.db.transaction() as conn:
            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue

                payload = json.loads(line)
                event = validate_event(payload)
                events_seen += 1

                if active_run_id is None:
                    active_run_id = event.run_id
                elif active_run_id != event.run_id:
                    raise ValueError(
                        f"Mismatched run_id in event stream: expected {active_run_id}, got {event.run_id}"
                    )

                if self.on_event is not None:
                    self.on_event(event)

                ts_iso = event.ts.isoformat()

                if event.type == "run_start":
                    run_started = True
                    target = str(event.data.get("target", ""))
                    tool_versions_data = event.data.get("tool_versions")
                    tool_versions: dict[str, str] = (
                        tool_versions_data if isinstance(tool_versions_data, dict) else {}
                    )
                    scope_hash = event.data.get("scope_hash")
                    self.db.upsert_run(
                        conn=conn,
                        run_id=active_run_id,
                        target=target,
                        started_at=ts_iso,
                        status="partial",
                        tool_versions=tool_versions,
                        scope_hash=str(scope_hash) if scope_hash else None,
                    )

                elif event.type == "host":
                    if not run_started:
                        # Ensure run row exists for foreign key integrity
                        run_started = True
                        self.db.upsert_run(
                            conn=conn,
                            run_id=active_run_id,
                            target=target,
                            started_at=ts_iso,
                            status="partial",
                        )

                    hostname = str(event.data.get("hostname", "")).strip().lower()
                    if hostname:
                        raw_ips = event.data.get("ips")
                        ips: list[str] = raw_ips if isinstance(raw_ips, list) else []
                        raw_sources = event.data.get("sources")
                        sources: list[str] = raw_sources if isinstance(raw_sources, list) else []

                        self.db.upsert_host(conn=conn, hostname=hostname, run_id=active_run_id)
                        self.db.upsert_host_obs(
                            conn=conn,
                            run_id=active_run_id,
                            hostname=hostname,
                            ips=[str(ip) for ip in ips],
                            sources=[str(s) for s in sources],
                        )
                        hosts_seen += 1

                elif event.type == "http":
                    if not run_started:
                        # Ensure run row exists for foreign key integrity
                        run_started = True
                        self.db.upsert_run(
                            conn=conn,
                            run_id=active_run_id,
                            target=target,
                            started_at=ts_iso,
                            status="partial",
                        )

                    hostname = str(event.data.get("hostname", "")).strip().lower()
                    url = str(event.data.get("url", "")).strip()
                    if hostname and url:
                        self.db.upsert_host(conn=conn, hostname=hostname, run_id=active_run_id)

                        raw_code = event.data.get("status_code")
                        status_code = int(raw_code) if raw_code is not None else None
                        raw_title = event.data.get("title")
                        title = str(raw_title) if raw_title is not None else None
                        raw_tech = event.data.get("tech")
                        tech: list[str] = (
                            [str(t) for t in raw_tech] if isinstance(raw_tech, list) else []
                        )
                        raw_cl = event.data.get("content_length")
                        content_length = int(raw_cl) if raw_cl is not None else None
                        raw_tls = event.data.get("tls_issuer")
                        tls_issuer = str(raw_tls) if raw_tls is not None else None

                        self.db.upsert_http_obs(
                            conn=conn,
                            run_id=active_run_id,
                            hostname=hostname,
                            url=url,
                            status_code=status_code,
                            title=title,
                            tech=tech,
                            content_length=content_length,
                            tls_issuer=tls_issuer,
                        )
                        http_seen += 1

                elif event.type == "finding":
                    if not run_started:
                        # Ensure run row exists for foreign key integrity
                        run_started = True
                        self.db.upsert_run(
                            conn=conn,
                            run_id=active_run_id,
                            target=target,
                            started_at=ts_iso,
                            status="partial",
                        )

                    finding_id = str(event.data.get("id", "")).strip()
                    template_id = str(event.data.get("template_id", "")).strip()
                    name = str(event.data.get("name", "")).strip()
                    severity = str(event.data.get("severity", "")).strip()
                    raw_cve = event.data.get("cve")
                    cve: list[str] = (
                        [str(c) for c in raw_cve] if isinstance(raw_cve, list) else []
                    )
                    matched_at = str(event.data.get("matched_at", "")).strip()
                    raw_evidence = event.data.get("evidence")
                    evidence = str(raw_evidence) if raw_evidence is not None else None
                    tool = str(event.data.get("tool", "nuclei")).strip()
                    tool_version = str(event.data.get("tool_version", "")).strip()
                    hostname = str(event.data.get("hostname", "")).strip().lower()

                    if finding_id and hostname and template_id:
                        # Check whether host exists in hosts table without modifying hosts
                        cur = conn.cursor()
                        cur.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,))
                        host_row = cur.fetchone()
                        if not host_row:
                            warnings_seen += 1

                        clean_matched_at = sanitize_matched_at(matched_at)
                        self.db.upsert_finding(
                            conn=conn,
                            finding_id=finding_id,
                            hostname=hostname,
                            template_id=template_id,
                            name=name,
                            severity=severity,
                            matched_at=clean_matched_at,
                            run_id=active_run_id,
                            observed_at=ts_iso,
                            cve=cve,
                        )
                        self.db.insert_finding_obs(
                            conn=conn,
                            run_id=active_run_id,
                            finding_id=finding_id,
                            evidence=evidence,
                            tool=tool,
                            tool_version=tool_version,
                            observed_at=ts_iso,
                        )
                        findings_seen += 1

                elif event.type == "warning":
                    warnings_seen += 1

                elif event.type == "run_end":
                    status = str(event.data.get("status", "complete"))
                    self.db.finish_run(
                        conn=conn,
                        run_id=active_run_id,
                        status=status,
                        finished_at=ts_iso,
                    )

            if not run_started and active_run_id:
                # If only non-host events were sent
                self.db.upsert_run(
                    conn=conn,
                    run_id=active_run_id,
                    target=target,
                    started_at="",
                    status=status,
                )

        return IngestResult(
            run_id=active_run_id or "",
            target=target,
            status=status,
            hosts_count=hosts_seen,
            warnings_count=warnings_seen,
            events_count=events_seen,
            http_count=http_seen,
            findings_count=findings_seen,
        )


def ingest_stream(
    lines: Iterable[str],
    db: Database,
    run_id: str | None = None,
    on_event: Callable[[Event], None] | None = None,
) -> IngestResult:
    """Convenience helper to ingest a stream of event lines into the database."""
    ingestor = Ingestor(db=db, run_id=run_id, on_event=on_event)
    return ingestor.ingest_lines(lines)


__all__ = ["IngestResult", "Ingestor", "ingest_stream"]
