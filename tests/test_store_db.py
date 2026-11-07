from __future__ import annotations

import hashlib
import sqlite3
import stat
from pathlib import Path

import pytest

from daysra.store.db import (
    Database,
    FindingRecord,
    HostObsRecord,
    HostRecord,
    HttpObsRecord,
    RunRecord,
    get_db_path,
    host_id,
    sanitize_matched_at,
)


class TestDbPathAndUtils:
    """Validate path resolution and sanitization utilities."""

    def test_get_db_path_custom(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom" / "custom.db"
        res = get_db_path(custom)
        assert res == custom
        assert res.parent.exists()

    def test_get_db_path_daysra_home(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        home_dir = tmp_path / "daysra_home"
        monkeypatch.setenv("DAYSRA_HOME", str(home_dir))
        res = get_db_path()
        assert res == home_dir / "daysra.db"
        assert res.parent.exists()

    def test_get_db_path_xdg_data_home(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_HOME", raising=False)
        xdg_dir = tmp_path / "xdg_data"
        monkeypatch.setenv("XDG_DATA_HOME", str(xdg_dir))
        res = get_db_path()
        assert res == xdg_dir / "daysra" / "daysra.db"
        assert res.parent.exists()

    def test_get_db_path_default_fallback(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_HOME", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        fake_home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        res = get_db_path()
        assert res == fake_home / ".local" / "share" / "daysra" / "daysra.db"
        assert res.parent.exists()

    def test_host_id_hash_consistency(self) -> None:
        h1 = host_id("sub.example.com")
        h2 = host_id("  SUB.EXAMPLE.COM  ")
        assert h1 == h2
        expected = hashlib.sha256(b"sub.example.com").hexdigest()
        assert h1 == expected

    @pytest.mark.parametrize(
        ("raw_url", "expected"),
        [
            ("", ""),
            ("   ", ""),
            (
                "http://user:pass@example.com/test",
                "http://example.com/test",
            ),
            (
                "http://example.com/test#fragment-here",
                "http://example.com/test",
            ),
            (
                "https://api.example.com/auth?token=secret123&user=alice",
                "https://api.example.com/auth?token=REDACTED&user=alice",
            ),
            (
                "https://example.com/?api_key=secretKey&session_id=sess1&sort=desc",
                "https://example.com/?api_key=REDACTED&session_id=REDACTED&sort=desc",
            ),
            (
                "https://example.com/?jwt=eyJhbGciOi...&sig=signature123",
                "https://example.com/?jwt=REDACTED&sig=REDACTED",
            ),
        ],
    )
    def test_sanitize_matched_at(self, raw_url: str, expected: str) -> None:
        assert sanitize_matched_at(raw_url) == expected


class TestDatabasePermissions:
    """Validate owner-only permissions for the database file, sidecars, and created directories."""

    def test_new_db_file_and_created_directory_are_owner_only(self, tmp_path: Path) -> None:
        db_path = tmp_path / "created" / "nested" / "daysra.db"
        Database(db_path)

        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(db_path.parent.parent.stat().st_mode) == 0o700

    def test_existing_db_permissions_are_tightened(self, tmp_path: Path) -> None:
        db_path = tmp_path / "existing.db"
        Database(db_path)
        db_path.chmod(0o644)

        Database(db_path)

        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600

    def test_existing_directory_permissions_are_not_changed(self, tmp_path: Path) -> None:
        db_dir = tmp_path / "user-data"
        db_dir.mkdir()
        db_dir.chmod(0o750)
        db_path = db_dir / "daysra.db"

        Database(db_path)

        assert stat.S_IMODE(db_dir.stat().st_mode) == 0o750
        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600

    def test_wal_and_shm_sidecars_are_owner_only(self, tmp_path: Path) -> None:
        db_path = tmp_path / "wal" / "daysra.db"
        db = Database(db_path)
        conn = db.connect()
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS t (a INTEGER)")
            conn.execute("INSERT INTO t VALUES (1)")
            conn.commit()

            for suffix in ("-wal", "-shm"):
                sidecar = db_path.with_name(f"{db_path.name}{suffix}")
                assert sidecar.exists(), f"missing sidecar {sidecar.name}"
                assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
        finally:
            conn.close()


class TestDatabaseOperations:
    """Validate CRUD operations, upserts, foreign key checks, and idempotency."""

    @pytest.fixture
    def db(self, tmp_path: Path) -> Database:
        db_path = tmp_path / "test_store.db"
        return Database(db_path)

    def test_init_creates_database_at_version_3(self, db: Database) -> None:
        assert db.get_user_version() == 3

    def test_upsert_run_and_finish_run(self, db: Database) -> None:
        run_id = "01J00000000000000000000001"
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                status="partial",
                tool_versions={"subfinder": "v2.17.0"},
                scope_hash="hash123",
            )

        run = db.get_run(run_id)
        assert run is not None
        assert isinstance(run, RunRecord)
        assert run.run_id == run_id
        assert run.target == "example.com"
        assert run.status == "partial"
        assert run.tool_versions == {"subfinder": "v2.17.0"}
        assert run.scope_hash == "hash123"
        assert run.finished_at is None

        # Idempotent upsert with updated tool versions
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                status="partial",
                tool_versions={"subfinder": "v2.17.0", "httpx": "v1.12.0"},
            )

        updated_run = db.get_run(run_id)
        assert updated_run is not None
        assert updated_run.tool_versions == {"subfinder": "v2.17.0", "httpx": "v1.12.0"}

        # Finish run
        with db.transaction() as conn:
            db.finish_run(
                conn=conn,
                run_id=run_id,
                status="complete",
                finished_at="2026-11-05T10:05:00Z",
            )

        finished_run = db.get_run(run_id)
        assert finished_run is not None
        assert finished_run.status == "complete"
        assert finished_run.finished_at == "2026-11-05T10:05:00Z"
        assert db.get_latest_run() == finished_run

    def test_run_status_check_constraint(self, db: Database) -> None:
        with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id="01J_INVALID_STATUS_000000",
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                status="invalid_status_not_in_enum",
            )

    def test_upsert_host_tracks_first_and_last_seen_run(self, db: Database) -> None:
        run1 = "01J00000000000000000000001"
        run2 = "01J00000000000000000000002"

        with db.transaction() as conn:
            db.upsert_run(conn=conn, run_id=run1, target="example.com", started_at="2026-11-05T10:00:00Z")
            db.upsert_run(conn=conn, run_id=run2, target="example.com", started_at="2026-11-05T11:00:00Z")

            # First seen in run1
            hid1 = db.upsert_host(conn=conn, hostname="app.example.com", run_id=run1)

        hosts = db.get_all_hosts()
        assert len(hosts) == 1
        h = hosts[0]
        assert isinstance(h, HostRecord)
        assert h.id == hid1
        assert h.hostname == "app.example.com"
        assert h.first_seen_run == run1
        assert h.last_seen_run == run1

        # Second seen in run2 -> last_seen_run updates, first_seen_run preserved
        with db.transaction() as conn:
            hid2 = db.upsert_host(conn=conn, hostname="APP.EXAMPLE.COM", run_id=run2)

        assert hid1 == hid2
        hosts_after = db.get_all_hosts()
        assert len(hosts_after) == 1
        h_after = hosts_after[0]
        assert h_after.first_seen_run == run1
        assert h_after.last_seen_run == run2

    def test_upsert_host_obs_merges_ips_and_sources(self, db: Database) -> None:
        run_id = "01J00000000000000000000001"
        hostname = "api.example.com"

        with db.transaction() as conn:
            db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            db.upsert_host(conn=conn, hostname=hostname, run_id=run_id)

            # Observation 1
            db.upsert_host_obs(
                conn=conn,
                run_id=run_id,
                hostname=hostname,
                ips=["192.0.2.1"],
                sources=["crtsh"],
            )

            # Observation 2 for same run and host -> should merge IPs and sources
            db.upsert_host_obs(
                conn=conn,
                run_id=run_id,
                hostname=hostname,
                ips=["192.0.2.2", "192.0.2.1"],
                sources=["virustotal", "crtsh"],
            )

        obs_list = db.get_hosts_for_run(run_id)
        assert len(obs_list) == 1
        obs = obs_list[0]
        assert isinstance(obs, HostObsRecord)
        assert obs.hostname == hostname
        assert obs.ips == ["192.0.2.1", "192.0.2.2"]
        assert obs.sources == ["crtsh", "virustotal"]

    def test_upsert_http_obs_merges_tech_and_updates_fields(self, db: Database) -> None:
        run_id = "01J00000000000000000000001"
        hostname = "web.example.com"
        url = "https://web.example.com:443"

        with db.transaction() as conn:
            db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            db.upsert_host(conn=conn, hostname=hostname, run_id=run_id)

            db.upsert_http_obs(
                conn=conn,
                run_id=run_id,
                hostname=hostname,
                url=url,
                status_code=200,
                title="Initial Title",
                tech=["Nginx"],
                content_length=1200,
                tls_issuer="Let's Encrypt",
            )

            # Second observation: adds tech, keeps/updates title
            db.upsert_http_obs(
                conn=conn,
                run_id=run_id,
                hostname=hostname,
                url=url,
                status_code=200,
                title="Updated Title",
                tech=["PHP", "Nginx"],
            )

        res = db.get_http_obs_for_run(run_id)
        assert len(res) == 1
        entry = res[0]
        assert isinstance(entry, HttpObsRecord)
        assert entry.title == "Updated Title"
        assert entry.tech == ["Nginx", "PHP"]
        assert entry.status_code == 200
        assert entry.content_length == 1200
        assert entry.tls_issuer == "Let's Encrypt"

        assert len(db.get_all_http_obs()) == 1

    def test_upsert_finding_merges_cves_and_updates_timestamps(self, db: Database) -> None:
        run1 = "01J00000000000000000000001"
        run2 = "01J00000000000000000000002"
        finding_id = "f_hash_123"

        with db.transaction() as conn:
            db.upsert_run(conn=conn, run_id=run1, target="example.com", started_at="2026-11-05T10:00:00Z")
            db.upsert_run(conn=conn, run_id=run2, target="example.com", started_at="2026-11-05T11:00:00Z")

            db.upsert_finding(
                conn=conn,
                finding_id=finding_id,
                hostname="app.example.com",
                template_id="cve-2023-0001",
                name="Vulnerability One",
                severity="high",
                matched_at="https://app.example.com/vuln?token=secretKey",
                run_id=run1,
                observed_at="2026-11-05T10:02:00Z",
                cve=["CVE-2023-0001"],
            )

            db.insert_finding_obs(
                conn=conn,
                run_id=run1,
                finding_id=finding_id,
                evidence="found high vuln",
                tool="nuclei",
                tool_version="v3.11.1",
                observed_at="2026-11-05T10:02:00Z",
            )

        f1 = db.get_finding(finding_id)
        assert f1 is not None
        assert isinstance(f1, FindingRecord)
        assert f1.first_seen_run == run1
        assert f1.last_seen_run == run1
        assert f1.first_seen == "2026-11-05T10:02:00Z"
        assert f1.matched_at == "https://app.example.com/vuln?token=REDACTED"
        assert f1.cve == ["CVE-2023-0001"]

        # Run 2 observes the same finding with an additional CVE
        with db.transaction() as conn:
            db.upsert_finding(
                conn=conn,
                finding_id=finding_id,
                hostname="app.example.com",
                template_id="cve-2023-0001",
                name="Vulnerability One",
                severity="high",
                matched_at="https://app.example.com/vuln",
                run_id=run2,
                observed_at="2026-11-05T11:02:00Z",
                cve=["CVE-2023-0002"],
            )
            db.insert_finding_obs(
                conn=conn,
                run_id=run2,
                finding_id=finding_id,
                evidence="found high vuln again",
                tool="nuclei",
                tool_version="v3.11.1",
                observed_at="2026-11-05T11:02:00Z",
            )

        f2 = db.get_finding(finding_id)
        assert f2 is not None
        assert f2.first_seen_run == run1  # preserved
        assert f2.last_seen_run == run2   # updated
        assert f2.first_seen == "2026-11-05T10:02:00Z"  # preserved
        assert f2.last_seen == "2026-11-05T11:02:00Z"   # updated
        assert f2.cve == ["CVE-2023-0001", "CVE-2023-0002"]

        # Check observations querying
        obs_for_finding = db.get_finding_obs_for_finding(finding_id)
        assert len(obs_for_finding) == 2
        obs_for_run = db.get_finding_obs_for_run(run1)
        assert len(obs_for_run) == 1

    def test_findings_ordered_by_severity(self, db: Database) -> None:
        run_id = "01J00000000000000000000001"

        with db.transaction() as conn:
            db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")

            severities = ["info", "critical", "low", "medium", "high"]
            for i, sev in enumerate(severities):
                fid = f"find_{sev}_{i}"
                db.upsert_finding(
                    conn=conn,
                    finding_id=fid,
                    hostname="example.com",
                    template_id=f"tpl-{sev}",
                    name=f"Issue {sev}",
                    severity=sev,
                    matched_at="https://example.com",
                    run_id=run_id,
                    observed_at="2026-11-05T10:00:00Z",
                )
                db.insert_finding_obs(
                    conn=conn,
                    run_id=run_id,
                    finding_id=fid,
                    evidence=None,
                    tool="nuclei",
                    tool_version="v3.11.1",
                    observed_at="2026-11-05T10:00:00Z",
                )

        findings = db.get_findings_for_run(run_id)
        assert len(findings) == 5
        sorted_severities = [f.severity for f in findings]
        assert sorted_severities == ["critical", "high", "medium", "low", "info"]

    def test_foreign_key_constraints_enforced(self, db: Database) -> None:
        # Inserting a host pointing to a non-existent run_id must fail
        with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
            db.upsert_host(conn=conn, hostname="orphan.example.com", run_id="NON_EXISTENT_RUN")

        # Inserting a finding_obs pointing to a non-existent run_id must fail
        with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
            db.insert_finding_obs(
                conn=conn,
                run_id="NON_EXISTENT_RUN",
                finding_id="NON_EXISTENT_FINDING",
                evidence=None,
                tool="nuclei",
                tool_version="v3.11.1",
                observed_at="2026-11-05T10:00:00Z",
            )
