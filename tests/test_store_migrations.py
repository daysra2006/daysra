from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from daysra.store.migrations import (
    MIGRATION_V1,
    MIGRATION_V2,
    MIGRATIONS,
    apply_migrations,
)


class TestMigrations:
    """Validate SQLite migrations, user_version tracking, and rollback semantics."""

    def test_new_database_migrates_to_latest_version(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_new.db"
        conn = sqlite3.connect(str(db_file))
        try:
            version = apply_migrations(conn)
            assert version == len(MIGRATIONS)
            assert version == 3

            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            row = cur.fetchone()
            assert row is not None
            assert row[0] == 3
        finally:
            conn.close()

    def test_migration_is_idempotent(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_idempotent.db"
        conn = sqlite3.connect(str(db_file))
        try:
            v1 = apply_migrations(conn)
            assert v1 == 3
            # Running apply_migrations again should be a no-op
            v2 = apply_migrations(conn)
            assert v2 == 3
        finally:
            conn.close()

    def test_migrate_from_v1_to_v3(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_v1.db"
        conn = sqlite3.connect(str(db_file))
        try:
            # Manually apply V1 schema and set user_version = 1
            conn.executescript(MIGRATION_V1)
            conn.execute("PRAGMA user_version = 1;")

            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            assert cur.fetchone()[0] == 1

            # Verify tables from V2/V3 don't exist yet
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('http_obs', 'findings', 'finding_obs');"
            )
            assert cur.fetchall() == []

            # Apply migrations to bring DB to latest
            final_version = apply_migrations(conn)
            assert final_version == 3

            # Verify V2 and V3 tables exist now
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('http_obs', 'findings', 'finding_obs');"
            )
            found_tables = {r[0] for r in cur.fetchall()}
            assert found_tables == {"http_obs", "findings", "finding_obs"}
        finally:
            conn.close()

    def test_migrate_from_v2_to_v3(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_v2.db"
        conn = sqlite3.connect(str(db_file))
        try:
            # Manually apply V1 and V2, and set user_version = 2
            conn.executescript(MIGRATION_V1)
            conn.executescript(MIGRATION_V2)
            conn.execute("PRAGMA user_version = 2;")

            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            assert cur.fetchone()[0] == 2

            # Apply migrations
            final_version = apply_migrations(conn)
            assert final_version == 3

            # Verify findings and finding_obs exist
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('findings', 'finding_obs');"
            )
            found_tables = {r[0] for r in cur.fetchall()}
            assert found_tables == {"findings", "finding_obs"}
        finally:
            conn.close()

    def test_all_expected_tables_and_indices_exist_after_migration(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_schema.db"
        conn = sqlite3.connect(str(db_file))
        try:
            apply_migrations(conn)
            cur = conn.cursor()

            # Verify all expected tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {r[0] for r in cur.fetchall()}
            expected_tables = {"runs", "hosts", "host_obs", "http_obs", "findings", "finding_obs"}
            assert expected_tables.issubset(tables)

            # Verify all expected indices
            cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
            indices = {r[0] for r in cur.fetchall()}
            expected_indices = {
                "idx_hosts_hostname",
                "idx_host_obs_run",
                "idx_host_obs_host",
                "idx_http_obs_run",
                "idx_http_obs_host",
                "idx_http_obs_status",
                "idx_findings_hostname",
                "idx_findings_severity",
                "idx_findings_template",
                "idx_finding_obs_run",
                "idx_finding_obs_finding",
            }
            assert expected_indices.issubset(indices)
        finally:
            conn.close()

    def test_unknown_future_user_version_is_unmodified(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test_future.db"
        conn = sqlite3.connect(str(db_file))
        try:
            conn.execute("PRAGMA user_version = 99;")
            version = apply_migrations(conn)
            # If DB version is already higher than known migrations, it should return 99 without running anything
            assert version == 99

            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            assert cur.fetchone()[0] == 99
        finally:
            conn.close()

    def test_rollback_on_migration_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        db_file = tmp_path / "test_rollback.db"
        conn = sqlite3.connect(str(db_file))
        try:
            # Set up V1 successfully
            conn.executescript(MIGRATION_V1)
            conn.execute("PRAGMA user_version = 1;")

            # Inject a failing migration as target_version 2
            broken_migration = "CREATE TABLE broken_table (id INT PRIMARY KEY); SYNTAX ERROR HERE;"
            monkeypatch.setattr(
                "daysra.store.migrations.MIGRATIONS",
                [MIGRATION_V1, broken_migration],
            )

            with pytest.raises(sqlite3.OperationalError):
                apply_migrations(conn)

            # Version must still be 1 (rolled back, not upgraded to 2)
            cur = conn.cursor()
            cur.execute("PRAGMA user_version;")
            assert cur.fetchone()[0] == 1

            # Broken table must not exist
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = 'broken_table';"
            )
            assert cur.fetchall() == []
        finally:
            conn.close()
