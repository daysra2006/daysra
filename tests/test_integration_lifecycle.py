from __future__ import annotations

import json
import subprocess
import unittest.mock
from pathlib import Path

import pytest
from rich.console import Console

from daysra.cli.recon import run_recon
from daysra.ingest import Ingestor
from daysra.store.db import Database


@pytest.fixture
def isolated_db(tmp_path: Path) -> Database:
    """Create an isolated temporary SQLite database for testing lifecycle integration."""
    return Database(tmp_path / "lifecycle_test.db")


def make_event(
    event_type: str,
    run_id: str,
    data: dict[str, object] | None = None,
    ts: str = "2026-11-05T12:00:00Z",
) -> str:
    """Generate a single JSONL event string with valid envelope."""
    payload = {
        "schema_version": "1",
        "type": event_type,
        "run_id": run_id,
        "ts": ts,
        "data": data or {},
    }
    return json.dumps(payload)


class TestFinding01ToolVersionsOverwrite:
    """Stage 7B-1: Reproduce FINDING-01 (tool_versions overwrite on chained recon -> probe)."""

    def test_finding01_tool_versions_overwritten_on_chained_run_start(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify whether tool_versions from recon is overwritten when probe emits its run_start."""
        run_id = "01J00000000000000000000001"

        # Stage 1: Recon stream (subfinder v2.17.0)
        # Stage 2: Probe stream (httpx v1.12.0) under the same run_id
        chained_lines = [
            # --- Recon Stage ---
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T12:00:00Z",
                data={
                    "target": "example.com",
                    "tool_versions": {"subfinder": "v2.17.0"},
                },
            ),
            make_event(
                "host",
                run_id=run_id,
                ts="2026-11-05T12:00:01Z",
                data={"hostname": "sub1.example.com", "sources": ["crtsh"], "ips": ["192.0.2.1"]},
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T12:00:02Z",
                data={"status": "complete", "total_hosts": 1},
            ),
            # --- Probe Stage ---
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T12:00:03Z",
                data={
                    "target": "example.com",
                    "tool_versions": {"httpx": "v1.12.0"},
                },
            ),
            make_event(
                "http",
                run_id=run_id,
                ts="2026-11-05T12:00:04Z",
                data={
                    "hostname": "sub1.example.com",
                    "url": "https://sub1.example.com:443",
                    "status_code": 200,
                    "title": "Example",
                    "tech": ["Nginx"],
                    "content_length": 512,
                },
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T12:00:05Z",
                data={"status": "complete", "total_http": 1},
            ),
        ]

        # Ingest the multi-stage event stream
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(chained_lines)

        run = isolated_db.get_run(run_id)
        assert run is not None

        # EXPECTATION (Design requirement for unified multi-stage run):
        # Both tool versions should be preserved in the run metadata.
        # ACTUAL BEHAVIOR (FINDING-01):
        # upsert_run overwrites tool_versions with probe's {"httpx": "v1.12.0"},
        # losing {"subfinder": "v2.17.0"}.
        assert "subfinder" in run.tool_versions, (
            f"FINDING-01 REPRODUCED: 'subfinder' was lost after probe stage. "
            f"Actual tool_versions: {run.tool_versions}"
        )
        assert "httpx" in run.tool_versions, "'httpx' must be recorded"
        assert run.tool_versions == {"subfinder": "v2.17.0", "httpx": "v1.12.0"}


class TestToolVersionsMergeRemediation:
    """Stage 7C-3: Regression tests for tool_versions cumulative merge."""

    def test_case_a_new_tool_added_to_existing_metadata(
        self,
        isolated_db: Database,
    ) -> None:
        """Case A: New tool added to existing metadata accumulates both tools."""
        run_id = "01J0000000000000000000007A"
        # Stage 1: initial run_start with subfinder
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                tool_versions={"subfinder": "v2.17.0"},
            )

        # Stage 2: chained run_start with httpx
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:01:00Z",
                tool_versions={"httpx": "v1.12.0"},
            )

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {
            "httpx": "v1.12.0",
            "subfinder": "v2.17.0",
        }

    def test_case_b_same_tool_updated_version(
        self,
        isolated_db: Database,
    ) -> None:
        """Case B: Tool with same name updates to the newest version."""
        run_id = "01J0000000000000000000007B"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                tool_versions={"httpx": "v1.11.0"},
            )

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:01:00Z",
                tool_versions={"httpx": "v1.12.0"},
            )

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {"httpx": "v1.12.0"}

    def test_case_c_empty_new_metadata_preserves_existing(
        self,
        isolated_db: Database,
    ) -> None:
        """Case C: Empty new metadata ({}) does not erase existing metadata."""
        run_id = "01J0000000000000000000007C"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                tool_versions={"subfinder": "v2.17.0"},
            )

        # Chained update with empty dict
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:01:00Z",
                tool_versions={},
            )

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {"subfinder": "v2.17.0"}

        # Also verify with None
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:02:00Z",
                tool_versions=None,
            )

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {"subfinder": "v2.17.0"}

    def test_case_d_empty_existing_metadata_receives_new(
        self,
        isolated_db: Database,
    ) -> None:
        """Case D: Empty existing metadata cleanly receives new metadata."""
        run_id = "01J0000000000000000000007D"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:00:00Z",
                tool_versions={},
            )

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="example.com",
                started_at="2026-11-05T10:01:00Z",
                tool_versions={"httpx": "v1.12.0"},
            )

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {"httpx": "v1.12.0"}

    def test_case_e_multi_stage_sequential_retains_all_tools(
        self,
        isolated_db: Database,
    ) -> None:
        """Case E: Three sequential stages (subfinder -> httpx -> nuclei) retain all 3 tools."""
        run_id = "01J0000000000000000000007E"
        events = [
            # Stage 1: Recon (subfinder)
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:05Z", data={"status": "complete"}),
            # Stage 2: Probe (httpx)
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:10Z",
                data={"target": "example.com", "tool_versions": {"httpx": "v1.12.0"}},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:15Z", data={"status": "complete"}),
            # Stage 3: Scan (nuclei)
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:20Z",
                data={"target": "example.com", "tool_versions": {"nuclei": "v3.2.0"}},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:25Z", data={"status": "complete"}),
        ]

        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(events)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.tool_versions == {
            "httpx": "v1.12.0",
            "nuclei": "v3.2.0",
            "subfinder": "v2.17.0",
        }


class TestRunLifecycleScenarios:
    """Stage 7B-2: Run Lifecycle Regression Tests (Scenarios A through E)."""

    def test_scenario_a_normal_recon_and_probe_lifecycle(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario A: Recon succeeds and probe succeeds under the same run_id."""
        run_id = "01J0000000000000000000000A"
        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}},
            ),
            make_event(
                "host",
                run_id=run_id,
                ts="2026-11-05T10:00:01Z",
                data={"hostname": "app.example.com", "sources": ["subfinder"], "ips": ["192.0.2.10"]},
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T10:00:02Z",
                data={"status": "complete", "total_hosts": 1},
            ),
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:03Z",
                data={"target": "example.com", "tool_versions": {"httpx": "v1.12.0"}},
            ),
            make_event(
                "http",
                run_id=run_id,
                ts="2026-11-05T10:00:04Z",
                data={
                    "hostname": "app.example.com",
                    "url": "https://app.example.com",
                    "status_code": 200,
                    "title": "Dashboard",
                    "tech": ["React", "Nginx"],
                },
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T10:00:05Z",
                data={"status": "complete", "total_http": 1},
            ),
        ]

        result = Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        assert result.status == "complete"
        assert result.hosts_count == 1
        assert result.http_count == 1

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "complete"
        assert run.finished_at == "2026-11-05T10:00:05+00:00"

        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "app.example.com"

        http_obs = isolated_db.get_http_obs_for_run(run_id)
        assert len(http_obs) == 1
        assert http_obs[0].status_code == 200

    def test_scenario_b_recon_success_probe_failure(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario B: Recon succeeds, but probe fails or produces partial output."""
        run_id = "01J0000000000000000000000B"
        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}},
            ),
            make_event(
                "host",
                run_id=run_id,
                ts="2026-11-05T10:00:01Z",
                data={"hostname": "api.example.com", "sources": ["certspotter"], "ips": ["192.0.2.20"]},
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T10:00:02Z",
                data={"status": "complete", "total_hosts": 1},
            ),
            # Probe starts, records partial observation, then finishes as partial/failed
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:03Z",
                data={"target": "example.com", "tool_versions": {"httpx": "v1.12.0"}},
            ),
            make_event(
                "http",
                run_id=run_id,
                ts="2026-11-05T10:00:04Z",
                data={
                    "hostname": "api.example.com",
                    "url": "https://api.example.com",
                    "status_code": 500,
                    "title": "Crash",
                    "tech": [],
                },
            ),
            make_event(
                "run_end",
                run_id=run_id,
                ts="2026-11-05T10:00:05Z",
                data={"status": "partial", "total_http": 1},
            ),
        ]

        result = Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        # Status must reflect the final partial status
        assert result.status == "partial"

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"

        # Host observations from recon must be retained
        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "api.example.com"

        # Partial HTTP observations emitted before failure must be retained
        http_obs = isolated_db.get_http_obs_for_run(run_id)
        assert len(http_obs) == 1
        assert http_obs[0].status_code == 500

    def test_scenario_c_recon_failure_saves_partial_state(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario C: Recon process fails mid-stream; partial events and partial status saved."""
        run_id = "01J0000000000000000000000C"
        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}},
            ),
            make_event(
                "host",
                run_id=run_id,
                ts="2026-11-05T10:00:01Z",
                data={"hostname": "dev.example.com", "sources": ["alienvault"], "ips": ["192.0.2.30"]},
            ),
            # Process terminated abruptly without run_end
        ]

        result = Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        # Default run status initialized on run_start is "partial"
        assert result.status == "partial"

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        assert run.finished_at is None

        # Partial host must be saved
        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "dev.example.com"

    def test_scenario_d_stream_without_run_end_remains_partial(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario D: Event stream arrives without any run_end event."""
        run_id = "01J0000000000000000000000D"
        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com"},
            ),
            make_event(
                "host",
                run_id=run_id,
                ts="2026-11-05T10:00:01Z",
                data={"hostname": "portal.example.com", "sources": ["hackertarget"], "ips": []},
            ),
            make_event(
                "http",
                run_id=run_id,
                ts="2026-11-05T10:00:02Z",
                data={
                    "hostname": "portal.example.com",
                    "url": "https://portal.example.com",
                    "status_code": 302,
                    "title": "Redirect",
                    "tech": [],
                },
            ),
        ]

        result = Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        assert result.status == "partial"

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        assert run.finished_at is None

        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "portal.example.com"

        http_obs = isolated_db.get_http_obs_for_run(run_id)
        assert len(http_obs) == 1
        assert http_obs[0].status_code == 302

    def test_scenario_e_run_id_mismatch_triggers_rollback(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario E: Ingestion stream containing mismatched run_id raises ValueError and rolls back."""
        valid_run_id = "01J0000000000000000000000E"
        alien_run_id = "01J00000000000000000000099"

        lines = [
            make_event(
                "run_start",
                run_id=valid_run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com"},
            ),
            make_event(
                "host",
                run_id=valid_run_id,
                ts="2026-11-05T10:00:01Z",
                data={"hostname": "valid.example.com", "sources": ["crtsh"], "ips": ["192.0.2.40"]},
            ),
            # Poison pill with different run_id
            make_event(
                "host",
                run_id=alien_run_id,
                ts="2026-11-05T10:00:02Z",
                data={"hostname": "alien.example.com", "sources": ["alien"], "ips": []},
            ),
        ]

        with pytest.raises(ValueError, match="Mismatched run_id in event stream"):
            Ingestor(db=isolated_db, run_id=valid_run_id).ingest_lines(lines)

        # Verification of atomic rollback:
        # Neither valid_run_id nor alien_run_id must be committed in SQLite
        assert isolated_db.get_run(valid_run_id) is None
        assert isolated_db.get_run(alien_run_id) is None
        assert isolated_db.get_hosts_for_run(valid_run_id) == []


class TestScopeHashContractSupport:
    """Stage 7B-3: Scope Hash Contract and Storage Tests."""

    def test_scope_hash_omitted_stores_none(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify runs.scope_hash defaults to None when run_start omits scope_hash."""
        run_id = "01J000000000000000000000S1"
        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                data={"target": "example.com"},
            ),
            make_event("run_end", run_id=run_id, data={"status": "complete"}),
        ]

        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.scope_hash is None

    def test_scope_hash_provided_stores_value(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify runs.scope_hash correctly stores synthetic sha256 hash when provided in run_start."""
        run_id = "01J000000000000000000000S2"
        synthetic_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                data={"target": "example.com", "scope_hash": synthetic_hash},
            ),
            make_event("run_end", run_id=run_id, data={"status": "complete"}),
        ]

        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.scope_hash == synthetic_hash

    def test_scope_hash_preserved_when_both_stages_provide_it(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify scope_hash remains consistent when both recon and probe provide the same hash."""
        run_id = "01J000000000000000000000S3"
        synthetic_hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "scope_hash": synthetic_hash},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"status": "complete"}),
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:02Z",
                data={"target": "example.com", "scope_hash": synthetic_hash},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"status": "complete"}),
        ]

        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.scope_hash == synthetic_hash

    def test_scope_hash_preserved_when_probe_omits_it(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify COALESCE in upsert_run preserves recon's scope_hash even if probe's run_start omits it."""
        run_id = "01J000000000000000000000S4"
        recon_hash = "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

        lines = [
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:00Z",
                data={"target": "example.com", "scope_hash": recon_hash},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"status": "complete"}),
            # Probe stage run_start omits scope_hash (as happens currently in Go engine)
            make_event(
                "run_start",
                run_id=run_id,
                ts="2026-11-05T10:00:02Z",
                data={"target": "example.com"},
            ),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"status": "complete"}),
        ]

        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)

        run = isolated_db.get_run(run_id)
        assert run is not None
        # COALESCE(excluded.scope_hash, runs.scope_hash) keeps recon's hash
        assert run.scope_hash == recon_hash


class TestFinding02OverallRunVsStageStatus:
    """Stage 7E-1A: FINDING-02 Overall Run vs Stage Status Semantics."""

    def test_scenario_a_recon_success_probe_success_overall_complete(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario A: Recon succeeds and probe succeeds under the same run_id -> complete."""
        run_id = "01J0000000000000000000002A"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}}),
            make_event("host", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"hostname": "sub.example.com", "sources": ["crtsh"], "ips": ["192.0.2.1"]}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:02Z", data={"status": "complete", "total_hosts": 1}),
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"target": "example.com", "tool_versions": {"httpx": "v1.12.0"}}),
            make_event("http", run_id=run_id, ts="2026-11-05T10:00:04Z", data={"hostname": "sub.example.com", "url": "https://sub.example.com", "status_code": 200, "tech": ["nginx"]}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:05Z", data={"status": "complete", "total_http": 1}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "complete"
        assert len(isolated_db.get_hosts_for_run(run_id)) == 1
        assert len(isolated_db.get_http_obs_for_run(run_id)) == 1
        assert run.tool_versions == {"httpx": "v1.12.0", "subfinder": "v2.17.0"}

    def test_scenario_b_recon_success_probe_fails_overall_partial_traceability(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario B: Recon succeeds, but probe fails -> overall is partial, but recon observations must remain traceable."""
        run_id = "01J0000000000000000000002B"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}}),
            make_event("host", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"hostname": "sub.example.com", "sources": ["crtsh"]}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:02Z", data={"status": "complete", "total_hosts": 1}),
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"target": "example.com", "tool_versions": {"httpx": "v1.12.0"}}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:04Z", data={"status": "partial", "total_http": 0}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        # Traceability: recon data is retained despite overall partial status
        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "sub.example.com"
        assert "subfinder" in run.tool_versions
        assert "httpx" in run.tool_versions
        # Gap analysis: schema has no stage_status field; stage success is inferred from observations

    def test_scenario_c_recon_fails_before_completion_saves_partial(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario C: Recon fails mid-stream before run_end -> status remains partial."""
        run_id = "01J0000000000000000000002C"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("host", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"hostname": "early.example.com", "sources": ["certspotter"]}),
        ]
        res = Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        assert res.status == "partial"
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        assert len(isolated_db.get_hosts_for_run(run_id)) == 1

    def test_scenario_d_recon_fails_prevents_false_success(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario D: When recon fails, no subsequent complete run_end must overwrite it without running."""
        run_id = "01J0000000000000000000002D"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z", status="partial")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial")
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"

    def test_scenario_e_terminal_status_protection_gap(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario E: Demonstrates gap in SQLite transition rules where finish_run permits overwriting terminal status."""
        run_id = "01J0000000000000000000002E"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled")
        run_before = isolated_db.get_run(run_id)
        assert run_before is not None
        assert run_before.status == "cancelled"

        # With SQL-level transition guard active, terminal status 'cancelled' is preserved:
        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete")
        run_after = isolated_db.get_run(run_id)
        assert run_after is not None
        # Confirms terminal status guard active: cancelled was NOT overwritten by complete
        assert run_after.status == "cancelled"


class TestFinding04CancellationLifecycle:
    """Stage 7E-1B: FINDING-04 Cancellation Regression Tests."""

    def test_cancellation_during_recon_stores_cancelled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scenario A: Ctrl+C during recon sets status to cancelled and exit code 130."""
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("authorization: test\nallow:\n  - example.com\n")
        monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/bin/true")

        class FakeStream:
            def __init__(self, lines: list[str]) -> None:
                self.lines = list(lines)
                self.raised = False
                self.closed = False

            def __iter__(self):
                if not self.raised:
                    self.raised = True
                    raise KeyboardInterrupt()
                return iter(self.lines)

            def close(self) -> None:
                self.closed = True

        class FakeProc:
            def __init__(self, cmd: list[str], *a: object, **kw: object) -> None:
                self.cmd = cmd
                self.stderr = None
                self.stdin = unittest.mock.MagicMock()
                self.stdout = FakeStream([])

            def wait(self, timeout: float | None = None) -> int:
                return 130

            def send_signal(self, sig: int) -> None:
                pass

            def kill(self) -> None:
                pass

        with (
            unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            unittest.mock.patch("subprocess.Popen", side_effect=FakeProc),
        ):
            exit_code = run_recon("example.com", scope=str(scope_file), console=Console(quiet=True))
            assert exit_code == 130
            run = Database(tmp_path / "data" / "daysra.db").get_latest_run()
            assert run is not None
            assert run.status == "cancelled"
            assert run.finished_at is not None

    def test_cancellation_during_probe_reproduces_finding04_bug(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scenario B: Ctrl+C during probe returns 130 but currently writes 'partial' instead of 'cancelled' (FINDING-04 RED)."""
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("authorization: test\nallow:\n  - example.com\n")
        monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/bin/true")

        class FakeStream:
            def __init__(self, lines: list[str], raise_on_iter: bool = False) -> None:
                self.lines = list(lines)
                self.raise_on_iter = raise_on_iter
                self.closed = False

            def __iter__(self):
                if self.raise_on_iter:
                    self.raise_on_iter = False
                    raise KeyboardInterrupt()
                return iter(self.lines)

            def close(self) -> None:
                self.closed = True

        class FakeProc:
            def __init__(self, cmd: list[str], *a: object, **kw: object) -> None:
                self.cmd = cmd
                self.stderr = None
                self.stdin = unittest.mock.MagicMock()
                if "recon" in cmd:
                    lines = [
                        '{"schema_version": "1", "type": "run_start", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:00Z", "data": {"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}}}\n',
                        '{"schema_version": "1", "type": "host", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "sub.example.com", "sources": ["test"]}}\n',
                        '{"schema_version": "1", "type": "run_end", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:02Z", "data": {"status": "complete"}}\n',
                    ]
                    self.stdout = FakeStream(lines)
                else:
                    lines = [
                        '{"schema_version": "1", "type": "run_start", "run_id": "' + cmd[cmd.index("--run-id") + 1] + '", "ts": "2026-11-05T10:00:03Z", "data": {"target": "example.com"}}\n',
                    ]
                    self.stdout = FakeStream(lines, raise_on_iter=True)

            def wait(self, timeout: float | None = None) -> int:
                return 0 if "recon" in self.cmd else 130

            def send_signal(self, sig: int) -> None:
                pass

            def kill(self) -> None:
                pass

        with (
            unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            unittest.mock.patch("subprocess.Popen", side_effect=FakeProc),
        ):
            exit_code = run_recon("example.com", scope=str(scope_file), console=Console(quiet=True))
            assert exit_code == 130
            run = Database(tmp_path / "data" / "daysra.db").get_latest_run()
            assert run is not None
            # FINDING-04 EXPECTED CONTRACT: A cancelled process returning 130 must store status="cancelled".
            # ACTUAL BUG: recon.py:386 calls db.finish_run(status="partial"), so run.status is "partial".
            assert run.status == "cancelled", (
                f"FINDING-04: expected status 'cancelled' on exit code 130, got '{run.status}'"
            )
            # Verified: finished_at is updated with fallback timestamp, not stale recon timestamp
            assert run.finished_at is not None
            assert run.finished_at != "2026-11-05T10:00:02+00:00"
            assert run.finished_at != "2026-11-05T10:00:02Z"

    def test_cancellation_with_timeout_triggers_forced_kill(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scenario C: When SIGINT does not terminate process within timeout, fallback kill is invoked."""
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("authorization: test\nallow:\n  - example.com\n")
        monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/bin/true")

        kill_called = False

        class FakeStream:
            def __init__(self) -> None:
                self.raised = False
                self.closed = False

            def __iter__(self):
                if not self.raised:
                    self.raised = True
                    raise KeyboardInterrupt()
                return iter([])

            def close(self) -> None:
                self.closed = True

        class FakeProc:
            def __init__(self, cmd: list[str], *a: object, **kw: object) -> None:
                self.cmd = cmd
                self.stderr = None
                self.stdin = unittest.mock.MagicMock()
                self.stdout = FakeStream()

            def wait(self, timeout: float | None = None) -> int:
                if timeout is not None:
                    # TimeoutExpired during graceful SIGINT wait
                    raise subprocess.TimeoutExpired(cmd=self.cmd, timeout=timeout)
                return 130

            def send_signal(self, sig: int) -> None:
                pass

            def kill(self) -> None:
                nonlocal kill_called
                kill_called = True

        with (
            unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            unittest.mock.patch("subprocess.Popen", side_effect=FakeProc),
        ):
            exit_code = run_recon("example.com", scope=str(scope_file), console=Console(quiet=True))
            assert exit_code == 130
            assert kill_called is True

    def test_cancellation_without_run_end_event_finalizes_db(
        self,
        isolated_db: Database,
    ) -> None:
        """Scenario D: When process is cancelled before emitting run_end, finish_run still finalizes."""
        run_id = "01J0000000000000000000004D"
        # Partial stream without run_end
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("host", run_id=run_id, ts="2026-11-05T10:00:01Z", data={"hostname": "sub.example.com", "sources": ["fake"]}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled")
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled"


class TestFinding05FinishedAtLifecycle:
    """Stage 7E-1C: FINDING-05 finished_at Lifecycle Regression Tests."""

    def test_finished_at_recon_success_with_run_end(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 1: Normal recon success populates finished_at from run_end timestamp."""
        run_id = "01J0000000000000000000005A"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:05Z", data={"status": "complete"}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.finished_at == "2026-11-05T10:00:05+00:00"

    def test_finished_at_recon_crash_before_run_end_reproduces_finding05(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case 2: Recon abrupt crash before run_end leaves finished_at as NULL (FINDING-05 RED)."""
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("authorization: test\nallow:\n  - example.com\n")
        monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/bin/true")

        class FakeStream:
            def __init__(self, lines: list[str]) -> None:
                self.lines = list(lines)
                self.closed = False

            def __iter__(self):
                return iter(self.lines)

            def close(self) -> None:
                self.closed = True

        class FakeProc:
            def __init__(self, cmd: list[str], *a: object, **kw: object) -> None:
                self.cmd = cmd
                self.stderr = None
                self.stdin = unittest.mock.MagicMock()
                # Emits run_start and host, but crashes before run_end
                lines = [
                    '{"schema_version": "1", "type": "run_start", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:00Z", "data": {"target": "example.com"}}\n',
                    '{"schema_version": "1", "type": "host", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "sub.example.com", "sources": ["fake"]}}\n',
                ]
                self.stdout = FakeStream(lines)

            def wait(self, timeout: float | None = None) -> int:
                return 4  # Subprocess error

            def send_signal(self, sig: int) -> None:
                pass

            def kill(self) -> None:
                pass

        with (
            unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            unittest.mock.patch("subprocess.Popen", side_effect=FakeProc),
        ):
            exit_code = run_recon("example.com", scope=str(scope_file), console=Console(quiet=True))
            assert exit_code == 4
            run = Database(tmp_path / "data" / "daysra.db").get_latest_run()
            assert run is not None
            assert run.status == "partial"
            # FINDING-05 EXPECTED CONTRACT: A finalized run in database must record finished_at timestamp.
            # ACTUAL BUG: recon.py:235 calls finish_run without finished_at, leaving finished_at as NULL.
            assert run.finished_at is not None, (
                "FINDING-05 REPRODUCED: finished_at is NULL on abrupt failure without run_end"
            )

    def test_finished_at_probe_success_updates_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 3: Probe success updates finished_at to probe run_end timestamp."""
        run_id = "01J0000000000000000000005C"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:02Z", data={"status": "complete"}),
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"target": "example.com"}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:10Z", data={"status": "complete"}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.finished_at == "2026-11-05T10:00:10+00:00"

    def test_finished_at_probe_crash_retains_recon_timestamp_gap(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 4: Probe crash without run_end retains recon's finished_at due to COALESCE."""
        run_id = "01J0000000000000000000005D"
        recon_finish_ts = "2026-11-05T10:00:02+00:00"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:02Z", data={"status": "complete"}),
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:03Z", data={"target": "example.com"}),
            # Probe crashed without run_end
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        with isolated_db.transaction() as conn:
            # recon.py:386 calls finish_run without finished_at
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial")
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        # Direct finish_run without finished_at retains existing timestamp via COALESCE
        assert run.finished_at == recon_finish_ts

    def test_finished_at_probe_crash_updates_timestamp_in_cli(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case 4b: In CLI recon, probe crash updates finished_at from workflow end time rather than keeping stale recon timestamp."""
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("authorization: test\nallow:\n  - example.com\n")
        monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/bin/true")

        recon_ts = "2026-11-05T10:00:02Z"

        class FakeStream:
            def __init__(self, lines: list[str]) -> None:
                self.lines = list(lines)
                self.closed = False

            def __iter__(self):
                return iter(self.lines)

            def close(self) -> None:
                self.closed = True

        class FakeProc:
            def __init__(self, cmd: list[str], *a: object, **kw: object) -> None:
                self.cmd = cmd
                self.stderr = None
                self.stdin = unittest.mock.MagicMock()
                if "recon" in cmd:
                    lines = [
                        '{"schema_version": "1", "type": "run_start", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:00Z", "data": {"target": "example.com", "tool_versions": {"subfinder": "v2.17.0"}}}\n',
                        '{"schema_version": "1", "type": "host", "run_id": "' + cmd[-1] + '", "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "sub.example.com", "sources": ["test"]}}\n',
                        '{"schema_version": "1", "type": "run_end", "run_id": "' + cmd[-1] + '", "ts": "' + recon_ts + '", "data": {"status": "complete"}}\n',
                    ]
                    self.stdout = FakeStream(lines)
                else:
                    lines = [
                        '{"schema_version": "1", "type": "run_start", "run_id": "' + cmd[cmd.index("--run-id") + 1] + '", "ts": "2026-11-05T10:00:03Z", "data": {"target": "example.com"}}\n',
                        # Crashes before run_end
                    ]
                    self.stdout = FakeStream(lines)

            def wait(self, timeout: float | None = None) -> int:
                return 0 if "recon" in self.cmd else 4  # Probe error

            def send_signal(self, sig: int) -> None:
                pass

            def kill(self) -> None:
                pass

        with (
            unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            unittest.mock.patch("subprocess.Popen", side_effect=FakeProc),
        ):
            exit_code = run_recon("example.com", scope=str(scope_file), console=Console(quiet=True))
            assert exit_code == 4
            run = Database(tmp_path / "data" / "daysra.db").get_latest_run()
            assert run is not None
            assert run.status == "partial"
            assert run.finished_at is not None
            # Verified: finished_at is updated to current fallback timestamp, not keeping stale recon_ts
            assert run.finished_at != "2026-11-05T10:00:02+00:00"
            assert run.finished_at != recon_ts

    def test_finished_at_recon_cancellation_without_run_end_is_null(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 5: Cancellation during recon without run_end leaves finished_at as NULL."""
        run_id = "01J0000000000000000000005E"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled")
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled"
        assert run.finished_at is None

    def test_finished_at_probe_cancellation_retains_recon_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 6: Cancellation during probe without probe run_end retains recon's finished_at."""
        run_id = "01J0000000000000000000005F"
        recon_ts = "2026-11-05T10:00:02Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=recon_ts)
            # Probe cancelled
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled")
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.finished_at == recon_ts

    def test_finished_at_timezone_utc_consistency(
        self,
        isolated_db: Database,
    ) -> None:
        """Case 7: Verifies finished_at preserves UTC timezone offset."""
        run_id = "01J0000000000000000000005G"
        lines = [
            make_event("run_start", run_id=run_id, ts="2026-11-05T10:00:00Z", data={"target": "example.com"}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:00:05Z", data={"status": "complete"}),
        ]
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(lines)
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.finished_at is not None
        assert "+00:00" in run.finished_at or run.finished_at.endswith("Z")


class TestFinding07TerminalStatusGuard:
    """Stage 7E-4A: FINDING-07 Terminal Status Transition Guard Regression Tests."""

    # --- Group A: Terminal Status 'cancelled' Immutability ---

    def test_cancelled_to_complete_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'cancelled' rejects transition to 'complete' and preserves finished_at."""
        run_id = "01J000000000000000000007A1"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=orig_finished)

        # Attempt invalid transition to complete with late timestamp
        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled", (
            f"FINDING-07 REPRODUCED: status 'cancelled' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished, (
            f"FINDING-07 REPRODUCED: finished_at was overwritten on rejected transition: {run.finished_at}"
        )

    def test_cancelled_to_partial_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'cancelled' rejects transition to 'partial' and preserves finished_at."""
        run_id = "01J000000000000000000007A2"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled", (
            f"FINDING-07 REPRODUCED: status 'cancelled' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished

    def test_cancelled_to_failed_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'cancelled' rejects transition to 'failed' and preserves finished_at."""
        run_id = "01J000000000000000000007A3"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled", (
            f"FINDING-07 REPRODUCED: status 'cancelled' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished

    def test_cancelled_to_cancelled_idempotent_preserves_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify repeated finish_run('cancelled') is idempotent and preserves initial finished_at."""
        run_id = "01J000000000000000000007A4"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled"
        assert run.finished_at == orig_finished, (
            f"FINDING-07 REPRODUCED: finished_at was overwritten on idempotent call: {run.finished_at}"
        )

    # --- Group B: Terminal Status 'failed' Immutability ---

    def test_failed_to_complete_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'failed' rejects transition to 'complete' and preserves finished_at."""
        run_id = "01J000000000000000000007B1"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed", (
            f"FINDING-07 REPRODUCED: status 'failed' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished

    def test_failed_to_partial_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'failed' rejects transition to 'partial' and preserves finished_at."""
        run_id = "01J000000000000000000007B2"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed", (
            f"FINDING-07 REPRODUCED: status 'failed' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished

    def test_failed_to_cancelled_rejected_preserves_status_and_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'failed' rejects transition to 'cancelled' and preserves finished_at."""
        run_id = "01J000000000000000000007B3"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed", (
            f"FINDING-07 REPRODUCED: status 'failed' was overwritten by '{run.status}'"
        )
        assert run.finished_at == orig_finished

    def test_failed_to_failed_idempotent_preserves_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify repeated finish_run('failed') is idempotent and preserves initial finished_at."""
        run_id = "01J000000000000000000007B4"
        orig_finished = "2026-11-05T10:05:00Z"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at=orig_finished)

        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at="2026-11-05T10:10:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed"
        assert run.finished_at == orig_finished, (
            f"FINDING-07 REPRODUCED: finished_at was overwritten on idempotent call: {run.finished_at}"
        )

    # --- Group C: Allowed 'partial' Transitions ---

    def test_partial_to_complete_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'partial' cleanly transitions to 'complete'."""
        run_id = "01J000000000000000000007C1"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z", status="partial")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at="2026-11-05T10:05:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "complete"
        assert run.finished_at == "2026-11-05T10:05:00Z"

    def test_partial_to_cancelled_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'partial' cleanly transitions to 'cancelled'."""
        run_id = "01J000000000000000000007C2"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z", status="partial")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at="2026-11-05T10:05:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled"
        assert run.finished_at == "2026-11-05T10:05:00Z"

    def test_partial_to_failed_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'partial' cleanly transitions to 'failed'."""
        run_id = "01J000000000000000000007C3"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z", status="partial")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at="2026-11-05T10:05:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed"
        assert run.finished_at == "2026-11-05T10:05:00Z"

    def test_partial_to_partial_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify run in status 'partial' can be finalized as 'partial'."""
        run_id = "01J000000000000000000007C4"
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z", status="partial")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial", finished_at="2026-11-05T10:05:00Z")

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        assert run.finished_at == "2026-11-05T10:05:00Z"

    # --- Group D: Allowed 'complete' Transitions & Sequential Timestamp Update ---

    def test_complete_to_complete_maintains_status_and_updates_timestamp(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify complete -> complete maintains 'complete' but updates finished_at for chained stages."""
        run_id = "01J000000000000000000007D1"
        recon_ts = "2026-11-05T10:02:00Z"
        probe_ts = "2026-11-05T10:08:00Z"

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            # Recon finishes complete
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=recon_ts)

        run1 = isolated_db.get_run(run_id)
        assert run1 is not None
        assert run1.status == "complete"
        assert run1.finished_at == recon_ts

        # Probe finishes complete under same run_id -> updates to probe_ts
        with isolated_db.transaction() as conn:
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=probe_ts)

        run2 = isolated_db.get_run(run_id)
        assert run2 is not None
        assert run2.status == "complete"
        assert run2.finished_at == probe_ts

    def test_complete_to_partial_workflow_downgrade_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify complete -> partial downgrade is allowed when probe fails after recon success."""
        run_id = "01J000000000000000000007D2"
        recon_ts = "2026-11-05T10:02:00Z"
        probe_fail_ts = "2026-11-05T10:08:00Z"

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=recon_ts)
            # Probe fails
            isolated_db.finish_run(conn=conn, run_id=run_id, status="partial", finished_at=probe_fail_ts)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "partial"
        assert run.finished_at == probe_fail_ts

    def test_complete_to_cancelled_workflow_downgrade_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify complete -> cancelled downgrade is allowed when probe is cancelled after recon success."""
        run_id = "01J000000000000000000007D3"
        recon_ts = "2026-11-05T10:02:00Z"
        probe_cancel_ts = "2026-11-05T10:08:00Z"

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=recon_ts)
            # Probe cancelled
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=probe_cancel_ts)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled"
        assert run.finished_at == probe_cancel_ts

    def test_complete_to_failed_workflow_downgrade_allowed(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify complete -> failed downgrade is allowed when probe experiences fatal crash."""
        run_id = "01J000000000000000000007D4"
        recon_ts = "2026-11-05T10:02:00Z"
        probe_crash_ts = "2026-11-05T10:08:00Z"

        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="complete", finished_at=recon_ts)
            # Probe crashed
            isolated_db.finish_run(conn=conn, run_id=run_id, status="failed", finished_at=probe_crash_ts)

        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "failed"
        assert run.finished_at == probe_crash_ts

    # --- Group E: Integration Test with Ingestor (Non-Throwing & Observation Preservation) ---

    def test_ingestor_rejected_transition_preserves_valid_observations(
        self,
        isolated_db: Database,
    ) -> None:
        """Verify that when a stream attempts an invalid transition on a terminal run:
        1. Ingestor does NOT raise an unhandled exception or abort the transaction.
        2. Valid observations in the stream are safely committed.
        3. The terminal status and original timestamp are preserved.
        """
        run_id = "01J000000000000000000007E1"
        orig_finished = "2026-11-05T10:05:00Z"

        # Pre-seed run as cancelled
        with isolated_db.transaction() as conn:
            isolated_db.upsert_run(conn=conn, run_id=run_id, target="example.com", started_at="2026-11-05T10:00:00Z")
            isolated_db.finish_run(conn=conn, run_id=run_id, status="cancelled", finished_at=orig_finished)

        # Ingestion stream contains valid host observation followed by late run_end 'complete'
        stream_lines = [
            make_event("host", run_id=run_id, ts="2026-11-05T10:06:00Z", data={"hostname": "persisted.example.com", "sources": ["crtsh"], "ips": ["192.0.2.77"]}),
            make_event("run_end", run_id=run_id, ts="2026-11-05T10:07:00Z", data={"status": "complete"}),
        ]

        # Ingesting must succeed without raising an unhandled exception
        Ingestor(db=isolated_db, run_id=run_id).ingest_lines(stream_lines)

        # Observations must be committed to database
        hosts = isolated_db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "persisted.example.com"

        # Run record must PRESERVE status 'cancelled' and original finished_at
        run = isolated_db.get_run(run_id)
        assert run is not None
        assert run.status == "cancelled", (
            f"FINDING-07 REPRODUCED: late run_end overwrote terminal status: {run.status}"
        )
        assert run.finished_at == orig_finished, (
            f"FINDING-07 REPRODUCED: late run_end overwrote terminal finished_at: {run.finished_at}"
        )



