from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from daysra.core.contracts import Event
from daysra.ingest import IngestLineError, Ingestor, IngestResult, ingest_stream
from daysra.store.db import Database


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Create a temporary isolated SQLite database."""
    return Database(tmp_path / "test_ingest.db")


def make_jsonl_line(
    event_type: str,
    run_id: str = "01J00000000000000000000001",
    data: dict[str, object] | None = None,
    ts: str = "2026-11-05T12:00:00Z",
) -> str:
    """Helper to generate a valid JSONL line string."""
    payload = {
        "schema_version": "1",
        "type": event_type,
        "run_id": run_id,
        "ts": ts,
        "data": data or {},
    }
    return json.dumps(payload)


class TestIngestorValidStreams:
    """Validate ingestion of complete and valid JSONL event streams."""

    def test_complete_recon_and_probe_lifecycle(self, db: Database) -> None:
        run_id = "01J00000000000000000000001"
        lines = [
            make_jsonl_line(
                "run_start",
                run_id=run_id,
                data={
                    "target": "example.com",
                    "tool_versions": {"subfinder": "v2.17.0", "httpx": "v1.12.0"},
                    "scope_hash": "sha_scope_1",
                },
            ),
            make_jsonl_line(
                "host",
                run_id=run_id,
                data={
                    "hostname": "api.example.com",
                    "ips": ["192.0.2.1"],
                    "sources": ["crtsh"],
                },
            ),
            make_jsonl_line(
                "http",
                run_id=run_id,
                data={
                    "hostname": "api.example.com",
                    "url": "https://api.example.com:443",
                    "status_code": 200,
                    "title": "API Gateway",
                    "tech": ["Nginx"],
                    "content_length": 512,
                    "tls_issuer": "Let's Encrypt",
                },
            ),
            make_jsonl_line(
                "finding",
                run_id=run_id,
                data={
                    "id": "finding_sha_123",
                    "hostname": "api.example.com",
                    "template_id": "cve-2023-9999",
                    "name": "Sample Vulnerability",
                    "severity": "medium",
                    "cve": ["CVE-2023-9999"],
                    "matched_at": "https://api.example.com:443/v1",
                    "evidence": "evidence string",
                    "tool": "nuclei",
                    "tool_version": "v3.11.1",
                },
            ),
            make_jsonl_line(
                "warning",
                run_id=run_id,
                data={"message": "Some subfinder timeout warning"},
            ),
            make_jsonl_line(
                "run_end",
                run_id=run_id,
                data={"status": "complete"},
            ),
        ]

        received_events: list[Event] = []
        result = ingest_stream(
            lines=lines,
            db=db,
            run_id=run_id,
            on_event=received_events.append,
        )

        assert isinstance(result, IngestResult)
        assert result.run_id == run_id
        assert result.target == "example.com"
        assert result.status == "complete"
        assert result.events_count == 6
        assert result.hosts_count == 1
        assert result.http_count == 1
        assert result.findings_count == 1
        assert result.warnings_count == 1
        assert result.errors_count == 0
        assert result.errors == ()
        assert len(received_events) == 6

        # Verify database contents
        run_record = db.get_run(run_id)
        assert run_record is not None
        assert run_record.target == "example.com"
        assert run_record.status == "complete"
        assert run_record.tool_versions == {"subfinder": "v2.17.0", "httpx": "v1.12.0"}

        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "api.example.com"

        http_obs = db.get_http_obs_for_run(run_id)
        assert len(http_obs) == 1
        assert http_obs[0].url == "https://api.example.com:443"

        findings = db.get_findings_for_run(run_id)
        assert len(findings) == 1
        assert findings[0].id == "finding_sha_123"

    def test_empty_lines_and_whitespace_are_safely_ignored(self, db: Database) -> None:
        run_id = "01J00000000000000000000002"
        lines = [
            "",
            "   ",
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            "\t\n",
            make_jsonl_line("host", run_id=run_id, data={"hostname": "sub.example.com"}),
            "   \n",
            make_jsonl_line("run_end", run_id=run_id, data={"status": "complete"}),
            "",
        ]

        result = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert result.events_count == 3
        assert result.hosts_count == 1
        assert result.errors_count == 0

    def test_empty_stream_handling(self, db: Database) -> None:
        # Empty stream with no predefined run_id
        res_empty = Ingestor(db=db).ingest_lines([])
        assert res_empty.run_id == ""
        assert res_empty.events_count == 0
        assert res_empty.hosts_count == 0
        assert res_empty.errors_count == 0

        # Empty stream with predefined run_id creates a partial run
        run_id = "01J00000000000000000000003"
        res_with_id = Ingestor(db=db, run_id=run_id).ingest_lines([])
        assert res_with_id.run_id == run_id
        assert db.get_run(run_id) is not None

    def test_host_without_prior_run_start_creates_run_row(self, db: Database) -> None:
        run_id = "01J00000000000000000000004"
        lines = [
            make_jsonl_line("host", run_id=run_id, data={"hostname": "direct.example.com"}),
        ]
        res = Ingestor(db=db).ingest_lines(lines)
        assert res.hosts_count == 1
        assert db.get_run(run_id) is not None
        assert len(db.get_hosts_for_run(run_id)) == 1

    def test_duplicate_events_idempotency_in_sqlite(self, db: Database) -> None:
        run_id = "01J00000000000000000000005"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "dup.example.com", "sources": ["src1"]}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "dup.example.com", "sources": ["src2"]}),
            make_jsonl_line(
                "http",
                run_id=run_id,
                data={"hostname": "dup.example.com", "url": "http://dup.example.com", "tech": ["Apache"]},
            ),
            make_jsonl_line(
                "http",
                run_id=run_id,
                data={"hostname": "dup.example.com", "url": "http://dup.example.com", "tech": ["PHP"]},
            ),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.hosts_count == 2
        assert res.http_count == 2

        # SQLite rows are deduplicated and merged
        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].sources == ["src1", "src2"]

        http_obs = db.get_http_obs_for_run(run_id)
        assert len(http_obs) == 1
        assert http_obs[0].tech == ["Apache", "PHP"]

    def test_finding_for_unknown_host_increments_warning_count(self, db: Database) -> None:
        run_id = "01J00000000000000000000006"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line(
                "finding",
                run_id=run_id,
                data={
                    "id": "find_unknown_host",
                    "hostname": "unseen.example.com",
                    "template_id": "tpl-1",
                    "name": "Vuln",
                    "severity": "low",
                    "matched_at": "https://unseen.example.com",
                },
            ),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.findings_count == 1
        assert res.warnings_count == 1

    def test_ingest_result_backward_compatibility(self) -> None:
        """Verify older callers instantiating IngestResult with 8 positional args continue to work."""
        res = IngestResult("run1", "target.com", "complete", 1, 0, 2, 1, 0)
        assert res.run_id == "run1"
        assert res.target == "target.com"
        assert res.status == "complete"
        assert res.hosts_count == 1
        assert res.warnings_count == 0
        assert res.events_count == 2
        assert res.http_count == 1
        assert res.findings_count == 0
        assert res.errors_count == 0
        assert res.errors == ()


class TestIngestorMalformedAndInvalidLinesHandling:
    """Validate per-line fault-tolerance for malformed JSON and schema violations."""

    def test_malformed_json_in_middle_of_stream_preserves_valid_events(self, db: Database) -> None:
        run_id = "01J00000000000000000000007"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "good1.example.com"}),
            "{ definitely broken json line [[",
            make_jsonl_line("host", run_id=run_id, data={"hostname": "good2.example.com"}),
            make_jsonl_line("run_end", run_id=run_id, data={"status": "complete"}),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        assert res.status == "complete"
        assert res.events_count == 4
        assert res.hosts_count == 2
        assert res.errors_count == 1
        assert len(res.errors) == 1
        assert res.errors[0].line_number == 3
        assert res.errors[0].error_type == "json_decode_error"

        # Verify both hosts are persisted in SQLite
        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 2
        hostnames = [h.hostname for h in hosts]
        assert "good1.example.com" in hostnames
        assert "good2.example.com" in hostnames

    def test_invalid_schema_in_middle_of_stream_preserves_valid_events(self, db: Database) -> None:
        run_id = "01J00000000000000000000008"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "good1.example.com"}),
            # Missing required 'ts' field
            json.dumps({"schema_version": "1", "type": "host", "run_id": run_id, "data": {}}),
            # Unknown event type
            json.dumps({
                "schema_version": "1",
                "type": "unsupported_event_type",
                "run_id": run_id,
                "ts": "2026-11-05T12:00:00Z",
                "data": {},
            }),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "good2.example.com"}),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        assert res.hosts_count == 2
        assert res.events_count == 3
        assert res.errors_count == 2
        assert len(res.errors) == 2
        assert res.errors[0].line_number == 3
        assert res.errors[0].error_type == "validation_error"
        assert res.errors[1].line_number == 4
        assert res.errors[1].error_type == "validation_error"

        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 2

    def test_valid_events_before_and_after_invalid_lines_are_persisted(self, db: Database) -> None:
        run_id = "01J00000000000000000000009"
        lines = [
            make_jsonl_line("host", run_id=run_id, data={"hostname": "before.example.com"}),
            "broken line 1",
            "broken line 2",
            make_jsonl_line("host", run_id=run_id, data={"hostname": "after.example.com"}),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.hosts_count == 2
        assert res.errors_count == 2

        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 2
        hostnames = [h.hostname for h in hosts]
        assert "before.example.com" in hostnames
        assert "after.example.com" in hostnames

    def test_error_line_numbers_and_details_are_accurate(self, db: Database) -> None:
        run_id = "01J00000000000000000000010"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),  # Line 1
            "",  # Line 2 (empty, skipped without incrementing line error)
            "{ bad json on line 3",  # Line 3
            make_jsonl_line("host", run_id=run_id, data={"hostname": "h1.example.com"}),  # Line 4
            json.dumps({"schema_version": "99", "type": "host", "run_id": run_id}),  # Line 5
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.errors_count == 2
        assert isinstance(res.errors[0], IngestLineError)
        assert res.errors[0].line_number == 3
        assert res.errors[0].error_type == "json_decode_error"
        assert "{ bad json on line 3" in res.errors[0].raw_preview

        assert res.errors[1].line_number == 5
        assert res.errors[1].error_type == "validation_error"

    def test_raw_preview_is_bounded_and_sanitizes_sensitive_information(self, db: Database) -> None:
        run_id = "01J00000000000000000000011"
        long_line = "{ 'bad': '" + "A" * 300 + "' }"
        secret_line1 = '{"authorization": "Bearer secret_api_token_12345", "broken": }'
        secret_line2 = 'Authorization: Bearer my_secret_token_12345'
        secret_line3 = 'bearer abc123'
        secret_line4 = 'BEARER abc123'
        secret_line5 = 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature'
        secret_line6 = '{"password": "super_secret_password"}'
        secret_line7 = 'api_key="12345-abcdef"'

        lines = [
            long_line,
            secret_line1,
            secret_line2,
            secret_line3,
            secret_line4,
            secret_line5,
            secret_line6,
            secret_line7,
        ]
        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        assert res.errors_count == 8
        # Verify length bounding
        assert len(res.errors[0].raw_preview) <= 120
        assert res.errors[0].raw_preview.endswith("...")

        # Line 1: {"authorization": "Bearer secret_api_token_12345", "broken": }
        p1 = res.errors[1].raw_preview
        assert "secret_api_token" not in p1
        assert "12345" not in p1
        assert '"Bearer [REDACTED]"' in p1

        # Line 2: Authorization: Bearer my_secret_token_12345
        p2 = res.errors[2].raw_preview
        assert "my_secret_token_12345" not in p2
        assert "my_secret" not in p2
        assert "token" not in p2
        assert p2 == "Authorization: Bearer [REDACTED]"

        # Line 3: bearer abc123
        p3 = res.errors[3].raw_preview
        assert "abc123" not in p3
        assert p3 == "bearer [REDACTED]"

        # Line 4: BEARER abc123
        p4 = res.errors[4].raw_preview
        assert "abc123" not in p4
        assert p4 == "BEARER [REDACTED]"

        # Line 5: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature
        p5 = res.errors[5].raw_preview
        assert "eyJhbGci" not in p5
        assert "payload" not in p5
        assert "signature" not in p5
        assert p5 == "Bearer [REDACTED]"

        # Line 6: {"password": "super_secret_password"}
        p6 = res.errors[6].raw_preview
        assert "super_secret_password" not in p6
        assert '{"password": "[REDACTED]"}' in p6

        # Line 7: api_key="12345-abcdef"
        p7 = res.errors[7].raw_preview
        assert "12345-abcdef" not in p7
        assert 'api_key="[REDACTED]"' in p7

    def test_error_message_bounded_at_300_characters(self, db: Database) -> None:
        run_id = "01J00000000000000000000099"
        bloated_payload = {
            "schema_version": "invalid_version_very_long_string_" * 5,
            "type": "invalid_type_very_long_string_" * 5,
            "run_id": " " * 50,
            "ts": "not_a_valid_timestamp_string_xyz" * 5,
            "data": "must_be_a_dict_not_a_string" * 5,
            "extra_field_1": "disallowed_extra_field_long_" * 5,
            "extra_field_2": "disallowed_extra_field_long_" * 5,
        }
        lines = [json.dumps(bloated_payload)]
        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        assert res.errors_count == 1
        err = res.errors[0]
        assert err.error_type == "validation_error"
        assert len(err.message) == 300
        assert err.message.endswith("...")

    def test_multiple_invalid_lines_in_stream(self, db: Database) -> None:
        run_id = "01J00000000000000000000012"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            "err 1",
            "err 2",
            make_jsonl_line("host", run_id=run_id, data={"hostname": "h1.example.com"}),
            "err 3",
            "err 4",
            "err 5",
            make_jsonl_line("run_end", run_id=run_id, data={"status": "complete"}),
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.errors_count == 5
        assert len(res.errors) == 5
        assert res.events_count == 3
        assert res.hosts_count == 1

    def test_stream_with_only_invalid_lines(self, db: Database) -> None:
        lines = [
            "completely invalid line 1",
            "completely invalid line 2",
            "completely invalid line 3",
        ]

        res = Ingestor(db=db).ingest_lines(lines)
        assert res.run_id == ""
        assert res.events_count == 0
        assert res.hosts_count == 0
        assert res.errors_count == 3
        assert len(res.errors) == 3
        assert db.get_all_hosts() == []

    def test_max_50_detail_errors_recorded_and_total_count_accurate(self, db: Database) -> None:
        run_id = "01J00000000000000000000013"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
        ]
        # Append 75 invalid lines
        for i in range(75):
            lines.append(f"malformed json payload line {i}")
        lines.append(make_jsonl_line("host", run_id=run_id, data={"hostname": "survivor.example.com"}))

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.hosts_count == 1
        assert res.errors_count == 75
        # Capped at exactly 50 details
        assert len(res.errors) == 50

        # Survivor host was persisted
        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "survivor.example.com"

    def test_callback_isolated_from_invalid_lines_and_called_for_valid(self, db: Database) -> None:
        run_id = "01J00000000000000000000014"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            "broken line 1",
            json.dumps({"schema_version": "1", "type": "bad"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "ok.example.com"}),
            "broken line 2",
        ]

        dispatched: list[Event] = []
        res = Ingestor(db=db, run_id=run_id, on_event=dispatched.append).ingest_lines(lines)

        assert res.errors_count == 3
        # Callback receives only the 2 valid events
        assert len(dispatched) == 2
        assert dispatched[0].type == "run_start"
        assert dispatched[1].type == "host"

    def test_duplicate_events_remain_idempotent_with_interleaved_errors(self, db: Database) -> None:
        run_id = "01J00000000000000000000015"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "dup.example.com", "sources": ["s1"]}),
            "broken json",
            make_jsonl_line("host", run_id=run_id, data={"hostname": "dup.example.com", "sources": ["s2"]}),
            "another broken line",
        ]

        res = Ingestor(db=db, run_id=run_id).ingest_lines(lines)
        assert res.hosts_count == 2
        assert res.errors_count == 2

        hosts = db.get_hosts_for_run(run_id)
        assert len(hosts) == 1
        assert hosts[0].sources == ["s1", "s2"]


class TestIngestorIntegrityAndRollback:
    """Validate non-recoverable error enforcement and complete transaction rollbacks."""

    def test_mismatched_run_id_raises_and_rolls_back(self, db: Database) -> None:
        run1 = "01J00000000000000000000001"
        run2 = "01J00000000000000000000002"

        lines = [
            make_jsonl_line("run_start", run_id=run1, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run1, data={"hostname": "host1.example.com"}),
            # Mismatched run_id in the same stream
            make_jsonl_line("host", run_id=run2, data={"hostname": "host2.example.com"}),
        ]

        with pytest.raises(ValueError, match="Mismatched run_id in event stream"):
            Ingestor(db=db, run_id=run1).ingest_lines(lines)

        # Transaction rollback verification: no rows should exist in database
        assert db.get_run(run1) is None
        assert db.get_all_hosts() == []

    def test_sqlite_integrity_error_triggers_full_rollback(
        self,
        db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run_id = "01J00000000000000000000016"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "valid.example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "crash.example.com"}),
        ]

        orig_upsert = db.upsert_host_obs

        def mock_upsert_host_obs(*args: object, **kwargs: object) -> str:
            if kwargs.get("hostname") == "crash.example.com":
                raise sqlite3.IntegrityError("Simulated constraint violation")
            return orig_upsert(*args, **kwargs)

        monkeypatch.setattr(db, "upsert_host_obs", mock_upsert_host_obs)

        with pytest.raises(sqlite3.IntegrityError, match="Simulated constraint violation"):
            Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        # Full rollback: valid.example.com must not be committed
        assert db.get_run(run_id) is None
        assert db.get_all_hosts() == []

    def test_sqlite_operational_error_triggers_full_rollback(
        self,
        db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run_id = "01J00000000000000000000017"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "valid.example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "locked.example.com"}),
        ]

        orig_upsert = db.upsert_host_obs

        def mock_upsert_host_obs(*args: object, **kwargs: object) -> str:
            if kwargs.get("hostname") == "locked.example.com":
                raise sqlite3.OperationalError("database is locked")
            return orig_upsert(*args, **kwargs)

        monkeypatch.setattr(db, "upsert_host_obs", mock_upsert_host_obs)

        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            Ingestor(db=db, run_id=run_id).ingest_lines(lines)

        assert db.get_run(run_id) is None
        assert db.get_all_hosts() == []

    def test_callback_exception_propagates_and_rolls_back(self, db: Database) -> None:
        run_id = "01J00000000000000000000018"
        lines = [
            make_jsonl_line("run_start", run_id=run_id, data={"target": "example.com"}),
            make_jsonl_line("host", run_id=run_id, data={"hostname": "valid.example.com"}),
        ]

        def crashing_callback(event: Event) -> None:
            if event.type == "host":
                raise RuntimeError("Callback crashed intentionally")

        with pytest.raises(RuntimeError, match="Callback crashed intentionally"):
            Ingestor(db=db, run_id=run_id, on_event=crashing_callback).ingest_lines(lines)

        assert db.get_run(run_id) is None
        assert db.get_all_hosts() == []

    def test_file_not_found_handling(self, db: Database, tmp_path: Path) -> None:
        non_existent_file = tmp_path / "non_existent.jsonl"
        with pytest.raises(FileNotFoundError), open(non_existent_file, encoding="utf-8") as f:
            Ingestor(db=db).ingest_lines(f)
