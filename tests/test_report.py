from __future__ import annotations

from pathlib import Path

import pytest

from daysra.report.generator import (
    generate_report_for_run,
    render_markdown_report,
    sanitize_text,
)
from daysra.store.db import Database, HostObsRecord, HttpObsRecord, RunRecord


@pytest.fixture
def sample_run_record() -> RunRecord:
    return RunRecord(
        run_id="01J00000000000000000000001",
        target="example.com",
        scope_hash="hash_scope_123",
        started_at="2026-11-05T10:00:00Z",
        finished_at="2026-11-05T10:05:00Z",
        status="complete",
        tool_versions={"subfinder": "v2.17.0", "httpx": "v1.12.0"},
    )


@pytest.fixture
def sample_hosts() -> list[HostObsRecord]:
    return [
        HostObsRecord(
            run_id="01J00000000000000000000001",
            host_id="hid1",
            hostname="api.example.com",
            ips=["192.0.2.1"],
            sources=["crtsh", "virustotal"],
        ),
        HostObsRecord(
            run_id="01J00000000000000000000001",
            host_id="hid2",
            hostname="web.example.com",
            ips=["192.0.2.2"],
            sources=["crtsh"],
        ),
    ]


@pytest.fixture
def sample_http_obs() -> list[HttpObsRecord]:
    return [
        HttpObsRecord(
            run_id="01J00000000000000000000001",
            host_id="hid1",
            hostname="api.example.com",
            url="https://api.example.com:443",
            status_code=200,
            title="API Gateway",
            tech=["Nginx", "Python"],
            content_length=512,
            tls_issuer="Let's Encrypt",
        ),
        HttpObsRecord(
            run_id="01J00000000000000000000001",
            host_id="hid2",
            hostname="web.example.com",
            url="http://web.example.com:80",
            status_code=301,
            title="Redirecting",
            tech=["Apache"],
            content_length=0,
            tls_issuer=None,
        ),
    ]


class TestSanitizeText:
    """Validate Markdown and ANSI sanitization."""

    def test_sanitize_none_and_empty(self) -> None:
        assert sanitize_text(None) == ""
        assert sanitize_text("") == ""
        assert sanitize_text("   ") == ""

    def test_strips_ansi_color_and_control_codes(self) -> None:
        raw = "\x1b[31mRed Text\x1b[0m \x07\x08clean"
        sanitized = sanitize_text(raw)
        assert sanitized == "Red Text clean"

    def test_escapes_markdown_table_pipes_and_newlines(self) -> None:
        raw = "Line1|column\nLine2|column"
        sanitized = sanitize_text(raw)
        assert sanitized == "Line1\\|column Line2\\|column"

    def test_observation_html_and_backticks_are_escaped(self) -> None:
        # Verified behavior per Stage 5C (OUT-02, OUT-03):
        # sanitize_text escapes HTML tags to entity representations and neutralizes backticks
        raw = "<script>alert(1)</script> `code_span`"
        sanitized = sanitize_text(raw)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in sanitized
        assert "`" not in sanitized
        assert "&#96;code_span&#96;" in sanitized


class TestRenderMarkdownReport:
    """Validate report generation and Jinja2 rendering logic."""

    def test_render_complete_report(
        self,
        sample_run_record: RunRecord,
        sample_hosts: list[HostObsRecord],
        sample_http_obs: list[HttpObsRecord],
    ) -> None:
        md = render_markdown_report(
            run=sample_run_record,
            hosts=sample_hosts,
            http_obs=sample_http_obs,
            generated_at="2026-11-05T10:06:00Z",
        )

        assert "# Laporan Reconnaissance DAYSRA" in md
        assert "**PERINGATAN: Run ini berstatus Parsial**" not in md
        assert "**PERINGATAN: Run ini Dibatalkan**" not in md
        assert "`example.com`" in md
        assert "`01J00000000000000000000001`" in md
        assert "**complete**" in md
        assert "| **Total Host Unik** | 2 |" in md
        assert "| **Host Hidup (HTTP)** | 2 |" in md
        # Tool versions sorted alphabetically
        assert "httpx `v1.12.0`" in md
        assert "subfinder `v2.17.0`" in md
        # Subdomains and HTTP endpoints rendered
        assert "`api.example.com`" in md
        assert "`https://api.example.com:443`" in md
        assert "Let's Encrypt" not in md  # tls_issuer not in table per template
        assert "API Gateway" in md
        assert "Nginx, Python" in md
        assert "*Dibuat oleh DAYSRA pada 2026-11-05T10:06:00Z*" in md

    def test_render_partial_run_warning_banner(
        self,
        sample_run_record: RunRecord,
        sample_hosts: list[HostObsRecord],
    ) -> None:
        partial_run = RunRecord(
            run_id=sample_run_record.run_id,
            target=sample_run_record.target,
            scope_hash=sample_run_record.scope_hash,
            started_at=sample_run_record.started_at,
            finished_at=None,
            status="partial",
            tool_versions={},
        )
        md = render_markdown_report(run=partial_run, hosts=sample_hosts)
        assert "> [!WARNING]" in md
        assert "**PERINGATAN: Run ini berstatus Parsial (Tidak Lengkap).**" in md
        assert "| **Waktu Selesai** | - |" in md

    def test_render_cancelled_run_warning_banner(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        cancelled_run = RunRecord(
            run_id=sample_run_record.run_id,
            target=sample_run_record.target,
            scope_hash=sample_run_record.scope_hash,
            started_at=sample_run_record.started_at,
            finished_at="2026-11-05T10:02:00Z",
            status="cancelled",
            tool_versions={},
        )
        md = render_markdown_report(run=cancelled_run, hosts=[])
        assert "> [!WARNING]" in md
        assert "**PERINGATAN: Run ini Dibatalkan (Cancelled).**" in md
        assert "*Tidak ada data sumber.*" in md
        assert "*Tidak ada subdomain yang ditemukan.*" in md
        assert "*Tidak ada host hidup yang terdeteksi.*" in md

    def test_render_null_and_empty_fields_fallback_to_hyphen(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        host_empty = HostObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_none",
            hostname="empty.example.com",
            ips=[],
            sources=[],
        )
        http_empty = HttpObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_none",
            hostname="empty.example.com",
            url="http://empty.example.com",
            status_code=None,
            title=None,
            tech=[],
            content_length=None,
            tls_issuer=None,
        )
        md = render_markdown_report(
            run=sample_run_record,
            hosts=[host_empty],
            http_obs=[http_empty],
        )
        # Verify fallback '-' is used in tables
        assert "| 1 | `empty.example.com` | - | - |" in md
        assert "| 1 | `http://empty.example.com` | - | - | - |" in md


class TestGenerateReportForRun:
    """Validate database-backed report retrieval and generation."""

    def test_generate_report_by_run_id(
        self,
        tmp_path: Path,
        sample_run_record: RunRecord,
    ) -> None:
        db = Database(tmp_path / "report_test.db")
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=sample_run_record.run_id,
                target=sample_run_record.target,
                started_at=sample_run_record.started_at,
                status="complete",
                tool_versions=sample_run_record.tool_versions,
            )
            db.upsert_host(conn=conn, hostname="app.example.com", run_id=sample_run_record.run_id)
            db.upsert_host_obs(
                conn=conn,
                run_id=sample_run_record.run_id,
                hostname="app.example.com",
                ips=["192.0.2.1"],
                sources=["crtsh"],
            )

        report = generate_report_for_run(db, run_id=sample_run_record.run_id)
        assert sample_run_record.run_id in report
        assert "app.example.com" in report

    def test_generate_report_latest_run_fallback(
        self,
        tmp_path: Path,
    ) -> None:
        db = Database(tmp_path / "latest_report_test.db")
        run_id = "01J00000000000000000000099"
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="latest.com",
                started_at="2026-11-05T12:00:00Z",
                status="complete",
            )

        report = generate_report_for_run(db, run_id=None)
        assert run_id in report
        assert "latest.com" in report

    def test_generate_report_raises_on_non_existent_run(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "missing_run.db")
        with pytest.raises(ValueError, match="tidak ditemukan di database"):
            generate_report_for_run(db, run_id="NON_EXISTENT_RUN")

    def test_generate_report_raises_when_no_runs_in_database(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "empty_db.db")
        with pytest.raises(ValueError, match="Belum ada riwayat run di database"):
            generate_report_for_run(db, run_id=None)

    def test_write_report_to_output_file(
        self,
        tmp_path: Path,
        sample_run_record: RunRecord,
    ) -> None:
        db = Database(tmp_path / "file_write_test.db")
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=sample_run_record.run_id,
                target=sample_run_record.target,
                started_at=sample_run_record.started_at,
                status="complete",
            )

        content = generate_report_for_run(db, run_id=sample_run_record.run_id)
        out_file = tmp_path / "reports" / "report.md"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")

        assert out_file.exists()
        saved_text = out_file.read_text(encoding="utf-8")
        assert sample_run_record.run_id in saved_text


class TestOutputSecurityMarkdownReport:
    """Validate Markdown report security against HTML injection, code span breakout, and ANSI/OSC (OUT-02, OUT-03, OUT-04)."""

    def test_out02_html_tags_are_escaped_in_markdown_report(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        malicious_host = HostObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_html_1",
            hostname="<script>alert('host')</script>.example.com",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        malicious_http = HttpObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_html_1",
            hostname="safe.example.com",
            url="https://example.com/<img src=x onerror=alert('url')>",
            status_code=200,
            title="</td><script>alert('title')</script>",
            tech=["<iframe src=\"https://evil.com\"></iframe>"],
            content_length=100,
            tls_issuer=None,
        )
        md = render_markdown_report(
            run=sample_run_record,
            hosts=[malicious_host],
            http_obs=[malicious_http],
        )

        # Raw HTML tags must NOT be emitted to the markdown report
        assert "<script>" not in md
        assert "</script>" not in md
        assert "<img " not in md
        assert "<iframe" not in md
        assert "</td>" not in md

        # Sanitized/escaped HTML entity representations must be present instead
        assert "&lt;script&gt;" in md
        assert "&lt;img " in md
        assert "&lt;iframe" in md
        assert "&lt;/td&gt;" in md

    def test_out02_sanitize_text_escapes_raw_html_tags(self) -> None:
        raw_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<iframe src=\"https://evil.com\"></iframe>",
            "</td><script>alert(1)</script>",
        ]
        for payload in raw_payloads:
            sanitized = sanitize_text(payload)
            assert "<script>" not in sanitized
            assert "<img " not in sanitized
            assert "<iframe" not in sanitized
            assert "</td>" not in sanitized
            assert "&lt;" in sanitized

    def test_out03_backtick_code_span_breakout_prevented(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        breakout_host = HostObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_bk_1",
            hostname="evil` [Phish](https://evil.com) `",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        breakout_http = HttpObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_bk_1",
            hostname="evil.example.com",
            url="https://example.com/` [Phish2](https://evil.com) `",
            status_code=200,
            title="Normal Title",
            tech=[],
            content_length=100,
            tls_issuer=None,
        )
        md = render_markdown_report(
            run=sample_run_record,
            hosts=[breakout_host],
            http_obs=[breakout_http],
        )

        # Backticks must not close the code span and expose an active Markdown link
        assert "`evil` [Phish](https://evil.com)" not in md

        # Tables must retain exact column count (5 delimiters for 4 columns in Subdomain, 6 for 5 in HTTP)
        for line in md.splitlines():
            stripped = line.strip()
            if stripped.startswith("| 1 |"):
                pipe_count = stripped.replace("\\|", "").count("|")
                if "evil" in stripped and "Phish2" not in stripped:
                    assert pipe_count == 5, f"Subdomain row corrupted: {line}"
                elif "Phish2" in stripped:
                    assert pipe_count == 6, f"HTTP row corrupted: {line}"

    def test_out03_table_syntax_and_special_characters_integrity(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        host = HostObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_spec_1",
            hostname="host|with|pipes.example.com",
            ips=["192.0.2.1"],
            sources=["crtsh | virustotal"],
        )
        http_obs = HttpObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_spec_1",
            hostname="host|with|pipes.example.com",
            url="https://example.com/page?a=1|b=2",
            status_code=200,
            title="Title with [Brackets] and *Markdown* and ~Tilde~",
            tech=["Tech1 | Tech2"],
            content_length=100,
            tls_issuer=None,
        )
        md = render_markdown_report(
            run=sample_run_record,
            hosts=[host],
            http_obs=[http_obs],
        )

        # Verify all table data rows have valid column count
        found_subdomain_row = False
        found_http_row = False
        for line in md.splitlines():
            stripped = line.strip()
            if stripped.startswith("| 1 |"):
                pipe_count = stripped.replace("\\|", "").count("|")
                if "host" in stripped:
                    assert pipe_count == 5, f"Subdomain row column mismatch: {line}"
                    found_subdomain_row = True
                elif "https://example.com" in stripped:
                    assert pipe_count == 6, f"HTTP row column mismatch: {line}"
                    found_http_row = True

        assert found_subdomain_row
        assert found_http_row

    def test_out04_sanitize_text_strips_osc_bidi_and_control_chars(self) -> None:
        # OSC 0 window title manipulation
        osc0 = "\x1b]0;HACKED\x07clean_text"
        assert "\x1b]0;" not in sanitize_text(osc0)
        assert "\x07" not in sanitize_text(osc0)

        # OSC 8 terminal hyperlink
        osc8 = "\x1b]8;;https://evil.com\x1b\\Click\x1b]8;;\x1b\\"
        assert "\x1b]8;" not in sanitize_text(osc8)

        # OSC 52 clipboard access
        osc52 = "\x1b]52;c;BASE64DATA\x07"
        assert "\x1b]52;" not in sanitize_text(osc52)

        # Right-to-Left Override (Bidi spoofing)
        bidi = "safe\u202e_spoofed.example.com"
        assert "\u202e" not in sanitize_text(bidi)

        # Carriage Return and Null Byte
        cr = "line1\rline2"
        assert "\r" not in sanitize_text(cr)

        null_byte = "clean\x00data"
        assert "\x00" not in sanitize_text(null_byte)

    def test_out04_markdown_report_strips_osc_and_bidi(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        host = HostObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_osc_1",
            hostname="\x1b]0;PWNED\x07host\u202eexample.com",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        http_obs = HttpObsRecord(
            run_id=sample_run_record.run_id,
            host_id="hid_osc_1",
            hostname="host.example.com",
            url="https://example.com/\r\x00test",
            status_code=200,
            title="Title \x1b]8;;https://evil.com\x1b\\Link\x1b]8;;\x1b\\",
            tech=["Tech \x1b]52;c;DATA\x07"],
            content_length=100,
            tls_issuer=None,
        )
        md = render_markdown_report(
            run=sample_run_record,
            hosts=[host],
            http_obs=[http_obs],
        )

        assert "\x1b]0;" not in md
        assert "\x1b]8;" not in md
        assert "\x1b]52;" not in md
        assert "\u202e" not in md
        assert "\r" not in md
        assert "\x00" not in md

    def test_render_failed_status_report_reproduces_finding06(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        """FINDING-06: Markdown report should render a warning alert block for status 'failed'."""
        failed_run = RunRecord(
            run_id=sample_run_record.run_id,
            target=sample_run_record.target,
            scope_hash=sample_run_record.scope_hash,
            started_at=sample_run_record.started_at,
            finished_at="2026-11-05T10:05:00Z",
            status="failed",
            tool_versions={},
        )
        md = render_markdown_report(run=failed_run, hosts=[])

        # EXPECTED CONTRACT: 'failed' runs should show a prominent [!WARNING] block in markdown,
        # informing readers that the run failed.
        # ACTUAL BUG: generator.py template lines 18-28 only handles "partial" and "cancelled".
        assert "> [!WARNING]" in md, (
            "FINDING-06 REPRODUCED: Markdown report missing warning banner for failed status"
        )
        assert "**PERINGATAN:" in md

    def test_report_all_valid_statuses_render_cleanly(
        self,
        sample_run_record: RunRecord,
    ) -> None:
        """Verify report generator handles all four valid schema statuses cleanly."""
        for st in ("complete", "partial", "cancelled", "failed"):
            test_run = RunRecord(
                run_id=sample_run_record.run_id,
                target=sample_run_record.target,
                scope_hash=sample_run_record.scope_hash,
                started_at=sample_run_record.started_at,
                finished_at="2026-11-05T10:05:00Z",
                status=st,
                tool_versions={},
            )
            md = render_markdown_report(run=test_run, hosts=[])
            assert f"| **Status** | **{st}** |" in md

