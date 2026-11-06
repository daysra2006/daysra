from __future__ import annotations

import io

import pytest
from rich.console import Console

from daysra.simple.summary import render_recon_summary
from daysra.store.db import HostObsRecord, HttpObsRecord, RunRecord


@pytest.fixture
def console() -> Console:
    """Create a recording Console capturing plain text without ANSI escape sequences."""
    return Console(record=True, width=120, file=io.StringIO(), color_system=None)


@pytest.fixture
def base_run() -> RunRecord:
    return RunRecord(
        run_id="01J00000000000000000000001",
        target="example.com",
        scope_hash="hash123",
        started_at="2026-11-05T10:00:00Z",
        finished_at="2026-11-05T10:05:00Z",
        status="complete",
        tool_versions={"subfinder": "v2.17.0"},
    )


class TestRenderReconSummary:
    """Validate terminal Simple Mode summary rendering with Rich components."""

    def test_complete_recon_and_http_summary(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        hosts = [
            HostObsRecord(
                run_id=base_run.run_id,
                host_id="h1",
                hostname="api.example.com",
                ips=["192.0.2.1"],
                sources=["crtsh"],
            ),
            HostObsRecord(
                run_id=base_run.run_id,
                host_id="h2",
                hostname="web.example.com",
                ips=["192.0.2.2"],
                sources=["crtsh", "virustotal"],
            ),
        ]
        http_obs = [
            HttpObsRecord(
                run_id=base_run.run_id,
                host_id="h1",
                hostname="api.example.com",
                url="https://api.example.com:443",
                status_code=200,
                title="API Service",
                tech=["Nginx", "Python"],
                content_length=500,
                tls_issuer="Let's Encrypt",
            ),
            HttpObsRecord(
                run_id=base_run.run_id,
                host_id="h2",
                hostname="web.example.com",
                url="http://web.example.com:80",
                status_code=403,
                title="Forbidden Area",
                tech=["Apache"],
                content_length=120,
                tls_issuer=None,
            ),
        ]

        render_recon_summary(run=base_run, hosts=hosts, http_obs=http_obs, console=console)
        output = console.export_text()

        # Meta table checks
        assert "Ringkasan Recon Simple Mode" in output
        assert "Selesai (Complete)" in output
        assert "example.com" in output
        assert base_run.run_id in output
        assert "Total Host Unik:" in output
        assert "2 host (2 endpoint)" in output

        # Source distribution checks
        assert "Sebaran Sumber Temuan" in output
        assert "crtsh" in output
        assert "virustotal" in output

        # Top hosts checks
        assert "10 Host Teratas" in output
        assert "api.example.com" in output
        assert "web.example.com" in output

        # HTTP status code and tech distribution checks
        assert "Sebaran Status Code HTTP" in output
        assert "200" in output
        assert "OK" in output
        assert "403" in output
        assert "Forbidden" in output
        assert "10 Teknologi Teratas" in output
        assert "Nginx" in output
        assert "Apache" in output

        # Interesting status endpoints (3xx/4xx/5xx)
        assert "Host dengan Status Menarik" in output
        assert "http://web.example.com:80" in output
        assert "Forbidden Area" in output

    def test_partial_status_warning(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        partial_run = RunRecord(
            run_id=base_run.run_id,
            target=base_run.target,
            scope_hash=None,
            started_at=base_run.started_at,
            finished_at=None,
            status="partial",
            tool_versions={},
        )
        hosts = [
            HostObsRecord(
                run_id=base_run.run_id,
                host_id="h1",
                hostname="partial.example.com",
                ips=[],
                sources=["crtsh"],
            )
        ]

        render_recon_summary(run=partial_run, hosts=hosts, console=console)
        output = console.export_text()

        assert "Parsial (Partial - Hasil Tidak Lengkap)" in output
        assert "PERINGATAN: Proses ini tidak selesai sempurna" in output

    def test_cancelled_status_warning(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        cancelled_run = RunRecord(
            run_id=base_run.run_id,
            target=base_run.target,
            scope_hash=None,
            started_at=base_run.started_at,
            finished_at=None,
            status="cancelled",
            tool_versions={},
        )
        render_recon_summary(run=cancelled_run, hosts=[], console=console)
        output = console.export_text()

        assert "Dibatalkan (Cancelled)" in output
        assert "PERINGATAN: Proses ini tidak selesai sempurna" in output
        assert "Tidak ada subdomain atau host hidup yang ditemukan." in output

    def test_empty_hosts_and_empty_http(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        render_recon_summary(run=base_run, hosts=[], http_obs=[], console=console)
        output = console.export_text()

        assert "Tidak ada subdomain atau host hidup yang ditemukan." in output
        # Details tables should not be rendered
        assert "Sebaran Sumber Temuan" not in output
        assert "10 Host Teratas" not in output

    def test_top_hosts_truncation_and_report_hint(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        # Create 15 hosts to test truncation to top 10
        many_hosts = [
            HostObsRecord(
                run_id=base_run.run_id,
                host_id=f"hid_{i}",
                hostname=f"sub{i:02d}.example.com",
                ips=["192.0.2.1"],
                sources=["crtsh"],
            )
            for i in range(15)
        ]

        render_recon_summary(run=base_run, hosts=many_hosts, console=console)
        output = console.export_text()

        assert "10 Host Teratas (Menampilkan 10 dari 15 host)" in output
        assert "sub00.example.com" in output
        assert "sub09.example.com" in output
        assert "sub14.example.com" not in output  # truncated
        assert f"Gunakan 'daysra report --run {base_run.run_id}' untuk melihat daftar lengkap." in output

    def test_interesting_status_truncation_to_15(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        # Create 20 interesting HTTP endpoints
        many_http = [
            HttpObsRecord(
                run_id=base_run.run_id,
                host_id=f"hid_{i}",
                hostname=f"sub{i}.example.com",
                url=f"https://sub{i}.example.com/err",
                status_code=500,
                title="Error Page",
                tech=[],
                content_length=100,
                tls_issuer=None,
            )
            for i in range(20)
        ]

        render_recon_summary(run=base_run, hosts=[], http_obs=many_http, console=console)
        output = console.export_text()

        assert "Host dengan Status Menarik (3xx/4xx/5xx) — Menampilkan 20 endpoint" in output
        assert "https://sub0.example.com/err" in output
        assert "https://sub14.example.com/err" in output
        assert "https://sub15.example.com/err" not in output  # row 16-20 truncated to 15 rows
        assert f"Gunakan 'daysra report --run {base_run.run_id}' untuk melihat daftar lengkap." in output

    def test_missing_and_optional_fields_rendered_gracefully(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        sparse_run = RunRecord(
            run_id=base_run.run_id,
            target=base_run.target,
            scope_hash=None,
            started_at="",
            finished_at=None,
            status="other_status",
            tool_versions={},
        )
        sparse_host = HostObsRecord(
            run_id=base_run.run_id,
            host_id="h1",
            hostname="sparse.example.com",
            ips=[],
            sources=[],
        )
        sparse_http = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h1",
            hostname="sparse.example.com",
            url="http://sparse.example.com",
            status_code=None,
            title=None,
            tech=[],
            content_length=None,
            tls_issuer=None,
        )

        render_recon_summary(
            run=sparse_run,
            hosts=[sparse_host],
            http_obs=[sparse_http],
            console=console,
        )
        output = console.export_text()

        assert "✖ Status: other_status" in output
        assert "sparse.example.com" in output

    def test_rich_markup_in_untrusted_title_is_not_interpreted(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        # Verified behavior per Stage 5C (OUT-01):
        # Untrusted title containing Rich tags like '[bold]Title[/bold]' is safely rendered
        # as plain text using rich.text.Text without parsing markup.
        http_with_markup = [
            HttpObsRecord(
                run_id=base_run.run_id,
                host_id="h1",
                hostname="markup.example.com",
                url="https://markup.example.com",
                status_code=403,
                title="[bold red]Injected Alert[/bold red]",
                tech=[],
                content_length=100,
                tls_issuer=None,
            )
        ]

        render_recon_summary(run=base_run, hosts=[], http_obs=http_with_markup, console=console)
        output = console.export_text()

        # Rich does NOT parse the markup tag; '[bold red]' appears literally in plain export
        assert "Injected Alert" in output
        assert "[bold red]" in output  # tag is treated as literal plain text, not parsed by Rich


class TestOutputSecuritySimpleSummary:
    """Validate terminal output security against Rich markup injection and terminal control sequences (OUT-01, OUT-04)."""

    def test_out01_untrusted_hostname_closing_tag_does_not_crash_summary(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        malicious_host = HostObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_1",
            hostname="[/bold] Injected.example.com",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        render_recon_summary(run=base_run, hosts=[malicious_host], console=console)
        output = console.export_text()
        assert "[/bold] Injected.example.com" in output

    def test_out01_untrusted_http_title_closing_tag_does_not_crash_summary(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        malicious_http = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_2",
            hostname="safe.example.com",
            url="https://safe.example.com/login",
            status_code=403,
            title="[/bold] Injected Title",
            tech=["Nginx"],
            content_length=100,
            tls_issuer=None,
        )
        render_recon_summary(run=base_run, hosts=[], http_obs=[malicious_http], console=console)
        output = console.export_text()
        assert "[/bold] Injected Title" in output

    def test_out01_untrusted_url_closing_tag_does_not_crash_summary(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        malicious_http = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_3",
            hostname="safe.example.com",
            url="https://safe.example.com/[/bold]admin",
            status_code=500,
            title="Error Page",
            tech=["Apache"],
            content_length=100,
            tls_issuer=None,
        )
        render_recon_summary(run=base_run, hosts=[], http_obs=[malicious_http], console=console)
        output = console.export_text()
        assert "https://safe.example.com/[/bold]admin" in output

    def test_out01_untrusted_tech_closing_tag_does_not_crash_summary(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        malicious_http = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_4",
            hostname="safe.example.com",
            url="https://safe.example.com/app",
            status_code=404,
            title="Not Found",
            tech=["[/bold] Injected Tech"],
            content_length=100,
            tls_issuer=None,
        )
        render_recon_summary(run=base_run, hosts=[], http_obs=[malicious_http], console=console)
        output = console.export_text()
        assert "[/bold] Injected Tech" in output

    def test_out01_untrusted_rich_formatting_markup_rendered_as_literal_text(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        host = HostObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_5",
            hostname="[bold red]Fake Warning Host[/bold red]",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        http_obs = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_5",
            hostname="[bold red]Fake Warning Host[/bold red]",
            url="https://safe.example.com",
            status_code=403,
            title="[bold red]Fake Warning Title[/bold red]",
            tech=["[link=https://evil.com]Login[/link]"],
            content_length=100,
            tls_issuer=None,
        )
        render_recon_summary(run=base_run, hosts=[host], http_obs=[http_obs], console=console)
        output = console.export_text()

        # Rich must NOT parse these tags as styling or hyperlinks; they must appear as literal text
        assert "[bold red]Fake Warning Host[/bold red]" in output
        assert "[bold red]Fake Warning Title[/bold red]" in output
        assert "[link=https://evil.com]Login[/link]" in output
        assert "Ringkasan Recon Simple Mode" in output

    def test_out04_untrusted_summary_data_neutralizes_osc_and_bidi(
        self,
        base_run: RunRecord,
    ) -> None:
        raw_buf = io.StringIO()
        raw_console = Console(record=True, width=120, file=raw_buf, color_system="standard")

        host = HostObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_6",
            hostname="\x1b]0;HACKED\x07evil\u202eexample.com",
            ips=["192.0.2.1"],
            sources=["crtsh"],
        )
        http_obs = HttpObsRecord(
            run_id=base_run.run_id,
            host_id="h_inj_6",
            hostname="evil.example.com",
            url="https://evil.example.com/\r\x00path",
            status_code=403,
            title="Site \x1b]8;;https://evil.com\x1b\\Click\x1b]8;;\x1b\\ \x1b]52;c;BASE64DATA\x07",
            tech=["Tech"],
            content_length=100,
            tls_issuer=None,
        )
        render_recon_summary(run=base_run, hosts=[host], http_obs=[http_obs], console=raw_console)
        raw_output = raw_buf.getvalue()

        # OSC terminal manipulation sequences, Bidi override, and raw CR/null bytes must not leak into terminal
        assert "\x1b]0;" not in raw_output
        assert "\x1b]8;" not in raw_output
        assert "\x1b]52;" not in raw_output
        assert "\u202e" not in raw_output
        assert "\r" not in raw_output
        assert "\x00" not in raw_output

    def test_render_failed_status_summary_reproduces_finding06(
        self,
        console: Console,
        base_run: RunRecord,
    ) -> None:
        """FINDING-06: Summary output should display an explicit warning panel for status 'failed'."""
        failed_run = RunRecord(
            run_id=base_run.run_id,
            target=base_run.target,
            scope_hash=None,
            started_at=base_run.started_at,
            finished_at="2026-11-05T10:05:00Z",
            status="failed",
            tool_versions={},
        )
        render_recon_summary(run=failed_run, hosts=[], console=console)
        output = console.export_text()

        # EXPECTED CONTRACT: 'failed' runs should display a visible warning banner,
        # just like 'partial' and 'cancelled' do.
        # ACTUAL BUG: summary.py line 58 only checks {"partial", "cancelled"}, omitting "failed".
        assert "PERINGATAN:" in output, (
            "FINDING-06 REPRODUCED: Summary missing warning panel for failed status"
        )

    def test_summary_all_valid_statuses_render_cleanly(
        self,
        base_run: RunRecord,
    ) -> None:
        """Verify summary renders each schema-valid status without unhandled exceptions."""
        valid_statuses = ("complete", "partial", "cancelled", "failed")
        for st in valid_statuses:
            test_run = RunRecord(
                run_id=base_run.run_id,
                target=base_run.target,
                scope_hash=None,
                started_at=base_run.started_at,
                finished_at="2026-11-05T10:05:00Z",
                status=st,
                tool_versions={},
            )
            c = Console(record=True, color_system=None)
            render_recon_summary(run=test_run, hosts=[], console=c)
            rendered = c.export_text()
            assert base_run.target in rendered
