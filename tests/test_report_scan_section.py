from __future__ import annotations

from pathlib import Path

from daysra.knowledge import KnowledgeBase, KnowledgeEntry, load_knowledge_base
from daysra.report.generator import generate_report_for_run, render_markdown_report
from daysra.store.db import (
    Database,
    FindingRecord,
    HostObsRecord,
    HttpObsRecord,
    RunRecord,
)

GOLDEN_DIR = Path(__file__).parent / "golden"


def _finding(
    finding_id: str,
    template_id: str,
    *,
    name: str = "Nama Temuan",
    severity: str = "info",
    cve: list[str] | None = None,
    matched_at: str = "https://example.com/finding",
) -> FindingRecord:
    return FindingRecord(
        id=finding_id,
        hostname="example.com",
        template_id=template_id,
        name=name,
        severity=severity,
        cve=list(cve or []),
        matched_at=matched_at,
        first_seen_run="01JTESTSCAN0000000000000001",
        last_seen_run="01JTESTSCAN0000000000000001",
        first_seen="2026-11-05T11:00:01Z",
        last_seen="2026-11-05T11:00:01Z",
    )


def _kb_entry(template_id: str) -> KnowledgeEntry:
    return KnowledgeEntry(
        template_id=template_id,
        title="Judul dari knowledge base",
        meaning="Arti dari knowledge base.",
        impact="Dampak dari knowledge base.",
        verify_steps=("Langkah dari knowledge base.",),
        concept="Konsep dari knowledge base.",
        lang="id",
        source=Path("knowledge/test.yaml"),
    )


def _complete_scan_run() -> RunRecord:
    return RunRecord(
        run_id="01JTESTSCAN0000000000000001",
        target="example.com",
        scope_hash="hash_scope_scan",
        started_at="2026-11-05T11:00:00Z",
        finished_at="2026-11-05T11:00:05Z",
        status="complete",
        tool_versions={"nuclei": "v3.11.1"},
    )


def _partial_scan_run() -> RunRecord:
    return RunRecord(
        run_id="01JTESTSCAN0000000000000002",
        target="partial.example.com",
        scope_hash="hash_scope_scan",
        started_at="2026-11-05T11:10:00Z",
        finished_at="2026-11-05T11:10:02Z",
        status="partial",
        tool_versions={"nuclei": "v3.11.1"},
    )


def _complete_scan_findings() -> list[FindingRecord]:
    return [
        _finding(
            "f-prometheus",
            "prometheus-metrics",
            name="Prometheus Metrics - Detect",
            severity="medium",
            cve=["CVE-2026-0001"],
            matched_at="https://metrics.example.com/metrics",
        ),
        _finding(
            "f-fingerprint",
            "fingerprinthub-web-fingerprints",
            name="FingerprintHub Technology Fingerprint",
            matched_at="https://web.example.com",
        ),
        _finding(
            "f-swagger-api",
            "swagger-api",
            name="Public Swagger API - Detect",
            matched_at="https://api.example.com/api-docs/swagger.json",
        ),
        _finding(
            "f-swagger-web",
            "swagger-api",
            name="Public Swagger API - Detect",
            matched_at="https://web.example.com/swagger.json",
        ),
    ]


def _partial_scan_findings() -> list[FindingRecord]:
    return [
        _finding(
            "f-tech",
            "tech-detect",
            name="Wappalyzer Technology Detection",
            matched_at="https://web.example.com",
        )
    ]


def _complete_recon_run() -> RunRecord:
    return RunRecord(
        run_id="01JTESTRECON000000000000001",
        target="example.com",
        scope_hash="hash_recon",
        started_at="2026-11-05T10:00:00Z",
        finished_at="2026-11-05T10:00:04Z",
        status="complete",
        tool_versions={"subfinder": "v2.17.0", "httpx": "v1.12.0"},
    )


def _complete_recon_hosts() -> list[HostObsRecord]:
    return [
        HostObsRecord(
            run_id="01JTESTRECON000000000000001",
            host_id="hid-api",
            hostname="api.example.com",
            ips=["192.0.2.1"],
            sources=["alienvault", "crtsh"],
        ),
        HostObsRecord(
            run_id="01JTESTRECON000000000000001",
            host_id="hid-web",
            hostname="web.example.com",
            ips=[],
            sources=["crtsh"],
        ),
    ]


def _complete_recon_http() -> list[HttpObsRecord]:
    return [
        HttpObsRecord(
            run_id="01JTESTRECON000000000000001",
            host_id="hid-api",
            hostname="api.example.com",
            url="https://api.example.com",
            status_code=200,
            title="API Gateway",
            tech=["Nginx", "Python"],
            content_length=512,
            tls_issuer=None,
        )
    ]


def _partial_recon_run() -> RunRecord:
    return RunRecord(
        run_id="01JTESTRECON000000000000002",
        target="partial.example.com",
        scope_hash="hash_recon",
        started_at="2026-11-05T10:00:00Z",
        finished_at="2026-11-05T10:00:02Z",
        status="partial",
        tool_versions={"subfinder": "v2.17.0"},
    )


def _partial_recon_hosts() -> list[HostObsRecord]:
    return [
        HostObsRecord(
            run_id="01JTESTRECON000000000000002",
            host_id="hid-partial",
            hostname="api.partial.example.com",
            ips=[],
            sources=["crtsh"],
        )
    ]


def _kb() -> KnowledgeBase:
    return load_knowledge_base()


class TestOldGoldenFilePreserved:
    def test_complete_recon_report_is_byte_identical_to_old_golden(self) -> None:
        rendered = render_markdown_report(
            run=_complete_recon_run(),
            hosts=_complete_recon_hosts(),
            http_obs=_complete_recon_http(),
            generated_at="2026-11-05T10:00:05Z",
        )

        expected = (GOLDEN_DIR / "report_complete.md").read_text(encoding="utf-8")
        assert rendered == expected

    def test_partial_recon_report_is_byte_identical_to_old_golden(self) -> None:
        rendered = render_markdown_report(
            run=_partial_recon_run(),
            hosts=_partial_recon_hosts(),
            generated_at="2026-11-05T10:00:03Z",
        )

        expected = (GOLDEN_DIR / "report_partial.md").read_text(encoding="utf-8")
        assert rendered == expected


class TestScanReportGolden:
    def test_complete_scan_report_matches_golden(self) -> None:
        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=_complete_scan_findings(),
            knowledge=_kb(),
            generated_at="2026-11-05T11:00:06Z",
        )

        expected = (GOLDEN_DIR / "report_scan_complete.md").read_text(encoding="utf-8")
        assert rendered == expected

    def test_partial_scan_report_matches_golden(self) -> None:
        rendered = render_markdown_report(
            run=_partial_scan_run(),
            hosts=[],
            findings=_partial_scan_findings(),
            knowledge=_kb(),
            generated_at="2026-11-05T11:10:03Z",
        )

        expected = (GOLDEN_DIR / "report_scan_partial.md").read_text(encoding="utf-8")
        assert rendered == expected


class TestScanReportContent:
    def test_findings_section_summarises_severity_and_groups_templates(self) -> None:
        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=_complete_scan_findings(),
            knowledge=_kb(),
            generated_at="2026-11-05T11:00:06Z",
        )

        assert "## Temuan" in rendered
        assert "| medium | 1 |" in rendered
        assert "| info | 3 |" in rendered
        assert rendered.count("#### `swagger-api`") == 1
        # Highest severity first, then template_id.
        positions = [
            rendered.index("#### `prometheus-metrics`"),
            rendered.index("#### `fingerprinthub-web-fingerprints`"),
            rendered.index("#### `swagger-api`"),
        ]
        assert positions == sorted(positions)
        assert "**Apa ini:**" in rendered
        assert "**Kenapa penting:**" in rendered
        assert "**Langkah berikutnya:**" in rendered
        assert "**Konsep untuk dipelajari:**" in rendered
        assert "**CVE:** CVE-2026-0001" in rendered
        assert "[fallback generik]" in rendered
        assert "> Daftar host yang dipindai tidak disimpan pada run scan ini." in rendered

    def test_fallback_templates_are_listed_for_new_knowledge_entries(self) -> None:
        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=_complete_scan_findings(),
            knowledge=_kb(),
            generated_at="2026-11-05T11:00:06Z",
        )

        section = rendered.split("## Template tanpa entri knowledge base", 1)[1]
        assert "- `fingerprinthub-web-fingerprints`" in section
        assert "swagger-api" not in section
        assert "prometheus-metrics" not in section

    def test_only_twenty_matched_at_values_are_listed(self) -> None:
        findings = [
            _finding(
                f"f-many-{index}",
                "many-results",
                severity="low",
                matched_at=f"https://example.com/path-{index}",
            )
            for index in range(1, 23)
        ]

        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=findings,
            knowledge=KnowledgeBase({}),
            generated_at="2026-11-05T11:00:06Z",
        )

        for index in range(1, 21):
            assert f"https://example.com/path-{index}" in rendered
        assert "https://example.com/path-21" not in rendered
        assert "https://example.com/path-22" not in rendered
        assert "- dan 2 lainnya" in rendered

    def test_evidence_is_never_rendered(self) -> None:
        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=_complete_scan_findings(),
            knowledge=_kb(),
            generated_at="2026-11-05T11:00:06Z",
        )

        assert "evidence" not in rendered.lower()
        assert "matched-at" not in rendered.lower()


class TestScanReportInjection:
    def test_untrusted_text_is_sanitized_and_cannot_break_tables(self) -> None:
        finding = _finding(
            "f-injection",
            "injected-template",
            name="[x](javascript:alert(1)) | `<script>alert(1)</script>` \x1b[31m",
            severity="info|injected",
            matched_at=(
                "https://example.com/[x](javascript:alert(1))|`<script>\x1b[0m"
                "| [link](https://evil.example)"
            ),
        )

        rendered = render_markdown_report(
            run=_complete_scan_run(),
            hosts=[],
            findings=[finding],
            knowledge=KnowledgeBase({}),
            generated_at="2026-11-05T11:00:06Z",
        )

        # ANSI/control sequences never reach the report.
        assert "\x1b" not in rendered
        # No raw HTML and no active Markdown link controlled by the target.
        assert "<script>" not in rendered
        assert "<script>alert" not in rendered
        assert "[x](javascript:alert(1))" not in rendered
        assert "&lt;script&gt;" in rendered
        assert "\\[x\\](javascript:alert(1))" in rendered
        # Backticks are neutralized instead of closing a code span.
        assert "&#96;" in rendered
        # A pipe in a table cell stays inside the cell.
        assert "info\\|injected" in rendered
        for line in rendered.splitlines():
            if line.startswith("| info"):
                assert line.replace("\\|", "").count("|") == 3, line.replace("\\|", "")


class TestGenerateScanReportFromDatabase:
    def test_generate_report_for_run_reads_finding_obs(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "scan_report.db")
        run_id = "01JTESTSCAN0000000000000099"
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="scan.example.com",
                started_at="2026-11-05T12:00:00Z",
                status="complete",
                tool_versions={"nuclei": "v3.11.1"},
            )
            db.upsert_finding(
                conn=conn,
                finding_id="f-db-scan",
                hostname="scan.example.com",
                template_id="tech-detect",
                name="Wappalyzer Technology Detection",
                severity="info",
                matched_at="https://scan.example.com",
                run_id=run_id,
                observed_at="2026-11-05T12:00:01Z",
            )
            db.insert_finding_obs(
                conn=conn,
                run_id=run_id,
                finding_id="f-db-scan",
                evidence="EVIDENCE-YANG-TIDAK-BOLEH-MUNCUL",
                tool="nuclei",
                tool_version="v3.11.1",
                observed_at="2026-11-05T12:00:01Z",
            )

        rendered = generate_report_for_run(
            db,
            run_id=run_id,
            knowledge=load_knowledge_base(),
            generated_at="2026-11-05T12:00:02Z",
        )

        assert "# Laporan Scan DAYSRA" in rendered
        assert "tech-detect" in rendered
        assert "EVIDENCE-YANG-TIDAK-BOLEH-MUNCUL" not in rendered
        assert "| **Total Temuan** | 1 |" in rendered

    def test_recon_run_without_finding_obs_keeps_recon_layout(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "recon_report.db")
        run_id = "01JTESTRECON0000000000000099"
        with db.transaction() as conn:
            db.upsert_run(
                conn=conn,
                run_id=run_id,
                target="recon.example.com",
                started_at="2026-11-05T12:10:00Z",
                status="complete",
                tool_versions={"subfinder": "v2.17.0"},
            )

        rendered = generate_report_for_run(db, run_id=run_id, generated_at="2026-11-05T12:10:01Z")

        assert rendered.startswith("# Laporan Reconnaissance DAYSRA")
        assert "## Temuan" not in rendered
        assert "Template tanpa entri knowledge base" not in rendered
