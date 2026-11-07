from __future__ import annotations

import stat
import textwrap
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from daysra.cli.app import app
from daysra.cli.recon import run_recon
from daysra.cli.scan import run_scan
from daysra.store.db import Database

EVIDENCE_MARKER = "EVIDENCE-SECRET-abc123"


@pytest.fixture
def fake_engine_script(tmp_path: Path) -> Path:
    """Create a fake daysra-engine covering check-scope, recon, probe, and scan."""
    engine_path = tmp_path / "fake-engine"
    script_content = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import json
        import os
        import sys

        args = sys.argv[1:]
        if not args:
            sys.exit(2)
        cmd = args[0]

        def arg_value(name):
            for i, arg in enumerate(args):
                if arg == name and i + 1 < len(args):
                    return args[i + 1]
            return ""

        def emit(run_id, event_type, ts, data):
            print(json.dumps({
                "schema_version": "1",
                "type": event_type,
                "run_id": run_id,
                "ts": ts,
                "data": data,
            }), flush=True)

        if cmd == "check-scope":
            sys.exit(0)

        if cmd == "recon":
            target = arg_value("--target")
            run_id = arg_value("--run-id")
            emit(run_id, "run_start", "2026-11-07T10:00:00Z", {
                "target": target,
                "tool_versions": {"subfinder": "v2.17.0"},
            })
            emit(run_id, "host", "2026-11-07T10:00:01Z", {
                "hostname": "sub1.example.com",
                "sources": ["fake_src"],
                "ips": ["192.0.2.1"],
            })
            emit(run_id, "host", "2026-11-07T10:00:02Z", {
                "hostname": "sub2.example.com",
                "sources": ["fake_src"],
                "ips": ["192.0.2.2"],
            })
            emit(run_id, "run_end", "2026-11-07T10:00:03Z", {
                "status": "complete",
                "total_hosts": 2,
            })
            sys.exit(0)

        if cmd == "probe":
            run_id = arg_value("--run-id")
            hosts = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
            emit(run_id, "run_start", "2026-11-07T10:01:00Z", {
                "tool_versions": {"httpx": "v1.12.0"},
            })
            for host in hosts:
                emit(run_id, "http", "2026-11-07T10:01:01Z", {
                    "hostname": host,
                    "url": f"https://{host}",
                    "status_code": 200,
                    "title": f"Site {host}",
                    "tech": ["Nginx"],
                    "content_length": 256,
                })
            emit(run_id, "run_end", "2026-11-07T10:01:02Z", {
                "status": "complete",
                "total_http": len(hosts),
            })
            sys.exit(0)

        if cmd == "scan":
            run_id = arg_value("--run-id")
            urls = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
            capture_path = os.environ.get("DAYSRA_FAKE_URLS_OUT")
            if capture_path:
                with open(capture_path, "w", encoding="utf-8") as capture_file:
                    capture_file.write("\\n".join(urls))

            emit(run_id, "run_start", "2026-11-07T10:02:00Z", {
                "tool_versions": {"nuclei": "v3.11.1"},
            })

            finding_info = {
                "id": "finding-swagger",
                "template_id": "swagger-api",
                "name": "Public Swagger API - Detect",
                "severity": "info",
                "cve": [],
                "matched_at": "https://sub1.example.com/swagger.json",
                "evidence": "EVIDENCE-SECRET-abc123",
                "tool": "nuclei",
                "tool_version": "v3.11.1",
                "hostname": "sub1.example.com",
            }
            finding_medium = {
                "id": "finding-metrics",
                "template_id": "prometheus-metrics",
                "name": "Prometheus Metrics - Detect",
                "severity": "medium",
                "cve": ["CVE-2026-0001"],
                "matched_at": "https://sub2.example.com/metrics",
                "evidence": "EVIDENCE-SECRET-abc123",
                "tool": "nuclei",
                "tool_version": "v3.11.1",
                "hostname": "sub2.example.com",
            }

            # The same finding id is emitted twice to prove deduplication.
            emit(run_id, "finding", "2026-11-07T10:02:01Z", finding_info)
            emit(run_id, "finding", "2026-11-07T10:02:02Z", finding_info)
            emit(run_id, "finding", "2026-11-07T10:02:03Z", finding_medium)

            emit(run_id, "run_end", "2026-11-07T10:02:04Z", {
                "status": "complete",
                "total_findings": 2,
            })
            sys.exit(0)

        sys.exit(2)
        """
    )
    engine_path.write_text(script_content, encoding="utf-8")
    engine_path.chmod(engine_path.stat().st_mode | stat.S_IEXEC)
    return engine_path


@pytest.fixture
def lifecycle_env(
    tmp_path: Path,
    fake_engine_script: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Database, Path]:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        textwrap.dedent(
            """\
            authorization: "Test authorized domain"
            allow:
              - "example.com"
              - "*.example.com"
            """
        ),
        encoding="utf-8",
    )

    urls_out = tmp_path / "scan-urls.txt"
    monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(fake_engine_script))
    monkeypatch.setenv("DAYSRA_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("DAYSRA_FAKE_URLS_OUT", str(urls_out))

    return scope_file, Database(tmp_path / "data" / "daysra.db"), urls_out


def _recording_console() -> Console:
    return Console(record=True, width=200, color_system=None)


def _run_count(db: Database) -> int:
    conn = db.connect()
    try:
        row = conn.execute("SELECT COUNT(*) AS total FROM runs").fetchone()
    finally:
        conn.close()
    assert row is not None
    return int(row["total"])


def _fetch_evidence(db: Database, run_id: str) -> list[str]:
    return [
        obs.evidence or ""
        for obs in db.get_finding_obs_for_run(run_id)
    ]


class TestFullReconScanReportLifecycle:
    def test_recon_then_scan_then_report_with_fake_engine(
        self,
        lifecycle_env: tuple[Path, Database, Path],
    ) -> None:
        scope_file, db, urls_out = lifecycle_env

        # 1. Recon (subfinder) followed by probe (httpx) under one run.
        recon_console = _recording_console()
        recon_exit = run_recon(
            domain="example.com",
            scope=str(scope_file),
            console=recon_console,
        )
        assert recon_exit == 0

        recon_run = db.get_latest_run()
        assert recon_run is not None
        assert recon_run.target == "example.com"
        assert recon_run.status == "complete"
        assert len(db.get_http_obs_for_run(recon_run.run_id)) == 2

        # 2. Scan automatically uses the latest recon run's live URLs.
        scan_console = _recording_console()
        scan_exit = run_scan(
            domain="example.com",
            scope=str(scope_file),
            console=scan_console,
        )
        assert scan_exit == 0

        scan_run = db.get_latest_run()
        assert scan_run is not None
        assert scan_run.run_id != recon_run.run_id
        assert scan_run.target == "example.com"
        assert scan_run.status == "complete"
        assert "nuclei" in scan_run.tool_versions

        captured_urls = sorted(
            line for line in urls_out.read_text(encoding="utf-8").splitlines() if line
        )
        assert captured_urls == [
            "https://sub1.example.com",
            "https://sub2.example.com",
        ]

        # 3. Two runs, both with the same target, and findings deduplicated.
        assert _run_count(db) == 2
        findings = db.get_all_findings()
        assert len(findings) == 2
        assert sorted(finding.template_id for finding in findings) == [
            "prometheus-metrics",
            "swagger-api",
        ]
        findings_for_run = db.get_findings_for_run_by_severity(scan_run.run_id)
        assert len(findings_for_run) == 2
        # Duplicate evidence observations are retained, the finding row is not.
        assert len(_fetch_evidence(db, scan_run.run_id)) == 3

        # 4. Evidence never reaches terminal output.
        recon_output = recon_console.export_text()
        scan_output = scan_console.export_text()
        assert EVIDENCE_MARKER not in recon_output
        assert EVIDENCE_MARKER not in scan_output
        assert EVIDENCE_MARKER in _fetch_evidence(db, scan_run.run_id)

        # 5. Report is a scan report and contains the findings, without evidence.
        result = CliRunner().invoke(
            app,
            ["report", "--run", scan_run.run_id],
        )
        assert result.exit_code == 0
        assert result.stdout.startswith("# Laporan Scan DAYSRA")
        assert "## Temuan" in result.stdout
        assert "| **Total Temuan** | 2 |" in result.stdout
        assert "| medium | 1 |" in result.stdout
        assert "| info | 1 |" in result.stdout
        assert "`swagger-api`" in result.stdout
        assert "`prometheus-metrics`" in result.stdout
        assert "CVE-2026-0001" in result.stdout
        assert EVIDENCE_MARKER not in result.stdout
        assert EVIDENCE_MARKER not in result.stderr
        assert f"Jenis run: scan | Run ID: {scan_run.run_id}" in result.stderr
