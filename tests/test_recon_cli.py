from __future__ import annotations

import json
import stat
import textwrap
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from daysra.cli.app import app
from daysra.cli.recon import run_recon
from daysra.store.db import Database


@pytest.fixture
def fake_engine_script(tmp_path: Path) -> Path:
    """Create a standalone executable Python script acting as a fake daysra-engine."""
    engine_path = tmp_path / "fake-engine"
    script_content = textwrap.dedent("""\
        #!/usr/bin/env python3
        import sys
        import json

        args = sys.argv[1:]
        if not args:
            sys.exit(2)

        cmd = args[0]

        if cmd == "check-scope":
            # parse --target
            target = ""
            for i, arg in enumerate(args):
                if arg == "--target" and i + 1 < len(args):
                    target = args[i + 1]
            if target == "out-of-scope.example.com":
                sys.stderr.write("target is out of scope\\n")
                sys.exit(2)
            if target == "crash.example.com":
                sys.stderr.write("unexpected engine error\\n")
                sys.exit(3)
            if target == "stderr-markup-scope.example.com":
                sys.stderr.write("[/dim] Scope check error\\n")
                sys.exit(3)
            if target == "stderr-ansi-scope.example.com":
                sys.stderr.write(
                    "\\x1b]0;PWNED Scope Window\\x07"
                    "\\x1b]8;;https://evil.com/scope-leak\\x1b\\\\ScopeHyperlinkText\\x1b]8;;\\x1b\\\\ "
                    "\\x1b]52;c;c2NvcGUtdG9rZW4=\\x07 "
                    "\\u202eReversedScopeDiagnostics "
                    "\\x1b[35mMagentaScopeFailure\\x1b[0m\\n"
                )
                sys.exit(3)
            # Default success
            sys.exit(0)

        elif cmd == "recon":
            target = ""
            run_id = ""
            for i, arg in enumerate(args):
                if arg == "--target" and i + 1 < len(args):
                    target = args[i + 1]
                elif arg == "--run-id" and i + 1 < len(args):
                    run_id = args[i + 1]

            if target == "stderr-markup-recon.example.com":
                ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target}}
                print(json.dumps(ev_start), flush=True)
                sys.stderr.write("[/dim] Injected error text\\n[bold red]FATAL SYSTEM FAILURE[/bold red]\\n")
                sys.stderr.flush()
                sys.exit(4)

            if target == "stderr-ansi-recon.example.com":
                ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target}}
                print(json.dumps(ev_start), flush=True)
                sys.stderr.write(
                    "\\x1b]0;PWNED Recon Window\\x07"
                    "\\x1b]8;;https://evil.com/recon-leak\\x1b\\\\ReconHyperlinkText\\x1b]8;;\\x1b\\\\ "
                    "\\x1b]52;c;cmVjb24tdG9rZW4=\\x07 "
                    "\\u202eReversedReconDiagnostics "
                    "\\x1b[31;1mRedReconFailure\\x1b[0m\\n"
                )
                sys.stderr.flush()
                sys.exit(4)

            if target == "fail-recon.example.com":
                # Emit 1 host then fail
                ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target}}
                ev_host = {"schema_version": "1", "type": "host", "run_id": run_id, "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "partial.example.com", "sources": ["fake"]}}
                print(json.dumps(ev_start), flush=True)
                print(json.dumps(ev_host), flush=True)
                sys.stderr.write("recon failed abruptly\\n")
                sys.exit(4)

            if target == "empty.example.com":
                ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target}}
                ev_end = {"schema_version": "1", "type": "run_end", "run_id": run_id, "ts": "2026-11-05T10:00:02Z", "data": {"status": "complete"}}
                print(json.dumps(ev_start), flush=True)
                print(json.dumps(ev_end), flush=True)
                sys.exit(0)

            if target == "large-stderr-recon.example.com":
                ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target}}
                print(json.dumps(ev_start), flush=True)
                # Write ~500 KB to stderr to fill OS pipe buffer (typically 64 KB)
                for i in range(10000):
                    sys.stderr.write(f"[subfinder debug log] Line {i:05d} flooding stderr buffer\\n")
                sys.stderr.flush()
                ev_host = {"schema_version": "1", "type": "host", "run_id": run_id, "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "flood.example.com", "sources": ["fake"]}}
                ev_end = {"schema_version": "1", "type": "run_end", "run_id": run_id, "ts": "2026-11-05T10:00:02Z", "data": {"status": "complete"}}
                print(json.dumps(ev_host), flush=True)
                print(json.dumps(ev_end), flush=True)
                sys.exit(0)

            # Normal success recon
            ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:00:00Z", "data": {"target": target, "tool_versions": {"subfinder": "v2.17.0"}}}
            ev_host1 = {"schema_version": "1", "type": "host", "run_id": run_id, "ts": "2026-11-05T10:00:01Z", "data": {"hostname": "sub1.example.com", "sources": ["fake_src"], "ips": ["192.0.2.1"]}}
            ev_host2 = {"schema_version": "1", "type": "host", "run_id": run_id, "ts": "2026-11-05T10:00:02Z", "data": {"hostname": "sub2.example.com", "sources": ["fake_src"], "ips": ["192.0.2.2"]}}
            ev_end = {"schema_version": "1", "type": "run_end", "run_id": run_id, "ts": "2026-11-05T10:00:03Z", "data": {"status": "complete"}}
            print(json.dumps(ev_start), flush=True)
            print(json.dumps(ev_host1), flush=True)
            print(json.dumps(ev_host2), flush=True)
            print(json.dumps(ev_end), flush=True)
            sys.exit(0)

        elif cmd == "probe":
            run_id = ""
            target = ""
            for i, arg in enumerate(args):
                if arg == "--run-id" and i + 1 < len(args):
                    run_id = args[i + 1]
                elif arg == "--target" and i + 1 < len(args):
                    target = args[i + 1]

            # Read hostnames from stdin
            stdin_hosts = sys.stdin.read().strip().split()

            if target == "fail-probe.example.com":
                sys.stderr.write("probe failed unexpectedly\\n")
                sys.exit(1)

            if target == "stderr-markup-probe.example.com":
                sys.stderr.write("[/dim] Injected probe error\\n[bold red]PROBE CRASH[/bold red]\\n")
                sys.stderr.flush()
                sys.exit(1)

            if target == "stderr-ansi-probe.example.com":
                sys.stderr.write(
                    "\\x1b]0;PWNED Probe Window\\x07"
                    "\\x1b]8;;https://evil.com/probe-leak\\x1b\\\\ProbeHyperlinkText\\x1b]8;;\\x1b\\\\ "
                    "\\x1b]52;c;cHJvYmUtdG9rZW4=\\x07 "
                    "\\u202eReversedProbeDiagnostics "
                    "\\x1b[33mYellowProbeFailure\\x1b[0m\\n"
                )
                sys.stderr.flush()
                sys.exit(1)

            if target == "large-stderr-probe.example.com":
                # Flood stderr in probe stage
                for i in range(10000):
                    sys.stderr.write(f"[httpx debug log] Line {i:05d} flooding stderr buffer\\n")
                sys.stderr.flush()

            ev_start = {"schema_version": "1", "type": "run_start", "run_id": run_id, "ts": "2026-11-05T10:01:00Z", "data": {"tool_versions": {"httpx": "v1.12.0"}}}
            print(json.dumps(ev_start), flush=True)

            for h in stdin_hosts:
                ev_http = {
                    "schema_version": "1",
                    "type": "http",
                    "run_id": run_id,
                    "ts": "2026-11-05T10:01:01Z",
                    "data": {
                        "hostname": h,
                        "url": f"https://{h}:443",
                        "status_code": 200,
                        "title": f"Site {h}",
                        "tech": ["Nginx"],
                        "content_length": 256,
                    },
                }
                print(json.dumps(ev_http), flush=True)

            ev_end = {"schema_version": "1", "type": "run_end", "run_id": run_id, "ts": "2026-11-05T10:01:02Z", "data": {"status": "complete"}}
            print(json.dumps(ev_end), flush=True)
            sys.exit(0)

        sys.exit(2)
    """)
    engine_path.write_text(script_content, encoding="utf-8")
    # Make executable
    engine_path.chmod(engine_path.stat().st_mode | stat.S_IEXEC)
    return engine_path


@pytest.fixture
def test_env(
    tmp_path: Path,
    fake_engine_script: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Database]:
    """Configure completely isolated DAYSRA test environment."""
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        textwrap.dedent("""\
            authorization: "Test authorized domain"
            allow:
              - "*.example.com"
              - "example.com"
            deny:
              - "admin.example.com"
        """),
        encoding="utf-8",
    )

    db_dir = tmp_path / "data"
    monkeypatch.setenv("DAYSRA_HOME", str(db_dir))
    monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(fake_engine_script))
    monkeypatch.setenv("DAYSRA_CONFIG_DIR", str(tmp_path / "config"))

    db = Database(db_dir / "daysra.db")
    return scope_file, db


class TestReconPreflightValidations:
    """Validate preflight checks: configuration permissions, scope file existence, and engine check-scope."""

    def test_missing_scope_file_returns_exit_2(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        console = Console(record=True, color_system=None)
        exit_code = run_recon(
            domain="example.com",
            scope="/non/existent/scope.yaml",
            console=console,
        )
        assert exit_code == 2
        output = console.export_text()
        assert "File scope tidak ditemukan" in output

    def test_invalid_config_permissions_returns_exit_2(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.toml"
        config_file.write_text("invalid_mode = true\n", encoding="utf-8")
        config_file.chmod(0o644)  # Invalid: requires 0600

        console = Console(record=True, color_system=None)
        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            console=console,
        )
        assert exit_code == 2
        output = console.export_text()
        assert "Error konfigurasi" in output
        assert "wajib 0600" in output

    def test_engine_binary_not_found_returns_exit_3(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, _ = test_env
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "/non/existent/engine-bin")

        console = Console(record=True, color_system=None)
        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            console=console,
        )
        assert exit_code == 3
        output = console.export_text()
        assert "Binary 'daysra-engine' tidak ditemukan" in output

    def test_target_out_of_scope_returns_exit_2(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)
        exit_code = run_recon(
            domain="out-of-scope.example.com",
            scope=str(scope_file),
            console=console,
        )
        assert exit_code == 2
        output = console.export_text()
        assert "di luar cakupan izin" in output

    def test_check_scope_engine_error_returns_exit_code(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)
        exit_code = run_recon(
            domain="crash.example.com",
            scope=str(scope_file),
            console=console,
        )
        assert exit_code == 3
        output = console.export_text()
        assert "Error pemeriksaan scope (exit 3)" in output


class TestReconExecutionWithFakeEngine:
    """Validate full reconnaissance and probing workflow using Fake Engine."""

    def test_full_recon_and_probe_success(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "Ringkasan Recon Simple Mode" in output
        assert "Selesai (Complete)" in output

        # Verify SQLite storage
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.target == "example.com"
        assert latest_run.status == "complete"

        hosts = db.get_hosts_for_run(latest_run.run_id)
        assert len(hosts) == 2
        hostnames = [h.hostname for h in hosts]
        assert "sub1.example.com" in hostnames
        assert "sub2.example.com" in hostnames

        http_obs = db.get_http_obs_for_run(latest_run.run_id)
        assert len(http_obs) == 2
        urls = [o.url for o in http_obs]
        assert "https://sub1.example.com:443" in urls
        assert "https://sub2.example.com:443" in urls

    def test_recon_no_probe_flag_skips_httpx(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            no_probe=True,
            console=console,
        )

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None

        # Hosts discovered but no HTTP probing was performed
        assert len(db.get_hosts_for_run(latest_run.run_id)) == 2
        assert len(db.get_http_obs_for_run(latest_run.run_id)) == 0

    def test_recon_no_hosts_found_skips_probe_stage(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="empty.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert len(db.get_hosts_for_run(latest_run.run_id)) == 0
        assert len(db.get_http_obs_for_run(latest_run.run_id)) == 0

    def test_recon_show_command_flag(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            show_command=True,
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "Subfinder tool syntax: subfinder -d example.com" in output
        assert "httpx tool syntax: httpx" in output

    def test_recon_raw_mode_streams_jsonl(
        self,
        test_env: tuple[Path, Database],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            raw=True,
            console=console,
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        lines = [line.strip() for line in captured.out.strip().split("\n") if line.strip()]
        assert len(lines) > 0
        # First event should be run_start
        assert '"type": "run_start"' in lines[0]


class TestReconFailureAndPartialState:
    """Validate partial observation recording and status update on failure."""

    def test_stage1_recon_failure_saves_partial_data(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="fail-recon.example.com",
            scope=str(scope_file),
            console=console,
        )

        # Non-zero exit code returned from engine
        assert exit_code == 4

        # Verify partial data was ingested
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.target == "fail-recon.example.com"
        assert latest_run.status == "partial"

        hosts = db.get_hosts_for_run(latest_run.run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "partial.example.com"

    def test_stage2_probe_failure_marks_run_partial(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="fail-probe.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 1
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"

        # Discovered hosts in stage 1 are preserved
        assert len(db.get_hosts_for_run(latest_run.run_id)) == 2


class TestTyperCliIntegration:
    """Validate Typer CLI commands invocation using CliRunner."""

    def test_cli_recon_command_success(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        runner = CliRunner()

        result = runner.invoke(
            app,
            ["recon", "example.com", "--scope", str(scope_file)],
        )

        assert result.exit_code == 0
        assert "Ringkasan Recon Simple Mode" in result.output
        assert db.get_latest_run() is not None

    def test_cli_recon_missing_arguments_displays_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["recon"])
        assert result.exit_code != 0
        assert "Missing argument 'DOMAIN'" in result.output or "Usage:" in result.output


class TestSubprocessDeadlockAndStderrDrain:
    """Demonstrate and verify protection against subprocess stderr pipe buffer deadlocks."""

    def test_large_stderr_in_recon_does_not_deadlock(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        # Before fix, this would hang indefinitely because the OS pipe buffer (~64 KB) fills up
        exit_code = run_recon(
            domain="large-stderr-recon.example.com",
            scope=str(scope_file),
            no_probe=True,
            console=console,
        )

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "complete"
        hosts = db.get_hosts_for_run(latest_run.run_id)
        assert len(hosts) == 1
        assert hosts[0].hostname == "flood.example.com"

    def test_large_stderr_in_probe_does_not_deadlock(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="large-stderr-probe.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "complete"
        http_obs = db.get_http_obs_for_run(latest_run.run_id)
        assert len(http_obs) == 2


class TestOutputSecuritySubprocessStderr:
    """Validate subprocess stderr output security against Rich markup injection (OUT-05)."""

    def test_out05_recon_stderr_closing_tag_does_not_crash_cli(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-markup-recon.example.com",
            scope=str(scope_file),
            no_probe=True,
            console=console,
        )

        assert exit_code == 4
        output = console.export_text()
        assert "[/dim] Injected error text" in output

    def test_out05_recon_stderr_markup_style_injection_rendered_as_literal_text(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-markup-recon.example.com",
            scope=str(scope_file),
            no_probe=True,
            console=console,
        )

        assert exit_code == 4
        output = console.export_text()
        # Injected formatting markup must not be interpreted as styling; it should be printed as literal plain text
        assert "[bold red]FATAL SYSTEM FAILURE[/bold red]" in output

    def test_out05_probe_stderr_closing_tag_does_not_crash_cli(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-markup-probe.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 1
        output = console.export_text()
        assert "[/dim] Injected probe error" in output

    def test_out05_check_scope_stderr_closing_tag_does_not_crash_cli(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-markup-scope.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 3
        output = console.export_text()
        assert "[/dim] Scope check error" in output

    def test_out05_engine_stderr_ansi_and_osc_sequences_are_neutralized(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-ansi-recon.example.com",
            scope=str(scope_file),
            no_probe=True,
            console=console,
        )

        assert exit_code == 4
        output = console.export_text()

        # Malicious terminal control sequences must not be forwarded
        assert "\x1b]0;" not in output
        assert "\x1b]8;" not in output
        assert "\x1b]52;" not in output
        assert "\u202e" not in output
        assert "\x1b[31" not in output

        # Legitimate diagnostic text must be preserved
        assert "ReconHyperlinkText" in output
        assert "ReversedReconDiagnostics" in output
        assert "RedReconFailure" in output

        # Database state remains valid
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"

    def test_out05_check_scope_stderr_ansi_and_osc_sequences_are_neutralized(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-ansi-scope.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 3
        output = console.export_text()

        # Malicious terminal control sequences must not be forwarded
        assert "\x1b]0;" not in output
        assert "\x1b]8;" not in output
        assert "\x1b]52;" not in output
        assert "\u202e" not in output
        assert "\x1b[35" not in output

        # Legitimate diagnostic text must be preserved
        assert "ScopeHyperlinkText" in output
        assert "ReversedScopeDiagnostics" in output
        assert "MagentaScopeFailure" in output

    def test_out05_probe_stderr_ansi_and_osc_sequences_are_neutralized(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-ansi-probe.example.com",
            scope=str(scope_file),
            no_probe=False,
            console=console,
        )

        assert exit_code == 1
        output = console.export_text()

        # Malicious terminal control sequences must not be forwarded
        assert "\x1b]0;" not in output
        assert "\x1b]8;" not in output
        assert "\x1b]52;" not in output
        assert "\u202e" not in output
        assert "\x1b[33" not in output

        # Legitimate diagnostic text must be preserved
        assert "ProbeHyperlinkText" in output
        assert "ReversedProbeDiagnostics" in output
        assert "YellowProbeFailure" in output

        # Database state remains valid
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"

    def test_out05_raw_mode_recon_failure_stderr_sanitized_and_stdout_intact(
        self,
        test_env: tuple[Path, Database],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-ansi-recon.example.com",
            scope=str(scope_file),
            no_probe=True,
            raw=True,
            console=console,
        )

        assert exit_code == 4
        captured = capsys.readouterr()

        # Diagnostics printed to raw stderr must be sanitized
        assert "Engine recon failed (exit 4):" in captured.err
        assert "\x1b]0;" not in captured.err
        assert "\x1b]8;" not in captured.err
        assert "\x1b]52;" not in captured.err
        assert "\u202e" not in captured.err
        assert "\x1b[31" not in captured.err

        # Legitimate diagnostic text in stderr must be preserved
        assert "ReconHyperlinkText" in captured.err
        assert "ReversedReconDiagnostics" in captured.err
        assert "RedReconFailure" in captured.err

        # Stdout JSONL stream must remain pure, parseable JSON
        stdout_lines = [line.strip() for line in captured.out.strip().split("\n") if line.strip()]
        assert len(stdout_lines) == 1
        event = json.loads(stdout_lines[0])
        assert event["type"] == "run_start"
        assert event["data"]["target"] == "stderr-ansi-recon.example.com"

        # Database state remains valid
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"

    def test_out05_raw_mode_probe_failure_stderr_sanitized_and_stdout_intact(
        self,
        test_env: tuple[Path, Database],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scope_file, db = test_env
        console = Console(record=True, color_system=None)

        exit_code = run_recon(
            domain="stderr-ansi-probe.example.com",
            scope=str(scope_file),
            no_probe=False,
            raw=True,
            console=console,
        )

        assert exit_code == 1
        captured = capsys.readouterr()

        # Diagnostics printed to raw stderr must be sanitized
        assert "Engine probe failed (exit 1):" in captured.err
        assert "\x1b]0;" not in captured.err
        assert "\x1b]8;" not in captured.err
        assert "\x1b]52;" not in captured.err
        assert "\u202e" not in captured.err
        assert "\x1b[33" not in captured.err

        # Legitimate diagnostic text in stderr must be preserved
        assert "ProbeHyperlinkText" in captured.err
        assert "ReversedProbeDiagnostics" in captured.err
        assert "YellowProbeFailure" in captured.err

        # Stdout JSONL stream must contain intact, valid JSON events from recon phase
        stdout_lines = [line.strip() for line in captured.out.strip().split("\n") if line.strip()]
        assert len(stdout_lines) == 4
        parsed_events = [json.loads(line) for line in stdout_lines]
        event_types = [ev["type"] for ev in parsed_events]
        assert event_types == ["run_start", "host", "host", "run_end"]

        # Database state and observations remain valid
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"
        hosts = db.get_hosts_for_run(latest_run.run_id)
        assert len(hosts) == 2
        assert {h.hostname for h in hosts} == {"sub1.example.com", "sub2.example.com"}

