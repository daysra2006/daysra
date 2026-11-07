from __future__ import annotations

import json
import stat
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from typer.testing import CliRunner

import daysra.cli.scan as scan_module
from daysra.cli.app import app
from daysra.cli.scan import run_scan
from daysra.cli.stages import StageResult
from daysra.core.ulid import generate_ulid
from daysra.ingest import Ingestor
from daysra.store.db import Database


@pytest.fixture
def fake_engine_script(tmp_path: Path) -> Path:
    """Create a standalone executable Python script acting as a fake daysra-engine."""
    engine_path = tmp_path / "fake-engine"
    script_content = textwrap.dedent("""\
        #!/usr/bin/env python3
        import json
        import os
        import sys

        args = sys.argv[1:]
        if not args:
            sys.exit(2)
        cmd = args[0]

        log_path = os.environ.get("DAYSRA_FAKE_SCAN_LOG")
        if log_path:
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps({"cmd": cmd, "args": args}) + "\\n")

        def arg_value(name):
            for i, arg in enumerate(args):
                if arg == name and i + 1 < len(args):
                    return args[i + 1]
            return ""

        if cmd == "check-scope":
            target = arg_value("--target")
            if target == "out-of-scope.example.com":
                sys.stderr.write("target is out of scope\\n")
                sys.exit(2)
            sys.exit(0)

        if cmd == "scan":
            run_id = arg_value("--run-id")
            stdin_urls = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
            capture_path = os.environ.get("DAYSRA_FAKE_URLS_OUT")
            if capture_path:
                with open(capture_path, "w", encoding="utf-8") as capture_file:
                    capture_file.write("\\n".join(stdin_urls))

            mode = os.environ.get("DAYSRA_FAKE_SCAN_MODE", "success")

            def emit(payload):
                print(json.dumps(payload), flush=True)

            emit({
                "schema_version": "1",
                "type": "run_start",
                "run_id": run_id,
                "ts": "2026-11-07T10:00:00Z",
                "data": {"tool_versions": {"nuclei": "v3.11.1"}},
            })

            if mode == "fail":
                sys.stderr.write("scan failed abruptly\\n")
                sys.exit(4)

            findings = json.loads(os.environ.get("DAYSRA_FAKE_FINDINGS", "[]"))
            for finding in findings:
                emit({
                    "schema_version": "1",
                    "type": "finding",
                    "run_id": run_id,
                    "ts": "2026-11-07T10:00:01Z",
                    "data": finding,
                })

            if mode == "partial":
                emit({
                    "schema_version": "1",
                    "type": "run_end",
                    "run_id": run_id,
                    "ts": "2026-11-07T10:00:02Z",
                    "data": {"status": "partial"},
                })
                sys.exit(4)

            emit({
                "schema_version": "1",
                "type": "run_end",
                "run_id": run_id,
                "ts": "2026-11-07T10:00:02Z",
                "data": {"status": "complete"},
            })
            sys.exit(0)

        sys.exit(2)
    """)
    engine_path.write_text(script_content, encoding="utf-8")
    engine_path.chmod(engine_path.stat().st_mode | stat.S_IEXEC)
    return engine_path


@pytest.fixture
def test_env(
    tmp_path: Path,
    fake_engine_script: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Database]:
    """Configure a fully isolated DAYSRA test environment."""
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
    monkeypatch.setenv("DAYSRA_FAKE_SCAN_LOG", str(tmp_path / "engine-calls.jsonl"))

    db = Database(db_dir / "daysra.db")
    return scope_file, db


def _recording_console() -> Console:
    return Console(record=True, width=200, color_system=None)


def _seed_recon_run(
    db: Database,
    *,
    target: str = "example.com",
    status: str = "complete",
    urls: list[str] | None = None,
) -> str:
    """Insert a recon run with HTTP observations into SQLite via the Ingestor."""
    run_id = generate_ulid()
    urls = urls or ["https://sub1.example.com/vuln", "https://sub2.example.com/vuln"]

    lines = [
        json.dumps(
            {
                "schema_version": "1",
                "type": "run_start",
                "run_id": run_id,
                "ts": "2026-11-05T10:00:00Z",
                "data": {"target": target, "tool_versions": {"httpx": "v1.12.0"}},
            }
        )
    ]
    for url in urls:
        hostname = url.split("//", 1)[1].split("/", 1)[0]
        lines.append(
            json.dumps(
                {
                    "schema_version": "1",
                    "type": "http",
                    "run_id": run_id,
                    "ts": "2026-11-05T10:00:01Z",
                    "data": {
                        "hostname": hostname,
                        "url": url,
                        "status_code": 200,
                        "title": f"Site {hostname}",
                        "tech": ["Nginx"],
                        "content_length": 256,
                    },
                }
            )
        )
    lines.append(
        json.dumps(
            {
                "schema_version": "1",
                "type": "run_end",
                "run_id": run_id,
                "ts": "2026-11-05T10:00:02Z",
                "data": {"status": status},
            }
        )
    )
    Ingestor(db=db, run_id=run_id).ingest_lines(lines)
    return run_id


def _finding(
    *,
    finding_id: str,
    template_id: str,
    name: str,
    severity: str,
    matched_at: str = "https://sub1.example.com/vuln",
    hostname: str = "sub1.example.com",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "template_id": template_id,
        "name": name,
        "severity": severity,
        "cve": [],
        "matched_at": matched_at,
        "evidence": "",
        "tool": "nuclei",
        "tool_version": "v3.11.1",
        "hostname": hostname,
    }


def _read_engine_calls(tmp_path: Path) -> list[dict[str, Any]]:
    log_path = tmp_path / "engine-calls.jsonl"
    if not log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _scan_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [call for call in calls if call["cmd"] == "scan"]


def _include_tags(args: list[str]) -> str | None:
    for i, arg in enumerate(args):
        if arg == "--include-tags" and i + 1 < len(args):
            return args[i + 1]
    return None


class _FakeStdin:
    def __init__(self, *, tty: bool, answer: str = "") -> None:
        self._tty = tty
        self._answer = answer

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        if not self._tty:
            raise AssertionError("readline must not be called when stdin is not a TTY")
        return self._answer


class TestScanExecution:
    def test_success_renders_findings_in_severity_order(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)

        findings = [
            _finding(finding_id="f-info-b", template_id="t-info-b", name="Info B", severity="info"),
            _finding(
                finding_id="f-critical",
                template_id="t-critical",
                name="Critical",
                severity="critical",
            ),
            _finding(finding_id="f-low", template_id="t-low", name="Low", severity="low"),
            _finding(finding_id="f-medium", template_id="t-medium", name="Medium", severity="medium"),
            _finding(finding_id="f-high", template_id="t-high", name="High", severity="high"),
            _finding(finding_id="f-info-a", template_id="t-info-a", name="Info A", severity="info"),
        ]
        monkeypatch.setenv("DAYSRA_FAKE_FINDINGS", json.dumps(findings))
        capture_path = tmp_path / "urls.txt"
        monkeypatch.setenv("DAYSRA_FAKE_URLS_OUT", str(capture_path))

        console = _recording_console()
        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 0
        output = console.export_text()
        assert "Ringkasan Scan" in output

        order = [
            output.index("t-critical"),
            output.index("t-high"),
            output.index("t-medium"),
            output.index("t-low"),
            output.index("t-info-a"),
            output.index("t-info-b"),
        ]
        assert order == sorted(order)

        captured_urls = capture_path.read_text(encoding="utf-8").splitlines()
        assert captured_urls == [
            "https://sub1.example.com/vuln",
            "https://sub2.example.com/vuln",
        ]

        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "complete"
        stored = db.get_findings_for_run_by_severity(latest_run.run_id)
        assert [finding.template_id for finding in stored] == [
            "t-critical",
            "t-high",
            "t-medium",
            "t-low",
            "t-info-a",
            "t-info-b",
        ]

    def test_no_live_hosts_skips_engine_and_returns_nonzero(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code != 0
        output = console.export_text()
        assert "daysra recon example.com" in output
        assert _scan_calls(_read_engine_calls(tmp_path)) == []

    def test_out_of_scope_domain_rejected_before_scan(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = _recording_console()

        exit_code = run_scan(
            domain="out-of-scope.example.com", scope=str(scope_file), console=console
        )

        assert exit_code == 2
        assert "di luar cakupan izin" in console.export_text()
        calls = _read_engine_calls(tmp_path)
        assert [call["cmd"] for call in calls] == ["check-scope"]

    def test_from_run_selects_the_requested_source_run(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        first_run = _seed_recon_run(db, urls=["https://sub1.example.com/vuln"])
        _seed_recon_run(db, urls=["https://sub2.example.com/vuln"])
        capture_path = tmp_path / "urls.txt"
        monkeypatch.setenv("DAYSRA_FAKE_URLS_OUT", str(capture_path))

        console = _recording_console()
        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            from_run=first_run,
            console=console,
        )

        assert exit_code == 0
        assert first_run in console.export_text()
        assert capture_path.read_text(encoding="utf-8").splitlines() == [
            "https://sub1.example.com/vuln"
        ]

    def test_raw_mode_keeps_stdout_as_pure_jsonl(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-raw",
                        template_id="t-raw",
                        name="Raw finding",
                        severity="low",
                    )
                ]
            ),
        )

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            raw=True,
            console=None,
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        stdout_lines = [line for line in captured.out.splitlines() if line.strip()]
        assert stdout_lines
        for line in stdout_lines:
            json.loads(line)
        assert "Run sumber:" in captured.err

    def test_partial_source_run_prints_warning(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db, status="partial")
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 0
        output = console.export_text()
        assert "Peringatan" in output
        assert "partial" in output


class TestScanDefaultLogin:
    def test_non_tty_drops_default_login_with_warning(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=False))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="tech,default-login",
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "default-login" in output
        assert "Peringatan" in output
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == "tech"

    def test_exact_confirmation_word_passes_default_login(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=True, answer="default-login\n"))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="default-login",
            console=console,
        )

        assert exit_code == 0
        assert "Ketik 'default-login'" in console.export_text()
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == "default-login"

    def test_accept_flag_passes_default_login_without_prompt(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=False))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="default-login",
            accept_default_login=True,
            console=console,
        )

        assert exit_code == 0
        assert "Ketik 'default-login'" not in console.export_text()
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == "default-login"

    def test_wrong_confirmation_word_drops_default_login(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=True, answer="yes\n"))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="default-login",
            console=console,
        )

        assert exit_code == 0
        assert "Peringatan" in console.export_text()
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) is None


class TestScanFailureState:
    def test_engine_partial_marks_run_partial_and_returns_exit_code(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv("DAYSRA_FAKE_SCAN_MODE", "partial")
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-partial",
                        template_id="t-partial",
                        name="Partial finding",
                        severity="medium",
                    )
                ]
            ),
        )
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 4
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "partial"
        assert len(db.get_findings_for_run_by_severity(latest_run.run_id)) == 1

    def test_cancelled_stage_marks_run_cancelled_and_returns_130(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)

        def fake_run_stage(command: list[str], **kwargs: object) -> StageResult:
            run_id = command[command.index("--run-id") + 1]
            run_start = json.dumps(
                {
                    "schema_version": "1",
                    "type": "run_start",
                    "run_id": run_id,
                    "ts": "2026-11-07T10:00:00Z",
                    "data": {"tool_versions": {"nuclei": "v3.11.1"}},
                }
            )
            return StageResult(
                exit_code=130,
                cancelled=True,
                has_run_end=False,
                stderr_history=(),
                lines=(run_start,),
            )

        monkeypatch.setattr(scan_module, "run_stage", fake_run_stage)
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 130
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "cancelled"


class TestScanTargetPersistence:
    def test_scan_run_stores_and_renders_normalized_target(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db, target="example.com")
        console = _recording_console()

        exit_code = run_scan(domain="Example.COM.", scope=str(scope_file), console=console)

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.target == "example.com"
        output = console.export_text()
        assert "Target:" in output
        assert "example.com" in output
        assert "Target:  -" not in output

    def test_from_run_matching_uses_the_same_target_normalization(
        self,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        source_run = _seed_recon_run(db, target="example.com")
        console = _recording_console()

        exit_code = run_scan(
            domain="Example.COM.",
            scope=str(scope_file),
            from_run=source_run,
            console=console,
        )

        assert exit_code == 0
        assert "tidak cocok" not in console.export_text()


class TestScanFromRunValidation:
    def test_from_run_with_different_target_is_rejected_before_scan(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        source_run = _seed_recon_run(db, target="other.example.com")
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            from_run=source_run,
            console=console,
        )

        assert exit_code != 0
        output = console.export_text()
        assert "tidak cocok" in output
        assert "other.example.com" in output
        assert _scan_calls(_read_engine_calls(tmp_path)) == []

    def test_from_run_that_does_not_exist_is_rejected_before_scan(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, _ = test_env
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            from_run="01MISSINGRUN00000000000000",
            console=console,
        )

        assert exit_code != 0
        assert "tidak ditemukan" in console.export_text()
        assert _scan_calls(_read_engine_calls(tmp_path)) == []


class TestDefaultLoginVariants:
    @pytest.mark.parametrize(
        ("include_tags", "expected"),
        [
            ("default-login", None),
            ("Default-Login", None),
            (" default-login ", None),
            ("tech, default-login", "tech"),
            ("tech,DEFAULT-LOGIN,exposure", "tech,exposure"),
            ("default-login,default-login", None),
            (["tech", "default-login"], "tech"),
            ("default-logins", "default-logins"),
        ],
    )
    def test_non_tty_drops_every_default_login_variant(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
        include_tags: str | list[str],
        expected: str | None,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=False))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags=include_tags,
            console=console,
        )

        assert exit_code == 0
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == expected

    @pytest.mark.parametrize(
        ("answer", "expected"),
        [
            ("default-login\n", "default-login"),
            ("  default-login  \n", "default-login"),
            ("Default-Login\n", None),
            ("DEFAULT-LOGIN\n", None),
            ("default-login extra\n", None),
        ],
    )
    def test_interactive_confirmation_requires_the_exact_word(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
        answer: str,
        expected: str | None,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=True, answer=answer))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="default-login",
            console=console,
        )

        assert exit_code == 0
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == expected

    def test_accept_flag_keeps_every_variant(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=False))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="tech,DEFAULT-LOGIN,exposure",
            accept_default_login=True,
            console=console,
        )

        assert exit_code == 0
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == "tech,DEFAULT-LOGIN,exposure"

    def test_repeated_cli_options_are_combined(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--scope",
                str(scope_file),
                "--include-tags",
                "tech",
                "--include-tags",
                "default-login",
                "--accept-default-login",
            ],
        )

        assert result.exit_code == 0
        scan_call = _scan_calls(_read_engine_calls(tmp_path))[0]
        assert _include_tags(scan_call["args"]) == "tech,default-login"

    def test_warning_does_not_echo_unsanitized_user_input(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(tty=False))
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="default-login,\x1b[31m[bold red]evil",
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "\x1b[31m" not in output
        assert "[bold red]evil" not in output


class TestScanOutputSecurity:
    def test_ansi_and_rich_markup_in_findings_are_not_rendered(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-evil",
                        template_id="t-evil",
                        name="\x1b[31m[bold red]Evil Name[/bold red]\x1b[0m",
                        severity="high",
                        matched_at="https://sub1.example.com/\x1b[32m[link]x[/link]",
                    )
                ]
            ),
        )
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 0
        output = console.export_text()
        assert "\x1b[31m" not in output
        assert "\x1b[32m" not in output
        assert "[bold red]Evil Name[/bold red]" in output
        assert "[link]x[/link]" in output


class TestScanKnowledgePreflight:
    def test_invalid_knowledge_base_blocks_every_engine_call(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        knowledge_dir = tmp_path / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "broken.yaml").write_text(
            "template_id: [unclosed\n", encoding="utf-8"
        )
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            knowledge_dir=knowledge_dir,
            console=console,
        )

        assert exit_code != 0
        output = console.export_text()
        assert "Error knowledge base" in output
        assert "broken.yaml" in output
        assert _read_engine_calls(tmp_path) == []

    def test_missing_knowledge_directory_uses_generic_fallback(
        self,
        tmp_path: Path,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-fallback",
                        template_id="t-without-entry",
                        name="Temuan Tanpa Entri",
                        severity="low",
                    )
                ]
            ),
        )
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            knowledge_dir=tmp_path / "absent-knowledge",
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "[fallback generik]" in output
        assert "Apa ini:" in output


class TestScanKnowledgeIntegration:
    def test_scan_renders_knowledge_block_for_known_template(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-swagger",
                        template_id="swagger-api",
                        name="Public Swagger API - Detect",
                        severity="info",
                    )
                ]
            ),
        )
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 0
        output = console.export_text()
        assert "Apa ini:" in output
        assert "Dokumentasi API publik dapat diakses" in output
        assert "[fallback generik]" not in output

    def test_scan_groups_findings_with_the_same_template_id(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-swagger-a",
                        template_id="swagger-api",
                        name="Public Swagger API - Detect",
                        severity="info",
                        matched_at="https://sub1.example.com/api-docs",
                    ),
                    _finding(
                        finding_id="f-swagger-b",
                        template_id="swagger-api",
                        name="Public Swagger API - Detect",
                        severity="info",
                        matched_at="https://sub2.example.com/api-docs",
                    ),
                ]
            ),
        )
        console = _recording_console()

        exit_code = run_scan(domain="example.com", scope=str(scope_file), console=console)

        assert exit_code == 0
        output = console.export_text()
        assert output.count("Penjelasan: swagger-api") == 1
        assert "https://sub1.example.com/api-docs" in output
        assert "https://sub2.example.com/api-docs" in output

    def test_raw_mode_omits_explanation_blocks(
        self,
        test_env: tuple[Path, Database],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scope_file, db = test_env
        _seed_recon_run(db)
        monkeypatch.setenv(
            "DAYSRA_FAKE_FINDINGS",
            json.dumps(
                [
                    _finding(
                        finding_id="f-raw-knowledge",
                        template_id="swagger-api",
                        name="Public Swagger API - Detect",
                        severity="info",
                    )
                ]
            ),
        )

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            raw=True,
            console=None,
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Apa ini" not in captured.out
        assert "Apa ini" not in captured.err
        for line in captured.out.splitlines():
            if line.strip():
                json.loads(line)
