from __future__ import annotations

import json
import stat
import textwrap
from pathlib import Path

import jsonschema
import pytest
from rich.console import Console

from daysra.cli.recon import run_recon
from daysra.cli.scan import run_scan
from daysra.ingest import Ingestor
from daysra.store.db import Database

SHOW_COMMAND_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schema" / "show-command.v1.json"
)


@pytest.fixture
def show_command_schema() -> dict[str, object]:
    return json.loads(SHOW_COMMAND_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def fake_engine_script(tmp_path: Path) -> Path:
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

        if cmd == "show-command":
            log_path = os.environ.get("DAYSRA_FAKE_SHOW_LOG")
            if log_path:
                with open(log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps({"args": args}) + "\\n")

            kind = args[1] if len(args) > 1 else ""
            if kind == "recon":
                tool = "subfinder"
                argv = [
                    "-d", arg_value("--target").lower().rstrip("."),
                    "-silent", "-oJ", "-cs", "-timeout", "99", "-rl", "7",
                ]
            elif kind == "probe":
                tool = "httpx"
                argv = [
                    "-silent", "-json", "-sc", "-title", "-td", "-cl",
                    "-timeout", "99", "-rl", "7",
                ]
            elif kind == "scan":
                tool = "nuclei"
                argv = [
                    "-j", "-silent", "-nc", "-duc", "-ni", "-timeout", "99",
                    "-s", "info,low", "-tags", "tech",
                    "-etags", "intrusive", "-rl", "7", "-c", "3",
                ]
            else:
                sys.exit(2)

            if os.environ.get("DAYSRA_FAKE_SHOW_MALICIOUS") == "1":
                argv = ["\\x1b[31mred\\x1b[0m", "[/dim]literal", "\\x1b]0;pwn\\x07"]

            print(json.dumps({
                "schema_version": "1",
                "tool": tool,
                "argv": argv,
            }), flush=True)
            sys.exit(0)

        if cmd == "check-scope":
            sys.exit(0)

        if cmd == "recon":
            run_id = arg_value("--run-id")
            emit(run_id, "run_start", "2026-11-07T10:00:00Z", {
                "target": arg_value("--target"),
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
            sys.stdin.read()
            emit(run_id, "run_start", "2026-11-07T10:02:00Z", {
                "tool_versions": {"nuclei": "v3.11.1"},
            })
            emit(run_id, "run_end", "2026-11-07T10:02:01Z", {
                "status": "complete",
                "total_findings": 0,
            })
            sys.exit(0)

        sys.exit(2)
        """
    )
    engine_path.write_text(script_content, encoding="utf-8")
    engine_path.chmod(engine_path.stat().st_mode | stat.S_IEXEC)
    return engine_path


@pytest.fixture
def show_env(
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
    log_path = tmp_path / "show-command.log"
    monkeypatch.setenv("DAYSRA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(fake_engine_script))
    monkeypatch.setenv("DAYSRA_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("DAYSRA_FAKE_SHOW_LOG", str(log_path))
    return scope_file, Database(tmp_path / "data" / "daysra.db"), log_path


def _recording_console() -> Console:
    return Console(record=True, width=300, color_system=None)


def _show_calls(log_path: Path) -> list[list[str]]:
    if not log_path.exists():
        return []
    return [
        json.loads(line)["args"]
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _seed_recon_run(db: Database, target: str = "example.com") -> str:
    from daysra.core.ulid import generate_ulid

    run_id = generate_ulid()
    lines = [
        json.dumps(
            {
                "schema_version": "1",
                "type": "run_start",
                "run_id": run_id,
                "ts": "2026-11-06T10:00:00Z",
                "data": {"target": target, "tool_versions": {"httpx": "v1.12.0"}},
            }
        ),
        json.dumps(
            {
                "schema_version": "1",
                "type": "http",
                "run_id": run_id,
                "ts": "2026-11-06T10:00:01Z",
                "data": {
                    "hostname": "sub1.example.com",
                    "url": "https://sub1.example.com",
                    "status_code": 200,
                    "title": "Site",
                    "tech": ["Nginx"],
                    "content_length": 256,
                },
            }
        ),
        json.dumps(
            {
                "schema_version": "1",
                "type": "run_end",
                "run_id": run_id,
                "ts": "2026-11-06T10:00:02Z",
                "data": {"status": "complete"},
            }
        ),
    ]
    Ingestor(db=db, run_id=run_id).ingest_lines(lines)
    return run_id


class TestShowCommandSchema:
    def test_schema_file_is_valid(self, show_command_schema: dict[str, object]) -> None:
        validator_cls = jsonschema.validators.validator_for(show_command_schema)
        validator_cls.check_schema(show_command_schema)
        assert show_command_schema.get("title") == "DAYSRA show-command v1"

    @pytest.mark.parametrize("tool", ["subfinder", "httpx", "nuclei"])
    def test_valid_payloads_pass_schema(
        self,
        show_command_schema: dict[str, object],
        tool: str,
    ) -> None:
        payload = {
            "schema_version": "1",
            "tool": tool,
            "argv": ["-d", "example.com"],
        }
        jsonschema.validate(instance=payload, schema=show_command_schema)

    def test_schema_rejects_wrong_version_tool_and_empty_argv(
        self,
        show_command_schema: dict[str, object],
    ) -> None:
        broken_payloads = [
            {"schema_version": 1, "tool": "subfinder", "argv": ["-d", "example.com"]},
            {"schema_version": "2", "tool": "subfinder", "argv": ["-d", "example.com"]},
            {"schema_version": "1", "tool": "nmap", "argv": ["-d", "example.com"]},
            {"schema_version": "1", "tool": "subfinder", "argv": []},
            {"schema_version": "1", "tool": "subfinder"},
            {"schema_version": "1", "tool": "subfinder", "argv": ["-d", 1]},
        ]
        for payload in broken_payloads:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(instance=payload, schema=show_command_schema)


class TestReconShowCommand:
    def test_recon_show_command_prints_engine_argv(
        self,
        show_env: tuple[Path, Database, Path],
    ) -> None:
        scope_file, _db, log_path = show_env
        console = _recording_console()

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            show_command=True,
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "Perintah subfinder: subfinder -d example.com" in output
        assert "-timeout 99" in output
        assert "-rl 7" in output
        assert "Perintah httpx: httpx" in output
        assert "-timeout 600" not in output
        assert "-rl 50" not in output

        calls = _show_calls(log_path)
        kinds = [call[1] for call in calls if len(call) > 1]
        assert kinds == ["recon", "probe"]
        recon_call = next(call for call in calls if call[1] == "recon")
        assert "--target" in recon_call
        assert recon_call[recon_call.index("--target") + 1] == "example.com"

    def test_recon_show_command_does_not_change_run_result(
        self,
        show_env: tuple[Path, Database, Path],
    ) -> None:
        scope_file, db, _ = show_env
        console = _recording_console()

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            show_command=True,
            console=console,
        )

        assert exit_code == 0
        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.target == "example.com"
        assert latest_run.status == "complete"
        assert len(db.get_hosts_for_run(latest_run.run_id)) == 2
        assert len(db.get_http_obs_for_run(latest_run.run_id)) == 2

    def test_engine_text_is_sanitized(
        self,
        show_env: tuple[Path, Database, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scope_file, _, _ = show_env
        monkeypatch.setenv("DAYSRA_FAKE_SHOW_MALICIOUS", "1")
        console = _recording_console()

        exit_code = run_recon(
            domain="example.com",
            scope=str(scope_file),
            show_command=True,
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "\x1b" not in output
        assert "Perintah subfinder:" in output
        assert "[/dim]literal" in output


class TestScanShowCommand:
    def test_scan_show_command_prints_full_nuclei_argv(
        self,
        show_env: tuple[Path, Database, Path],
    ) -> None:
        scope_file, db, log_path = show_env
        _seed_recon_run(db)
        console = _recording_console()

        exit_code = run_scan(
            domain="example.com",
            scope=str(scope_file),
            include_tags="tech",
            show_command=True,
            console=console,
        )

        assert exit_code == 0
        output = console.export_text()
        assert "Perintah nuclei: nuclei" in output
        for flag in ["-j", "-silent", "-nc", "-duc", "-ni", "-timeout 99", "-rl 7"]:
            assert flag in output
        assert "-etags intrusive" in output
        assert "-timeout 600" not in output
        assert "-rl 50" not in output

        scan_calls = [call for call in _show_calls(log_path) if call[1] == "scan"]
        assert len(scan_calls) == 1
        call = scan_calls[0]
        assert "--target" in call
        assert call[call.index("--target") + 1] == "example.com"
        assert "--include-tags" in call
        assert call[call.index("--include-tags") + 1] == "tech"

        latest_run = db.get_latest_run()
        assert latest_run is not None
        assert latest_run.status == "complete"
        assert "nuclei" in latest_run.tool_versions

    def test_scan_show_command_does_not_change_exit_code(
        self,
        show_env: tuple[Path, Database, Path],
    ) -> None:
        scope_file, db, _ = show_env
        _seed_recon_run(db)
        console = _recording_console()

        without_flag = run_scan(domain="example.com", scope=str(scope_file), console=console)
        with_flag = run_scan(
            domain="example.com",
            scope=str(scope_file),
            show_command=True,
            console=_recording_console(),
        )

        assert without_flag == 0
        assert with_flag == 0
