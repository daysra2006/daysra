from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from daysra.cli.stages import report_stage_failure, run_stage
from daysra.core.config import find_engine_binary, validate_config_permissions
from daysra.core.contracts import Event
from daysra.core.sanitizer import sanitize_terminal_text
from daysra.core.ulid import generate_ulid
from daysra.ingest import Ingestor
from daysra.simple.summary import render_scan_summary
from daysra.store.db import Database, get_db_path

DEFAULT_LOGIN_TAG = "default-login"


def _parse_include_tags(raw_tags: str | Iterable[str] | None) -> list[str]:
    """Normalize --include-tags values, including repeated options.

    Every value is split on commas, each element is trimmed, empty elements are
    ignored, and repeated options are combined in the order given.
    """
    if raw_tags is None:
        return []
    raw_values = [raw_tags] if isinstance(raw_tags, str) else list(raw_tags)
    tags: list[str] = []
    for raw_value in raw_values:
        for raw_tag in str(raw_value).split(","):
            tag = raw_tag.strip()
            if tag:
                tags.append(tag)
    return tags


def _normalize_target(domain: str) -> str:
    """Normalize a target the way recon stores it (trim, lowercase, no trailing dot).

    The Go engine additionally converts IDN labels to punycode. Python's built-in
    IDNA codec is used as a best-effort fallback so the common ASCII case matches
    exactly; invalid values are left to the engine's fail-closed preflight.
    """
    candidate = domain.strip().lower().removesuffix(".")
    if not candidate:
        return candidate
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return candidate


def _contains_default_login(tags: list[str]) -> bool:
    return any(tag.lower() == DEFAULT_LOGIN_TAG for tag in tags)


def _drop_default_login(tags: list[str]) -> list[str]:
    return [tag for tag in tags if tag.lower() != DEFAULT_LOGIN_TAG]


def _resolve_default_login_tags(
    tags: list[str],
    *,
    accept_default_login: bool,
    console: Console,
) -> list[str]:
    """Gate the default-login tag behind an explicit, interactive confirmation.

    The tag is kept when --accept-default-login is set or when the user types
    exactly ``default-login`` on a TTY. Otherwise it is dropped with a warning,
    and the scan continues without it.
    """
    if not _contains_default_login(tags):
        return tags

    if accept_default_login:
        return tags

    if not sys.stdin.isatty():
        console.print(
            "[bold yellow]Peringatan:[/bold yellow] Tag 'default-login' dibuang karena "
            "--accept-default-login tidak diberikan dan stdin bukan TTY."
        )
        return _drop_default_login(tags)

    console.print(
        "[yellow]Tag 'default-login' mencoba kredensial default. "
        "Ketik 'default-login' untuk melanjutkan; teks lain akan membuang tag ini.[/yellow]"
    )
    try:
        answer = sys.stdin.readline()
    except OSError:
        answer = ""

    if answer.strip() == DEFAULT_LOGIN_TAG:
        return tags

    console.print(
        "[bold yellow]Peringatan:[/bold yellow] Konfirmasi default-login tidak cocok; "
        "tag 'default-login' dibuang."
    )
    return _drop_default_login(tags)


def _report_scope_error(
    console: Console,
    domain: str,
    scope_path: Path,
    check_res: subprocess.CompletedProcess[str],
) -> int:
    if check_res.returncode == 2:
        console.print(
            f"[bold red]Error scope (exit 2):[/bold red] Target "
            f"'{escape(sanitize_terminal_text(domain))}' di luar cakupan izin "
            f"{escape(scope_path.name)}"
        )
        if check_res.stderr.strip():
            console.print(Text(sanitize_terminal_text(check_res.stderr.strip()), style="dim"))
        return 2
    scope_err = Text(
        f"Error pemeriksaan scope (exit {check_res.returncode}): ", style="bold red"
    )
    scope_err.append(Text(sanitize_terminal_text(check_res.stderr.strip()), style="dim"))
    console.print(scope_err)
    return check_res.returncode


def run_scan(
    domain: str,
    scope: str = "scope.yaml",
    include_tags: str | Iterable[str] | None = None,
    accept_default_login: bool = False,
    from_run: str | None = None,
    raw: bool = False,
    show_command: bool = False,
    console: Console | None = None,
) -> int:
    """Scan live HTTP URLs for a domain with Nuclei via the Go engine."""
    if console is None:
        # In --raw mode stdout is reserved for the JSONL event stream.
        console = Console(stderr=raw)

    # 1. Check config file permissions if config exists
    valid_perm, perm_msg = validate_config_permissions()
    if not valid_perm:
        console.print(f"[bold red]Error konfigurasi:[/bold red] {perm_msg}")
        return 2

    # 2. Validate scope file exists
    scope_path = Path(scope).resolve()
    if not scope_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File scope tidak ditemukan: {scope_path}")
        return 2

    # 3. Locate daysra-engine binary
    engine_bin = find_engine_binary()
    if engine_bin is None:
        console.print(
            "[bold red]Error:[/bold red] Binary 'daysra-engine' tidak ditemukan.\n"
            "Jalankan 'daysra doctor' untuk memeriksa status instalasi dan kompilasi engine."
        )
        return 3

    # 4. Preflight scope check via engine (Go is sole scope implementation)
    check_scope_cmd = [
        str(engine_bin),
        "check-scope",
        "--scope",
        str(scope_path),
        "--target",
        domain,
    ]
    try:
        check_res = subprocess.run(
            check_scope_cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as err:
        console.print(f"[bold red]Error menjalankan daysra-engine:[/bold red] {err}")
        return 3

    if check_res.returncode != 0:
        return _report_scope_error(console, domain, scope_path, check_res)

    # 5. Select the source run and its live HTTP URLs from SQLite
    db = Database(get_db_path())
    normalized_target = _normalize_target(domain)

    if from_run:
        source_run = db.get_run(from_run)
        if source_run is None:
            console.print(
                f"[bold red]Error:[/bold red] Run sumber "
                f"'{escape(sanitize_terminal_text(from_run))}' tidak ditemukan."
            )
            return 1
        if _normalize_target(source_run.target) != normalized_target:
            console.print(
                f"[bold red]Error:[/bold red] Run sumber "
                f"'{escape(sanitize_terminal_text(from_run))}' memiliki target "
                f"'{escape(sanitize_terminal_text(source_run.target))}' yang tidak cocok "
                f"dengan domain '{escape(sanitize_terminal_text(domain))}'."
            )
            return 1
    else:
        source_run = db.get_latest_run_with_http_for_target(normalized_target)

    if source_run is None:
        console.print(
            f"[bold red]Error:[/bold red] Tidak ada host hidup untuk "
            f"'{escape(sanitize_terminal_text(domain))}'. "
            f"Jalankan 'daysra recon {escape(sanitize_terminal_text(domain))}' "
            "terlebih dahulu."
        )
        return 1

    http_obs = db.get_http_obs_for_run(source_run.run_id)
    if not http_obs:
        console.print(
            f"[bold red]Error:[/bold red] Tidak ada host hidup untuk "
            f"'{escape(sanitize_terminal_text(domain))}'. "
            f"Jalankan 'daysra recon {escape(sanitize_terminal_text(domain))}' terlebih dahulu."
        )
        return 1

    urls = [obs.url for obs in http_obs]

    console.print(
        "[dim]Run sumber:[/dim] "
        f"{escape(sanitize_terminal_text(source_run.run_id))} "
        f"({escape(sanitize_terminal_text(source_run.status))})"
    )
    if source_run.status != "complete":
        console.print(
            "[bold yellow]Peringatan:[/bold yellow] Run sumber berstatus "
            f"{escape(sanitize_terminal_text(source_run.status))}; "
            "URL yang dipakai mungkin tidak lengkap."
        )

    # 6. Resolve the default-login tag with explicit confirmation
    requested_tags = _parse_include_tags(include_tags)
    approved_tags = _resolve_default_login_tags(
        requested_tags,
        accept_default_login=accept_default_login,
        console=console,
    )

    # 7. Generate a new run ID for the scan run
    run_id = generate_ulid()
    scan_cmd = [
        str(engine_bin),
        "scan",
        "--scope",
        str(scope_path),
        "--run-id",
        run_id,
    ]
    if approved_tags:
        scan_cmd.extend(["--include-tags", ",".join(approved_tags)])

    if show_command:
        console.print(f"[dim]Engine command (scan):[/dim] {escape(' '.join(scan_cmd))}")

    finding_events = 0

    def handle_scan_event(ev: Event) -> None:
        nonlocal finding_events
        # Progress only counts events: matched_at and evidence never leave the stage.
        if ev.type == "finding":
            finding_events += 1

    scan_stage = run_stage(
        scan_cmd,
        stage_name="scan",
        initial_description=(
            f"[1/1] Menjalankan scan (Nuclei) untuk "
            f"{escape(sanitize_terminal_text(domain))}..."
        ),
        update_description=lambda: f"[1/1] Diterima {finding_events} event temuan...",
        on_event=handle_scan_event,
        console=console,
        raw=raw,
        stdin_payload="\n".join(urls) + "\n",
    )

    if scan_stage.spawn_failed:
        return scan_stage.exit_code

    # 8. Ingest scan events as a new run (Python remains the sole SQLite writer)
    Ingestor(db=db, run_id=run_id).ingest_lines(scan_stage.lines)

    # The Go scan stage has no --target flag and omits target from run_start.
    # Python fills the scope-checked domain so the run row matches recon rows
    # without fabricating any engine event. Prefer the source run's target,
    # which recon already stored in the engine's canonical normalized form.
    scan_target = _normalize_target(source_run.target) or normalized_target
    with db.transaction() as conn:
        db.upsert_run(conn=conn, run_id=run_id, target=scan_target, started_at="")

    scan_cancelled = scan_stage.cancelled
    scan_exit = scan_stage.exit_code
    final_exit_code = 0

    if scan_cancelled or scan_exit != 0:
        final_status = "cancelled" if (scan_cancelled or scan_exit == 130) else "partial"
        fallback_ts = None if scan_stage.has_run_end else datetime.now(UTC).isoformat()
        with db.transaction() as conn:
            db.finish_run(conn=conn, run_id=run_id, status=final_status, finished_at=fallback_ts)

        if scan_exit != 0 and not scan_cancelled:
            report_stage_failure(
                stage_name="scan",
                exit_code=scan_exit,
                stderr_history=scan_stage.stderr_history,
                raw=raw,
                console=console,
            )
        final_exit_code = scan_exit

    # 9. Printable summary (skipped in --raw mode, like recon)
    if not raw:
        run_record = db.get_run(run_id)
        if run_record:
            findings = db.get_findings_for_run_by_severity(run_id)
            render_scan_summary(run_record, findings, console=console)

    return final_exit_code


__all__ = ["run_scan"]
