from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.text import Text

from daysra.cli.stages import report_stage_failure, run_stage
from daysra.core.config import find_engine_binary, validate_config_permissions
from daysra.core.contracts import Event
from daysra.core.sanitizer import sanitize_terminal_text
from daysra.core.ulid import generate_ulid
from daysra.ingest import Ingestor
from daysra.simple.summary import render_recon_summary
from daysra.store.db import Database, get_db_path


def run_recon(
    domain: str,
    scope: str = "scope.yaml",
    no_probe: bool = False,
    raw: bool = False,
    show_command: bool = False,
    console: Console | None = None,
) -> int:
    """Orchestrates subdomain reconnaissance: check-scope -> spawn engine recon -> spawn engine probe -> Simple Mode summary."""
    console = console or Console()

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
    check_scope_cmd = [str(engine_bin), "check-scope", "--scope", str(scope_path), "--target", domain]
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
        if check_res.returncode == 2:
            console.print(
                f"[bold red]Error scope (exit 2):[/bold red] Target '{domain}' di luar cakupan izin {scope_path.name}"
            )
            if check_res.stderr.strip():
                console.print(Text(sanitize_terminal_text(check_res.stderr.strip()), style="dim"))
            return 2
        scope_err = Text(f"Error pemeriksaan scope (exit {check_res.returncode}): ", style="bold red")
        scope_err.append(Text(sanitize_terminal_text(check_res.stderr.strip()), style="dim"))
        console.print(scope_err)
        return check_res.returncode

    # 5. Generate run ID (ULID)
    run_id = generate_ulid()

    # 6. Show command if requested
    if show_command:
        console.print(
            f"[dim]Engine command:[/dim] {engine_bin} recon --target {domain} --scope {scope_path} --run-id {run_id}"
        )
        console.print(
            f"[dim]Subfinder tool syntax:[/dim] subfinder -d {domain} -silent -oJ -cs -rl 50 -timeout 600"
        )
        if not no_probe:
            console.print(
                f"[dim]Engine command (probe):[/dim] {engine_bin} probe --scope {scope_path} --run-id {run_id}"
            )
            console.print(
                "[dim]httpx tool syntax:[/dim] httpx -silent -json -sc -title -td -cl -rl 50 -timeout 600"
            )

    db = Database(get_db_path())
    collected_lines: list[str] = []
    discovered_hosts: list[str] = []
    discovered_hosts_set: set[str] = set()

    # 7. Tahap 1: Recon (Subfinder)
    recon_cmd = [
        str(engine_bin),
        "recon",
        "--target",
        domain,
        "--scope",
        str(scope_path),
        "--run-id",
        run_id,
    ]

    def handle_recon_event(ev: Event) -> None:
        if ev.type == "host":
            h_name = str(ev.data.get("hostname", "")).strip().lower()
            if h_name and h_name not in discovered_hosts_set:
                discovered_hosts_set.add(h_name)
                discovered_hosts.append(h_name)

    recon_stage = run_stage(
        recon_cmd,
        stage_name="recon",
        initial_description=f"[cyan][1/2] Menjalankan recon (subdomain) untuk {domain}...",
        update_description=(
            lambda: f"[cyan][1/2] Ditemukan {len(discovered_hosts)} host untuk {domain}..."
        ),
        on_event=handle_recon_event,
        console=console,
        raw=raw,
    )
    collected_lines.extend(recon_stage.lines)

    if recon_stage.spawn_failed:
        return recon_stage.exit_code

    recon_cancelled = recon_stage.cancelled
    recon_exit = recon_stage.exit_code

    # If recon was cancelled or failed, ingest what we have and exit
    if recon_cancelled or recon_exit != 0:
        Ingestor(db=db, run_id=run_id).ingest_lines(collected_lines)
        final_status = "cancelled" if (recon_cancelled or recon_exit == 130) else "partial"
        fallback_ts = None if recon_stage.has_run_end else datetime.now(UTC).isoformat()
        with db.transaction() as conn:
            db.finish_run(conn=conn, run_id=run_id, status=final_status, finished_at=fallback_ts)

        if recon_exit != 0 and not recon_cancelled:
            report_stage_failure(
                stage_name="recon",
                exit_code=recon_exit,
                stderr_history=recon_stage.stderr_history,
                raw=raw,
                console=console,
            )
        if not raw:
            run_rec = db.get_run(run_id)
            if run_rec:
                hosts_obs = db.get_hosts_for_run(run_id)
                http_obs = db.get_http_obs_for_run(run_id)
                render_recon_summary(run_rec, hosts_obs, http_obs, console=console)
        return recon_exit

    # 8. Tahap 2: Probe (httpx) - if not --no-probe and hosts found
    probe_failed = False
    probe_cancelled = False
    probe_exit = 0
    probe_has_run_end = False

    if not no_probe and discovered_hosts:
        probe_cmd = [
            str(engine_bin),
            "probe",
            "--scope",
            str(scope_path),
            "--run-id",
            run_id,
            "--target",
            domain,
        ]

        http_seen = 0

        def handle_probe_event(ev: Event) -> None:
            nonlocal http_seen
            if ev.type == "http":
                http_seen += 1

        def report_probe_failure(exit_code: int, stderr_history: tuple[str, ...]) -> None:
            report_stage_failure(
                stage_name="probe",
                exit_code=exit_code,
                stderr_history=stderr_history,
                raw=raw,
                console=console,
            )

        probe_stage = run_stage(
            probe_cmd,
            stage_name="probe",
            initial_description=(
                f"[cyan][2/2] Menjalankan probe HTTP untuk {len(discovered_hosts)} host..."
            ),
            update_description=lambda: f"[cyan][2/2] Ditemukan {http_seen} host hidup...",
            on_event=handle_probe_event,
            console=console,
            raw=raw,
            stdin_payload="\n".join(discovered_hosts) + "\n",
            on_nonzero_exit=report_probe_failure,
        )
        collected_lines.extend(probe_stage.lines)

        if probe_stage.spawn_failed:
            return probe_stage.exit_code

        probe_cancelled = probe_stage.cancelled
        probe_exit = probe_stage.exit_code
        probe_has_run_end = probe_stage.has_run_end
        if probe_exit != 0 and not probe_cancelled:
            probe_failed = True

    # 9. Ingest all collected events into SQLite
    Ingestor(db=db, run_id=run_id).ingest_lines(collected_lines)

    # If probe failed or was cancelled, mark status as cancelled or partial
    final_exit_code = 0
    if probe_cancelled or probe_failed:
        final_exit_code = 130 if probe_cancelled else probe_exit
        final_status = "cancelled" if (probe_cancelled or probe_exit == 130) else "partial"
        fallback_ts = None if probe_has_run_end else datetime.now(UTC).isoformat()
        with db.transaction() as conn:
            db.finish_run(conn=conn, run_id=run_id, status=final_status, finished_at=fallback_ts)

    # 10. Simple Mode Summary Output (when not in --raw mode)
    if not raw:
        run_record = db.get_run(run_id)
        if run_record:
            hosts_obs = db.get_hosts_for_run(run_id)
            http_obs = db.get_http_obs_for_run(run_id)
            render_recon_summary(run_record, hosts_obs, http_obs, console=console)

    return final_exit_code


__all__ = ["run_recon"]
