from __future__ import annotations

import collections
import json
import signal
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from daysra.core.config import find_engine_binary, validate_config_permissions
from daysra.core.contracts import validate_event
from daysra.core.sanitizer import sanitize_terminal_text
from daysra.core.ulid import generate_ulid
from daysra.ingest import Ingestor
from daysra.simple.summary import render_recon_summary
from daysra.store.db import Database, get_db_path


def _start_stderr_drain(
    proc: subprocess.Popen[str], max_history: int = 50
) -> tuple[threading.Thread, collections.deque[str]]:
    """Drains proc.stderr concurrently in a daemon thread to prevent pipe buffer deadlocks.

    Retains up to max_history lines of stderr output for diagnostic reporting upon failure.
    """
    stderr_history: collections.deque[str] = collections.deque(maxlen=max_history)

    def drain() -> None:
        if proc.stderr is None:
            return
        try:
            for line in proc.stderr:
                stripped = line.strip()
                if stripped:
                    stderr_history.append(stripped)
        except (ValueError, OSError):
            pass
        finally:
            try:
                proc.stderr.close()
            except OSError:
                pass

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    return t, stderr_history


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
    recon_cancelled = False

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

    try:
        recon_proc = subprocess.Popen(
            recon_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as err:
        console.print(f"[bold red]Error menjalankan subprocess engine recon:[/bold red] {err}")
        return 3

    recon_stderr_thread, recon_stderr_history = _start_stderr_drain(recon_proc)
    recon_has_run_end = False

    def handle_recon_line(raw_line: str) -> None:
        nonlocal recon_has_run_end
        stripped = raw_line.strip()
        if not stripped:
            return
        if raw:
            sys.stdout.write(stripped + "\n")
            sys.stdout.flush()

        collected_lines.append(stripped)
        try:
            ev_data = json.loads(stripped)
            ev = validate_event(ev_data)
            if ev.type == "host":
                h_name = str(ev.data.get("hostname", "")).strip().lower()
                if h_name and h_name not in discovered_hosts:
                    discovered_hosts.append(h_name)
            elif ev.type == "run_end":
                recon_has_run_end = True
        except (json.JSONDecodeError, ValidationError):
            return

    # Stream Stage 1 with Rich Progress
    if raw:
        try:
            if recon_proc.stdout:
                for line in recon_proc.stdout:
                    handle_recon_line(line)
        except KeyboardInterrupt:
            recon_cancelled = True
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task1 = progress.add_task(f"[cyan][1/2] Menjalankan recon (subdomain) untuk {domain}...", total=None)
            try:
                if recon_proc.stdout:
                    for line in recon_proc.stdout:
                        handle_recon_line(line)
                        progress.update(
                            task1,
                            description=f"[cyan][1/2] Ditemukan {len(discovered_hosts)} host untuk {domain}...",
                        )
            except KeyboardInterrupt:
                recon_cancelled = True

    # Handle Stage 1 Cancellation
    if recon_cancelled:
        console.print("\n[yellow]Menerima Ctrl+C pada tahap recon. Menghentikan proses anak...[/yellow]")
        try:
            recon_proc.send_signal(signal.SIGINT)
            if recon_proc.stdout:
                for line in recon_proc.stdout:
                    handle_recon_line(line)
            recon_proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            recon_proc.kill()
            recon_proc.wait()

    recon_exit = 130 if recon_cancelled else recon_proc.wait()
    recon_stderr_thread.join(timeout=2.0)
    if recon_proc.stdout and not recon_proc.stdout.closed:
        try:
            recon_proc.stdout.close()
        except OSError:
            pass

    # If recon was cancelled or failed, ingest what we have and exit
    if recon_cancelled or recon_exit != 0:
        Ingestor(db=db, run_id=run_id).ingest_lines(collected_lines)
        final_status = "cancelled" if (recon_cancelled or recon_exit == 130) else "partial"
        fallback_ts = None if recon_has_run_end else datetime.now(UTC).isoformat()
        with db.transaction() as conn:
            db.finish_run(conn=conn, run_id=run_id, status=final_status, finished_at=fallback_ts)

        if not raw:
            if recon_exit != 0 and not recon_cancelled and recon_stderr_history:
                console.print(f"[bold red]Engine recon gagal (exit {recon_exit}):[/bold red]")
                for err_line in list(recon_stderr_history)[-10:]:
                    console.print(Text(sanitize_terminal_text(err_line), style="dim"))
            run_rec = db.get_run(run_id)
            if run_rec:
                hosts_obs = db.get_hosts_for_run(run_id)
                http_obs = db.get_http_obs_for_run(run_id)
                render_recon_summary(run_rec, hosts_obs, http_obs, console=console)
        elif raw and recon_exit != 0 and not recon_cancelled and recon_stderr_history:
            sys.stderr.write(f"Engine recon failed (exit {recon_exit}):\n")
            for err_line in list(recon_stderr_history)[-10:]:
                sys.stderr.write(f"  {sanitize_terminal_text(err_line)}\n")
            sys.stderr.flush()
        return recon_exit

    # 8. Tahap 2: Probe (httpx) - if not --no-probe and hosts found
    probe_failed = False
    probe_cancelled = False
    probe_exit = 0

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

        try:
            probe_proc = subprocess.Popen(
                probe_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as err:
            console.print(f"[bold red]Error menjalankan subprocess engine probe:[/bold red] {err}")
            return 3

        probe_stderr_thread, probe_stderr_history = _start_stderr_drain(probe_proc)

        # Send discovered hostnames to probe stdin
        if probe_proc.stdin:
            stdin_payload = "\n".join(discovered_hosts) + "\n"
            try:
                probe_proc.stdin.write(stdin_payload)
                probe_proc.stdin.close()
            except OSError:
                pass

        http_seen = 0
        probe_has_run_end = False

        def handle_probe_line(raw_line: str) -> None:
            nonlocal http_seen, probe_has_run_end
            stripped = raw_line.strip()
            if not stripped:
                return
            if raw:
                sys.stdout.write(stripped + "\n")
                sys.stdout.flush()

            collected_lines.append(stripped)
            try:
                ev_data = json.loads(stripped)
                ev = validate_event(ev_data)
                if ev.type == "http":
                    http_seen += 1
                elif ev.type == "run_end":
                    probe_has_run_end = True
            except (json.JSONDecodeError, ValidationError):
                return

        # Stream Stage 2 with Rich Progress
        if raw:
            try:
                if probe_proc.stdout:
                    for line in probe_proc.stdout:
                        handle_probe_line(line)
            except KeyboardInterrupt:
                probe_cancelled = True
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task2 = progress.add_task(
                    f"[cyan][2/2] Menjalankan probe HTTP untuk {len(discovered_hosts)} host...", total=None
                )
                try:
                    if probe_proc.stdout:
                        for line in probe_proc.stdout:
                            handle_probe_line(line)
                            progress.update(
                                task2,
                                description=f"[cyan][2/2] Ditemukan {http_seen} host hidup...",
                            )
                except KeyboardInterrupt:
                    probe_cancelled = True

        # Handle Stage 2 Cancellation
        if probe_cancelled:
            console.print("\n[yellow]Menerima Ctrl+C pada tahap probe. Menghentikan proses anak...[/yellow]")
            try:
                probe_proc.send_signal(signal.SIGINT)
                if probe_proc.stdout:
                    for line in probe_proc.stdout:
                        handle_probe_line(line)
                probe_proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                probe_proc.kill()
                probe_proc.wait()
            probe_exit = 130
        else:
            probe_exit = probe_proc.wait()
            if probe_exit != 0:
                probe_failed = True
                if not raw and probe_stderr_history:
                    console.print(f"[bold red]Engine probe gagal (exit {probe_exit}):[/bold red]")
                    for err_line in list(probe_stderr_history)[-10:]:
                        console.print(Text(sanitize_terminal_text(err_line), style="dim"))
                elif raw and probe_stderr_history:
                    sys.stderr.write(f"Engine probe failed (exit {probe_exit}):\n")
                    for err_line in list(probe_stderr_history)[-10:]:
                        sys.stderr.write(f"  {sanitize_terminal_text(err_line)}\n")
                    sys.stderr.flush()

        probe_stderr_thread.join(timeout=2.0)
        if probe_proc.stdout and not probe_proc.stdout.closed:
            try:
                probe_proc.stdout.close()
            except OSError:
                pass

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
