from __future__ import annotations

import collections
import json
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import ValidationError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from daysra.core.contracts import Event, validate_event
from daysra.core.sanitizer import sanitize_terminal_text


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


@dataclass(frozen=True)
class StageResult:
    """Structured outcome of one engine subprocess stage."""

    exit_code: int
    cancelled: bool
    has_run_end: bool
    stderr_history: tuple[str, ...]
    lines: tuple[str, ...]
    spawn_failed: bool = False


def report_stage_failure(
    *,
    stage_name: str,
    exit_code: int,
    stderr_history: tuple[str, ...],
    raw: bool,
    console: Console,
) -> None:
    """Print the last 10 stderr lines from a failed engine stage."""
    if not stderr_history:
        return

    if raw:
        sys.stderr.write(f"Engine {stage_name} failed (exit {exit_code}):\n")
        for err_line in list(stderr_history)[-10:]:
            sys.stderr.write(f"  {sanitize_terminal_text(err_line)}\n")
        sys.stderr.flush()
    else:
        console.print(f"[bold red]Engine {stage_name} gagal (exit {exit_code}):[/bold red]")
        for err_line in list(stderr_history)[-10:]:
            console.print(Text(sanitize_terminal_text(err_line), style="dim"))


def run_stage(
    command: Sequence[str],
    *,
    stage_name: str,
    initial_description: str,
    update_description: Callable[[], str],
    on_event: Callable[[Event], None],
    console: Console,
    raw: bool,
    stdin_payload: str | None = None,
    on_nonzero_exit: Callable[[int, tuple[str, ...]], None] | None = None,
    max_stderr_history: int = 50,
) -> StageResult:
    """Spawn one engine stage and stream its JSONL stdout.

    The helper owns subprocess creation, stderr draining, optional stdin delivery,
    raw/Progress stdout display, Ctrl+C handling, and process cleanup. Event parsing
    and stage-specific counters are delegated to on_event.
    """
    popen_kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "bufsize": 1,
    }
    if stdin_payload is not None:
        popen_kwargs["stdin"] = subprocess.PIPE

    try:
        proc = subprocess.Popen(command, **popen_kwargs)
    except OSError as err:
        console.print(
            f"[bold red]Error menjalankan subprocess engine {stage_name}:[/bold red] {err}"
        )
        return StageResult(
            exit_code=3,
            cancelled=False,
            has_run_end=False,
            stderr_history=(),
            lines=(),
            spawn_failed=True,
        )

    stderr_thread, stderr_history = _start_stderr_drain(
        proc, max_history=max_stderr_history
    )

    if stdin_payload is not None and proc.stdin:
        try:
            proc.stdin.write(stdin_payload)
            proc.stdin.close()
        except OSError:
            pass

    collected_lines: list[str] = []
    has_run_end = False

    def handle_line(raw_line: str) -> None:
        nonlocal has_run_end
        stripped = raw_line.strip()
        if not stripped:
            return
        if raw:
            sys.stdout.write(stripped + "\n")
            sys.stdout.flush()

        collected_lines.append(stripped)
        try:
            ev = validate_event(json.loads(stripped))
        except (json.JSONDecodeError, ValidationError):
            return

        if ev.type == "run_end":
            has_run_end = True
        on_event(ev)

    cancelled = False
    if raw:
        try:
            if proc.stdout:
                for line in proc.stdout:
                    handle_line(line)
        except KeyboardInterrupt:
            cancelled = True
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(initial_description, total=None)
            try:
                if proc.stdout:
                    for line in proc.stdout:
                        handle_line(line)
                        progress.update(task, description=update_description())
            except KeyboardInterrupt:
                cancelled = True

    if cancelled:
        console.print(
            f"\n[yellow]Menerima Ctrl+C pada tahap {stage_name}. "
            "Menghentikan proses anak...[/yellow]"
        )
        try:
            proc.send_signal(signal.SIGINT)
            if proc.stdout:
                for line in proc.stdout:
                    handle_line(line)
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            proc.kill()
            proc.wait()
        exit_code = 130
    else:
        exit_code = proc.wait()
        if exit_code != 0 and on_nonzero_exit is not None:
            on_nonzero_exit(exit_code, tuple(stderr_history))

    stderr_thread.join(timeout=2.0)
    if proc.stdout and not proc.stdout.closed:
        try:
            proc.stdout.close()
        except OSError:
            pass

    return StageResult(
        exit_code=exit_code,
        cancelled=cancelled,
        has_run_end=has_run_end,
        stderr_history=tuple(stderr_history),
        lines=tuple(collected_lines),
    )


__all__ = ["StageResult", "report_stage_failure", "run_stage"]
