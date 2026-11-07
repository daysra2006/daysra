from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.text import Text

from daysra.core.sanitizer import sanitize_terminal_text

SHOW_COMMAND_SCHEMA_VERSION = "1"
VALID_SHOW_COMMAND_TOOLS = frozenset({"subfinder", "httpx", "nuclei"})


class ShowCommandError(Exception):
    """Raised when the engine cannot produce a valid show-command payload."""

    def __init__(self, message: str, exit_code: int = 3) -> None:
        self.exit_code = exit_code
        super().__init__(message)


def fetch_show_command(
    engine_bin: Path,
    kind: str,
    scope_path: Path,
    *,
    target: str | None = None,
    include_tags: str | None = None,
) -> dict[str, Any]:
    """Ask the engine which argv it would execute for one stage.

    The engine builds the argv with the same adapters used by real execution.
    This helper never runs the tool itself, and it never builds command text
    from constants.
    """
    if kind not in {"recon", "probe", "scan"}:
        raise ShowCommandError(f"subcommand show-command tidak dikenal: {kind}", exit_code=2)

    command = [str(engine_bin), "show-command", kind, "--scope", str(scope_path)]
    if target is not None:
        command.extend(["--target", target])
    if include_tags:
        command.extend(["--include-tags", include_tags])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as err:
        raise ShowCommandError(f"gagal menjalankan daysra-engine: {err}", exit_code=3) from err

    if result.returncode != 0:
        detail = sanitize_terminal_text(result.stderr.strip())
        message = f"daysra-engine show-command gagal (exit {result.returncode})"
        if detail:
            message = f"{message}: {detail}"
        raise ShowCommandError(message, exit_code=result.returncode or 2)

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        raise ShowCommandError("keluaran show-command bukan JSON yang valid", exit_code=3) from err

    if not isinstance(payload, dict):
        raise ShowCommandError("keluaran show-command harus berupa objek JSON", exit_code=3)
    if payload.get("schema_version") != SHOW_COMMAND_SCHEMA_VERSION:
        raise ShowCommandError("schema_version show-command tidak didukung", exit_code=3)

    tool = payload.get("tool")
    if not isinstance(tool, str) or tool not in VALID_SHOW_COMMAND_TOOLS:
        raise ShowCommandError("tool show-command tidak dikenal", exit_code=3)

    argv = payload.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) for item in argv)
    ):
        raise ShowCommandError("argv show-command tidak valid", exit_code=3)

    return {
        "schema_version": SHOW_COMMAND_SCHEMA_VERSION,
        "tool": tool,
        "argv": list(argv),
    }


def print_tool_command(console: Console, payload: dict[str, Any]) -> None:
    """Render one display-only tool command from the engine-provided argv."""
    tool = sanitize_terminal_text(str(payload["tool"]))
    argv = [sanitize_terminal_text(str(item)) for item in payload["argv"]]
    # shlex.join is for display only. Nothing is executed from this string.
    line = Text(f"Perintah {tool}: ", style="dim")
    line.append(shlex.join([tool, *argv]))
    console.print(line)


__all__ = [
    "SHOW_COMMAND_SCHEMA_VERSION",
    "ShowCommandError",
    "fetch_show_command",
    "print_tool_command",
]
