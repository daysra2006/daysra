from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from daysra import __version__
from daysra.cli.doctor import run_doctor

app = typer.Typer(add_completion=False, no_args_is_help=True)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """DAYSRA security orchestration CLI."""


@app.command()
def doctor() -> None:
    """Check the local DAYSRA development environment."""
    raise typer.Exit(run_doctor())


@app.command()
def init(
    dir: Annotated[
        Path | None,
        typer.Option("--dir", help="Directory where scope.yaml will be created (default: current directory)."),
    ] = None,
) -> None:
    """Initialize DAYSRA config.toml and sample scope.yaml."""
    from daysra.cli.init import run_init

    raise typer.Exit(run_init(dest_dir=dir))


@app.command()
def recon(
    domain: Annotated[str, typer.Argument(help="Target domain to enumerate")],
    scope: Annotated[str, typer.Option("--scope", help="Path to scope.yaml")] = "scope.yaml",
    no_probe: Annotated[
        bool, typer.Option("--no-probe", help="Lewati tahap probing httpx")
    ] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Output raw JSONL events")] = False,
    show_command: Annotated[
        bool, typer.Option("--show-command", help="Display tool commands being executed")
    ] = False,
) -> None:
    """Enumerate subdomains and probe live HTTP hosts within authorized scope."""
    from daysra.cli.recon import run_recon

    raise typer.Exit(
        run_recon(
            domain=domain,
            scope=scope,
            no_probe=no_probe,
            raw=raw,
            show_command=show_command,
        )
    )


@app.command()
def report(
    run: Annotated[
        str | None,
        typer.Option("--run", help="ID spesifik run yang ingin dilaporkan (default: run terakhir)"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", help="Jalur file untuk menyimpan laporan Markdown (default: cetak ke layar)"),
    ] = None,
) -> None:
    """Generate Markdown report for a reconnaissance run."""
    from daysra.report.generator import generate_report_for_run
    from daysra.store.db import Database, get_db_path

    db = Database(get_db_path())
    try:
        report_md = generate_report_for_run(db, run_id=run)
    except ValueError as err:
        typer.echo(f"Error: {err}", err=True)
        raise typer.Exit(1)

    if output:
        output.write_text(report_md, encoding="utf-8")
        typer.echo(f"Laporan berhasil disimpan ke: {output}")
    else:
        typer.echo(report_md)
