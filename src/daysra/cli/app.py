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
def scan(
    domain: Annotated[str, typer.Argument(help="Target domain whose live hosts will be scanned")],
    scope: Annotated[str, typer.Option("--scope", help="Path to scope.yaml")] = "scope.yaml",
    include_tags: Annotated[
        list[str] | None,
        typer.Option(
            "--include-tags",
            help="Comma-separated additional Nuclei template tags (may be repeated)",
        ),
    ] = None,
    accept_default_login: Annotated[
        bool,
        typer.Option(
            "--accept-default-login",
            help="Accept the default-login tag without an interactive confirmation",
        ),
    ] = False,
    from_run: Annotated[
        str | None,
        typer.Option("--from-run", help="Use live URLs from this specific run ID"),
    ] = None,
    raw: Annotated[bool, typer.Option("--raw", help="Output raw JSONL events")] = False,
    show_command: Annotated[
        bool, typer.Option("--show-command", help="Display the engine command being executed")
    ] = False,
) -> None:
    """Scan live HTTP hosts for findings using Nuclei within authorized scope."""
    from daysra.cli.scan import run_scan

    raise typer.Exit(
        run_scan(
            domain=domain,
            scope=scope,
            include_tags=include_tags,
            accept_default_login=accept_default_login,
            from_run=from_run,
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
    """Generate Markdown report for a reconnaissance or scan run."""
    from daysra.knowledge import KnowledgeError
    from daysra.report.generator import classify_run_kind, generate_report_for_run
    from daysra.store.db import Database, get_db_path

    db = Database(get_db_path())
    try:
        run_record = db.get_run(run) if run else db.get_latest_run()
        if run_record is None:
            if run:
                raise ValueError(f"Run dengan ID '{run}' tidak ditemukan di database.")
            raise ValueError("Belum ada riwayat run di database.")
        report_md = generate_report_for_run(db, run_id=run_record.run_id)
    except (KnowledgeError, ValueError) as err:
        typer.echo(f"Error: {err}", err=True)
        raise typer.Exit(1)

    run_kind = classify_run_kind(run_record)
    typer.echo(f"Jenis run: {run_kind} | Run ID: {run_record.run_id}", err=True)

    if output:
        output.write_text(report_md, encoding="utf-8")
        typer.echo(f"Laporan berhasil disimpan ke: {output}")
    else:
        typer.echo(report_md)
