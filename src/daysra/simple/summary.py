from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from daysra.core.sanitizer import sanitize_terminal_text
from daysra.knowledge import FindingExplanation, KnowledgeBase, build_explanations
from daysra.store.db import FindingRecord, HostObsRecord, HttpObsRecord, RunRecord

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Backward-compatible internal alias
_sanitize_terminal_text = sanitize_terminal_text


def render_recon_summary(
    run: RunRecord,
    hosts: Sequence[HostObsRecord],
    http_obs: Sequence[HttpObsRecord] = (),
    console: Console | None = None,
) -> None:
    """Render Simple Mode reconnaissance and HTTP probing summary using Rich components."""
    console = console or Console()

    # 1. Status and warning header
    status_text = Text()
    if run.status == "complete":
        status_text.append("✓ Selesai (Complete)", style="bold green")
    elif run.status == "partial":
        status_text.append("⚠ Parsial (Partial - Hasil Tidak Lengkap)", style="bold yellow")
    elif run.status == "cancelled":
        status_text.append("✖ Dibatalkan (Cancelled)", style="bold red")
    elif run.status == "failed":
        status_text.append("✖ Gagal (Failed)", style="bold red")
    else:
        status_text.append(f"✖ Status: {run.status}", style="bold red")

    live_hosts = {o.hostname for o in http_obs}

    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_column(style="bold")
    meta_table.add_column()
    meta_table.add_row("Target:", Text(_sanitize_terminal_text(run.target)))
    meta_table.add_row("Run ID:", Text(_sanitize_terminal_text(run.run_id)))
    meta_table.add_row("Status:", status_text)
    meta_table.add_row("Total Host Unik:", str(len(hosts)))
    if http_obs:
        meta_table.add_row("Host Hidup (HTTP):", f"{len(live_hosts)} host ({len(http_obs)} endpoint)")
    if run.started_at:
        meta_table.add_row("Waktu Mulai:", Text(_sanitize_terminal_text(run.started_at)))
    if run.finished_at:
        meta_table.add_row("Waktu Selesai:", Text(_sanitize_terminal_text(run.finished_at)))

    console.print()
    console.print(Panel(meta_table, title="[bold]Ringkasan Recon Simple Mode[/bold]", border_style="cyan"))

    if run.status in {"partial", "cancelled"}:
        warning_msg = (
            "[bold yellow]PERINGATAN:[/bold yellow] Proses ini tidak selesai sempurna. "
            "Data di bawah ini adalah hasil pengamatan parsial sebelum proses dihentikan."
        )
        console.print(Panel(warning_msg, border_style="yellow"))
    elif run.status == "failed":
        warning_msg = (
            "[bold red]PERINGATAN:[/bold red] Proses ini mengalami kegagalan. "
            "Data di bawah ini hanya mencerminkan hasil pengamatan sebelum terjadi kesalahan."
        )
        console.print(Panel(warning_msg, border_style="red"))

    if not hosts and not http_obs:
        console.print("[dim]Tidak ada subdomain atau host hidup yang ditemukan.[/dim]")
        return

    # 2. Sebaran Sumber (Distribution of sources)
    source_counts: Counter[str] = Counter()
    for h in hosts:
        for s in h.sources:
            source_counts[s] += 1

    if source_counts:
        src_table = Table(title="Sebaran Sumber Temuan", border_style="blue")
        src_table.add_column("Sumber", style="cyan")
        src_table.add_column("Jumlah Host", justify="right", style="green")
        for source, count in source_counts.most_common():
            src_table.add_row(Text(_sanitize_terminal_text(source)), str(count))
        console.print(src_table)

    # 3. 10 Host Teratas (Top 10 hosts)
    if hosts:
        top_10 = hosts[:10]
        host_table = Table(
            title=f"10 Host Teratas (Menampilkan {len(top_10)} dari {len(hosts)} host)",
            border_style="magenta",
        )
        host_table.add_column("No", justify="right", style="dim", width=4)
        host_table.add_column("Hostname", style="bold white")
        host_table.add_column("Sumber", style="cyan")
        host_table.add_column("IP Address", style="dim")

        for i, h in enumerate(top_10, start=1):
            sources_str = ", ".join(_sanitize_terminal_text(s) for s in h.sources) if h.sources else "-"
            ips_str = ", ".join(_sanitize_terminal_text(ip) for ip in h.ips) if h.ips else "-"
            host_table.add_row(str(i), Text(_sanitize_terminal_text(h.hostname)), Text(sources_str), Text(ips_str))

        console.print(host_table)

    # 4. HTTP Sections (if http_obs available)
    if http_obs:
        # Sebaran Status Code
        code_counts: Counter[int] = Counter()
        for o in http_obs:
            if o.status_code is not None:
                code_counts[o.status_code] += 1

        if code_counts:
            status_table = Table(title="Sebaran Status Code HTTP", border_style="green")
            status_table.add_column("Status Code", style="bold cyan")
            status_table.add_column("Deskripsi", style="white")
            status_table.add_column("Jumlah", justify="right", style="green")

            status_descriptions = {
                200: "OK",
                201: "Created",
                204: "No Content",
                301: "Moved Permanently",
                302: "Found / Redirect",
                304: "Not Modified",
                307: "Temporary Redirect",
                308: "Permanent Redirect",
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
                504: "Gateway Timeout",
            }

            for code, count in sorted(code_counts.items()):
                desc = status_descriptions.get(code, "HTTP Status")
                code_style = "green" if 200 <= code < 300 else ("yellow" if 300 <= code < 400 else "red")
                status_table.add_row(f"[{code_style}]{code}[/{code_style}]", desc, str(count))

            console.print(status_table)

        # 10 Teknologi Teratas
        tech_counts: Counter[str] = Counter()
        for o in http_obs:
            for t in o.tech:
                tech_counts[t] += 1

        if tech_counts:
            tech_table = Table(title="10 Teknologi Teratas", border_style="cyan")
            tech_table.add_column("No", justify="right", style="dim", width=4)
            tech_table.add_column("Teknologi", style="bold white")
            tech_table.add_column("Kemunculan", justify="right", style="green")

            for i, (t, count) in enumerate(tech_counts.most_common(10), start=1):
                tech_table.add_row(str(i), Text(_sanitize_terminal_text(t)), str(count))

            console.print(tech_table)

        # Host dengan Status Menarik (3xx / 4xx / 5xx)
        interesting = [o for o in http_obs if o.status_code is not None and (300 <= o.status_code < 600)]
        if interesting:
            int_table = Table(
                title=f"Host dengan Status Menarik (3xx/4xx/5xx) — Menampilkan {len(interesting)} endpoint",
                border_style="yellow",
            )
            int_table.add_column("URL", style="bold white")
            int_table.add_column("Status", justify="center")
            int_table.add_column("Judul Halaman", style="dim")
            int_table.add_column("Teknologi", style="cyan")

            for o in interesting[:15]:
                code = o.status_code
                code_style = "yellow" if 300 <= (code or 0) < 400 else "red"
                code_str = f"[{code_style}]{code}[/{code_style}]"
                raw_title = _sanitize_terminal_text(o.title) if o.title else ""
                title_str = (raw_title[:40] + "...") if len(raw_title) > 40 else (raw_title or "-")
                tech_str = (
                    ", ".join(_sanitize_terminal_text(t) for t in o.tech[:3])
                    if o.tech
                    else "-"
                )
                int_table.add_row(
                    Text(_sanitize_terminal_text(o.url)),
                    code_str,
                    Text(title_str),
                    Text(tech_str),
                )

            console.print(int_table)

    if len(hosts) > 10 or len(http_obs) > 15:
        safe_run_id = escape(run.run_id)
        console.print(f"[dim]Gunakan 'daysra report --run {safe_run_id}' untuk melihat daftar lengkap.[/dim]")


def render_scan_summary(
    run: RunRecord,
    findings: Sequence[FindingRecord],
    console: Console | None = None,
) -> None:
    """Render the scan result summary: per-severity counts and a findings table.

    Every field that originates from the target or the tool is sanitized and
    rendered through ``Text`` so Rich markup is never interpreted.
    """
    console = console or Console()

    status_text = Text()
    if run.status == "complete":
        status_text.append("✓ Selesai (Complete)", style="bold green")
    elif run.status == "partial":
        status_text.append("⚠ Parsial (Partial - Hasil Tidak Lengkap)", style="bold yellow")
    elif run.status == "cancelled":
        status_text.append("✖ Dibatalkan (Cancelled)", style="bold red")
    elif run.status == "failed":
        status_text.append("✖ Gagal (Failed)", style="bold red")
    else:
        status_text.append("✖ Status: ", style="bold red")
        status_text.append(_sanitize_terminal_text(run.status))

    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_column(style="bold")
    meta_table.add_column()
    meta_table.add_row("Target:", Text(_sanitize_terminal_text(run.target) or "-"))
    meta_table.add_row("Run ID:", Text(_sanitize_terminal_text(run.run_id)))
    meta_table.add_row("Status:", status_text)
    meta_table.add_row("Total Temuan:", str(len(findings)))

    console.print()
    console.print(Panel(meta_table, title="[bold]Ringkasan Scan[/bold]", border_style="cyan"))

    if run.status in {"partial", "cancelled"}:
        console.print(
            Panel(
                "[bold yellow]PERINGATAN:[/bold yellow] Scan tidak selesai sempurna. "
                "Temuan di bawah ini berasal dari hasil parsial.",
                border_style="yellow",
            )
        )
    elif run.status == "failed":
        console.print(
            Panel(
                "[bold red]PERINGATAN:[/bold red] Scan mengalami kegagalan. "
                "Temuan di bawah ini hanya yang berhasil diamati sebelum kegagalan.",
                border_style="red",
            )
        )

    severity_counts: Counter[str] = Counter(f.severity.strip().lower() for f in findings)
    count_table = Table(title="Jumlah Temuan per Severity", border_style="blue")
    count_table.add_column("Severity", style="bold")
    count_table.add_column("Jumlah", justify="right", style="green")
    for severity in SEVERITY_ORDER:
        count_table.add_row(severity, str(severity_counts.get(severity, 0)))
    for severity in sorted(set(severity_counts) - set(SEVERITY_ORDER)):
        count_table.add_row(Text(_sanitize_terminal_text(severity)), str(severity_counts[severity]))
    console.print(count_table)

    if not findings:
        console.print("[dim]Tidak ada temuan.[/dim]")
        return

    table = Table(
        title=f"Temuan ({len(findings)})",
        border_style="magenta",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Template ID", style="cyan")
    table.add_column("Nama")
    table.add_column("Matched At", style="dim")

    for finding in findings:
        # Text() does not parse Rich markup and sanitize_terminal_text removes
        # ANSI/control sequences, so untrusted tool output cannot style the terminal.
        table.add_row(
            Text(_sanitize_terminal_text(finding.severity)),
            Text(_sanitize_terminal_text(finding.template_id)),
            Text(_sanitize_terminal_text(finding.name)),
            Text(_sanitize_terminal_text(finding.matched_at)),
        )

    console.print(table)


def _render_explanation_block(explanation: FindingExplanation, console: Console) -> None:
    body = Text()
    body.append("Apa ini: ", style="bold")
    body.append(Text(_sanitize_terminal_text(explanation.title)))
    body.append("\n")
    body.append(Text(_sanitize_terminal_text(explanation.meaning)))
    body.append("\n\n")
    body.append("Kenapa penting: ", style="bold")
    body.append(Text(_sanitize_terminal_text(explanation.impact)))
    body.append("\n\n")
    body.append("Langkah berikutnya:", style="bold")
    if explanation.verify_steps:
        for index, step in enumerate(explanation.verify_steps, start=1):
            body.append(f"\n  {index}. ")
            body.append(Text(_sanitize_terminal_text(step)))
    else:
        body.append("\n  (tidak ada langkah spesifik)")
    body.append("\n\n")
    body.append("Konsep untuk dipelajari: ", style="bold")
    body.append(Text(_sanitize_terminal_text(explanation.concept)))
    body.append("\n\n")
    body.append("Matched At:", style="bold")
    shown = explanation.matched_at[:5]
    for matched_at in shown:
        body.append("\n  - ")
        body.append(Text(_sanitize_terminal_text(matched_at)))
    remaining = len(explanation.matched_at) - len(shown)
    if remaining > 0:
        body.append(f"\n  dan {remaining} lainnya")

    title = Text("Penjelasan: ")
    title.append(_sanitize_terminal_text(explanation.template_id), style="bold")
    title.append(" — ")
    title.append(_sanitize_terminal_text(explanation.name))
    title.append(f" ({_sanitize_terminal_text(explanation.severity)})")

    subtitle = Text("[fallback generik]", style="yellow") if explanation.is_fallback else None
    console.print(
        Panel(
            body,
            title=title,
            subtitle=subtitle,
            border_style="yellow" if explanation.is_fallback else "cyan",
        )
    )


def render_finding_explanations(
    findings: Sequence[FindingRecord],
    knowledge: KnowledgeBase,
    console: Console | None = None,
) -> None:
    """Render one Simple Mode explanation block per unique template_id.

    Narrative text comes from the validated offline knowledge base, or from a
    deterministic severity fallback. Tool facts (template_id, name, severity,
    CVE, matched_at) are never rewritten. Untrusted text is sanitized and all
    text is rendered through ``Text`` so Rich markup is not interpreted.
    """
    console = console or Console()
    explanations = build_explanations(findings, knowledge)
    if not explanations:
        return

    console.print()
    console.print("[bold]Penjelasan Temuan[/bold]")
    for explanation in explanations:
        _render_explanation_block(explanation, console)


__all__ = [
    "SEVERITY_ORDER",
    "render_finding_explanations",
    "render_recon_summary",
    "render_scan_summary",
]
