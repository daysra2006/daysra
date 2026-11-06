from __future__ import annotations

import html
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from jinja2 import Environment

from daysra.core.sanitizer import (
    CONTROL_SEQUENCE,
    strip_control_characters,
)
from daysra.store.db import Database, HostObsRecord, HttpObsRecord, RunRecord

REPORT_TEMPLATE = """# Laporan Reconnaissance DAYSRA

{% if run.status == "partial" %}
> [!WARNING]
> **PERINGATAN: Run ini berstatus Parsial (Tidak Lengkap).**
> Proses pengumpulan data terputus atau mengalami batas waktu (timeout). Data di bawah ini hanya mencerminkan hasil sementara yang berhasil diamati.

{% elif run.status == "cancelled" %}
> [!WARNING]
> **PERINGATAN: Run ini Dibatalkan (Cancelled).**
> Proses recon dihentikan oleh pengguna sebelum proses selesai.

{% elif run.status == "failed" %}
> [!WARNING]
> **PERINGATAN: Run ini Gagal (Failed).**
> Proses recon mengalami kegagalan pada saat eksekusi. Data di bawah ini hanya mencerminkan hasil sementara sebelum terjadi kesalahan.

{% endif %}
## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `{{ run.target | sanitize_code }}` |
| **Run ID** | `{{ run.run_id | sanitize_code }}` |
| **Status** | **{{ run.status | sanitize_text }}** |
| **Total Host Unik** | {{ hosts | length }} |
| **Host Hidup (HTTP)** | {{ http_obs | length }} |
| **Waktu Mulai** | {{ run.started_at | sanitize_cell }} |
| **Waktu Selesai** | {{ (run.finished_at or '-') | sanitize_cell }} |
{% if run.tool_versions %}
| **Versi Tool** | {% for tool, ver in run.tool_versions | dictsort %}{{ tool | sanitize_cell }} `{{ ver | sanitize_code }}`{% if not loop.last %}, {% endif %}{% endfor %} |
{% endif %}

## Sebaran Sumber Temuan

{% if source_counts %}
| Sumber | Jumlah Host |
| --- | ---: |
{% for source, count in source_counts %}
| {{ source | sanitize_cell }} | {{ count }} |
{% endfor %}
{% else %}
*Tidak ada data sumber.*
{% endif %}

## Daftar Subdomain

{% if hosts %}
| No | Hostname | Sumber | Alamat IP |
| ---: | --- | --- | --- |
{% for h in hosts %}
| {{ loop.index }} | `{{ h.hostname | sanitize_code }}` | {{ (h.sources | join(', ') if h.sources else '-') | sanitize_cell }} | {{ (h.ips | join(', ') if h.ips else '-') | sanitize_cell }} |
{% endfor %}
{% else %}
*Tidak ada subdomain yang ditemukan.*
{% endif %}

## Host Hidup (HTTP)

{% if http_obs %}
| No | URL | Status | Judul Halaman | Teknologi |
| ---: | --- | :---: | --- | --- |
{% for o in http_obs %}
| {{ loop.index }} | `{{ o.url | sanitize_code }}` | {{ o.status_code if o.status_code is not none else '-' }} | {{ (o.title or '-') | sanitize_cell }} | {{ (o.tech | join(', ') if o.tech else '-') | sanitize_cell }} |
{% endfor %}
{% else %}
*Tidak ada host hidup yang terdeteksi.*
{% endif %}

---
*Dibuat oleh DAYSRA pada {{ generated_at | sanitize_text }}*
"""


def sanitize_inline_code(value: object) -> str:
    """Sanitize values rendered inside Markdown inline code spans (`...`).

    - Strips ANSI/OSC/C0/Bidi control characters.
    - Encodes HTML entities to prevent XSS.
    - Neutralizes backticks to &#96; to prevent breaking out of code spans.
    - Escapes table pipes (|) to preserve table cell boundaries in GFM.
    - Replaces newlines with space.
    """
    if value is None:
        return ""
    text = strip_control_characters(value)
    text = html.escape(text, quote=True)
    text = text.replace("`", "&#96;")
    text = text.replace("|", "\\|").replace("\n", " ")
    return text.strip()


def sanitize_table_cell(value: object) -> str:
    """Sanitize free-text values rendered inside Markdown table cells.

    - Strips ANSI/OSC/C0/Bidi control characters.
    - Encodes HTML entities to prevent XSS.
    - Escapes table pipes (|) to preserve table columns.
    - Neutralizes backticks to &#96;.
    - Escapes brackets ([ and ]) to prevent Markdown link injection.
    - Replaces newlines with space.
    """
    if value is None:
        return ""
    text = strip_control_characters(value)
    text = html.escape(text, quote=True)
    text = text.replace("`", "&#96;")
    text = text.replace("[", "\\[").replace("]", "\\]")
    text = text.replace("|", "\\|").replace("\n", " ")
    return text.strip()


def sanitize_inline_text(value: object) -> str:
    """Sanitize free text in normal Markdown flow outside tables and code spans.

    - Strips ANSI/OSC/C0/Bidi control characters.
    - Encodes HTML entities to prevent XSS.
    - Neutralizes backticks to &#96;.
    - Escapes Markdown formatting characters ([ ], *, _, ~).
    - Replaces newlines with space.
    """
    if value is None:
        return ""
    text = strip_control_characters(value)
    text = html.escape(text, quote=True)
    text = text.replace("`", "&#96;")
    text = (
        text.replace("[", "\\[")
        .replace("]", "\\]")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("~", "\\~")
    )
    return text.replace("\n", " ").strip()


def sanitize_text(value: object) -> str:
    """Universal backward-compatible sanitization function.

    Performs control character stripping, HTML entity escaping, backtick neutralization,
    pipe escaping, and newline collapse.
    """
    return sanitize_table_cell(value)


def render_markdown_report(
    run: RunRecord,
    hosts: Sequence[HostObsRecord],
    http_obs: Sequence[HttpObsRecord] = (),
    generated_at: str | None = None,
) -> str:
    """Render a GitHub-Flavored Markdown report from RunRecord, HostObsRecord list, and HttpObsRecord list using Jinja2."""
    if generated_at is None:
        generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    source_counts: Counter[str] = Counter()
    for h in hosts:
        for s in h.sources:
            source_counts[s] += 1

    sorted_sources = source_counts.most_common()

    env = Environment(
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["sanitize"] = sanitize_text
    env.filters["sanitize_code"] = sanitize_inline_code
    env.filters["sanitize_cell"] = sanitize_table_cell
    env.filters["sanitize_text"] = sanitize_inline_text

    template = env.from_string(REPORT_TEMPLATE)

    rendered = template.render(
        run=run,
        hosts=hosts,
        http_obs=http_obs,
        source_counts=sorted_sources,
        generated_at=generated_at,
    )
    if not rendered.endswith("\n"):
        rendered += "\n"
    return rendered


def generate_report_for_run(
    db: Database,
    run_id: str | None = None,
    generated_at: str | None = None,
) -> str:
    """Fetch run, host observations, and HTTP observations from SQLite and render the Markdown report."""
    if run_id:
        run_record = db.get_run(run_id)
        if run_record is None:
            raise ValueError(f"Run dengan ID '{run_id}' tidak ditemukan di database.")
    else:
        run_record = db.get_latest_run()
        if run_record is None:
            raise ValueError("Belum ada riwayat run di database.")

    hosts = db.get_hosts_for_run(run_record.run_id)
    http_obs = db.get_http_obs_for_run(run_record.run_id)
    return render_markdown_report(
        run=run_record,
        hosts=hosts,
        http_obs=http_obs,
        generated_at=generated_at,
    )


__all__ = [
    "CONTROL_SEQUENCE",
    "generate_report_for_run",
    "render_markdown_report",
    "sanitize_inline_code",
    "sanitize_inline_text",
    "sanitize_table_cell",
    "sanitize_text",
    "strip_control_characters",
]
