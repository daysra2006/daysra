from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from jinja2 import Environment

from daysra.store.db import Database, HostObsRecord, HttpObsRecord, RunRecord

CONTROL_SEQUENCE = re.compile(r"(?:\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f])")

REPORT_TEMPLATE = """# Laporan Reconnaissance DAYSRA

{% if run.status == "partial" %}
> [!WARNING]
> **PERINGATAN: Run ini berstatus Parsial (Tidak Lengkap).**
> Proses pengumpulan data terputus atau mengalami batas waktu (timeout). Data di bawah ini hanya mencerminkan hasil sementara yang berhasil diamati.

{% elif run.status == "cancelled" %}
> [!WARNING]
> **PERINGATAN: Run ini Dibatalkan (Cancelled).**
> Proses recon dihentikan oleh pengguna sebelum proses selesai.

{% endif %}
## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `{{ run.target | sanitize }}` |
| **Run ID** | `{{ run.run_id | sanitize }}` |
| **Status** | **{{ run.status | sanitize }}** |
| **Total Host Unik** | {{ hosts | length }} |
| **Host Hidup (HTTP)** | {{ http_obs | length }} |
| **Waktu Mulai** | {{ run.started_at | sanitize }} |
| **Waktu Selesai** | {{ (run.finished_at or '-') | sanitize }} |
{% if run.tool_versions %}
| **Versi Tool** | {% for tool, ver in run.tool_versions | dictsort %}{{ tool | sanitize }} `{{ ver | sanitize }}`{% if not loop.last %}, {% endif %}{% endfor %} |
{% endif %}

## Sebaran Sumber Temuan

{% if source_counts %}
| Sumber | Jumlah Host |
| --- | ---: |
{% for source, count in source_counts %}
| {{ source | sanitize }} | {{ count }} |
{% endfor %}
{% else %}
*Tidak ada data sumber.*
{% endif %}

## Daftar Subdomain

{% if hosts %}
| No | Hostname | Sumber | Alamat IP |
| ---: | --- | --- | --- |
{% for h in hosts %}
| {{ loop.index }} | `{{ h.hostname | sanitize }}` | {{ (h.sources | join(', ') if h.sources else '-') | sanitize }} | {{ (h.ips | join(', ') if h.ips else '-') | sanitize }} |
{% endfor %}
{% else %}
*Tidak ada subdomain yang ditemukan.*
{% endif %}

## Host Hidup (HTTP)

{% if http_obs %}
| No | URL | Status | Judul Halaman | Teknologi |
| ---: | --- | :---: | --- | --- |
{% for o in http_obs %}
| {{ loop.index }} | `{{ o.url | sanitize }}` | {{ o.status_code if o.status_code is not none else '-' }} | {{ (o.title or '-') | sanitize }} | {{ (o.tech | join(', ') if o.tech else '-') | sanitize }} |
{% endfor %}
{% else %}
*Tidak ada host hidup yang terdeteksi.*
{% endif %}

---
*Dibuat oleh DAYSRA pada {{ generated_at | sanitize }}*
"""


def sanitize_text(value: object) -> str:
    """Sanitize text per Design Freeze 8.2: strip ANSI escape codes and escape table pipes."""
    if value is None:
        return ""
    text = str(value)
    clean = CONTROL_SEQUENCE.sub("", text)
    return clean.replace("|", "\\|").replace("\n", " ").strip()


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


__all__ = ["generate_report_for_run", "render_markdown_report", "sanitize_text"]
