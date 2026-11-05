from __future__ import annotations

import os
from pathlib import Path

from rich.console import Console

from daysra.core.config import get_config_dir, get_config_path

DEFAULT_CONFIG_CONTENT = """# DAYSRA Configuration
# File ini berisi pengaturan default DAYSRA.
# Izin file ini wajib 0600 (hanya pemilik yang boleh membaca dan menulis).

[general]
lang = "id"

[engine]
timeout = 600
max_rate = 50
"""

DEFAULT_SCOPE_CONTENT = """# DAYSRA Scope Configuration
# File ini mendefinisikan batas otorisasi dan domain yang diizinkan untuk diuji.
authorization: "domain milik sendiri / lab / bug bounty <nama program>"

allow:
  - "example.com"
  - "*.example.com"

deny:
  - "admin.example.com"

max_rate: 50
timeout: 600
"""


def run_init(
    dest_dir: Path | None = None,
    config_dir: Path | None = None,
    console: Console | None = None,
) -> int:
    """Initialize DAYSRA config.toml (mode 0600) and sample scope.yaml."""
    console = console or Console()

    # 1. Initialize config.toml
    target_config_dir = config_dir or get_config_dir()
    target_config_dir.mkdir(parents=True, exist_ok=True)
    config_file = target_config_dir / "config.toml" if config_dir else get_config_path()

    if config_file.exists():
        # Enforce 0600 permissions
        os.chmod(config_file, 0o600)
        console.print(f"[yellow]i[/yellow] File konfigurasi sudah ada: {config_file} (izin diset ke 0600)")
    else:
        config_file.write_text(DEFAULT_CONFIG_CONTENT, encoding="utf-8")
        os.chmod(config_file, 0o600)
        console.print(f"[green]✓[/green] Dibuat file konfigurasi: {config_file} (izin 0600)")

    # 2. Initialize sample scope.yaml
    work_dir = dest_dir or Path.cwd()
    scope_file = work_dir / "scope.yaml"

    if scope_file.exists():
        console.print(f"[yellow]i[/yellow] File scope sudah ada: {scope_file} (tidak ditimpa)")
    else:
        scope_file.write_text(DEFAULT_SCOPE_CONTENT, encoding="utf-8")
        console.print(f"[green]✓[/green] Dibuat contoh scope: {scope_file}")

    console.print("\n[bold green]Inisialisasi selesai.[/bold green] Edit [cyan]scope.yaml[/cyan] dengan target yang sah sebelum menjalankan recon.")
    return 0


__all__ = ["run_init"]
