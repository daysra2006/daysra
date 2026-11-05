from __future__ import annotations

import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

VERSION_TIMEOUT_SECONDS = 5
CONTROL_SEQUENCE = re.compile(r"(?:\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f])")
GO_VERSION = re.compile(r"^go version (go\d\S*) \S+$")
VERSION_VALUE = re.compile(r"v?\d+\.\d+(?:\.\d+)?", re.IGNORECASE)
INFO_PREFIX = re.compile(r"^\[INF\]\s*", re.IGNORECASE)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    required: bool = False


@dataclass(frozen=True)
class VersionCommand:
    returncode: int | None
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return sanitize_version_output(f"{self.stdout}\n{self.stderr}")


def run_doctor(console: Console | None = None) -> int:
    console = console or Console()
    checks = [check_python(), check_go()]
    checks.extend(
        (check_tool("subfinder"), check_httpx(), check_tool("nuclei"), check_binary("docker"))
    )
    checks.extend((check_config_permissions(), check_engine()))

    table = Table(title="DAYSRA doctor")
    table.add_column("Pemeriksaan")
    table.add_column("Status")
    table.add_column("Detail")
    for check in checks:
        table.add_row(check.name, check.status, check.detail)
    console.print(table)

    return 3 if any(check.required and check.status != "OK" for check in checks) else 0


def check_python() -> Check:
    version = sys.version_info
    detail = f"{sys.executable} ({version.major}.{version.minor}.{version.micro})"
    if version >= (3, 11):
        return Check("python", "OK", detail, required=True)
    return Check("python", "SALAH", f"butuh Python >= 3.11; ditemukan {detail}", required=True)


def check_binary(name: str, *, required: bool = False) -> Check:
    path = shutil.which(name)
    if path is None:
        return Check(name, "HILANG" if required else "PERINGATAN", "belum terpasang", required)
    result = run_version_command(path, ["--version"])
    if result.returncode != 0 or not result.output:
        detail = version_error_detail(path, result)
        return Check(name, "SALAH" if required else "PERINGATAN", detail, required)
    detail = f"{path}; {result.output}"
    return Check(name, "OK", detail, required)


def check_tool(name: str) -> Check:
    path = find_tool_binary(name)
    if path is None:
        return Check(name, "PERINGATAN", "belum terpasang")
    result = run_version_command(path, ["-version"])
    version = parse_tool_version(name, result.stdout, result.stderr) if result.returncode == 0 else None
    if result.returncode != 0:
        return Check(name, "PERINGATAN", version_error_detail(path, result))
    if version is None:
        return Check(name, "PERINGATAN", f"{path}; versi tidak terbaca")
    return Check(name, "OK", f"{path}; {version}")


def check_go() -> Check:
    path = shutil.which("go")
    if path is None:
        return Check("go", "HILANG", "belum terpasang", required=True)
    result = run_version_command(path, ["version"])
    version = parse_go_version(result.output) if result.returncode == 0 else None
    if version is None:
        return Check("go", "ERROR", version_error_detail(path, result), required=True)
    return Check("go", "OK", f"{path}; {version}", required=True)


def check_httpx() -> Check:
    path = find_tool_binary("httpx")
    if path is None:
        return Check("httpx", "PERINGATAN", "belum terpasang")
    result = run_version_command(path, ["-version"])
    version = parse_projectdiscovery_httpx_version(result.stdout, result.stderr) if result.returncode == 0 else None
    if result.returncode != 0:
        return Check("httpx", "PERINGATAN", version_error_detail(path, result))
    if version is None:
        return Check("httpx", "PERINGATAN", f"{path}; versi tidak terbaca")
    return Check("httpx", "OK", f"{path}; {version}")


def parse_go_version(output: str) -> str | None:
    """Extract a Go version from the exact `go version` banner."""
    match = GO_VERSION.fullmatch(output.strip())
    return match.group(1) if match else None


def parse_tool_version(name: str, stdout: str, stderr: str) -> str | None:
    """Extract a short ProjectDiscovery tool version from separate command streams."""
    lines = [sanitize_version_output(line) for line in f"{stdout}\n{stderr}".splitlines()]
    lines = [INFO_PREFIX.sub("", line) for line in lines]
    candidates = [line for line in lines if line and not line.lstrip().startswith("WARNING")]

    if name == "httpx" and not any(
        "projectdiscovery" in line.lower() or "current version" in line.lower()
        for line in candidates
    ):
        return None

    for line in candidates:
        lowered = line.lower()
        if name.lower() in lowered or "version" in lowered:
            match = VERSION_VALUE.search(line)
            if match:
                return match.group(0)
    return None


def parse_projectdiscovery_httpx_version(stdout: str, stderr: str = "") -> str | None:
    """Extract a ProjectDiscovery httpx version without running a command."""
    return parse_tool_version("httpx", stdout, stderr)


def run_version_command(path: str, arguments: list[str]) -> VersionCommand:
    try:
        result = subprocess.run(
            [path, *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return VersionCommand(returncode=None, stdout="", stderr="")
    return VersionCommand(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def sanitize_version_output(output: str) -> str:
    return CONTROL_SEQUENCE.sub("", output).replace("\n", " ").strip()[:200]


def find_tool_binary(name: str) -> str | None:
    path = shutil.which(name)
    if path is not None:
        return path
    candidate = Path.home() / "go" / "bin" / name
    if candidate.is_file() and candidate.stat().st_mode & stat.S_IXUSR:
        return str(candidate)
    return None


def version_error_detail(path: str, result: VersionCommand) -> str:
    if result.returncode is None:
        return f"{path}; perintah versi gagal dijalankan"
    if result.output:
        return f"{path}; perintah versi gagal (exit {result.returncode}): {result.output}"
    return f"{path}; perintah versi gagal (exit {result.returncode})"


def check_config_permissions() -> Check:
    config_path = Path.home() / ".config" / "daysra" / "config.toml"
    if not config_path.exists():
        return Check("config.toml", "OK", "tidak ada (belum dikonfigurasi)")
    permissions = stat.S_IMODE(config_path.stat().st_mode)
    if permissions != 0o600:
        return Check("config.toml", "SALAH", f"{config_path}; izin {permissions:04o}, harus 0600")
    return Check("config.toml", "OK", f"{config_path}; izin 0600")


def check_engine() -> Check:
    project_engine = Path(__file__).resolve().parents[3] / "bin" / "daysra-engine"
    path = shutil.which("daysra-engine")
    candidate = Path(path) if path else project_engine
    if not candidate.is_file() or not candidate.exists():
        return Check("daysra-engine", "PERINGATAN", "belum dibangun")
    result = run_version_command(str(candidate), ["--version"])
    if result.returncode != 0 or not result.output:
        return Check("daysra-engine", "PERINGATAN", version_error_detail(str(candidate), result))
    return Check("daysra-engine", "OK", f"{candidate}; {result.output}")
