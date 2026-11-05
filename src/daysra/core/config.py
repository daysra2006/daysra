from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def get_config_dir() -> Path:
    """Return the configuration directory for DAYSRA."""
    if "DAYSRA_CONFIG_DIR" in os.environ and os.environ["DAYSRA_CONFIG_DIR"].strip():
        p = Path(os.environ["DAYSRA_CONFIG_DIR"])
    else:
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg_config) if (xdg_config and xdg_config.strip()) else (Path.home() / ".config")
        p = base / "daysra"
    return p


def get_config_path() -> Path:
    """Return the configuration file path."""
    return get_config_dir() / "config.toml"


def validate_config_permissions(config_path: Path | None = None) -> tuple[bool, str]:
    """Validate that config.toml permissions are strict (0600 per Design Freeze 11)."""
    path = config_path or get_config_path()
    if not path.exists():
        return True, "tidak ada (belum dikonfigurasi)"

    permissions = stat.S_IMODE(path.stat().st_mode)
    if permissions != 0o600:
        return (
            False,
            f"File konfigurasi {path} memiliki izin {permissions:04o}; wajib 0600. Jalankan: chmod 600 {path}",
        )
    return True, f"{path}; izin 0600"


def find_engine_binary() -> Path | None:
    """Locate the daysra-engine binary."""
    # 1. Environment variable override
    env_bin = os.environ.get("DAYSRA_ENGINE_BIN")
    if env_bin is not None:
        if not env_bin.strip():
            return None
        p = Path(env_bin.strip())
        if p.is_file() and os.access(p, os.X_OK):
            return p
        return None

    # 2. PATH search
    which_path = shutil.which("daysra-engine")
    if which_path:
        p = Path(which_path)
        if p.is_file() and os.access(p, os.X_OK):
            return p

    # 3. Project repo bin/daysra-engine
    repo_engine = Path(__file__).resolve().parents[3] / "bin" / "daysra-engine"
    if repo_engine.is_file() and os.access(repo_engine, os.X_OK):
        return repo_engine

    return None


__all__ = [
    "find_engine_binary",
    "get_config_dir",
    "get_config_path",
    "validate_config_permissions",
]
