from __future__ import annotations

import os
from pathlib import Path

import pytest

from daysra.core.config import (
    find_engine_binary,
    get_config_dir,
    get_config_path,
    validate_config_permissions,
)


class TestConfigDirectoryResolution:
    """Validate configuration directory and path resolution hierarchy."""

    def test_daysra_config_dir_precedence(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        custom_dir = tmp_path / "custom_config"
        monkeypatch.setenv("DAYSRA_CONFIG_DIR", str(custom_dir))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))

        resolved = get_config_dir()
        assert resolved == custom_dir
        assert get_config_path() == custom_dir / "config.toml"

    def test_daysra_config_dir_empty_falls_back_to_xdg(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("DAYSRA_CONFIG_DIR", "   ")
        xdg_dir = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))

        resolved = get_config_dir()
        assert resolved == xdg_dir / "daysra"
        assert get_config_path() == xdg_dir / "daysra" / "config.toml"

    def test_xdg_config_home_resolution(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_CONFIG_DIR", raising=False)
        xdg_dir = tmp_path / "xdg_config"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))

        resolved = get_config_dir()
        assert resolved == xdg_dir / "daysra"
        assert get_config_path() == xdg_dir / "daysra" / "config.toml"

    def test_default_fallback_to_home_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_CONFIG_DIR", raising=False)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        fake_home = tmp_path / "fake_home"
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        resolved = get_config_dir()
        assert resolved == fake_home / ".config" / "daysra"
        assert get_config_path() == fake_home / ".config" / "daysra" / "config.toml"


class TestValidateConfigPermissions:
    """Validate permission enforcement (strict 0600) on config.toml."""

    def test_nonexistent_config_is_valid_with_unconfigured_message(
        self,
        tmp_path: Path,
    ) -> None:
        nonexistent = tmp_path / "nonexistent_config.toml"
        valid, msg = validate_config_permissions(nonexistent)
        assert valid is True
        assert "tidak ada" in msg
        assert "belum dikonfigurasi" in msg

    def test_valid_0600_permissions(
        self,
        tmp_path: Path,
    ) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_text("dummy = true\n", encoding="utf-8")
        cfg.chmod(0o600)

        valid, msg = validate_config_permissions(cfg)
        assert valid is True
        assert "izin 0600" in msg

    @pytest.mark.parametrize(
        "invalid_mode",
        [0o644, 0o660, 0o664, 0o700, 0o755, 0o777],
    )
    def test_invalid_permissions_rejected(
        self,
        tmp_path: Path,
        invalid_mode: int,
    ) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_text("dummy = true\n", encoding="utf-8")
        cfg.chmod(invalid_mode)

        valid, msg = validate_config_permissions(cfg)
        assert valid is False
        assert "wajib 0600" in msg
        assert f"{invalid_mode:04o}" in msg


class TestFindEngineBinary:
    """Validate engine binary discovery hierarchy and executable verification."""

    def test_env_var_override_valid_executable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        fake_engine = tmp_path / "custom-engine"
        fake_engine.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_engine.chmod(0o755)

        monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(fake_engine))
        found = find_engine_binary()
        assert found == fake_engine

    def test_env_var_override_non_executable_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        fake_engine = tmp_path / "custom-engine-no-exec"
        fake_engine.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_engine.chmod(0o644)  # not executable

        monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(fake_engine))
        assert find_engine_binary() is None

    def test_env_var_override_nonexistent_path_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", str(tmp_path / "missing-binary"))
        assert find_engine_binary() is None

    def test_env_var_override_empty_string_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # If DAYSRA_ENGINE_BIN is set to empty or whitespace, it explicitly returns None
        monkeypatch.setenv("DAYSRA_ENGINE_BIN", "   ")
        assert find_engine_binary() is None

    def test_path_search_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_ENGINE_BIN", raising=False)
        fake_bin_dir = tmp_path / "bin"
        fake_bin_dir.mkdir()
        fake_bin = fake_bin_dir / "daysra-engine"
        fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        # Prepend fake_bin_dir to PATH
        monkeypatch.setenv("PATH", f"{fake_bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        found = find_engine_binary()
        assert found == fake_bin

    def test_repo_binary_fallback(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("DAYSRA_ENGINE_BIN", raising=False)
        # Isolate PATH from any system daysra-engine
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        repo_engine = Path(__file__).resolve().parents[1] / "bin" / "daysra-engine"
        found = find_engine_binary()
        if repo_engine.is_file() and os.access(repo_engine, os.X_OK):
            assert found == repo_engine
        else:
            assert found is None

    def test_binary_not_found_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("DAYSRA_ENGINE_BIN", raising=False)
        monkeypatch.setenv("PATH", str(tmp_path))  # empty directory in PATH

        # Mock repo binary path by pointing config resolution away or checking missing
        import daysra.core.config as config_mod

        # Temporarily mock repo_engine path in find_engine_binary
        orig_file = config_mod.__file__
        try:
            config_mod.__file__ = str(tmp_path / "dummy_core" / "config.py")
            found = find_engine_binary()
            assert found is None
        finally:
            config_mod.__file__ = orig_file

