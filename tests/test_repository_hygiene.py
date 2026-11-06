from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def isolated_git_sandbox(tmp_path: Path) -> Path:
    """Creates a temporary isolated git repository using the project's root .gitignore."""
    repo_root = Path(__file__).resolve().parent.parent
    gitignore_src = repo_root / ".gitignore"
    assert gitignore_src.is_file(), "Root .gitignore must exist"

    sandbox = tmp_path / "sandbox_repo"
    sandbox.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(sandbox)], check=True, capture_output=True)

    # Copy the actual .gitignore from DAYSRA repository root
    (sandbox / ".gitignore").write_text(gitignore_src.read_text(encoding="utf-8"), encoding="utf-8")
    return sandbox


def is_path_ignored(repo_path: Path, relative_file: str) -> bool:
    """Queries git check-ignore in the sandbox repository."""
    res = subprocess.run(
        ["git", "check-ignore", "-q", relative_file],
        cwd=str(repo_path),
        check=False,
    )
    return res.returncode == 0


class TestGitIgnoreHygiene:
    """Validate repository .gitignore rules against secret leaks and template accessibility."""

    def test_env_files_are_ignored(self, isolated_git_sandbox: Path) -> None:
        """Sensitive environment files must be ignored."""
        assert is_path_ignored(isolated_git_sandbox, ".env"), ".env must be ignored by Git"
        assert is_path_ignored(isolated_git_sandbox, ".env.local"), ".env.local must be ignored by Git"
        assert is_path_ignored(isolated_git_sandbox, ".env.production"), ".env.production must be ignored by Git"
        assert is_path_ignored(isolated_git_sandbox, "subdir/.env"), "Subdirectory .env must be ignored"

    def test_env_example_templates_are_not_ignored(self, isolated_git_sandbox: Path) -> None:
        """Sample environment templates must be trackable in Git."""
        assert not is_path_ignored(isolated_git_sandbox, ".env.example"), ".env.example must not be ignored"
        assert not is_path_ignored(isolated_git_sandbox, ".env.sample"), ".env.sample must not be ignored"

    def test_scope_yaml_is_ignored(self, isolated_git_sandbox: Path) -> None:
        """User scope.yaml containing authorized operational scope must be ignored to prevent accidental leaks."""
        assert is_path_ignored(isolated_git_sandbox, "scope.yaml"), "scope.yaml must be ignored by Git"
        assert is_path_ignored(isolated_git_sandbox, "subdir/scope.yaml"), "Subdirectory scope.yaml must be ignored"

    def test_scope_yaml_example_is_not_ignored(self, isolated_git_sandbox: Path) -> None:
        """Sample scope template scope.yaml.example must be trackable in Git."""
        assert not is_path_ignored(isolated_git_sandbox, "scope.yaml.example"), "scope.yaml.example must not be ignored"


class TestScopeYamlIntegrity:
    """Validate repository root scope.yaml schema compliance and absence of sensitive targets."""

    def test_scope_yaml_schema_and_placeholders(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        scope_path = repo_root / "scope.yaml"
        assert scope_path.is_file(), "scope.yaml must exist in repository root"

        content = scope_path.read_text(encoding="utf-8")
        lines = content.splitlines()

        # Validate allowed top-level keys
        allowed_keys = {"authorization", "allow", "deny", "max_rate", "timeout"}
        found_keys: set[str] = set()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            if ":" in stripped and not line.startswith((" ", "\t")):
                key = stripped.split(":", 1)[0].strip()
                found_keys.add(key)

        assert found_keys.issubset(allowed_keys), f"Unexpected keys in scope.yaml: {found_keys - allowed_keys}"
        assert "authorization" in found_keys, "authorization key is required"
        assert "allow" in found_keys, "allow key is required"

        # Check for sensitive keywords / real targets
        forbidden_terms = [
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "bearer",
            "private_key",
            "credentials",
        ]
        lower_content = content.lower()
        for term in forbidden_terms:
            assert term not in lower_content, f"Found sensitive term '{term}' in scope.yaml"

        # Check placeholder targets
        assert "example.com" in content, "scope.yaml should reference generic example.com placeholder"
