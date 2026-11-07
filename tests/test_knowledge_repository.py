from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from daysra.knowledge import load_knowledge_base

REPO_ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = REPO_ROOT / "knowledge"
SCHEMA_PATH = REPO_ROOT / "schema" / "knowledge.v1.json"


def _raw_entries(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [data]
    assert isinstance(data, list)
    return [entry for entry in data if isinstance(entry, dict)]


def _knowledge_files() -> list[Path]:
    files = sorted(KNOWLEDGE_DIR.glob("*.yaml"))
    assert files, f"folder knowledge tidak memuat file YAML: {KNOWLEDGE_DIR}"
    return files


def test_repository_knowledge_base_loads_without_duplicates() -> None:
    knowledge = load_knowledge_base(KNOWLEDGE_DIR, schema_path=SCHEMA_PATH)

    template_ids = [
        entry["template_id"]
        for path in _knowledge_files()
        for entry in _raw_entries(path)
    ]
    assert knowledge.entries
    assert len(template_ids) == len(set(template_ids)), "template_id duplikat"
    assert set(knowledge.entries) == set(template_ids)


def test_every_repository_entry_matches_the_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)

    for path in _knowledge_files():
        entries = _raw_entries(path)
        assert entries, f"{path} tidak memuat entri"
        for entry in entries:
            errors = sorted(validator.iter_errors(entry), key=lambda error: list(error.path))
            assert not errors, f"{path}: {errors[0].message}"


def test_each_knowledge_file_template_id_matches_its_filename() -> None:
    for path in _knowledge_files():
        for entry in _raw_entries(path):
            assert entry["template_id"] == path.stem, (
                f"{path.name} memuat template_id {entry['template_id']!r}"
            )
