from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import jsonschema
import yaml

KNOWLEDGE_SCHEMA_FILENAME = "knowledge.v1.json"


class KnowledgeError(Exception):
    """Raised when a knowledge base file cannot be read, parsed, or validated."""

    def __init__(self, path: Path | str, field: str, message: str) -> None:
        self.path = Path(path)
        self.field = field
        self.message = message
        super().__init__(f"{self.path}: field '{field}': {message}")


@dataclass(frozen=True)
class KnowledgeEntry:
    template_id: str
    title: str
    meaning: str
    impact: str
    verify_steps: tuple[str, ...]
    concept: str
    lang: str
    source: Path


@dataclass(frozen=True)
class KnowledgeBase:
    """Validated knowledge entries keyed by template_id."""

    entries: Mapping[str, KnowledgeEntry]

    def get(self, template_id: str) -> KnowledgeEntry | None:
        return self.entries.get(template_id)

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)


def default_knowledge_dir() -> Path:
    """Return the knowledge directory, allowing tests and users to override it."""
    override = os.environ.get("DAYSRA_KNOWLEDGE_DIR", "")
    if override.strip():
        return Path(override).expanduser()
    # src/daysra/knowledge/loader.py -> repository root
    return Path(__file__).resolve().parents[3] / "knowledge"


def default_schema_path() -> Path:
    """Return the knowledge JSON Schema shipped at the repository root."""
    return Path(__file__).resolve().parents[3] / "schema" / KNOWLEDGE_SCHEMA_FILENAME


def _load_schema(schema_path: Path | str | None) -> tuple[dict[str, Any], Any]:
    path = Path(schema_path) if schema_path is not None else default_schema_path()
    try:
        raw_schema = path.read_text(encoding="utf-8")
    except OSError as err:
        raise KnowledgeError(path, "<schema>", f"tidak dapat dibaca: {err}") from err
    try:
        schema = json.loads(raw_schema)
    except json.JSONDecodeError as err:
        raise KnowledgeError(path, "<schema>", f"JSON skema tidak valid: {err}") from err

    validator_cls = jsonschema.validators.validator_for(schema)
    try:
        validator_cls.check_schema(schema)
    except jsonschema.exceptions.SchemaError as err:
        raise KnowledgeError(path, "<schema>", f"skema tidak valid: {err.message}") from err
    return schema, validator_cls


def _error_field(error: jsonschema.ValidationError) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    if path:
        return path
    if error.validator == "required":
        missing = [name for name in error.validator_value if name not in error.instance]
        return ", ".join(str(name) for name in missing) or "<entri>"
    if error.validator == "additionalProperties":
        allowed = set(error.schema.get("properties", {}))
        extra = [name for name in error.instance if name not in allowed]
        return ", ".join(sorted(str(name) for name in extra)) or "<entri>"
    return "<entri>"


def _read_entries(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        raise KnowledgeError(path, "<file>", f"tidak dapat dibaca: {err}") from err

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise KnowledgeError(path, "<yaml>", f"YAML tidak valid: {err}") from err

    if data is None:
        raise KnowledgeError(path, "<yaml>", "file tidak memuat entri")
    if isinstance(data, Mapping):
        return [dict(data)]
    if isinstance(data, list):
        entries: list[dict[str, Any]] = []
        for index, item in enumerate(data):
            if not isinstance(item, Mapping):
                raise KnowledgeError(
                    path, f"[{index}]", "entri harus berupa objek YAML"
                )
            entries.append(dict(item))
        return entries
    raise KnowledgeError(path, "<yaml>", "isi file harus objek atau daftar objek")


def _to_entry(raw: Mapping[str, Any], source: Path) -> KnowledgeEntry:
    return KnowledgeEntry(
        template_id=str(raw["template_id"]),
        title=str(raw["title"]),
        meaning=str(raw["meaning"]),
        impact=str(raw["impact"]),
        verify_steps=tuple(str(step) for step in raw["verify_steps"]),
        concept=str(raw["concept"]),
        lang=str(raw["lang"]),
        source=source,
    )


def load_knowledge_base(
    directory: Path | str | None = None,
    *,
    schema_path: Path | str | None = None,
) -> KnowledgeBase:
    """Load and validate every ``knowledge/*.yaml`` entry.

    A missing or empty directory is not an error. Broken YAML, schema-invalid
    entries, and duplicate template_id values fail closed with a message that
    names the offending file and field.
    """
    knowledge_dir = Path(directory) if directory is not None else default_knowledge_dir()
    if not knowledge_dir.exists():
        return KnowledgeBase(MappingProxyType({}))
    if not knowledge_dir.is_dir():
        raise KnowledgeError(knowledge_dir, "<directory>", "bukan direktori")

    schema, validator_cls = _load_schema(schema_path)
    validator = validator_cls(schema)

    entries: dict[str, KnowledgeEntry] = {}
    sources: dict[str, Path] = {}
    for path in sorted(knowledge_dir.glob("*.yaml")):
        for raw_entry in _read_entries(path):
            errors = sorted(
                validator.iter_errors(raw_entry),
                key=lambda error: [str(part) for part in error.absolute_path],
            )
            if errors:
                first_error = errors[0]
                raise KnowledgeError(
                    path, _error_field(first_error), first_error.message
                )

            entry = _to_entry(raw_entry, path)
            existing_source = sources.get(entry.template_id)
            if existing_source is not None:
                raise KnowledgeError(
                    path,
                    "template_id",
                    f"duplikat '{entry.template_id}' juga ada di {existing_source}",
                )
            sources[entry.template_id] = path
            entries[entry.template_id] = entry

    return KnowledgeBase(MappingProxyType(entries))


__all__ = [
    "KNOWLEDGE_SCHEMA_FILENAME",
    "KnowledgeBase",
    "KnowledgeEntry",
    "KnowledgeError",
    "default_knowledge_dir",
    "default_schema_path",
    "load_knowledge_base",
]
