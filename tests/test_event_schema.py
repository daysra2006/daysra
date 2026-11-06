from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from daysra.core.contracts import Event, validate_event


@pytest.fixture
def event_schema() -> dict[str, object]:
    """Load schema/event.v1.json from project root."""
    schema_path = Path(__file__).resolve().parents[1] / "schema" / "event.v1.json"
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def valid_event_payload() -> dict[str, object]:
    """Return a baseline valid event payload."""
    return {
        "schema_version": "1",
        "type": "run_start",
        "run_id": "01J00000000000000000000000",
        "ts": "2026-11-05T12:00:00Z",
        "data": {"target": "example.com"},
    }


VALID_EVENT_TYPES = [
    "run_start",
    "host",
    "http",
    "finding",
    "progress",
    "warning",
    "run_end",
]


class TestJsonSchemaValidation:
    """Validate JSON Schema enforcement using jsonschema validator."""

    def test_schema_file_exists_and_is_valid(self, event_schema: dict[str, object]) -> None:
        validator_cls = jsonschema.validators.validator_for(event_schema)
        validator_cls.check_schema(event_schema)
        assert event_schema.get("title") == "DAYSRA event v1"

    @pytest.mark.parametrize("event_type", VALID_EVENT_TYPES)
    def test_all_valid_event_types_pass_schema(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
        event_type: str,
    ) -> None:
        payload = dict(valid_event_payload)
        payload["type"] = event_type
        jsonschema.validate(instance=payload, schema=event_schema)

    def test_schema_rejects_missing_required_fields(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        for field in ["schema_version", "type", "run_id", "ts", "data"]:
            broken = dict(valid_event_payload)
            del broken[field]
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(instance=broken, schema=event_schema)

    def test_schema_rejects_invalid_schema_version(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["schema_version"] = "2"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=broken, schema=event_schema)

    def test_schema_rejects_unknown_event_type(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["type"] = "unknown_type"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=broken, schema=event_schema)

    def test_schema_rejects_empty_run_id(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["run_id"] = ""
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=broken, schema=event_schema)

    def test_schema_rejects_non_object_data(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["data"] = "not an object"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=broken, schema=event_schema)

    def test_schema_rejects_additional_properties(
        self,
        event_schema: dict[str, object],
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["unexpected_key"] = "forbidden"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=broken, schema=event_schema)


class TestPydanticContractValidation:
    """Validate Pydantic Event model and validate_event function."""

    @pytest.mark.parametrize("event_type", VALID_EVENT_TYPES)
    def test_valid_event_parsing(
        self,
        valid_event_payload: dict[str, object],
        event_type: str,
    ) -> None:
        payload = dict(valid_event_payload)
        payload["type"] = event_type
        event = validate_event(payload)

        assert isinstance(event, Event)
        assert event.schema_version == "1"
        assert event.type == event_type
        assert event.run_id == "01J00000000000000000000000"
        assert isinstance(event.ts, datetime)
        assert event.ts == datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)
        assert event.data == {"target": "example.com"}

    def test_reject_whitespace_only_run_id(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["run_id"] = "    \t  \n "
        with pytest.raises(ValidationError, match="run_id must not be blank"):
            validate_event(broken)

    def test_reject_empty_run_id(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["run_id"] = ""
        with pytest.raises(ValidationError):
            validate_event(broken)

    def test_reject_extra_fields(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["extra_property"] = 123
        with pytest.raises(ValidationError, match="extra_forbidden"):
            validate_event(broken)

    def test_reject_invalid_schema_version(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["schema_version"] = "2"
        with pytest.raises(ValidationError):
            validate_event(broken)

    def test_reject_invalid_event_type(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["type"] = "invalid_event"
        with pytest.raises(ValidationError):
            validate_event(broken)

    def test_reject_invalid_timestamp(
        self,
        valid_event_payload: dict[str, object],
    ) -> None:
        broken = dict(valid_event_payload)
        broken["ts"] = "not-a-timestamp"
        with pytest.raises(ValidationError):
            validate_event(broken)

