from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"]
    type: Literal["run_start", "host", "http", "finding", "progress", "warning", "run_end"]
    run_id: str = Field(min_length=1)
    ts: datetime
    data: dict[str, object]

    @field_validator("run_id")
    @classmethod
    def run_id_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("run_id must not be blank")
        return value


def validate_event(payload: object) -> Event:
    """Validate one JSONL event against the M0 event contract."""
    return Event.model_validate(payload)


__all__ = ["Event", "ValidationError", "validate_event"]
