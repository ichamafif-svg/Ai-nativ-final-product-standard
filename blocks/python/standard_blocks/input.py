"""Request and response models (VALIDATE, CANON, MASS-ASSIGN, FIELD-AUTHZ, DATA-MIN): every body is declared, unknown
fields are refused, types are strict; responses list the fields they return."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Input(BaseModel):
    """Base of every request body: unknown fields refused, no coercion between types, strings stripped once."""
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True, frozen=True)


class Output(BaseModel):
    """Base of every response: built from ORM objects by attribute, only the declared fields leave."""
    model_config = ConfigDict(extra="ignore", from_attributes=True)
