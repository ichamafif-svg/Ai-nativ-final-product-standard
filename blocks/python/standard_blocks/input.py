"""Request and response models (VALIDATE, CANON, MASS-ASSIGN, FIELD-AUTHZ, DATA-MIN): every body is declared, unknown
fields are refused, types are strict; responses list the fields they return.

    class OrderIn(Input):
        item: Text[100]
        quantity: Count
        email: Email

Beyond the checklists, every Input:
    - bounds what it holds even where a field forgot to: strings at MAX_TEXT, collections at MAX_ITEMS, numbers at
      MAX_NUMBER (no float NaN or infinity, no integer that costs seconds to print);
    - reads text in one Unicode form (NFC), and refuses invisible control characters and the bidirectional
      overrides behind "Trojan Source" and spoofed names (U+202A–U+202E, U+2066–U+2069), NUL and lone surrogates;
    - is frozen once validated: nothing downstream rewrites what was checked.
The JSON itself was already read strictly by the web guard (depth, duplicate keys, NaN, size).
"""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MAX_TEXT = 100_000
MAX_ITEMS = 10_000
MAX_NUMBER = 10 ** 15
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩﻿]")


class _Text:
    def __class_getitem__(cls, size: int):
        return Annotated[str, StringConstraints(max_length=int(size))]


Text = _Text                                                  # Text[100]: a string of at most 100 characters
Name = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Id = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)]
Email = Annotated[str, StringConstraints(pattern=r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$",
                                         max_length=254, to_lower=True)]
Count = Annotated[int, Field(ge=0, le=MAX_NUMBER)]
Money = Annotated[int, Field(ge=-MAX_NUMBER, le=MAX_NUMBER, description="minor units (cents): never a float")]


class InputRefused(ValueError):
    pass


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 64:
        raise InputRefused("nested too deep")
    if isinstance(value, str):
        if len(value) > MAX_TEXT:
            raise InputRefused("text too long")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise InputRefused("a lone surrogate") from None
        value = unicodedata.normalize("NFC", value)
        if CONTROL.search(value):
            raise InputRefused("an invisible control character")
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if abs(value) > MAX_NUMBER:
            raise InputRefused("number out of range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > MAX_NUMBER:
            raise InputRefused("number out of range")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise InputRefused("too many fields")
        return {_clean(k, depth + 1): _clean(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise InputRefused("too many items")
        return [_clean(v, depth + 1) for v in value]
    return value


class Input(BaseModel):
    """Base of every request body: unknown fields refused, no coercion between types, strings stripped once,
    bounded, one Unicode form, no invisible controls, frozen."""
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True, frozen=True,
                              allow_inf_nan=False, str_max_length=MAX_TEXT, hide_input_in_errors=True,
                              validate_default=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def _bounded(cls, data):
        try:
            return _clean(data)
        except InputRefused as exc:
            raise ValueError(str(exc)) from None


class Output(BaseModel):
    """Base of every response: built from ORM objects by attribute, only the declared fields leave."""
    model_config = ConfigDict(extra="ignore", from_attributes=True, allow_inf_nan=False)
