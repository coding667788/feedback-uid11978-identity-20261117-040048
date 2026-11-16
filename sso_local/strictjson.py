"""Strict JSON helpers.

The local protocol treats every JSON object as a security boundary: duplicate
member names are rejected at every nesting level, and NaN/Infinity are not
accepted.  This module deliberately does not rely on a third party parser.
"""

from __future__ import annotations

import json
from typing import Any


class StrictJSONError(ValueError):
    """Raised when input is not strict, duplicate-free JSON."""


def _reject_constant(value: str) -> Any:
    raise StrictJSONError(f"non-finite JSON number is not allowed: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError(f"duplicate JSON member: {key!r}")
        obj[key] = value
    return obj


def loads_strict(text: str | bytes) -> Any:
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("input is not valid UTF-8") from exc
    if not isinstance(text, str):
        raise StrictJSONError("JSON input must be text")
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise StrictJSONError(str(exc)) from exc


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic bytes used for signatures and content hashes."""

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def require_object(value: Any, what: str = "value") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StrictJSONError(f"{what} must be a JSON object")
    return value
