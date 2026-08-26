# SPDX-License-Identifier: Apache-2.0
"""Deterministic JSON, timestamp, and identifier helpers."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import cast

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def bounded_string(value: object, field_name: str, maximum: int = 512) -> str:
    """Validate one safe bounded string."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or _CONTROL_RE.search(value) is not None
    ):
        raise ValueError(f"{field_name} must be a bounded non-empty string")
    return value


def optional_string(value: object, field_name: str, maximum: int = 512) -> str | None:
    return None if value is None else bounded_string(value, field_name, maximum)


def fingerprint(value: object, field_name: str = "fingerprint") -> str:
    result = bounded_string(value, field_name, 71)
    if _FINGERPRINT_RE.fullmatch(result) is None:
        raise ValueError(f"{field_name} must be a sha256 fingerprint")
    return result


def canonical_value(
    value: object,
    *,
    field_name: str = "value",
    maximum_depth: int = 12,
    maximum_items: int = 10_000,
) -> JsonValue:
    """Return a defensive JSON copy while rejecting ambiguous values."""

    seen_items = 0

    def visit(item: object, path: str, depth: int) -> JsonValue:
        nonlocal seen_items
        seen_items += 1
        if seen_items > maximum_items:
            raise ValueError(f"{field_name} contains too many values")
        if depth > maximum_depth:
            raise ValueError(f"{field_name} exceeds maximum nesting depth")
        if item is None or isinstance(item, (bool, int, str)):
            return cast(JsonScalar, item)
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError(f"{path} must not contain NaN or infinity")
            return item
        if isinstance(item, Mapping):
            result: dict[str, JsonValue] = {}
            keys = tuple(item)
            if any(
                not isinstance(key, str) or not key or _CONTROL_RE.search(key) is not None
                for key in keys
            ):
                raise ValueError(f"{path} contains an invalid object key")
            for key in sorted(cast(tuple[str, ...], keys)):
                if not key:
                    raise ValueError(f"{path} contains an invalid object key")
                result[key] = visit(item[key], f"{path}.{key}", depth + 1)
            return result
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            return [visit(child, f"{path}[{index}]", depth + 1) for index, child in enumerate(item)]
        raise TypeError(f"{path} must contain only JSON-compatible values")

    return visit(value, field_name, 0)


def canonical_mapping(
    value: object,
    *,
    field_name: str = "value",
    maximum_entries: int = 256,
) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be an object")
    if len(value) > maximum_entries:
        raise ValueError(f"{field_name} may contain at most {maximum_entries} entries")
    result = canonical_value(value, field_name=field_name)
    assert isinstance(result, dict)
    return result


def canonical_json(value: object) -> str:
    normalized = canonical_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_fingerprint(value: object) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def utc_timestamp(value: datetime | str, field_name: str = "timestamp") -> str:
    """Normalize a timestamp to RFC 3339 UTC with microsecond precision."""

    parsed: datetime
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from exc
    else:
        raise TypeError(f"{field_name} must be a datetime or RFC 3339 string")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


__all__ = [
    "JsonScalar",
    "JsonValue",
    "bounded_string",
    "canonical_json",
    "canonical_mapping",
    "canonical_value",
    "fingerprint",
    "optional_string",
    "sha256_fingerprint",
    "utc_timestamp",
]
