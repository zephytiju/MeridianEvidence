# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from meridian_storage.evidence.canonical import (
    bounded_string,
    canonical_json,
    canonical_mapping,
    canonical_value,
    fingerprint,
    optional_string,
    sha256_fingerprint,
    utc_timestamp,
)


def test_canonical_json_is_sorted_and_defensive() -> None:
    original = {"z": [2, 1], "a": {"ok": True}}
    normalized = canonical_mapping(original)
    original["z"].append(0)
    assert canonical_json(normalized) == '{"a":{"ok":true},"z":[2,1]}'
    assert sha256_fingerprint(normalized).startswith("sha256:")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), b"bytes"])
def test_canonical_rejects_non_json_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_value(value)


def test_canonical_rejects_bad_keys_depth_and_size() -> None:
    with pytest.raises(ValueError, match="invalid object key"):
        canonical_mapping({1: "value"})
    with pytest.raises(ValueError, match="invalid object key"):
        canonical_mapping({"bad\x00": "value"})
    with pytest.raises(ValueError, match="nesting depth"):
        canonical_value([[[1]]], maximum_depth=1)
    with pytest.raises(ValueError, match="too many"):
        canonical_value([1, 2], maximum_items=2)
    with pytest.raises(TypeError, match="object"):
        canonical_mapping([])
    with pytest.raises(ValueError, match="at most"):
        canonical_mapping({"a": 1, "b": 2}, maximum_entries=1)


def test_string_and_fingerprint_bounds() -> None:
    assert bounded_string("ok", "field") == "ok"
    assert optional_string(None, "field") is None
    assert optional_string("ok", "field") == "ok"
    with pytest.raises(ValueError, match="bounded"):
        bounded_string("", "field")
    with pytest.raises(ValueError, match="bounded"):
        bounded_string("x" * 513, "field")
    with pytest.raises(ValueError, match="sha256"):
        fingerprint("bad")
    valid = "sha256:" + "a" * 64
    assert fingerprint(valid) == valid


def test_timestamp_normalization() -> None:
    value = datetime(2026, 8, 25, 5, tzinfo=UTC) + timedelta(microseconds=123)
    assert utc_timestamp(value) == "2026-08-25T05:00:00.000123Z"
    assert utc_timestamp("2026-08-25T05:00:00Z") == "2026-08-25T05:00:00.000000Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        utc_timestamp(datetime(2026, 8, 25))
    with pytest.raises(ValueError, match="RFC 3339"):
        utc_timestamp("yesterday")
    with pytest.raises(TypeError, match="datetime"):
        utc_timestamp(1)  # type: ignore[arg-type]
