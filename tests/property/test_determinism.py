# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from meridian_storage.evidence import EvidencePolicy, EvidenceQuery, deterministic_evidence_id
from meridian_storage.evidence.canonical import canonical_json, sha256_fingerprint

safe_keys = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1, max_size=12)
json_scalars = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=30)
)
json_values = st.recursive(
    json_scalars,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(safe_keys, children, max_size=5)
    ),
    max_leaves=20,
)


@given(st.dictionaries(safe_keys, json_values, max_size=10))
def test_canonical_fingerprint_ignores_mapping_insertion_order(value: dict[str, object]) -> None:
    reversed_value = dict(reversed(tuple(value.items())))
    assert canonical_json(value) == canonical_json(reversed_value)
    assert sha256_fingerprint(value) == sha256_fingerprint(reversed_value)


@given(st.dictionaries(safe_keys, json_values, min_size=1, max_size=10))
def test_record_id_and_policy_decision_are_deterministic(value: dict[str, object]) -> None:
    policy = EvidencePolicy("deterministic")
    assert deterministic_evidence_id(value) == deterministic_evidence_id(dict(value))
    assert policy.apply(value).to_dict() == policy.apply(dict(value)).to_dict()


@given(st.dictionaries(safe_keys, json_values, max_size=8))
def test_query_fingerprint_is_deterministic(where: dict[str, object]) -> None:
    first = EvidenceQuery("runtime.logs", where=where)
    second = EvidenceQuery("runtime.logs", where=dict(reversed(tuple(where.items()))))
    assert first.fingerprint == second.fingerprint
