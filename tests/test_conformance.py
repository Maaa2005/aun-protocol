"""Conformance checks for the AUN Protocol 0.2 examples and reference tool.

Run from the repository root: `pytest -q`.

Optional cross-check against the ENISHI Local Core verifier: set
ENISHI_LOCAL_CORE to the path of services/local-core. The cross-check tests
are skipped when it is not set.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import make_examples  # noqa: E402
from aun_reference import (  # noqa: E402
    VerificationError,
    compute_payload_hash,
    node_id_from_public_key,
    sign_envelope,
    verify_envelope,
)

EXAMPLES = ROOT / "examples"
SESSION_DIRS = sorted(p for p in EXAMPLES.iterdir() if p.is_dir())
KEYS = json.loads((EXAMPLES / "keys.json").read_text(encoding="utf-8"))["nodes"]
PUBLIC_KEY_BY_NODE = {n["node_id"]: n["public_key"] for n in KEYS.values()}
TERMINAL = {"ACCEPT", "REJECT", "ERROR"}
# SPEC section 4.
TRANSITIONS = {
    None: {"REQUEST"},
    "REQUEST": {"PROPOSE", "REJECT", "ERROR"},
    "PROPOSE": {"ACCEPT", "COUNTER", "REJECT", "ERROR"},
    "COUNTER": {"ACCEPT", "COUNTER", "REJECT", "ERROR"},
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def session_messages(directory: Path) -> list[dict]:
    return [load(p) for p in sorted(directory.glob("*.json"))]


ALL_FILES = sorted(p for d in SESSION_DIRS for p in d.glob("*.json"))


def created_at(envelope: dict) -> datetime:
    return datetime.fromisoformat(envelope["created_at"])


# ---- canonicalization ------------------------------------------------------


def test_jcs_vectors_reproduce():
    vectors = load(ROOT / "test-vectors" / "jcs-v0.2.json")["vectors"]
    assert vectors
    for vector in vectors:
        assert rfc8785.dumps(vector["value"]).decode("utf-8") == vector["canonical_utf8"]


def test_jcs_serializes_whole_floats_without_fraction():
    assert rfc8785.dumps({"x": 3000.0}) == b'{"x":3000}'


# ---- examples --------------------------------------------------------------


def test_expected_example_set_exists():
    names = {d.name: [p.name for p in sorted(d.glob("*.json"))] for d in SESSION_DIRS}
    assert names == {
        "cost-split": ["01-request.json", "02-propose.json", "03-counter.json", "04-accept.json"],
        "cost-split-rejected": ["01-request.json", "02-propose.json", "03-reject.json"],
        "meeting-schedule": ["01-request.json", "02-propose.json", "03-accept.json"],
        "meeting-schedule-no-slot": [
            "01-request.json", "02-propose.json", "03-counter.json",
            "04-counter.json", "05-error.json",
        ],
    }


def test_keys_file_is_marked_test_only():
    text = (EXAMPLES / "keys.json").read_text(encoding="utf-8")
    assert "TEST ONLY - never use these keys" in text


def test_node_ids_match_public_keys():
    for node in KEYS.values():
        raw = base64.b64decode(node["public_key"])
        assert len(raw) == 32
        assert node["node_id"] == node_id_from_public_key(raw)
        seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(node["seed_hex"]))
        derived = seed.public_key().public_bytes_raw()
        assert derived == raw


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_example_verifies(path):
    envelope = load(path)
    key = PUBLIC_KEY_BY_NODE[envelope["sender_node_id"]]
    # Schema, signature and payload_hash. The time window is checked against
    # the message's own created_at because the examples are dated 2099.
    verify_envelope(envelope, key, now=created_at(envelope))
    assert envelope["payload_hash"] == compute_payload_hash(
        envelope["payload"], envelope["delta"]
    )
    assert node_id_from_public_key(base64.b64decode(key)) == envelope["sender_node_id"]
    assert envelope["receiver_node_id"] in PUBLIC_KEY_BY_NODE
    assert envelope["sender_node_id"] != envelope["receiver_node_id"]
    assert envelope["sender_agent_id"] != envelope["receiver_agent_id"]
    # The file uses the field order of SPEC section 2 and a trailing newline.
    assert path.read_text(encoding="utf-8").endswith("}\n")


def test_message_ids_and_nonces_unique_across_examples():
    envelopes = [load(p) for p in ALL_FILES]
    assert len({e["message_id"] for e in envelopes}) == len(envelopes)
    assert len({e["nonce"] for e in envelopes}) == len(envelopes)


@pytest.mark.parametrize("directory", SESSION_DIRS, ids=lambda d: d.name)
def test_session_sequence_and_transitions(directory):
    messages = session_messages(directory)
    first = messages[0]
    previous_type = None
    counters = 0
    for index, message in enumerate(messages, start=1):
        assert message["sequence"] == index
        # TRANSITIONS has no entry for terminal types, so a message after
        # ACCEPT, REJECT or ERROR fails here.
        assert previous_type not in TERMINAL
        assert message["message_type"] in TRANSITIONS[previous_type]
        # Session binding (SPEC section 8 step 9).
        for field in ("session_id", "intent", "session_version"):
            assert message[field] == first[field]
        parties = {first["sender_agent_id"], first["receiver_agent_id"]}
        assert {message["sender_agent_id"], message["receiver_agent_id"]} == parties
        if message["message_type"] == "COUNTER":
            counters += 1
            assert counters <= 3
        previous_type = message["message_type"]
        # Timestamps do not go backwards.
        if index > 1:
            assert created_at(message) >= created_at(messages[index - 2])
    assert messages[-1]["message_type"] in TERMINAL


@pytest.mark.parametrize("directory", SESSION_DIRS, ids=lambda d: d.name)
def test_session_party_alternation(directory):
    messages = session_messages(directory)
    # REQUEST and PROPOSE come from the initiator; replies alternate after that.
    assert messages[0]["sender_agent_id"] == messages[1]["sender_agent_id"]
    for earlier, later in zip(messages[1:], messages[2:]):
        assert later["sender_agent_id"] == earlier["receiver_agent_id"]
        assert later["sender_node_id"] == earlier["receiver_node_id"]
        assert later["receiver_node_id"] == earlier["sender_node_id"]
    assert messages[0]["sender_node_id"] == messages[1]["sender_node_id"]
    assert messages[0]["receiver_node_id"] == messages[1]["receiver_node_id"]


def test_message_shapes_follow_spec_section_3():
    for path in ALL_FILES:
        e = load(path)
        kind = e["message_type"]
        if kind == "REQUEST":
            assert e["delta"] == {}
            assert e["payload"]["intent"] == e["intent"]
        elif kind in ("PROPOSE", "ACCEPT", "ERROR"):
            assert e["payload"] == {}
        elif kind in ("COUNTER", "REJECT"):
            assert set(e["payload"]) == {"public_reason"}
        if kind in ("REJECT", "ERROR"):
            assert set(e["delta"]) == {"code"}
        assert e["requires_human_approval"] is False
        assert e["session_version"] == 1


def test_meeting_examples_are_consistent():
    for directory in SESSION_DIRS:
        if not directory.name.startswith("meeting-schedule"):
            continue
        messages = session_messages(directory)
        request = messages[0]["payload"]
        offered = None
        for message in messages[1:]:
            slots = message["delta"].get("candidate_slots", [])
            assert len(slots) <= 5
            for s in slots + ([message["delta"]["selected_slot"]] if "selected_slot" in message["delta"] else []):
                start = datetime.fromisoformat(s["start"])
                end = datetime.fromisoformat(s["end"])
                assert start.utcoffset() == timedelta(hours=9)
                assert end - start == timedelta(minutes=request["duration_minutes"])
                assert start.second == 0 and "T" in s["start"] and len(s["start"]) == len("2099-01-01T13:00+09:00")
                assert request["date_range"]["start"] <= s["start"][:10] <= request["date_range"]["end"]
                times = request["preferred_time_ranges"]
                assert any(r["start"] <= s["start"][11:16] and s["end"][11:16] <= r["end"] for r in times)
            if message["message_type"] == "ACCEPT":
                assert message["delta"]["selected_slot"] in offered
            if slots:
                offered = slots
            if message["message_type"] == "COUNTER":
                assert message["payload"]["public_reason"] == "no_common_slot"


def test_cost_examples_are_consistent():
    for directory in SESSION_DIRS:
        if not directory.name.startswith("cost-split"):
            continue
        messages = session_messages(directory)
        request = messages[0]["payload"]
        assert 0 < request["total_amount"]
        assert 0 <= request["proposed_share"] <= request["total_amount"]
        assert len(request["currency"]) == 3
        standing = None
        for message in messages[1:]:
            delta = message["delta"]
            for field in ("proposed_share", "agreed_share"):
                if field in delta:
                    assert 0 <= delta[field] <= request["total_amount"]
                    assert delta[field] == round(delta[field], 2)
            if message["message_type"] == "PROPOSE":
                assert delta["proposed_share"] == request["proposed_share"]
            if message["message_type"] == "ACCEPT":
                assert delta["agreed_share"] == standing
            if "proposed_share" in delta:
                standing = delta["proposed_share"]
            if message["message_type"] == "COUNTER":
                assert message["payload"]["public_reason"] == "constraint_violation"
        text = "".join(p.read_text(encoding="utf-8") for p in directory.glob("*.json"))
        for banned in ("reservation_ratio", "preferred_ratio", "concession_ratio",
                       "max_auto_accept_amount", "max_negotiable_amount"):
            assert banned not in text


def test_rejected_example_uses_human_rejected():
    last = session_messages(EXAMPLES / "cost-split-rejected")[-1]
    assert last["message_type"] == "REJECT"
    assert last["payload"] == {"public_reason": "policy_declined"}
    assert last["delta"] == {"code": "HUMAN_REJECTED"}


def test_no_slot_example_ends_with_no_available_slot():
    messages = session_messages(EXAMPLES / "meeting-schedule-no-slot")
    assert [m["message_type"] for m in messages] == [
        "REQUEST", "PROPOSE", "COUNTER", "COUNTER", "ERROR",
    ]
    assert messages[-1]["delta"] == {"code": "NO_AVAILABLE_SLOT"}


def test_regenerating_examples_gives_identical_bytes():
    generated = make_examples.build_all()
    on_disk = {
        str(p.relative_to(ROOT)): p.read_bytes()
        for p in EXAMPLES.rglob("*.json")
    }
    assert generated == on_disk
    assert make_examples.build_all() == generated


# ---- reference tool behavior ----------------------------------------------


def _sample():
    envelope = load(EXAMPLES / "cost-split" / "02-propose.json")
    return envelope, PUBLIC_KEY_BY_NODE[envelope["sender_node_id"]]


def test_tampered_delta_is_rejected():
    envelope, key = _sample()
    envelope["delta"]["proposed_share"] = 1.0
    with pytest.raises(VerificationError) as err:
        verify_envelope(envelope, key, now=created_at(envelope))
    assert err.value.code == "MESSAGE_SIGNATURE_INVALID"


def test_tampered_delta_with_fixed_hash_still_fails_signature():
    envelope, key = _sample()
    envelope["delta"]["proposed_share"] = 1.0
    envelope["payload_hash"] = compute_payload_hash(envelope["payload"], envelope["delta"])
    with pytest.raises(VerificationError) as err:
        verify_envelope(envelope, key, now=created_at(envelope))
    assert err.value.code == "MESSAGE_SIGNATURE_INVALID"


def test_wrong_public_key_is_rejected():
    envelope, _ = _sample()
    other = KEYS["a"]["public_key"] if envelope["sender_node_id"] == KEYS["b"]["node_id"] else KEYS["b"]["public_key"]
    with pytest.raises(VerificationError) as err:
        verify_envelope(envelope, other, now=created_at(envelope))
    assert err.value.code == "MESSAGE_SIGNATURE_INVALID"


def test_stale_and_future_messages_are_expired():
    envelope, key = _sample()
    base = created_at(envelope)
    verify_envelope(envelope, key, now=base + timedelta(seconds=300))
    for offset in (301, -301):
        with pytest.raises(VerificationError) as err:
            verify_envelope(envelope, key, now=base + timedelta(seconds=offset))
        assert err.value.code == "MESSAGE_EXPIRED"
    with pytest.raises(VerificationError) as err:
        verify_envelope(envelope, key)  # real clock: 2099 is far away
    assert err.value.code == "MESSAGE_EXPIRED"
    verify_envelope(envelope, key, window_seconds=None)


def test_schema_violations_are_rejected():
    envelope, key = _sample()
    extra = dict(envelope, unexpected=1)
    with pytest.raises(VerificationError) as err:
        verify_envelope(extra, key, now=created_at(envelope))
    assert err.value.code == "MESSAGE_SCHEMA_INVALID"
    naive = dict(envelope, created_at="2099-01-01T09:00:10")
    with pytest.raises(VerificationError) as err:
        verify_envelope(naive, key, window_seconds=None)
    assert err.value.code == "MESSAGE_SCHEMA_INVALID"


def test_sign_then_verify_roundtrip():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes_raw()
    now = datetime.now(timezone.utc)
    base = {k: v for k, v in load(EXAMPLES / "cost-split" / "02-propose.json").items()
            if k not in ("payload_hash", "signature")}
    base["created_at"] = now.isoformat()
    envelope = sign_envelope(base, private)
    verify_envelope(envelope, base64.b64encode(raw).decode(), now=now)


# ---- cross-check with the ENISHI reference implementation ------------------

ENISHI_LOCAL_CORE = os.environ.get("ENISHI_LOCAL_CORE")
needs_enishi = pytest.mark.skipif(
    not ENISHI_LOCAL_CORE, reason="ENISHI_LOCAL_CORE is not set"
)


def _enishi_envelope_module():
    sys.path.insert(0, ENISHI_LOCAL_CORE)  # source tree wins over installed copies
    from enishi_core.security import envelope as module

    assert Path(module.__file__).resolve().is_relative_to(Path(ENISHI_LOCAL_CORE).resolve())
    return module


@needs_enishi
@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_enishi_verifier_accepts_example(path):
    module = _enishi_envelope_module()
    envelope = load(path)
    key = PUBLIC_KEY_BY_NODE[envelope["sender_node_id"]]
    module.verify_envelope(envelope, key, now=created_at(envelope))


@needs_enishi
def test_this_verifier_accepts_enishi_envelope():
    module = _enishi_envelope_module()
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes_raw()
    sender = node_id_from_public_key(raw)
    envelope = module.build_envelope(
        "agent-a", "agent-b", "session-x", "PROPOSE", "cost.split", 1, 2,
        {}, {"proposed_share": 3000.0}, False, private,
        sender_node_id=sender, receiver_node_id="agt_0000000000000000",
    )
    verify_envelope(envelope, base64.b64encode(raw).decode())
