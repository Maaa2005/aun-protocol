"""Conformance checks for AUN Protocol 0.3: examples, reference checker, cases.

Run from the repository root: `pytest -q`.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import aun_reference  # noqa: E402
import make_examples  # noqa: E402
from aun_reference import (  # noqa: E402
    MAX_BYTES,
    PROTOCOL,
    Node,
    Peer,
    VerificationError,
    check_session,
    encode,
    node_id_from_public_key,
    parse_envelope_bytes,
    sign_envelope,
    verify_envelope,
)

EXAMPLES = ROOT / "examples"
SESSION_DIRS = sorted(p for p in EXAMPLES.iterdir() if p.is_dir())
KEYS = json.loads((EXAMPLES / "keys.json").read_text(encoding="utf-8"))["nodes"]
PUBLIC_KEY_BY_NODE = {n["node_id"]: n["public_key"] for n in KEYS.values()}
ALL_FILES = sorted(p for d in SESSION_DIRS for p in d.glob("*.json"))

JST = timezone(timedelta(hours=9))
T0 = datetime(2099, 1, 1, 9, 0, tzinfo=JST)
EXPIRES = T0 + timedelta(hours=1)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def session_messages(directory: Path) -> list[dict]:
    return [load(p) for p in sorted(directory.glob("*.json"))]


# ---- helpers for hand-made sessions ---------------------------------------


def _key(label: str) -> Ed25519PrivateKey:
    return make_examples._node(label, f"agent-{label}")["private"]


def make_nodes() -> dict[str, Node]:
    """Nodes a, b and c. Each trusts the other two."""
    nodes = {label: Node(f"agent-{label}", _key(label)) for label in "abc"}
    for label, node in nodes.items():
        for other, peer in nodes.items():
            if other != label:
                public = base64.b64encode(
                    peer.private_key.public_key().public_bytes_raw()
                ).decode("ascii")
                node.trust(Peer(peer.agent_id, public))
    return nodes


class Conversation:
    """Builds messages for one session between hand-made nodes."""

    def __init__(self, nodes: dict[str, Node], session_id: str = "s1") -> None:
        self.nodes = nodes
        self.session_id = session_id
        self.count = 0

    def unsigned(self, who: str, to: str, message_type: str, payload: dict,
                 delta: dict, sequence: int, at: datetime | None = None,
                 **override) -> dict:
        self.count += 1
        sender, receiver = self.nodes[who], self.nodes[to]
        fields = {
            "protocol": PROTOCOL,
            "message_id": f"{self.session_id}-m{self.count}",
            "session_id": self.session_id,
            "sender_agent_id": sender.agent_id,
            "receiver_agent_id": receiver.agent_id,
            "sender_node_id": sender.node_id,
            "receiver_node_id": receiver.node_id,
            "message_type": message_type,
            "intent": "test.case",
            "session_version": 1,
            "sequence": sequence,
            "payload": payload,
            "delta": delta,
            "nonce": f"{self.session_id}-n{self.count}",
            "created_at": (at or T0 + timedelta(seconds=sequence)).isoformat(),
        }
        fields.update(override)
        return fields

    def signed(self, who: str, *args, **kwargs) -> bytes:
        """Signed bytes that skip the sender's own checks (a peer's message)."""
        fields = self.unsigned(who, *args, **kwargs)
        return encode(sign_envelope(fields, self.nodes[who].private_key))

    def exchange(self, who: str, to: str, *args, now: datetime | None = None,
                 **kwargs) -> bytes:
        """Send through both nodes' full checks."""
        fields = self.unsigned(who, to, *args, **kwargs)
        at = now or datetime.fromisoformat(fields["created_at"])
        data = self.nodes[who].send(fields, at)
        assert self.nodes[to].receive(data, at) == "accepted"
        return data


def request(issues: list[dict], expires_at: datetime = EXPIRES) -> dict:
    return {"topic": "Test", "expires_at": expires_at.isoformat(), "issues": issues}


def slot(hour: int, minute: int = 0, length: int = 60, tz=JST) -> dict:
    start = datetime(2099, 1, 1, hour, minute, tzinfo=JST).astimezone(tz)
    end = start + timedelta(minutes=length)
    fmt = "%Y-%m-%dT%H:%M%z"
    return {"start": _rfc(start.strftime(fmt)), "end": _rfc(end.strftime(fmt))}


def _rfc(text: str) -> str:
    return text[:-2] + ":" + text[-2:]


PLACE = {"name": "place", "kind": "choice", "options": ["Sushi", "Pasta"]}
OPEN_PLACE = {"name": "place", "kind": "choice"}
TIME = {"name": "time", "kind": "time", "duration_minutes": 60,
        "window": {"start": slot(17)["start"], "end": slot(22)["start"]}}
AMOUNT = {"name": "share", "kind": "amount", "unit": "JPY", "scale": 0,
          "min": 0, "max": 10000, "step": 100}
DINNER = [PLACE, TIME]


def open_dinner(nodes=None) -> Conversation:
    """A offers {Sushi 18:00} and {Pasta 19:00}; B has received it."""
    conv = Conversation(nodes or make_nodes())
    conv.exchange("a", "b", "REQUEST", request(DINNER), {"offer": [
        {"place": "Sushi", "time": slot(18)},
        {"place": "Pasta", "time": slot(19)},
    ]}, 1)
    return conv


def dropped(code: str, node: Node, data: bytes, now: datetime) -> None:
    with pytest.raises(VerificationError) as caught:
        node.receive(data, now)
    assert caught.value.code == code


# ---- canonicalization ------------------------------------------------------


def test_jcs_vectors_reproduce():
    vectors = load(ROOT / "test-vectors" / "jcs-v0.2.json")["vectors"]
    assert vectors
    for vector in vectors:
        assert rfc8785.dumps(vector["value"]).decode("utf-8") == vector["canonical_utf8"]


# ---- examples --------------------------------------------------------------

EXPECTED = {
    "cost-split": (["request", "counter", "accept"], "agreed"),
    "cost-split-rejected": (["request", "reject"], "rejected"),
    "dinner-plan": (["request", "counter", "accept"], "agreed"),
    "favor-ask": (["request", "accept"], "agreed"),
    "gift-pick": (["request", "counter", "accept"], "agreed"),
    "meeting-schedule": (["request", "accept"], "agreed"),
    "meeting-schedule-no-agreement": (
        ["request", "counter", "counter", "counter", "reject"], "rejected"),
}


def test_expected_example_set_exists():
    names = {d.name: [p.name for p in sorted(d.glob("*.json"))] for d in SESSION_DIRS}
    assert names == {
        name: [f"{i:02d}-{t}.json" for i, t in enumerate(types, start=1)]
        for name, (types, _) in EXPECTED.items()
    }


def test_keys_file_is_marked_test_only():
    text = (EXAMPLES / "keys.json").read_text(encoding="utf-8")
    assert "TEST ONLY - never use these keys" in text


def test_node_ids_match_public_keys():
    for node in KEYS.values():
        raw = base64.b64decode(node["public_key"])
        assert node["node_id"] == node_id_from_public_key(raw)
        seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(node["seed_hex"]))
        assert seed.public_key().public_bytes_raw() == raw


@pytest.mark.parametrize("directory", SESSION_DIRS, ids=lambda d: d.name)
def test_example_session_passes_full_receiver(directory):
    session = check_session(directory, KEYS)
    assert session.status == EXPECTED[directory.name][1]
    if session.status == "agreed":
        assert session.agreed == session_messages(directory)[-1]["delta"]["agreed"]


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_example_verifies_alone(path):
    envelope = parse_envelope_bytes(path.read_bytes())
    key = PUBLIC_KEY_BY_NODE[envelope["sender_node_id"]]
    verify_envelope(envelope, key, now=datetime.fromisoformat(envelope["created_at"]))
    assert len(path.read_bytes()) <= MAX_BYTES


def test_message_ids_and_nonces_unique_across_examples():
    envelopes = [load(p) for p in ALL_FILES]
    assert len({e["message_id"] for e in envelopes}) == len(envelopes)
    assert len({e["nonce"] for e in envelopes}) == len(envelopes)


def test_regenerating_examples_is_byte_identical():
    for relative, data in make_examples.build_all().items():
        assert (ROOT / relative).read_bytes() == data, relative


# ---- success criteria (docs/design-0.3.md) --------------------------------


def test_checker_contains_no_domain_names():
    source = (ROOT / "tools" / "aun_reference.py").read_text(encoding="utf-8")
    intents = {session_messages(d)[0]["intent"] for d in SESSION_DIRS}
    words = intents | {i.split(".")[0] for i in intents}
    assert not [w for w in words if w in source]


def test_at_least_two_domains_beyond_meetings_and_costs():
    intents = {session_messages(d)[0]["intent"] for d in SESSION_DIRS}
    assert len(intents - {"meeting.schedule", "cost.split"}) >= 2


def test_fast_path_agrees_in_two_messages():
    fast = [d.name for d in SESSION_DIRS
            if [m["message_type"] for m in session_messages(d)] == ["REQUEST", "ACCEPT"]]
    assert "meeting-schedule" in fast and len(fast) >= 2


def test_examples_respect_session_and_offer_limits():
    for directory in SESSION_DIRS:
        messages = session_messages(directory)
        assert len(messages) <= 5
        offers = [m["delta"]["offer"] for m in messages if "offer" in m["delta"]]
        assert len(offers) <= 4
        assert all(1 <= len(o) <= 5 for o in offers)


def test_fourth_counter_is_rejected_on_both_sides():
    conv = Conversation(make_nodes())
    conv.exchange("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 3000}]}, 1)
    reason = {"public_reason": "no_common_option"}
    for seq, (who, to, share) in enumerate(
            [("b", "a", 2000), ("a", "b", 2900), ("b", "a", 2100)], start=2):
        conv.exchange(who, to, "COUNTER", reason, {"offer": [{"share": share}]}, seq)
    fourth = conv.unsigned("a", "b", "COUNTER", reason, {"offer": [{"share": 2800}]}, 5)
    at = T0 + timedelta(seconds=5)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["a"].send(dict(fourth), at)
    assert caught.value.code == "INVALID_STATE_TRANSITION"
    data = encode(sign_envelope(fourth, conv.nodes["a"].private_key))
    dropped("INVALID_STATE_TRANSITION", conv.nodes["b"], data, at)
    # REJECT is still allowed as the fifth message.
    conv.exchange("a", "b", "REJECT", reason, {"code": "NO_AGREEMENT"}, 5)
    assert conv.nodes["b"].sessions["s1"].status == "rejected"


def test_offer_of_six_packages_fails_schema():
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([AMOUNT]),
                       {"offer": [{"share": 100 * i} for i in range(6)]}, 1)
    dropped("MESSAGE_SCHEMA_INVALID", conv.nodes["b"], data, T0)


# ---- case table (docs/design-0.3.md) ---------------------------------------


def test_case1_unapproved_combination_is_dropped():
    conv = open_dinner()
    at = T0 + timedelta(seconds=2)
    data = conv.signed("b", "a", "ACCEPT", {},
                       {"agreed": {"place": "Sushi", "time": slot(19)}}, 2)
    dropped("INVALID_NEGOTIATION_PAYLOAD", conv.nodes["a"], data, at)
    assert conv.nodes["a"].sessions["s1"].status == "open"
    assert conv.nodes["a"].sessions["s1"].sequence == 1
    conv.exchange("b", "a", "ACCEPT", {},
                  {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    assert conv.nodes["a"].sessions["s1"].status == "agreed"


def test_case2a_value_outside_declared_options_is_dropped():
    conv = open_dinner()
    data = conv.signed("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                       {"offer": [{"place": "Ramen", "time": slot(19)}]}, 2)
    dropped("INVALID_NEGOTIATION_PAYLOAD", conv.nodes["a"], data, T0)


def test_case2b_open_choice_takes_a_new_value():
    conv = Conversation(make_nodes())
    conv.exchange("a", "b", "REQUEST", request([OPEN_PLACE]),
                  {"offer": [{"place": "Sushi"}]}, 1)
    conv.exchange("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                  {"offer": [{"place": "Ramen"}]}, 2)
    conv.exchange("a", "b", "ACCEPT", {}, {"agreed": {"place": "Ramen"}}, 3)
    assert conv.nodes["b"].sessions["s1"].agreed == {"place": "Ramen"}


def test_case3a_accept_created_in_time_received_after_deadline():
    conv = open_dinner()
    created = EXPIRES - timedelta(seconds=10)
    conv.exchange("b", "a", "ACCEPT", {},
                  {"agreed": {"place": "Pasta", "time": slot(19)}}, 2,
                  at=created, now=created + timedelta(seconds=200))
    assert conv.nodes["a"].sessions["s1"].status == "agreed"


def test_case3b_accept_created_after_deadline_is_dropped():
    conv = open_dinner()
    created = EXPIRES + timedelta(seconds=1)
    data = conv.signed("b", "a", "ACCEPT", {},
                       {"agreed": {"place": "Pasta", "time": slot(19)}}, 2, at=created)
    dropped("SESSION_EXPIRED", conv.nodes["a"], data, created)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["b"].send(conv.unsigned(
            "b", "a", "ACCEPT", {}, {"agreed": {"place": "Pasta", "time": slot(19)}},
            2, at=created), created)
    assert caught.value.code == "SESSION_EXPIRED"


def test_case4a_identical_resend_is_a_duplicate():
    conv = open_dinner()
    data = conv.exchange("b", "a", "ACCEPT", {},
                         {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    session = conv.nodes["a"].sessions["s1"]
    before = (session.status, session.sequence, dict(session.agreed))
    assert conv.nodes["a"].receive(data, T0 + timedelta(seconds=30)) == "duplicate"
    assert (session.status, session.sequence, session.agreed) == before


def test_case4b_other_message_for_recorded_sequence_is_dropped():
    conv = open_dinner()
    conv.exchange("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                  {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    other = conv.signed("b", "a", "ACCEPT", {},
                        {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    dropped("MESSAGE_REPLAYED", conv.nodes["a"], other, T0)
    second_request = conv.signed("a", "b", "REQUEST", request(DINNER), {"offer": [
        {"place": "Pasta", "time": slot(21)}]}, 1)
    dropped("MESSAGE_REPLAYED", conv.nodes["b"], second_request, T0)


# ---- binding and turn ------------------------------------------------------


def test_turns_alternate_in_both_directions():
    conv = Conversation(make_nodes())
    reason = {"public_reason": "constraint_violation"}
    conv.exchange("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 3000}]}, 1)
    conv.exchange("b", "a", "COUNTER", reason, {"offer": [{"share": 2000}]}, 2)
    conv.exchange("a", "b", "COUNTER", reason, {"offer": [{"share": 2500}]}, 3)
    conv.exchange("b", "a", "ACCEPT", {}, {"agreed": {"share": 2500}}, 4)
    for label in "ab":
        assert conv.nodes[label].sessions["s1"].status == "agreed"


def test_same_party_twice_is_not_its_turn():
    conv = open_dinner()
    data = conv.signed("a", "b", "COUNTER", {"public_reason": "no_common_option"},
                       {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    dropped("INVALID_STATE_TRANSITION", conv.nodes["b"], data, T0)


def test_third_party_cannot_join_a_session():
    nodes = make_nodes()
    conv = open_dinner(nodes)
    data = conv.signed("c", "b", "ACCEPT", {},
                       {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    dropped("SESSION_BINDING_MISMATCH", nodes["b"], data, T0)


def test_message_for_another_node_is_dropped():
    nodes = make_nodes()
    conv = Conversation(nodes)
    data = conv.signed("a", "c", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]}, 1)
    dropped("SESSION_BINDING_MISMATCH", nodes["b"], data, T0)


def test_intent_cannot_change_inside_a_session():
    conv = open_dinner()
    data = conv.signed("b", "a", "ACCEPT", {},
                       {"agreed": {"place": "Pasta", "time": slot(19)}}, 2,
                       intent="other.case")
    dropped("SESSION_BINDING_MISMATCH", conv.nodes["a"], data, T0)


def test_untrusted_peer_and_wrong_agent_id():
    nodes = make_nodes()
    stranger = Node("agent-x", _key("x"))
    conv = Conversation({**nodes, "x": stranger})
    data = conv.signed("x", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]}, 1)
    dropped("PEER_NOT_TRUSTED", nodes["b"], data, T0)
    data = conv.signed("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]},
                       1, sender_agent_id="agent-c")
    dropped("AGENT_IDENTITY_MISMATCH", nodes["b"], data, T0)


def test_error_only_answers_a_request():
    conv = open_dinner()
    conv.exchange("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                  {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    data = conv.signed("a", "b", "ERROR", {}, {"code": "NOT_SUPPORTED"}, 3)
    dropped("INVALID_STATE_TRANSITION", conv.nodes["b"], data, T0)
    fresh = open_dinner()
    fresh.exchange("b", "a", "ERROR", {}, {"code": "NOT_SUPPORTED"}, 2)
    assert fresh.nodes["a"].sessions["s1"].status == "not_supported"


# ---- deadline --------------------------------------------------------------


def test_open_session_expires_300_seconds_after_deadline():
    conv = open_dinner()
    session = conv.nodes["b"].sessions["s1"]
    assert session.expire_if_due(EXPIRES + timedelta(seconds=300)) == "open"
    assert session.expire_if_due(EXPIRES + timedelta(seconds=301)) == "expired"


@pytest.mark.parametrize("expires_at", [T0, T0 - timedelta(minutes=1),
                                        T0 + timedelta(days=7, seconds=2)])
def test_deadline_must_be_after_request_and_within_seven_days(expires_at):
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([AMOUNT], expires_at),
                       {"offer": [{"share": 0}]}, 1, at=T0)
    dropped("INVALID_NEGOTIATION_PAYLOAD", conv.nodes["b"], data, T0)


# ---- packages --------------------------------------------------------------


@pytest.mark.parametrize("package", [
    {"share": 150},           # not on a step
    {"share": 10100},         # above max
    {"share": True},          # a boolean is not an integer
    {"share": "100"},         # a string is not an integer
    {},                       # missing issue
    {"share": 100, "x": 1},   # undeclared issue
])
def test_bad_amount_package_opens_no_session(package):
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([AMOUNT]), {"offer": [package]}, 1)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["b"].receive(data, T0)
    assert caught.value.code in {"INVALID_NEGOTIATION_PAYLOAD", "MESSAGE_SCHEMA_INVALID"}
    assert conv.nodes["b"].sessions == {}


@pytest.mark.parametrize("time_value", [
    slot(18, length=30),      # wrong duration
    slot(21, 30),             # ends after the window
    slot(16, 30),             # starts before the window
    {"start": "2099-01-01T18:00:30+09:00", "end": "2099-01-01T19:00:30+09:00"},
])
def test_bad_slot_is_dropped(time_value):
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([TIME]),
                       {"offer": [{"time": time_value}]}, 1)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["b"].receive(data, T0)
    assert caught.value.code in {"INVALID_NEGOTIATION_PAYLOAD", "MESSAGE_SCHEMA_INVALID"}


def test_slots_compare_as_instants():
    conv = Conversation(make_nodes())
    conv.exchange("a", "b", "REQUEST", request([TIME]), {"offer": [{"time": slot(18)}]}, 1)
    conv.exchange("b", "a", "ACCEPT", {}, {"agreed": {"time": slot(18, tz=timezone.utc)}}, 2)
    assert conv.nodes["a"].sessions["s1"].status == "agreed"


def test_offer_repeating_a_package_is_dropped():
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([TIME]), {"offer": [
        {"time": slot(18)}, {"time": slot(18, tz=timezone.utc)}]}, 1)
    dropped("INVALID_NEGOTIATION_PAYLOAD", conv.nodes["b"], data, T0)


@pytest.mark.parametrize("issues", [
    [PLACE, dict(PLACE)],                                              # duplicate names
    [dict(TIME, window={"start": slot(22)["start"], "end": slot(17)["start"]})],
    [dict(TIME, window={"start": "2099-01-01T00:00+09:00",
                        "end": "2099-02-02T00:00+09:00"})],            # over 31 days
    [dict(TIME, duration_minutes=600)],                                # longer than window
    [dict(AMOUNT, min=200, max=100)],
])
def test_bad_declaration_opens_no_session(issues):
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request(issues), {"offer": [{"z": True}]}, 1)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["b"].receive(data, T0)
    assert caught.value.code == "INVALID_NEGOTIATION_PAYLOAD"
    assert conv.nodes["b"].sessions == {}


# ---- input limits ----------------------------------------------------------


def test_largest_declaration_is_refused_by_size_on_both_sides():
    options = [f"{i:02d}" + "x" * 98 for i in range(20)]
    issues = [{"name": f"q{i}", "kind": "choice", "options": options} for i in range(8)]
    package = {f"q{i}": options[0] for i in range(8)}
    conv = Conversation(make_nodes())
    fields = conv.unsigned("a", "b", "REQUEST", request(issues), {"offer": [package]}, 1)
    with pytest.raises(VerificationError) as caught:
        conv.nodes["a"].send(dict(fields), T0)
    assert caught.value.code == "MESSAGE_TOO_LARGE"
    data = encode(sign_envelope(fields, conv.nodes["a"].private_key))
    assert len(data) > MAX_BYTES
    dropped("MESSAGE_TOO_LARGE", conv.nodes["b"], data, T0)


@pytest.mark.parametrize("raw", [
    b'{"a": 1, "a": 2}',
    b'{"a": 1.5}',
    b'{"a": NaN}',
    b'{"a": [[[[[[[[[1]]]]]]]]]}',
    b'[]',
    b'\xff',
])
def test_strict_json(raw):
    with pytest.raises(VerificationError) as caught:
        parse_envelope_bytes(raw)
    assert caught.value.code == "MESSAGE_SCHEMA_INVALID"


def test_tampered_delta_and_fixed_hash_fail():
    conv = Conversation(make_nodes())
    envelope = json.loads(conv.signed("a", "b", "REQUEST", request([AMOUNT]),
                                      {"offer": [{"share": 3000}]}, 1))
    tampered = dict(envelope, delta={"offer": [{"share": 100}]})
    dropped("MESSAGE_SIGNATURE_INVALID", conv.nodes["b"], encode(tampered), T0)
    tampered["payload_hash"] = aun_reference.compute_payload_hash(
        tampered["payload"], tampered["delta"])
    dropped("MESSAGE_SIGNATURE_INVALID", conv.nodes["b"], encode(tampered), T0)


def test_wrong_key_fails():
    nodes = make_nodes()
    conv = Conversation(nodes)
    fields = conv.unsigned("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]}, 1)
    data = encode(sign_envelope(fields, nodes["c"].private_key))
    dropped("MESSAGE_SIGNATURE_INVALID", nodes["b"], data, T0)


@pytest.mark.parametrize("offset", [-301, 301])
def test_stale_or_future_message_fails(offset):
    conv = Conversation(make_nodes())
    data = conv.signed("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]},
                       1, at=T0)
    dropped("MESSAGE_EXPIRED", conv.nodes["b"], data, T0 + timedelta(seconds=offset))


def test_reused_nonce_is_replay():
    conv = Conversation(make_nodes())
    conv.exchange("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]}, 1)
    data = conv.signed("b", "a", "ACCEPT", {}, {"agreed": {"share": 0}}, 2)
    other = Conversation(conv.nodes, "s2")
    reused = other.signed("a", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]},
                          1, nonce="s1-n1")
    dropped("MESSAGE_REPLAYED", conv.nodes["b"], reused, T0)
    assert conv.nodes["a"].receive(data, T0) == "accepted"


@pytest.mark.parametrize("change", [
    {"protocol": "aun/0.2"},
    {"intent": "Bad Intent"},
    {"session_id": "x" * 129},
    {"requires_human_approval": False},
])
def test_envelope_schema_violations(change):
    conv = Conversation(make_nodes())
    fields = conv.unsigned("a", "b", "REQUEST", request([AMOUNT]),
                           {"offer": [{"share": 0}]}, 1, **change)
    data = encode(sign_envelope(fields, conv.nodes["a"].private_key))
    dropped("MESSAGE_SCHEMA_INVALID", conv.nodes["b"], data, T0)


def test_cli_check_session_roundtrip(capsys):
    code = aun_reference.main(["check-session", str(EXAMPLES / "dinner-plan"),
                               "--keys", str(EXAMPLES / "keys.json")])
    assert code == 0
    assert "agreed after 3 messages" in capsys.readouterr().out
