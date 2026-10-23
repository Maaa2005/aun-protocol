"""Conformance checks for AUN Protocol 0.3: examples, reference checker, cases.

Run from the repository root: `pytest -q`.
"""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import aun_reference  # noqa: E402
import make_card_vectors  # noqa: E402
import make_examples  # noqa: E402
import make_vectors  # noqa: E402
from aun_reference import (  # noqa: E402
    MAX_BYTES,
    PROTOCOL,
    Node,
    Peer,
    VerificationError,
    check_session,
    encode,
    make_card,
    node_id_from_public_key,
    parse_envelope_bytes,
    parse_time,
    sign_envelope,
    verify_card,
    verify_envelope,
)

EXAMPLES = ROOT / "examples"
SESSION_DIRS = sorted(p for p in EXAMPLES.iterdir() if p.is_dir() and p.name != "cards")
CARD_FILES = sorted((EXAMPLES / "cards").glob("*.json"))
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

    def state(self, label: str, session_id: str | None = None):
        """The session as node `label` holds it, keyed by the other party."""
        node = self.nodes[label]
        for (other, sid), session in node.sessions.items():
            if sid == (session_id or self.session_id):
                assert other in {session.initiator.node_id, session.responder.node_id}
                return session
        raise KeyError(session_id or self.session_id)

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
    assert conv.state("b").status == "rejected"


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
    assert conv.state("a").status == "open"
    assert conv.state("a").sequence == 1
    conv.exchange("b", "a", "ACCEPT", {},
                  {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    assert conv.state("a").status == "agreed"


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
    assert conv.state("b").agreed == {"place": "Ramen"}


def test_case3a_accept_created_in_time_received_after_deadline():
    conv = open_dinner()
    created = EXPIRES - timedelta(seconds=10)
    conv.exchange("b", "a", "ACCEPT", {},
                  {"agreed": {"place": "Pasta", "time": slot(19)}}, 2,
                  at=created, now=created + timedelta(seconds=200))
    assert conv.state("a").status == "agreed"


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
    session = conv.state("a")
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
        assert conv.state(label).status == "agreed"


def test_same_party_twice_is_not_its_turn():
    conv = open_dinner()
    data = conv.signed("a", "b", "COUNTER", {"public_reason": "no_common_option"},
                       {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    dropped("INVALID_STATE_TRANSITION", conv.nodes["b"], data, T0)


def test_third_party_cannot_join_a_session():
    """Sessions are per pair of nodes: C has no session s1 with B."""
    nodes = make_nodes()
    conv = open_dinner(nodes)
    data = conv.signed("c", "b", "ACCEPT", {},
                       {"agreed": {"place": "Pasta", "time": slot(19)}}, 2)
    dropped("INVALID_STATE_TRANSITION", nodes["b"], data, T0)
    assert conv.state("b").status == "open"


def test_same_ids_from_another_peer_are_a_separate_session():
    """Session, message IDs and nonces are unique per node, not worldwide."""
    nodes = make_nodes()
    first = open_dinner(nodes)
    second = Conversation(nodes)  # same session ID, message IDs and nonces
    second.exchange("c", "b", "REQUEST", request([AMOUNT]), {"offer": [{"share": 0}]}, 1)
    second.exchange("b", "c", "ACCEPT", {}, {"agreed": {"share": 0}}, 2)
    assert len(nodes["b"].sessions) == 2
    assert first.state("b").status == "open"
    assert nodes["b"].sessions[(nodes["c"].node_id, "s1")].status == "agreed"


def test_sender_never_reuses_its_own_nonce():
    conv = open_dinner()  # A's REQUEST used nonce s1-n1
    conv.exchange("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                  {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    fields = conv.unsigned("a", "b", "ACCEPT", {},
                           {"agreed": {"place": "Pasta", "time": slot(20)}}, 3,
                           nonce="s1-n1")
    with pytest.raises(VerificationError) as caught:
        conv.nodes["a"].send(fields, T0 + timedelta(seconds=3))
    assert caught.value.code == "MESSAGE_REPLAYED"


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
    assert fresh.state("a").status == "not_supported"


# ---- deadline --------------------------------------------------------------


def test_open_session_expires_300_seconds_after_deadline():
    conv = open_dinner()
    session = conv.state("b")
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
    assert conv.state("a").status == "agreed"


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


# ---- shared vectors (test-vectors/receiver-v0.3.json) ---------------------
#
# Receiver cases for other implementations, hostile input included. Each case
# replays through a fresh node B; a drop must leave B's state unchanged.

VECTORS = json.loads((ROOT / make_vectors.OUTPUT).read_text(encoding="utf-8"))


def test_regenerating_vectors_is_byte_identical():
    assert make_vectors.build() == (ROOT / make_vectors.OUTPUT).read_bytes()


def test_vectors_use_only_defined_codes():
    codes = {step["expect"] for case in VECTORS["cases"] for step in case["steps"]}
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    assert {"accepted", "duplicate"} <= codes
    assert all(f"`{code}`" in spec for code in codes - {"accepted", "duplicate"})


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_vector_case(case):
    expected = ([step["expect"] for step in case["steps"]], case["final"])
    assert make_vectors.run_case(case) == expected


@pytest.mark.parametrize("path", [aun_reference.SCHEMA_PATH, aun_reference.CARD_SCHEMA_PATH],
                         ids=lambda p: p.name)
def test_every_schema_pattern_is_anchored(path):
    schema = json.loads(path.read_text(encoding="utf-8"))
    found = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("pattern"), str):
                found.append(node["pattern"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(schema)
    assert found and all(p.startswith("^") and p.endswith("$") for p in found)


# ---- agent cards (SPEC section 11) ------------------------------------------
#
# Card cases for other implementations (test-vectors/card-v1.json), the example
# cards, and what a stored card does for messages.

CARD_VECTORS = json.loads((ROOT / make_card_vectors.OUTPUT).read_text(encoding="utf-8"))
CARD_AT = "2099-01-01T08:00:00+09:00"
CARD_NOW = T0 - timedelta(seconds=1)


def test_regenerating_card_vectors_is_byte_identical():
    assert make_card_vectors.build() == (ROOT / make_card_vectors.OUTPUT).read_bytes()


def test_card_vectors_check_exits_zero():
    done = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "make_card_vectors.py"), "--check"],
        capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


def test_receiver_vectors_check_still_exits_zero():
    done = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "make_vectors.py"), "--check"],
        capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


def test_card_vectors_use_only_defined_codes():
    codes = {step["expect"] for case in CARD_VECTORS["cases"] for step in case["steps"]}
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    assert {"trusted", "updated"} <= codes
    assert all(f"`{code}`" in spec for code in codes - {"trusted", "updated"})


@pytest.mark.parametrize("case", CARD_VECTORS["cases"], ids=lambda case: case["name"])
def test_card_vector_case(case):
    expected = ([step["expect"] for step in case["steps"]], case["final"])
    assert make_card_vectors.run_case(case) == expected


def test_card_vectors_cover_every_code_of_section_11_2():
    codes = {step["expect"] for case in CARD_VECTORS["cases"] for step in case["steps"]}
    assert {c for c in codes if c.startswith("CARD_")} == {
        "CARD_TOO_LARGE", "CARD_SCHEMA_INVALID", "CARD_IDENTITY_MISMATCH",
        "CARD_SIGNATURE_INVALID", "CARD_VERSION_UNSUPPORTED", "CARD_NOT_YET_VALID",
        "CARD_PEER_NOT_TRUSTED", "CARD_STALE"}


def test_card_schema_defs_equal_the_message_schema_defs():
    message = json.loads(aun_reference.SCHEMA_PATH.read_text(encoding="utf-8"))["$defs"]
    card = json.loads(aun_reference.CARD_SCHEMA_PATH.read_text(encoding="utf-8"))["$defs"]
    assert card
    for name, definition in card.items():
        assert message[name] == definition, name


def test_example_cards_exist_and_are_marked_test_only():
    assert [p.name for p in CARD_FILES] == ["a.json", "b.json"]
    for path, label in zip(CARD_FILES, "ab"):
        card = load(path)
        assert "test key only" in card["display_name"]
        assert card["public_key"] == KEYS[label]["public_key"]
        assert card["node_id"] == KEYS[label]["node_id"]
        assert card["agent_id"] == KEYS[label]["personal_agent_id"]


@pytest.mark.parametrize("path", CARD_FILES, ids=lambda p: p.name)
def test_example_card_verifies(path, capsys):
    card = verify_card(path.read_bytes(), parse_time("2026-10-01T09:00:00+09:00"))
    assert aun_reference.main(["verify-card", str(path)]) == 0
    assert capsys.readouterr().out == (
        f"OK card {card['node_id']} ({card['agent_id']}) issued_at {card['issued_at']}\n")


@pytest.mark.parametrize("path", CARD_FILES, ids=lambda p: p.name)
def test_tampered_example_card_fails(path, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_bytes(path.read_bytes().replace(b"test key only", b"test key none"))
    assert aun_reference.main(["verify-card", str(bad)]) == 1
    assert capsys.readouterr().err.startswith("FAIL CARD_SIGNATURE_INVALID:")


def test_cli_verify_card_now_option(capsys):
    path = str(CARD_FILES[0])
    assert aun_reference.main(["verify-card", path, "--now", "2026-10-01T08:55:00+09:00"]) == 0
    assert aun_reference.main(["verify-card", path, "--now", "2026-10-01T08:54:59+09:00"]) == 1
    assert "CARD_NOT_YET_VALID" in capsys.readouterr().err


def bare_nodes() -> dict[str, Node]:
    """Nodes a, b and c that trust no one and hold no card."""
    return {label: Node(f"agent-{label}", _key(label)) for label in "abc"}


def card_of(node: Node, issued_at: str = CARD_AT, **kwargs) -> bytes:
    return make_card(node.private_key, node.agent_id, kwargs.pop("display_name", "Node"),
                     "https://relay.example/aun", issued_at, **kwargs)


def request_from_a(conv: Conversation) -> bytes:
    return conv.signed("a", "b", "REQUEST", request(DINNER), {"offer": [
        {"place": "Sushi", "time": slot(18)}, {"place": "Pasta", "time": slot(19)}]}, 1)


def test_message_is_accepted_after_the_card_came_in_person():
    nodes = bare_nodes()
    conv = Conversation(nodes)
    assert nodes["b"].accept_card(card_of(nodes["a"]), CARD_NOW, in_person=True) == "trusted"
    assert nodes["b"].receive(request_from_a(conv), T0 + timedelta(seconds=1)) == "accepted"


def test_message_is_dropped_after_only_a_refused_card():
    nodes = bare_nodes()
    conv = Conversation(nodes)
    with pytest.raises(VerificationError) as caught:
        nodes["b"].accept_card(card_of(nodes["a"]), CARD_NOW)
    assert caught.value.code == "CARD_PEER_NOT_TRUSTED"
    assert not nodes["b"].cards and not nodes["b"].trusted
    dropped("PEER_NOT_TRUSTED", nodes["b"], request_from_a(conv), T0 + timedelta(seconds=1))


def test_card_update_keeps_sessions_ids_and_nonces():
    nodes = bare_nodes()
    a, b = nodes["a"], nodes["b"]
    a.trust(Peer(b.agent_id, base64.b64encode(
        b.private_key.public_key().public_bytes_raw()).decode("ascii")))
    b.accept_card(card_of(a), CARD_NOW, in_person=True)
    conv = Conversation(nodes)
    conv.exchange("a", "b", "REQUEST", request(DINNER), {"offer": [
        {"place": "Sushi", "time": slot(18)}, {"place": "Pasta", "time": slot(19)}]}, 1)
    conv.exchange("b", "a", "COUNTER", {"public_reason": "no_common_option"},
                  {"offer": [{"place": "Pasta", "time": slot(20)}]}, 2)
    before = copy.deepcopy((b.sessions, b.seen, b.nonces))
    update = card_of(a, "2099-01-01T08:30:00+09:00", display_name="Renamed")
    assert b.accept_card(update, CARD_NOW) == "updated"
    assert b.cards[a.node_id]["display_name"] == "Renamed"
    assert (b.sessions, b.seen, b.nonces) == before
    conv.exchange("a", "b", "ACCEPT", {}, {"agreed": {"place": "Pasta", "time": slot(20)}}, 3)
    assert conv.state("b").status == "agreed"


def test_peer_registered_without_a_card_takes_a_card_for_the_same_key_and_agent():
    nodes = bare_nodes()
    a, b = nodes["a"], nodes["b"]
    public = base64.b64encode(a.private_key.public_key().public_bytes_raw()).decode("ascii")
    b.trust(Peer(a.agent_id, public))
    other_agent = make_card(a.private_key, "agent-x", "Node", "https://relay.example/aun",
                            CARD_AT)
    with pytest.raises(VerificationError) as caught:
        b.accept_card(other_agent, CARD_NOW)
    assert caught.value.code == "CARD_IDENTITY_MISMATCH"
    assert not b.cards and b.trusted[a.node_id].agent_id == a.agent_id
    assert b.accept_card(card_of(a), CARD_NOW) == "updated"
    assert b.cards[a.node_id]["issued_at"] == CARD_AT
    with pytest.raises(VerificationError) as caught:
        b.accept_card(card_of(a), CARD_NOW)
    assert caught.value.code == "CARD_STALE"


def test_a_refused_card_changes_nothing():
    nodes = bare_nodes()
    a, b = nodes["a"], nodes["b"]
    b.accept_card(card_of(a), CARD_NOW, in_person=True)
    before = copy.deepcopy((b.cards, b.trusted))
    for data, code in (
        (card_of(a), "CARD_STALE"),
        (make_card(a.private_key, "agent-x", "Node", "https://relay.example/aun",
                   "2099-01-01T08:30:00+09:00"), "CARD_IDENTITY_MISMATCH"),
        (card_of(a, "2099-01-01T08:30:00+09:00")[:-5], "CARD_SCHEMA_INVALID"),
    ):
        with pytest.raises(VerificationError) as caught:
            b.accept_card(data, CARD_NOW, in_person=True)
        assert caught.value.code == code
        assert (b.cards, b.trusted) == before


def test_make_card_refuses_to_build_a_card_that_fails_its_own_checks():
    a = bare_nodes()["a"]
    with pytest.raises(VerificationError) as caught:
        card_of(a, protocol_versions=["aun/0.2"])
    assert caught.value.code == "CARD_VERSION_UNSUPPORTED"
    with pytest.raises(VerificationError) as caught:
        card_of(a, CARD_AT, display_name="")
    assert caught.value.code == "CARD_SCHEMA_INVALID"


def test_issue_card_needs_a_strictly_later_issued_at():
    a = bare_nodes()["a"]
    endpoint = "https://relay.example/aun"
    first = a.issue_card("Node", endpoint, "2099-01-01T09:00:00+09:00")
    assert verify_card(first, T0)["issued_at"] == "2099-01-01T09:00:00+09:00"
    for same_or_older in ("2099-01-01T09:00:00+09:00", "2099-01-01T00:00:00Z",
                          "2099-01-01T08:59:59+09:00"):
        with pytest.raises(ValueError):
            a.issue_card("Node", endpoint, same_or_older)
    assert a.last_issued_at == parse_time("2099-01-01T09:00:00+09:00")
    a.issue_card("Node", endpoint, "2099-01-01T09:00:01+09:00")
    assert a.last_issued_at == parse_time("2099-01-01T09:00:01+09:00")
