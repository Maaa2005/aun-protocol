"""Deterministic generator for test-vectors/receiver-v0.3.json (format: FORMAT below).

Usage:
  python tools/make_vectors.py           write the file
  python tools/make_vectors.py --check   replay the file through the reference node
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aun_reference import (  # noqa: E402
    MAX_BYTES,
    PROTOCOL,
    Node,
    Peer,
    VerificationError,
    encode,
    sign_envelope,
)
from make_examples import TEST_ONLY_NOTE, _node  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = "test-vectors/receiver-v0.3.json"

JST = timezone(timedelta(hours=9))
UTC = timezone.utc
T0 = datetime(2099, 1, 1, 9, 0, tzinfo=JST)
NOW = T0 + timedelta(seconds=10)
EXPIRES = T0 + timedelta(hours=1)
FAR = datetime(9999, 12, 31, 23, 50, tzinfo=UTC)
BAD_DATE = "2099-02-29T18:00+09:00"  # 2099 is not a leap year
MAX_INT = 2**53 - 1

KEYS = {label: _node(label, f"agent-{label}") for label in "abcd"}
ROLES = {"a": "trusted peer", "b": "receiver", "c": "trusted peer", "d": "not trusted"}
FORMAT = [
    "Receiver cases for SPEC sections 4 to 9, for an implementation in any language.",
    "Each case starts a fresh node B that trusts A and C, not D. Its steps run in order.",
    "receive: B runs the receiver checks on `message` (Base64 of the bytes) at time `now`.",
    "send: B runs the sender checks on its own `message` at time `now` and records it.",
    "`expect` is accepted, duplicate or the code of the drop. A drop changes nothing.",
    "After the last step, `final` is the status of B's session with A for session_id s1,",
    "or null when B holds none.",
]


# ---- messages ---------------------------------------------------------------


def unsigned(who: str, message_type: str, payload: dict, delta: dict, sequence: int,
             *, to: str = "b", session: str = "s1", **override: Any) -> dict[str, Any]:
    sender, receiver = KEYS[who], KEYS[to]
    fields = {
        "protocol": PROTOCOL,
        "message_id": f"{session}-m{sequence}",
        "session_id": session,
        "sender_agent_id": sender["personal_agent_id"],
        "receiver_agent_id": receiver["personal_agent_id"],
        "sender_node_id": sender["node_id"],
        "receiver_node_id": receiver["node_id"],
        "message_type": message_type,
        "intent": "test.case",
        "session_version": 1,
        "sequence": sequence,
        "payload": payload,
        "delta": delta,
        "nonce": f"{session}-n{sequence}",
        "created_at": (T0 + timedelta(seconds=sequence)).isoformat(),
    }
    fields.update(override)
    return fields


def signed(who: str, *args: Any, **kwargs: Any) -> bytes:
    return encode(sign_envelope(unsigned(who, *args, **kwargs), KEYS[who]["private"]))


def slot(hour: int, minute: int = 0, length: int = 60, tz: timezone = JST) -> dict[str, str]:
    start = datetime(2099, 1, 1, hour, minute, tzinfo=JST).astimezone(tz)
    end = start + timedelta(minutes=length)
    return {"start": start.isoformat(timespec="minutes"),
            "end": end.isoformat(timespec="minutes")}


PLACE = {"name": "place", "kind": "choice", "options": ["Sushi", "Pasta"]}
TIME = {"name": "time", "kind": "time", "duration_minutes": 60,
        "window": {"start": slot(17)["start"], "end": slot(22)["start"]}}
AMOUNT = {"name": "share", "kind": "amount", "unit": "JPY", "scale": 0,
          "min": 0, "max": 10000, "step": 100}
DINNER = [PLACE, TIME]
FIRST_OFFER = {"offer": [{"place": "Sushi", "time": slot(18)},
                         {"place": "Pasta", "time": slot(19)}]}
REASON = {"public_reason": "no_common_option"}


def request(issues: list[dict] = DINNER, expires_at: str = EXPIRES.isoformat()) -> dict:
    return {"topic": "Test", "expires_at": expires_at, "issues": issues}


def opening(payload: dict | None = None, **override: Any) -> bytes:
    """A asks B: {Sushi 18:00} or {Pasta 19:00}."""
    return signed("a", "REQUEST", payload or request(), FIRST_OFFER, 1, **override)


def counter(who: str, sequence: int, place: str, hour: int, **override: Any) -> bytes:
    to = "a" if who == "b" else "b"
    return signed(who, "COUNTER", REASON, {"offer": [{"place": place, "time": slot(hour)}]},
                  sequence, to=to, **override)


def accept(who: str, sequence: int, package: dict, **override: Any) -> bytes:
    to = "a" if who == "b" else "b"
    return signed(who, "ACCEPT", {}, {"agreed": package}, sequence, to=to, **override)


def amount_request(issue: dict, package: dict, **override: Any) -> bytes:
    expires_at = override.pop("expires_at", EXPIRES.isoformat())
    return signed("a", "REQUEST", request([issue], expires_at), {"offer": [package]}, 1,
                  **override)


def time_request(window_start: str = slot(17)["start"], offer: dict | None = None,
                 expires_at: str = EXPIRES.isoformat()) -> bytes:
    issue = dict(TIME, window={"start": window_start, "end": slot(22)["start"]})
    payload = {"topic": "Test", "expires_at": expires_at, "issues": [issue]}
    return signed("a", "REQUEST", payload, {"offer": [{"time": offer or slot(18)}]}, 1)


def raw(old: bytes, new: bytes) -> bytes:
    data = opening()
    assert data.count(old) == 1
    return data.replace(old, new)


def padded(total: int) -> bytes:
    """The opening REQUEST with spaces after `{`, `total` bytes long."""
    data = opening()
    return b"{" + b" " * (total - len(data)) + data[1:]


def edited(data: bytes, **change: Any) -> bytes:
    """Change fields after signing, so the signature no longer matches."""
    envelope = json.loads(data)
    envelope.update(change)
    return encode(envelope)


def bad_signature(data: bytes) -> bytes:
    """A well-formed signature that does not verify."""
    signature = json.loads(data)["signature"]
    return edited(data, signature=("B" if signature[0] == "A" else "A") + signature[1:])


def spare_bits_set(data: bytes) -> bytes:
    """The last data character moved off A, Q, g or w: the same bytes, another spelling."""
    signature = json.loads(data)["signature"]
    return edited(data, signature=signature[:-3] + chr(ord(signature[-3]) + 1) + "==")


def compact(data: bytes) -> bytes:
    """The same JSON value without whitespace and with `T` of "Test" escaped."""
    text = json.dumps(json.loads(data), separators=(",", ":"), ensure_ascii=False).encode()
    assert text.count(b'"Test"') == 1
    return text.replace(b'"Test"', b'"\\u0054est"')


# ---- cases ------------------------------------------------------------------


def receive(data: bytes, expect: str, now: datetime = NOW) -> dict[str, str]:
    return {"action": "receive", "now": now.isoformat(),
            "message": base64.b64encode(data).decode("ascii"), "expect": expect}


def send(data: bytes, expect: str = "accepted", now: datetime = NOW) -> dict[str, str]:
    return dict(receive(data, expect, now), action="send")


def build_cases() -> dict[str, dict[str, Any]]:
    schema, payload = "MESSAGE_SCHEMA_INVALID", "INVALID_NEGOTIATION_PAYLOAD"
    state, replayed = "INVALID_STATE_TRANSITION", "MESSAGE_REPLAYED"
    sushi18 = {"place": "Sushi", "time": slot(18)}
    pasta19 = {"place": "Pasta", "time": slot(19)}
    pasta20 = {"place": "Pasta", "time": slot(20)}
    cases: dict[str, tuple[list[dict], str | None]] = {}

    def single(name: str, data: bytes, expect: str, now: datetime = NOW) -> None:
        cases[name] = ([receive(data, expect, now)], None if expect != "accepted" else "open")

    # Sessions (sections 5 and 6).
    cases["agreed at once"] = ([
        receive(opening(), "accepted"), send(accept("b", 2, pasta19))], "agreed")
    cases["agreed after a counter"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, pasta20), "accepted")], "agreed")
    cases["accept written with another offset"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, {"place": "Pasta", "time": slot(20, tz=UTC)}), "accepted"),
    ], "agreed")
    cases["accept of a package not in the standing offer"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, sushi18), payload)], "open")
    cases["rejected"] = ([
        receive(opening(), "accepted"),
        send(signed("b", "REJECT", REASON, {"code": "NO_AGREEMENT"}, 2, to="a"))], "rejected")
    cases["not supported"] = ([
        receive(opening(), "accepted"),
        send(signed("b", "ERROR", {}, {"code": "NOT_SUPPORTED"}, 2, to="a"))], "not_supported")
    cases["five messages, the fourth counter refused"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 17)),
        receive(counter("a", 3, "Sushi", 21), "accepted"), send(counter("b", 4, "Pasta", 20)),
        receive(counter("a", 5, "Sushi", 19), state),
        receive(accept("a", 5, pasta20, message_id="s1-m6", nonce="s1-n6"), "accepted"),
    ], "agreed")
    cases["same party twice"] = ([
        receive(opening(), "accepted"), receive(counter("a", 2, "Sushi", 20), state)], "open")
    cases["sequence skips"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 4, pasta20), state)], "open")
    cases["message after the session closed"] = ([
        receive(opening(), "accepted"), send(accept("b", 2, pasta19)),
        receive(counter("a", 3, "Sushi", 20), state)], "agreed")
    cases["message for an unknown session"] = ([
        receive(counter("a", 2, "Sushi", 20, session="s9"), state)], None)
    cases["a third node cannot join"] = ([
        receive(opening(), "accepted"), receive(accept("c", 2, sushi18), state)], "open")
    cases["the same session ID from another node is another session"] = ([
        receive(opening(), "accepted"),
        receive(signed("c", "REQUEST", request(), FIRST_OFFER, 1), "accepted")], "open")
    cases["second REQUEST for a known session"] = ([
        receive(opening(), "accepted"),
        receive(opening(message_id="s1-m9", nonce="s1-n9"), replayed)], "open")
    late = EXPIRES + timedelta(seconds=1)
    cases["created after the deadline"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, pasta20, created_at=late.isoformat()), "SESSION_EXPIRED", late),
    ], "open")
    week = T0 + timedelta(seconds=1, days=7)
    single("deadline exactly 7 days after the request",
           opening(payload=request(expires_at=week.isoformat())), "accepted")
    single("deadline more than 7 days after the request",
           opening(payload=request(expires_at=(week + timedelta(seconds=1)).isoformat())),
           payload)

    cases["intent changed in the session"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, pasta20, intent="other.case"), "SESSION_BINDING_MISMATCH"),
    ], "open")
    cases["session version changed in the session"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(accept("a", 3, pasta20, session_version=2), "SESSION_BINDING_MISMATCH"),
    ], "open")
    single("session version 7 is fixed for the session", opening(session_version=7), "accepted")

    # Declarations and packages (sections 4 and 6).
    def offer(*packages: dict, issues: list[dict] = DINNER) -> bytes:
        return signed("a", "REQUEST", request(issues), {"offer": list(packages)}, 1)

    single("option not declared", offer({"place": "Ramen", "time": slot(18)}), payload)
    single("open choice takes a new option",
           offer({"place": "Ramen", "time": slot(18)}, issues=[{"name": "place", "kind": "choice"},
                                                              TIME]), "accepted")
    single("package without an issue", offer({"place": "Sushi"}), payload)
    single("package with an undeclared key",
           offer({"place": "Sushi", "time": slot(18), "note": "x"}), payload)
    single("slot outside the window", offer({"place": "Sushi", "time": slot(21, 30)}), payload)
    single("slot of the wrong length", offer({"place": "Sushi", "time": slot(18, length=30)}),
           payload)
    single("slot with seconds", offer({"place": "Sushi", "time": {
        "start": "2099-01-01T18:00:30+09:00", "end": "2099-01-01T19:00:30+09:00"}}), schema)
    single("window longer than 31 days", signed("a", "REQUEST", request([dict(
        TIME, window={"start": slot(17)["start"], "end": "2099-02-01T17:01+09:00"})]),
        {"offer": [{"time": slot(18)}]}, 1), payload)
    single("issue name used twice", offer({"place": "Sushi"}, issues=[PLACE, PLACE]), payload)
    single("amount on the step", amount_request(AMOUNT, {"share": 2500}), "accepted")
    single("amount off the step", amount_request(AMOUNT, {"share": 2550}), payload)
    single("amount above max", amount_request(AMOUNT, {"share": 10100}), payload)
    single("amount with min above max", amount_request(dict(AMOUNT, min=200, max=100),
                                                       {"share": 100}), payload)
    single("value of the wrong kind", amount_request(AMOUNT, {"share": "2500"}), payload)
    single("flag", amount_request({"name": "ok", "kind": "flag"}, {"ok": True}), "accepted")

    # Duplicates and replay (section 9 step 7).
    cases["identical copy"] = ([
        receive(opening(), "accepted"), receive(opening(), "duplicate")], "open")
    cases["the same message with other whitespace and escapes"] = ([
        receive(opening(), "accepted"), receive(compact(opening()), "duplicate")], "open")
    cases["known message ID with other content"] = ([
        receive(opening(), "accepted"),
        receive(opening(session_id="s2", nonce="s2-n1"), replayed)], "open")
    cases["nonce used again"] = ([
        receive(opening(), "accepted"),
        receive(opening(session_id="s2", message_id="s2-m1"), replayed)], "open")
    cases["B never reuses its own nonce"] = ([
        receive(opening(), "accepted"), send(counter("b", 2, "Pasta", 20)),
        receive(counter("a", 3, "Sushi", 21), "accepted"),
        send(counter("b", 4, "Pasta", 17, nonce="s1-n2"), replayed)], "open")
    cases["a copy after the time window"] = ([
        receive(opening(), "accepted"),
        receive(opening(), "MESSAGE_EXPIRED", T0 + timedelta(seconds=302))], "open")

    # Limits and order of the checks (section 9).
    single("16384 bytes", padded(MAX_BYTES), "accepted")
    single("16385 bytes", padded(MAX_BYTES + 1), "MESSAGE_TOO_LARGE")
    for seconds, expect in ((300, "accepted"), (301, "MESSAGE_EXPIRED")):
        single(f"created {seconds} seconds before now",
               opening(created_at=(NOW - timedelta(seconds=seconds)).isoformat()), expect)
        single(f"created {seconds} seconds after now",
               opening(created_at=(NOW + timedelta(seconds=seconds)).isoformat()), expect)
    untrusted = signed("d", "REQUEST", request(), FIRST_OFFER, 1)
    single("untrusted node with a bad signature", bad_signature(untrusted), "PEER_NOT_TRUSTED")
    single("untrusted node with an unknown field", edited(untrusted, extra=1), schema)
    single("bad signature, created an hour ago",
           edited(opening(created_at=(T0 - timedelta(hours=1)).isoformat()),
                  payload=dict(request(), topic="Changed")),
           "MESSAGE_SIGNATURE_INVALID")
    single("addressed to another node", signed("a", "REQUEST", request(), FIRST_OFFER, 1, to="c"),
           "SESSION_BINDING_MISMATCH")
    single("agent not registered for the node", opening(sender_agent_id="agent-x"),
           "AGENT_IDENTITY_MISMATCH")
    single("payload changed after signing",
           edited(opening(), payload=request(expires_at=(EXPIRES + timedelta(minutes=1))
                                             .isoformat())),
           "MESSAGE_SIGNATURE_INVALID")

    # Hostile input: parser, patterns, dates and numbers.
    single("empty", b"", schema)
    single("invalid UTF-8", b'{"a": "\xc3\x28"}', schema)
    single("byte order mark", b"\xef\xbb\xbf" + opening(), schema)
    single("lone surrogate", raw(b'"topic": "Test"', b'"topic": "\\ud800"'), schema)
    single("5000-digit integer",
           raw(b'"session_version": 1', b'"session_version": 1' + b"0" * 4999), schema)
    single("integer 2^53", raw(b'"session_version": 1', b'"session_version": 9007199254740992'),
           schema)
    single("exponent", raw(b'"session_version": 1', b'"session_version": 1E0'), schema)
    single("nesting 3000 levels", b"[" * 3000 + b"]" * 3000, schema)
    single("oversized field", raw(b'"topic": "Test"', b'"topic": "' + b" " * MAX_BYTES + b'"'),
           "MESSAGE_TOO_LARGE")
    single("newline after intent", opening(intent="test.case\n"), schema)
    single("newline after created_at", opening(created_at="2099-01-01T09:00:01+09:00\n"), schema)
    single("newline in a package key", amount_request(AMOUNT, {"share\n": 0}), schema)
    single("non-ASCII digits", opening(created_at="٢٠٩٩-01-01T09:00:01+09:00"), schema)
    single("leap second", opening(created_at="2099-01-01T08:59:60+09:00"), schema)
    single("seven fraction digits", opening(created_at="2099-01-01T09:00:00.1234567+09:00"),
           schema)
    single("offset +24:00", opening(created_at="2099-01-01T09:00:00+24:00"), schema)
    single("year 0001 at +23:59", opening(created_at="0001-01-01T00:00:00+23:59"), schema)
    single("year 9999 at -23:59", opening(created_at="9999-12-31T23:59:00-23:59"), schema)
    single("year 0001 in UTC", opening(created_at="0001-01-01T00:00:00Z"), "MESSAGE_EXPIRED")
    single("offset -00:00 is UTC", opening(created_at="2099-01-01T00:00:01-00:00"), "accepted")
    single("no such date in expires_at", time_request(expires_at=BAD_DATE), schema)
    single("no such date in a window", time_request(window_start=BAD_DATE), schema)
    single("no such date in an offer",
           time_request(offer={"start": BAD_DATE, "end": "2099-02-29T19:00+09:00"}), schema)
    single("deadline near year 9999", amount_request(
        AMOUNT, {"share": 0}, expires_at=(FAR + timedelta(minutes=9)).isoformat(),
        created_at=FAR.isoformat()), "accepted", FAR)
    single("amount range above 2^53-1",
           amount_request(dict(AMOUNT, min=-MAX_INT, max=MAX_INT, step=1), {"share": 0}), payload)
    single("the same instant twice in an offer", signed(
        "a", "REQUEST", request([TIME]), {"offer": [{"time": slot(18)}, {"time": slot(18, tz=UTC)}]},
        1), payload)
    single("signature with spare bits set", spare_bits_set(opening()), schema)

    return {name: {"steps": steps, "final": final} for name, (steps, final) in cases.items()}


def build() -> bytes:
    document = {
        "WARNING": TEST_ONLY_NOTE,
        "protocol": PROTOCOL,
        "format": FORMAT,
        "nodes": {
            label: {"role": ROLES[label]}
            | {k: v for k, v in node.items() if k != "private"}
            for label, node in KEYS.items()
        },
        "cases": [{"name": name} | case for name, case in build_cases().items()],
    }
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# ---- replay -----------------------------------------------------------------


def fresh_receiver() -> Node:
    node = Node(KEYS["b"]["personal_agent_id"], KEYS["b"]["private"])
    for label, role in ROLES.items():
        if role == "trusted peer":
            node.trust(Peer(KEYS[label]["personal_agent_id"], KEYS[label]["public_key"]))
    return node


def run_case(case: dict[str, Any]) -> tuple[list[str], str | None]:
    """Each step's result through a fresh reference node B, and the final status."""
    node = fresh_receiver()
    results = []
    for step in case["steps"]:
        data = base64.b64decode(step["message"])
        now = datetime.fromisoformat(step["now"])
        before = copy.deepcopy((node.sessions, node.seen, node.nonces))
        try:
            if step["action"] == "receive":
                results.append(node.receive(data, now))
            else:
                fields = json.loads(data)
                del fields["signature"]
                same = node.send(fields, now) == data
                results.append("accepted" if same else "signed bytes differ")
        except VerificationError as exc:
            changed = (node.sessions, node.seen, node.nonces) != before
            results.append(exc.code + (" (state changed)" if changed else ""))
    session = node.sessions.get((KEYS["a"]["node_id"], "s1"))
    return results, session.status if session else None


def check(path: Path) -> int:
    failures = 0
    for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
        expected = ([step["expect"] for step in case["steps"]], case["final"])
        got = run_case(case)
        if got != expected:
            failures += 1
            print(f"FAIL {case['name']}: expected {expected}, got {got}")
    print("ok" if failures == 0 else f"{failures} failing")
    return 1 if failures else 0


def main() -> None:
    path = ROOT / OUTPUT
    if sys.argv[1:] == ["--check"]:
        sys.exit(check(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build())
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
