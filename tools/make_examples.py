"""Deterministic generator for the signed example messages in examples/.

The keys are derived from public strings and are TEST ONLY. Seeds, message IDs,
nonces and timestamps are fixed, so running this twice writes identical bytes.

Usage: python tools/make_examples.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aun_reference import PROTOCOL, Node, Peer, node_id_from_public_key  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
JST = timezone(timedelta(hours=9))
BASE_TIME = datetime(2099, 1, 1, 9, 0, 0, tzinfo=JST)

TEST_ONLY_NOTE = (
    "TEST ONLY - never use these keys. The seeds are derived from public "
    "strings and are published here so the examples can be reproduced."
)


def _node(label: str, agent_id: str) -> dict[str, Any]:
    seed = hashlib.sha256(f"aun-example-node-{label}".encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "personal_agent_id": agent_id,
        "node_id": node_id_from_public_key(raw_public),
        "public_key": base64.b64encode(raw_public).decode("ascii"),
        "seed_hex": seed.hex(),
        "private": private,
    }


NODES = {"a": _node("a", "agent-a"), "b": _node("b", "agent-b")}


def keys_document() -> dict[str, Any]:
    return {
        "WARNING": TEST_ONLY_NOTE,
        "nodes": {
            name: {k: v for k, v in node.items() if k != "private"}
            for name, node in NODES.items()
        },
    }


def slot(hour: int, minute: int, length: int = 30) -> dict[str, str]:
    """A slot on 2099-01-01 (+09:00)."""
    start = datetime(2099, 1, 1, hour, minute, tzinfo=JST)
    end = start + timedelta(minutes=length)
    fmt = "%Y-%m-%dT%H:%M+09:00"
    return {"start": start.strftime(fmt), "end": end.strftime(fmt)}


def _hex(label: str, length: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:length]


EXPIRES_AT = (BASE_TIME + timedelta(days=1)).isoformat()


def build_session(
    name: str, intent: str, steps: list[tuple[str, str, dict, dict]]
) -> dict[str, bytes]:
    """Build signed envelopes. `steps` is (sender 'a'|'b', type, payload, delta).

    Every message is recorded by its sender and checked by the receiver
    exactly as SPEC section 9 says, so an example that breaks a rule fails
    here. Returns {relative path: file bytes}.
    """
    files: dict[str, bytes] = {}
    nodes = {who: Node(n["personal_agent_id"], n["private"]) for who, n in NODES.items()}
    for who, n in NODES.items():
        for other, peer in NODES.items():
            if other != who:
                nodes[who].trust(Peer(peer["personal_agent_id"], peer["public_key"]))
    for seq, (who, message_type, payload, delta) in enumerate(steps, start=1):
        sender = NODES[who]
        to = "b" if who == "a" else "a"
        receiver = NODES[to]
        created_at = BASE_TIME + timedelta(seconds=10 * (seq - 1))
        unsigned = {
            "protocol": PROTOCOL,
            "message_id": _hex(f"msg-{name}-{seq}", 32),
            "session_id": f"session-{name}",
            "sender_agent_id": sender["personal_agent_id"],
            "receiver_agent_id": receiver["personal_agent_id"],
            "sender_node_id": sender["node_id"],
            "receiver_node_id": receiver["node_id"],
            "message_type": message_type,
            "intent": intent,
            "session_version": 1,
            "sequence": seq,
            "payload": payload,
            "delta": delta,
            "nonce": _hex(f"nonce-{name}-{seq}", 32),
            "created_at": created_at.isoformat(),
        }
        data = nodes[who].send(unsigned, created_at)
        if nodes[to].receive(data, created_at) != "accepted":
            raise AssertionError(f"{name} message {seq} was not accepted")
        filename = f"{seq:02d}-{message_type.lower()}.json"
        files[f"examples/{name}/{filename}"] = data
    return files


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def request(topic: str, issues: list[dict[str, Any]]) -> dict[str, Any]:
    return {"topic": topic, "expires_at": EXPIRES_AT, "issues": issues}


def offer(*packages: dict[str, Any]) -> dict[str, Any]:
    return {"offer": list(packages)}


def reason(public_reason: str) -> dict[str, str]:
    return {"public_reason": public_reason}


# Profiles (SPEC section 12): the old domains are issue declarations.
def meeting_issue(window_start: tuple[int, int], window_end: tuple[int, int]) -> dict[str, Any]:
    start = slot(*window_start, length=0)["start"]
    end = slot(*window_end, length=0)["start"]
    return {"name": "slot", "kind": "time", "duration_minutes": 30,
            "window": {"start": start, "end": end}}


SHARE = {"name": "share", "kind": "amount", "unit": "JPY", "scale": 0,
         "min": 0, "max": 10000, "step": 100}


def build_all() -> dict[str, bytes]:
    """Return every generated file as {relative path: bytes}."""
    files: dict[str, bytes] = {"examples/keys.json": _dump(keys_document())}

    # Fast path: the first offer already contains an acceptable slot.
    files.update(build_session("meeting-schedule", "meeting.schedule", [
        ("a", "REQUEST", request("Project sync", [meeting_issue((13, 0), (15, 0))]),
         offer({"slot": slot(13, 0)}, {"slot": slot(13, 30)}, {"slot": slot(14, 0)})),
        ("b", "ACCEPT", {}, {"agreed": {"slot": slot(13, 30)}}),
    ]))

    # Longest session: three counters, then the round limit ends it.
    files.update(build_session("meeting-schedule-no-agreement", "meeting.schedule", [
        ("a", "REQUEST", request("Project sync", [meeting_issue((9, 0), (18, 0))]),
         offer({"slot": slot(9, 0)}, {"slot": slot(9, 30)})),
        ("b", "COUNTER", reason("no_common_option"),
         offer({"slot": slot(16, 0)}, {"slot": slot(16, 30)})),
        ("a", "COUNTER", reason("no_common_option"),
         offer({"slot": slot(10, 0)}, {"slot": slot(10, 30)})),
        ("b", "COUNTER", reason("no_common_option"),
         offer({"slot": slot(17, 0)}, {"slot": slot(17, 30)})),
        ("a", "REJECT", reason("no_common_option"), {"code": "NO_AGREEMENT"}),
    ]))

    # Integer amounts in the smallest unit: a counter, then accept it.
    files.update(build_session("cost-split", "cost.split", [
        ("a", "REQUEST", request("Team dinner, total 10000 JPY", [SHARE]),
         offer({"share": 3000})),
        ("b", "COUNTER", reason("constraint_violation"), offer({"share": 2500})),
        ("a", "ACCEPT", {}, {"agreed": {"share": 2500}}),
    ]))

    # The responder's human declines.
    files.update(build_session("cost-split-rejected", "cost.split", [
        ("a", "REQUEST", request("Team dinner, total 10000 JPY", [SHARE]),
         offer({"share": 3000})),
        ("b", "REJECT", reason("policy_declined"), {"code": "HUMAN_REJECTED"}),
    ]))

    # Several issues: each package keeps a place, a time and a flag together.
    dinner = [
        {"name": "place", "kind": "choice", "options": ["Sushi", "Pasta", "Ramen"]},
        {"name": "time", "kind": "time", "duration_minutes": 90,
         "window": {"start": slot(17, 0, 0)["start"], "end": slot(22, 0, 0)["start"]}},
        {"name": "split_bill", "kind": "flag"},
    ]
    files.update(build_session("dinner-plan", "dinner.plan", [
        ("a", "REQUEST", request("Dinner on Friday", dinner),
         offer({"place": "Sushi", "time": slot(18, 0, 90), "split_bill": True},
               {"place": "Pasta", "time": slot(19, 0, 90), "split_bill": True})),
        ("b", "COUNTER", reason("no_common_option"),
         offer({"place": "Ramen", "time": slot(19, 0, 90), "split_bill": True},
               {"place": "Pasta", "time": slot(19, 30, 90), "split_bill": True})),
        ("a", "ACCEPT", {}, {"agreed": {"place": "Pasta", "time": slot(19, 30, 90),
                                        "split_bill": True}}),
    ]))

    # A favour: a yes/no term and a day, agreed in two messages.
    favor = [
        {"name": "day", "kind": "choice", "options": ["Saturday", "Sunday"]},
        {"name": "water_plants", "kind": "flag"},
    ]
    files.update(build_session("favor-ask", "favor.ask", [
        ("a", "REQUEST", request("Water my plants this weekend", favor),
         offer({"day": "Saturday", "water_plants": True},
               {"day": "Sunday", "water_plants": True})),
        ("b", "ACCEPT", {}, {"agreed": {"day": "Sunday", "water_plants": True}}),
    ]))

    # Open choice: no options are declared, so a counter may name a new gift.
    gift = [
        {"name": "gift", "kind": "choice"},
        {"name": "budget", "kind": "amount", "unit": "JPY", "scale": 0,
         "min": 1000, "max": 5000, "step": 500},
    ]
    files.update(build_session("gift-pick", "gift.pick", [
        ("a", "REQUEST", request("Joint birthday gift for a friend", gift),
         offer({"gift": "Coffee beans", "budget": 3000})),
        ("b", "COUNTER", reason("policy_declined"),
         offer({"gift": "Tea set", "budget": 3000},
               {"gift": "Coffee beans", "budget": 2000})),
        ("a", "ACCEPT", {}, {"agreed": {"gift": "Tea set", "budget": 3000}}),
    ]))
    return files


def main() -> None:
    for relative, data in build_all().items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"wrote {relative}")


if __name__ == "__main__":
    main()
