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
from aun_reference import node_id_from_public_key, sign_envelope  # noqa: E402

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


def slot(hour: int, minute: int) -> dict[str, str]:
    """A 30 minute slot on 2099-01-01 (+09:00)."""
    start = datetime(2099, 1, 1, hour, minute, tzinfo=JST)
    end = start + timedelta(minutes=30)
    fmt = "%Y-%m-%dT%H:%M+09:00"
    return {"start": start.strftime(fmt), "end": end.strftime(fmt)}


def _hex(label: str, length: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:length]


def build_session(
    name: str, intent: str, steps: list[tuple[str, str, dict, dict]]
) -> dict[str, bytes]:
    """Build signed envelopes. `steps` is (sender 'a'|'b', type, payload, delta).

    Returns {relative path: file bytes}.
    """
    files: dict[str, bytes] = {}
    for seq, (who, message_type, payload, delta) in enumerate(steps, start=1):
        sender = NODES[who]
        receiver = NODES["b" if who == "a" else "a"]
        unsigned = {
            "protocol": "aun/0.2",
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
            "requires_human_approval": False,
            "nonce": _hex(f"nonce-{name}-{seq}", 32),
            "created_at": (BASE_TIME + timedelta(seconds=10 * (seq - 1))).isoformat(),
        }
        envelope = sign_envelope(unsigned, sender["private"])
        filename = f"{seq:02d}-{message_type.lower()}.json"
        files[f"examples/{name}/{filename}"] = _dump(envelope)
    return files


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def meeting_request() -> dict[str, Any]:
    return {
        "intent": "meeting.schedule",
        "topic": "Project sync",
        "duration_minutes": 30,
        "date_range": {"start": "2099-01-01", "end": "2099-01-01"},
        "preferred_time_ranges": [{"start": "13:00", "end": "15:00"}],
        "timezone": "Asia/Tokyo",
    }


def cost_request() -> dict[str, Any]:
    return {
        "intent": "cost.split",
        "title": "Team dinner",
        "total_amount": 10000.0,
        "currency": "JPY",
        "proposed_share": 3000.0,
        "deadline": None,
    }


def build_all() -> dict[str, bytes]:
    """Return every generated file as {relative path: bytes}."""
    files: dict[str, bytes] = {"examples/keys.json": _dump(keys_document())}

    # Section 6: meeting with a common slot.
    files.update(build_session("meeting-schedule", "meeting.schedule", [
        ("a", "REQUEST", meeting_request(), {}),
        ("a", "PROPOSE", {}, {"candidate_slots": [slot(13, 0), slot(13, 30), slot(14, 0)]}),
        ("b", "ACCEPT", {}, {"selected_slot": slot(13, 30)}),
    ]))

    # Section 6: meeting with no common slot, ending in ERROR.
    files.update(build_session("meeting-schedule-no-slot", "meeting.schedule", [
        ("a", "REQUEST", meeting_request(), {}),
        ("a", "PROPOSE", {}, {"candidate_slots": [slot(13, 0), slot(13, 30)]}),
        ("b", "COUNTER", {"public_reason": "no_common_slot"},
         {"candidate_slots": [slot(14, 0), slot(14, 30)]}),
        ("a", "COUNTER", {"public_reason": "no_common_slot"},
         {"candidate_slots": [slot(13, 0), slot(13, 30)]}),
        ("b", "ERROR", {}, {"code": "NO_AVAILABLE_SLOT"}),
    ]))

    # cost.split: counter, then accept the counter.
    files.update(build_session("cost-split", "cost.split", [
        ("a", "REQUEST", cost_request(), {}),
        ("a", "PROPOSE", {}, {"proposed_share": 3000.0}),
        ("b", "COUNTER", {"public_reason": "constraint_violation"},
         {"proposed_share": 2500.5}),
        ("a", "ACCEPT", {}, {"agreed_share": 2500.5}),
    ]))

    # cost.split: the responder's human rejects.
    files.update(build_session("cost-split-rejected", "cost.split", [
        ("a", "REQUEST", cost_request(), {}),
        ("a", "PROPOSE", {}, {"proposed_share": 3000.0}),
        ("b", "REJECT", {"public_reason": "policy_declined"}, {"code": "HUMAN_REJECTED"}),
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
