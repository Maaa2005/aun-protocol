"""Reference checker for AUN Protocol 0.3.

Implements SPEC.md: signing (section 8), the receiver checks in order
(section 9), session state (section 5), the package rules (section 6) and the
agent card checks (section 11.2).
It knows the four issue kinds and nothing about any domain: no intent name
appears in this file.

Usage:
    python tools/aun_reference.py verify <envelope.json> --public-key <base64>
        [--no-time-check]
    python tools/aun_reference.py check-session <dir> --keys <keys.json>
    python tools/aun_reference.py verify-card <card.json> [--now <date-time>]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import ValidationError

PROTOCOL = "aun/0.3"
MAX_BYTES = 16384
MAX_DEPTH = 8
WINDOW_SECONDS = 300
MAX_COUNTERS = 3
MAX_SESSION_DAYS = 7
MAX_WINDOW_DAYS = 31
MAX_INT = 2**53 - 1
CARD_VERSION = "aun-card/1"
CARD_MAX_BYTES = 2048
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "negotiation-message.schema.json"
)
CARD_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "agent-card.schema.json"
)

_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})"
    r"(?::([0-9]{2})(?:\.([0-9]{1,6}))?)?(Z|[+-][0-9]{2}:[0-9]{2})"
)


class VerificationError(Exception):
    """Raised when a message is dropped. `code` follows SPEC section 10."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# ---- encoding --------------------------------------------------------------


def canonical(obj: Any) -> bytes:
    """RFC 8785 (JCS) serialization."""
    return rfc8785.dumps(obj)


def node_id_from_public_key(raw32: bytes) -> str:
    """SPEC section 2: `agt_` + first 16 hex chars of SHA-256 of the raw key."""
    if len(raw32) != 32:
        raise ValueError("public key must be 32 raw bytes")
    return "agt_" + hashlib.sha256(raw32).hexdigest()[:16]


def b64decode_strict(text: str, length: int) -> bytes:
    """Base64 with padding and no other form of the same bytes (SPEC section 2).

    Unused trailing bits must be zero, so each byte string has one text.
    """
    if not isinstance(text, str):
        raise ValueError("base64 value must be a string")
    raw = base64.b64decode(text, validate=True)
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != text:
        raise ValueError(f"not the canonical base64 of {length} bytes")
    return raw


def compute_payload_hash(payload: dict[str, Any], delta: dict[str, Any]) -> str:
    """SPEC section 8 step 1."""
    return hashlib.sha256(canonical({"payload": payload, "delta": delta})).hexdigest()


def sign_envelope(
    unsigned_fields: dict[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    """Return a signed envelope.

    `unsigned_fields` holds every envelope field except `payload_hash` and
    `signature`. Both are computed here.
    """
    envelope = {
        k: v for k, v in unsigned_fields.items() if k not in ("payload_hash", "signature")
    }
    envelope["payload_hash"] = compute_payload_hash(
        envelope["payload"], envelope["delta"]
    )
    signature = private_key.sign(canonical(envelope))
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope


def encode(envelope: dict[str, Any]) -> bytes:
    """The byte form used by the examples. Any JSON form is valid on the wire."""
    return (json.dumps(envelope, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("MESSAGE_SCHEMA_INVALID", f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_float(text: str) -> Any:
    raise VerificationError("MESSAGE_SCHEMA_INVALID", f"non-integer number {text}")


def _reject_constant(text: str) -> Any:
    raise VerificationError("MESSAGE_SCHEMA_INVALID", f"{text} is not JSON")


def _parse_int(text: str) -> int:
    """I-JSON integers only: within plus or minus 2^53-1 (RFC 7493).

    The length is checked first, so a huge number is refused before conversion.
    """
    if len(text.lstrip("-")) > 16 or abs(int(text)) > MAX_INT:
        raise VerificationError("MESSAGE_SCHEMA_INVALID", "integer out of range")
    return int(text)


def _check_tree(value: Any, level: int = 1) -> None:
    """Nesting (the top-level object is level 1) and I-JSON strings.

    A lone surrogate such as "\\ud800" is valid JSON syntax but not I-JSON
    (RFC 7493), and JCS cannot encode it, so it is refused here.
    """
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VerificationError("MESSAGE_SCHEMA_INVALID", "lone surrogate") from exc
    elif isinstance(value, (dict, list)):
        if level > MAX_DEPTH:
            raise VerificationError("MESSAGE_SCHEMA_INVALID", "nested too deep")
        children = (
            [item for pair in value.items() for item in pair]
            if isinstance(value, dict)
            else value
        )
        for child in children:
            _check_tree(child, level + 1)


def parse_strict_json(data: bytes, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """SPEC section 9 steps 1 and 2: size, then strict JSON."""
    if len(data) > max_bytes:
        raise VerificationError("MESSAGE_TOO_LARGE", f"{len(data)} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise VerificationError("MESSAGE_SCHEMA_INVALID", "byte order mark")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise VerificationError("MESSAGE_SCHEMA_INVALID", "not valid JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError("MESSAGE_SCHEMA_INVALID", "not an object")
    _check_tree(value)
    return value


def parse_envelope_bytes(data: bytes) -> dict[str, Any]:
    """SPEC section 9 steps 1 and 2 for a message."""
    return parse_strict_json(data, MAX_BYTES)


# ---- time ------------------------------------------------------------------


def parse_time(text: str) -> datetime:
    """RFC 3339 date-time with an offset, returned in UTC (SPEC section 3).

    Works the same on all Python 3.9+. A leap second, a date that does not
    exist and an instant outside years 0001 to 9999 in UTC raise ValueError.
    """
    match = _DATE_TIME.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise ValueError(f"bad date-time {text!r}")
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        hours, minutes = int(offset[1:3]), int(offset[4:6])
        if hours > 23 or minutes > 59:
            raise ValueError(f"bad offset {offset!r}")
        tz = timezone(sign * timedelta(hours=hours, minutes=minutes))
    micro = int((fraction or "0").ljust(6, "0"))
    local = datetime(
        int(year), int(month), int(day), int(hour), int(minute),
        int(second or 0), micro, tzinfo=tz,
    )
    try:
        return local.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError(f"{text!r} is outside years 0001 to 9999 in UTC") from exc


# ---- schema ----------------------------------------------------------------

def _whole_string(validator: Any, pattern: str, instance: Any, schema: Any):
    """`pattern` as ECMA-262 reads the schema: the whole string, ASCII only.

    Python's `$` also matches before a final newline and `\\d` matches other
    scripts' digits, so the stock keyword would accept "a\\n" for "^a$".
    Every pattern in the schema is anchored with `^` and `$`.
    """
    if not validator.is_type(instance, "string"):
        return
    if re.fullmatch(f"(?:{pattern[1:-1]})", instance, re.ASCII) is None:
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_StrictValidator = validators.extend(Draft202012Validator, {"pattern": _whole_string})
_VALIDATOR: Any = None


def _validator() -> Any:
    global _VALIDATOR
    if _VALIDATOR is None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        _VALIDATOR = _StrictValidator(schema)
    return _VALIDATOR


_CARD_VALIDATOR: Any = None


def _card_validator() -> Any:
    global _CARD_VALIDATOR
    if _CARD_VALIDATOR is None:
        schema = json.loads(CARD_SCHEMA_PATH.read_text(encoding="utf-8"))
        _CARD_VALIDATOR = _StrictValidator(schema)
    return _CARD_VALIDATOR


def _date_times(envelope: dict[str, Any]) -> list[str]:
    """Every date-time in a message that already matches the schema."""
    found = [envelope["created_at"]]
    payload, delta = envelope["payload"], envelope["delta"]
    if envelope["message_type"] == "REQUEST":
        found.append(payload["expires_at"])
        found += [t for i in payload["issues"] if "window" in i
                  for t in (i["window"]["start"], i["window"]["end"])]
    packages = delta.get("offer", []) + ([delta["agreed"]] if "agreed" in delta else [])
    found += [t for p in packages for v in p.values() if isinstance(v, dict)
              for t in (v["start"], v["end"])]
    return found


def validate_schema(envelope: dict[str, Any]) -> None:
    """SPEC section 9 step 3: the schema, then every date-time is a real instant."""
    errors = sorted(_validator().iter_errors(envelope), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "(root)"
        raise VerificationError("MESSAGE_SCHEMA_INVALID", f"{where}: {first.message}")
    try:
        for text in _date_times(envelope):
            parse_time(text)
    except ValueError as exc:
        raise VerificationError("MESSAGE_SCHEMA_INVALID", str(exc)) from exc


def verify_signature(envelope: dict[str, Any], public_key: str | bytes) -> None:
    """SPEC section 9 step 5: signature and payload hash."""
    try:
        raw_key = (
            public_key
            if isinstance(public_key, bytes)
            else b64decode_strict(public_key, 32)
        )
        key = Ed25519PublicKey.from_public_bytes(raw_key)
        signature = b64decode_strict(envelope["signature"], 64)
        signed = {k: v for k, v in envelope.items() if k != "signature"}
        key.verify(signature, canonical(signed))
    except (InvalidSignature, ValueError, TypeError, binascii.Error,
            rfc8785.CanonicalizationError) as exc:
        raise VerificationError(
            "MESSAGE_SIGNATURE_INVALID", "signature does not verify"
        ) from exc
    if envelope["payload_hash"] != compute_payload_hash(
        envelope["payload"], envelope["delta"]
    ):
        raise VerificationError("MESSAGE_SIGNATURE_INVALID", "payload_hash mismatch")


def verify_envelope(
    envelope: dict[str, Any],
    public_key: str | bytes,
    now: datetime | None = None,
    window_seconds: int | None = WINDOW_SECONDS,
) -> None:
    """Stateless checks: schema, signature, payload hash and time window."""
    validate_schema(envelope)
    verify_signature(envelope, public_key)
    if window_seconds is not None:
        current = now or datetime.now(timezone.utc)
        age = abs((current - parse_time(envelope["created_at"])).total_seconds())
        if age > window_seconds:
            raise VerificationError(
                "MESSAGE_EXPIRED", f"created_at is {age:.0f}s from now"
            )


# ---- issues and packages (SPEC section 6) ---------------------------------


def _bad(message: str) -> VerificationError:
    return VerificationError("INVALID_NEGOTIATION_PAYLOAD", message)


def _slot(value: dict[str, str]) -> tuple[datetime, datetime]:
    try:
        return parse_time(value["start"]), parse_time(value["end"])
    except ValueError as exc:
        raise _bad(str(exc)) from exc


def validate_issues(issues: list[dict[str, Any]]) -> None:
    """Checks the schema cannot express."""
    names = [issue["name"] for issue in issues]
    if len(set(names)) != len(names):
        raise _bad("issue names are not unique")
    for issue in issues:
        kind = issue["kind"]
        if kind == "time":
            start, end = _slot(issue["window"])
            if not start < end:
                raise _bad(f"{issue['name']}: window ends before it starts")
            if end - start > timedelta(days=MAX_WINDOW_DAYS):
                raise _bad(f"{issue['name']}: window longer than {MAX_WINDOW_DAYS} days")
            if timedelta(minutes=issue["duration_minutes"]) > end - start:
                raise _bad(f"{issue['name']}: duration longer than window")
        elif kind == "amount":
            if issue["min"] > issue["max"]:
                raise _bad(f"{issue['name']}: min is above max")
            if issue["max"] - issue["min"] > MAX_INT:
                raise _bad(f"{issue['name']}: max minus min is above 2^53-1")


def validate_value(issue: dict[str, Any], value: Any) -> None:
    name, kind = issue["name"], issue["kind"]
    if kind == "choice":
        if not isinstance(value, str):
            raise _bad(f"{name}: needs a string")
        if "options" in issue and value not in issue["options"]:
            raise _bad(f"{name}: not one of the declared options")
    elif kind == "time":
        if not isinstance(value, dict):
            raise _bad(f"{name}: needs a slot")
        start, end = _slot(value)
        window_start, window_end = _slot(issue["window"])
        if start < window_start or end > window_end:
            raise _bad(f"{name}: slot outside the window")
        if end - start != timedelta(minutes=issue["duration_minutes"]):
            raise _bad(f"{name}: slot is not {issue['duration_minutes']} minutes")
    elif kind == "amount":
        if not isinstance(value, int) or isinstance(value, bool):
            raise _bad(f"{name}: needs an integer")
        if not issue["min"] <= value <= issue["max"]:
            raise _bad(f"{name}: outside min and max")
        if (value - issue["min"]) % issue["step"] != 0:
            raise _bad(f"{name}: not on a step")
    elif kind == "flag":
        if not isinstance(value, bool):
            raise _bad(f"{name}: needs true or false")
    else:  # unreachable after the schema check
        raise _bad(f"{name}: unknown kind")


def validate_package(issues: list[dict[str, Any]], package: dict[str, Any]) -> None:
    """A package has exactly one valid value for every declared issue."""
    if set(package) != {issue["name"] for issue in issues}:
        raise _bad("package keys differ from the declared issues")
    for issue in issues:
        validate_value(issue, package[issue["name"]])


def comparable(issues: list[dict[str, Any]], package: dict[str, Any]) -> tuple:
    """A key that is equal for two packages exactly when they are the same.

    Time slots compare as instants, so 09:00+09:00 equals 00:00Z.
    """
    key = []
    for issue in sorted(issues, key=lambda i: i["name"]):
        value = package[issue["name"]]
        if issue["kind"] == "time":
            value = _slot(value)
        key.append((issue["name"], type(value).__name__, value))
    return tuple(key)


def validate_offer(issues: list[dict[str, Any]], offer: list[dict[str, Any]]) -> None:
    for package in offer:
        validate_package(issues, package)
    keys = [comparable(issues, package) for package in offer]
    if len(set(keys)) != len(keys):
        raise _bad("offer repeats a package")


# ---- agent card (SPEC section 11) -------------------------------------------


def sign_card(fields: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """SPEC section 11.1: `signature` covers the JCS of the card without it.

    Any `signature` in `fields` is dropped. Nothing is checked here.
    """
    card = {k: v for k, v in fields.items() if k != "signature"}
    card["signature"] = base64.b64encode(private_key.sign(canonical(card))).decode("ascii")
    return card


def encode_card(card: dict[str, Any]) -> bytes:
    """The byte form used by the examples. Any JSON form is valid on the wire."""
    return encode(card)


def _card_error(code: str, exc: VerificationError) -> VerificationError:
    return VerificationError(code, str(exc).partition(": ")[2])


def verify_card(data: bytes, now: datetime) -> dict[str, Any]:
    """SPEC section 11.2 steps 1 to 7, in order. Returns the parsed card.

    Step 8 needs the stored cards and is `Node.accept_card`.
    """
    if len(data) > CARD_MAX_BYTES:
        raise VerificationError("CARD_TOO_LARGE", f"{len(data)} bytes")
    try:
        card = parse_strict_json(data, CARD_MAX_BYTES)
    except VerificationError as exc:
        code = "CARD_TOO_LARGE" if exc.code == "MESSAGE_TOO_LARGE" else "CARD_SCHEMA_INVALID"
        raise _card_error(code, exc) from exc
    errors = sorted(_card_validator().iter_errors(card), key=lambda e: list(e.path))
    if errors:
        where = "/".join(str(p) for p in errors[0].path) or "(root)"
        raise VerificationError("CARD_SCHEMA_INVALID", f"{where}: {errors[0].message}")
    try:
        issued_at = parse_time(card["issued_at"])
    except ValueError as exc:
        raise VerificationError("CARD_SCHEMA_INVALID", str(exc)) from exc

    try:
        raw_key = b64decode_strict(card["public_key"], 32)
        derived = node_id_from_public_key(raw_key)
    except ValueError as exc:
        raise VerificationError("CARD_IDENTITY_MISMATCH", "public_key is not a key") from exc
    if card["node_id"] != derived:
        raise VerificationError("CARD_IDENTITY_MISMATCH", f"node_id is not {derived}")

    try:
        key = Ed25519PublicKey.from_public_bytes(raw_key)
        signature = b64decode_strict(card["signature"], 64)
        signed = {k: v for k, v in card.items() if k != "signature"}
        key.verify(signature, canonical(signed))
    except (InvalidSignature, ValueError, TypeError, binascii.Error,
            rfc8785.CanonicalizationError) as exc:
        raise VerificationError("CARD_SIGNATURE_INVALID", "signature does not verify") from exc

    if PROTOCOL not in card["protocol_versions"]:
        raise VerificationError("CARD_VERSION_UNSUPPORTED", f"no {PROTOCOL}")

    ahead = (issued_at - now).total_seconds()
    if ahead > WINDOW_SECONDS:
        raise VerificationError("CARD_NOT_YET_VALID", f"issued_at is {ahead:.0f}s ahead")
    return card


def make_card(
    private_key: Ed25519PrivateKey, agent_id: str, display_name: str,
    relay_endpoint: str, issued_at: str,
    protocol_versions: tuple[str, ...] | list[str] = (PROTOCOL,),
    now: datetime | None = None,
) -> bytes:
    """Sign a card and run steps 1 to 7 on it, so a sender never hands out a bad one."""
    raw = private_key.public_key().public_bytes_raw()
    card = sign_card({
        "version": CARD_VERSION,
        "node_id": node_id_from_public_key(raw),
        "agent_id": agent_id,
        "public_key": base64.b64encode(raw).decode("ascii"),
        "display_name": display_name,
        "protocol_versions": list(protocol_versions),
        "relay_endpoint": relay_endpoint,
        "issued_at": issued_at,
    }, private_key)
    data = encode_card(card)
    verify_card(data, now or parse_time(issued_at))
    return data


# ---- session state (SPEC section 5) ----------------------------------------


@dataclass(frozen=True)
class Party:
    agent_id: str
    node_id: str


@dataclass
class Session:
    session_id: str
    intent: str
    session_version: int
    initiator: Party
    responder: Party
    expires_at: datetime
    issues: list[dict[str, Any]]
    standing_offer: list[dict[str, Any]]
    last_sender: Party
    sequence: int = 1
    counters: int = 0
    status: str = "open"  # open | agreed | rejected | not_supported | expired
    agreed: dict[str, Any] | None = None
    final_code: str | None = None

    def other(self, party: Party) -> Party:
        return self.responder if party == self.initiator else self.initiator

    def expire_if_due(self, now: datetime) -> str:
        """SPEC section 5.3: an open session ends 300 s after `expires_at`."""
        if self.status == "open" and now - timedelta(seconds=WINDOW_SECONDS) > (
            self.expires_at
        ):
            self.status = "expired"
        return self.status


def _party(envelope: dict[str, Any], side: str) -> Party:
    return Party(envelope[f"{side}_agent_id"], envelope[f"{side}_node_id"])


@dataclass
class Peer:
    agent_id: str
    public_key: str

    @property
    def node_id(self) -> str:
        return node_id_from_public_key(b64decode_strict(self.public_key, 32))


@dataclass
class Node:
    """One side of the conversation: keeps sessions and seen message IDs.

    `trusted` maps node IDs to peers registered out of band (SPEC section 11).
    A session ID is unique per pair of nodes, and a message ID and a nonce
    per sender node (SPEC section 3), so every key includes a node ID:
    `sessions` by (other node, session ID), `seen` by (sender node, message
    ID) and `nonces` by (sender node, nonce).
    """

    agent_id: str
    private_key: Ed25519PrivateKey
    trusted: dict[str, Peer] = field(default_factory=dict)
    sessions: dict[tuple[str, str], Session] = field(default_factory=dict)
    seen: dict[tuple[str, str], bytes] = field(default_factory=dict)
    nonces: set[tuple[str, str]] = field(default_factory=set)
    cards: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_issued_at: datetime | None = None

    @property
    def node_id(self) -> str:
        raw = self.private_key.public_key().public_bytes_raw()
        return node_id_from_public_key(raw)

    @property
    def me(self) -> Party:
        return Party(self.agent_id, self.node_id)

    def trust(self, peer: Peer) -> None:
        self.trusted[peer.node_id] = peer

    # -- cards (SPEC section 11.2) ----------------------------------------

    def accept_card(self, data: bytes, now: datetime, in_person: bool = False) -> str:
        """Run SPEC section 11.2 steps 1 to 8. Returns "trusted" or "updated".

        Raises VerificationError when the card is refused. A refusal changes
        nothing. A peer registered with `trust()` and no card counts as the
        stored identity without an `issued_at`: any valid card with the same
        key and agent is an update.

        The compare and the replace are one step here because the reference
        is single-threaded. A real node does them atomically and durably.
        """
        card = verify_card(data, now)
        node_id = card["node_id"]
        stored = self.cards.get(node_id)
        peer = self.trusted.get(node_id)
        if stored is None and peer is None:
            if not in_person:
                raise VerificationError("CARD_PEER_NOT_TRUSTED", node_id)
            result = "trusted"
        else:
            known_key, known_agent = (
                (stored["public_key"], stored["agent_id"]) if stored is not None
                else (peer.public_key, peer.agent_id)
            )
            if card["public_key"] != known_key or card["agent_id"] != known_agent:
                raise VerificationError("CARD_IDENTITY_MISMATCH", "key or agent differs")
            if stored is not None and not (
                parse_time(card["issued_at"]) > parse_time(stored["issued_at"])
            ):
                raise VerificationError("CARD_STALE", "issued_at is not later")
            result = "updated"
        self.cards[node_id] = card
        self.trust(Peer(card["agent_id"], card["public_key"]))
        return result

    def issue_card(
        self, display_name: str, relay_endpoint: str, issued_at: str,
        protocol_versions: tuple[str, ...] | list[str] = (PROTOCOL,),
        now: datetime | None = None,
    ) -> bytes:
        """Make this node's card. `issued_at` must be later than every earlier card.

        SPEC section 11.2: the node keeps the last `issued_at` instead of
        trusting its clock alone.
        """
        when = parse_time(issued_at)
        if self.last_issued_at is not None and not when > self.last_issued_at:
            raise ValueError(f"issued_at must be later than {self.last_issued_at.isoformat()}")
        data = make_card(self.private_key, self.agent_id, display_name, relay_endpoint,
                         issued_at, protocol_versions, now)
        self.last_issued_at = when
        return data

    # -- receiving ---------------------------------------------------------

    def receive(self, data: bytes, now: datetime) -> str:
        """Run SPEC section 9 in order. Returns "accepted" or "duplicate".

        Raises VerificationError when the message is dropped. A dropped
        message changes nothing and gets no reply.
        """
        envelope = parse_envelope_bytes(data)
        validate_schema(envelope)

        peer = self.trusted.get(envelope["sender_node_id"])
        if peer is None:
            raise VerificationError("PEER_NOT_TRUSTED", envelope["sender_node_id"])
        if envelope["sender_agent_id"] != peer.agent_id:
            raise VerificationError("AGENT_IDENTITY_MISMATCH", "agent ID not registered")
        if _party(envelope, "receiver") != self.me:
            raise VerificationError("SESSION_BINDING_MISMATCH", "not addressed to me")

        verify_signature(envelope, peer.public_key)

        age = abs((now - parse_time(envelope["created_at"])).total_seconds())
        if age > WINDOW_SECONDS:
            raise VerificationError("MESSAGE_EXPIRED", f"created_at is {age:.0f}s away")

        if self._is_duplicate(envelope):
            return "duplicate"
        if (envelope["sender_node_id"], envelope["nonce"]) in self.nonces:
            raise VerificationError("MESSAGE_REPLAYED", "nonce already used")

        self._apply(envelope, now)
        return "accepted"

    def _is_duplicate(self, envelope: dict[str, Any]) -> bool:
        known = self.seen.get((envelope["sender_node_id"], envelope["message_id"]))
        if known is None:
            return False
        if known == canonical(envelope):
            return True
        raise VerificationError("MESSAGE_REPLAYED", "message_id reused")

    # -- sending -----------------------------------------------------------

    def send(self, unsigned_fields: dict[str, Any], now: datetime) -> bytes:
        """Sign, run the same state and payload checks, record, return bytes.

        Approval of every package (SPEC section 7) is the caller's duty and
        cannot be checked here.
        """
        envelope = sign_envelope(unsigned_fields, self.private_key)
        data = encode(envelope)
        self.record_sent(data, now)
        return data

    def record_sent(self, data: bytes, now: datetime) -> None:
        """Record a message this node signed, after the sender-side checks."""
        if len(data) > MAX_BYTES:
            raise VerificationError("MESSAGE_TOO_LARGE", f"{len(data)} bytes")
        envelope = parse_envelope_bytes(data)
        validate_schema(envelope)
        if _party(envelope, "sender") != self.me:
            raise VerificationError("SESSION_BINDING_MISMATCH", "sender is not me")
        verify_signature(envelope, self.private_key.public_key().public_bytes_raw())
        if (self.node_id, envelope["message_id"]) in self.seen:
            raise VerificationError("MESSAGE_REPLAYED", "message_id reused")
        if (self.node_id, envelope["nonce"]) in self.nonces:
            raise VerificationError("MESSAGE_REPLAYED", "nonce reused")
        self._apply(envelope, now)

    # -- shared state machine ---------------------------------------------

    def _apply(self, envelope: dict[str, Any], now: datetime) -> None:
        message_type = envelope["message_type"]
        sender = _party(envelope, "sender")
        receiver = _party(envelope, "receiver")
        created_at = parse_time(envelope["created_at"])
        other = receiver if sender == self.me else sender
        key = (other.node_id, envelope["session_id"])
        session = self.sessions.get(key)

        if message_type == "REQUEST":
            if session is not None:
                raise VerificationError("MESSAGE_REPLAYED", "sequence 1 already recorded")
            session = self._open(envelope, sender, receiver, created_at)
        else:
            if session is None:
                raise VerificationError("INVALID_STATE_TRANSITION", "unknown session")
            self._check_turn(session, envelope, sender, receiver, now)
            if created_at > session.expires_at:
                raise VerificationError("SESSION_EXPIRED", "created after expires_at")
            self._check_and_advance(session, envelope)

        self.seen[(sender.node_id, envelope["message_id"])] = canonical(envelope)
        self.nonces.add((sender.node_id, envelope["nonce"]))
        self.sessions[key] = session

    def _open(
        self, envelope: dict[str, Any], sender: Party, receiver: Party,
        created_at: datetime,
    ) -> Session:
        payload = envelope["payload"]
        try:
            expires_at = parse_time(payload["expires_at"])
        except ValueError as exc:
            raise _bad(str(exc)) from exc
        if not timedelta(0) < expires_at - created_at <= timedelta(days=MAX_SESSION_DAYS):
            raise _bad(f"expires_at must be after created_at and within {MAX_SESSION_DAYS} days")
        issues = payload["issues"]
        validate_issues(issues)
        offer = envelope["delta"]["offer"]
        validate_offer(issues, offer)
        return Session(
            session_id=envelope["session_id"],
            intent=envelope["intent"],
            session_version=envelope["session_version"],
            initiator=sender,
            responder=receiver,
            expires_at=expires_at,
            issues=issues,
            standing_offer=offer,
            last_sender=sender,
        )

    def _check_turn(
        self, session: Session, envelope: dict[str, Any], sender: Party,
        receiver: Party, now: datetime,
    ) -> None:
        if envelope["intent"] != session.intent or (
            envelope["session_version"] != session.session_version
        ):
            raise VerificationError("SESSION_BINDING_MISMATCH", "intent or version differs")
        parties = {session.initiator, session.responder}
        if sender not in parties or receiver != session.other(sender):
            raise VerificationError("SESSION_BINDING_MISMATCH", "not the session's parties")
        if envelope["sequence"] <= session.sequence:
            raise VerificationError("MESSAGE_REPLAYED", "sequence already recorded")
        if session.expire_if_due(now) != "open":
            raise VerificationError(
                "SESSION_EXPIRED" if session.status == "expired" else "INVALID_STATE_TRANSITION",
                f"session is {session.status}",
            )
        if envelope["sequence"] != session.sequence + 1:
            raise VerificationError("INVALID_STATE_TRANSITION", "sequence skips")
        if sender == session.last_sender:
            raise VerificationError("INVALID_STATE_TRANSITION", "not this party's turn")

    def _check_and_advance(self, session: Session, envelope: dict[str, Any]) -> None:
        message_type = envelope["message_type"]
        delta = envelope["delta"]
        if message_type == "COUNTER":
            if session.counters >= MAX_COUNTERS:
                raise VerificationError("INVALID_STATE_TRANSITION", "counter limit reached")
            validate_offer(session.issues, delta["offer"])
            session.counters += 1
            session.standing_offer = delta["offer"]
        elif message_type == "ACCEPT":
            agreed = delta["agreed"]
            validate_package(session.issues, agreed)
            offered = {comparable(session.issues, p) for p in session.standing_offer}
            if comparable(session.issues, agreed) not in offered:
                raise _bad("agreed package is not in the standing offer")
            session.status, session.agreed = "agreed", agreed
        elif message_type == "REJECT":
            session.status, session.final_code = "rejected", delta["code"]
        elif message_type == "ERROR":
            if session.sequence != 1:
                raise VerificationError("INVALID_STATE_TRANSITION", "ERROR only answers REQUEST")
            session.status, session.final_code = "not_supported", delta["code"]
        session.sequence = envelope["sequence"]
        session.last_sender = _party(envelope, "sender")


# ---- CLI -------------------------------------------------------------------


def _load_keys(path: Path) -> dict[str, dict[str, str]]:
    return json.loads(path.read_text(encoding="utf-8"))["nodes"]


def check_session(directory: Path, keys: dict[str, dict[str, str]],
                  now: datetime | None = None) -> Session:
    """Replay a directory of messages between two fresh nodes.

    Each message is recorded by its sender and checked by its receiver.
    """
    files = sorted(directory.glob("*.json"))
    if not files:
        raise ValueError(f"no messages in {directory}")
    observers: dict[str, Node] = {}
    for entry in keys.values():
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
        observers[entry["node_id"]] = Node(entry["personal_agent_id"], private)
    for node in observers.values():
        for entry in keys.values():
            if entry["node_id"] != node.node_id:
                node.trust(Peer(entry["personal_agent_id"], entry["public_key"]))
    session = None
    for path in files:
        data = path.read_bytes()
        envelope = parse_envelope_bytes(data)
        at = now or parse_time(envelope["created_at"])
        observers[envelope["sender_node_id"]].record_sent(data, at)
        receiver = observers[envelope["receiver_node_id"]]
        if receiver.receive(data, at) != "accepted":
            raise ValueError(f"{path.name} is a duplicate")
        session = receiver.sessions[(envelope["sender_node_id"], envelope["session_id"])]
    return session


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AUN Protocol 0.3 reference checker")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify one envelope file")
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--public-key", required=True, help="Base64 raw Ed25519 key")
    verify.add_argument("--no-time-check", action="store_true",
                        help="skip the 300 second window")
    replay = sub.add_parser("check-session", help="replay one session directory")
    replay.add_argument("directory", type=Path)
    replay.add_argument("--keys", required=True, type=Path,
                        help="keys file with seeds (test keys only)")
    card = sub.add_parser("verify-card", help="run card checks 1 to 7 on one card file")
    card.add_argument("card", type=Path)
    card.add_argument("--now", help="date-time of the clock (default: now, UTC)")
    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            envelope = parse_envelope_bytes(args.envelope.read_bytes())
            verify_envelope(envelope, args.public_key,
                            window_seconds=None if args.no_time_check else WINDOW_SECONDS)
            expected = node_id_from_public_key(b64decode_strict(args.public_key, 32))
            if envelope["sender_node_id"] != expected:
                raise VerificationError("AGENT_IDENTITY_MISMATCH",
                                        f"sender_node_id is not {expected}")
            print(f"OK {envelope['message_type']} seq={envelope['sequence']} "
                  f"from {envelope['sender_node_id']}")
        elif args.command == "verify-card":
            now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
            parsed = verify_card(args.card.read_bytes(), now)
            print(f"OK card {parsed['node_id']} ({parsed['agent_id']}) "
                  f"issued_at {parsed['issued_at']}")
        else:
            session = check_session(args.directory, _load_keys(args.keys))
            print(f"OK {session.session_id}: {session.status} after "
                  f"{session.sequence} messages")
    except (VerificationError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
