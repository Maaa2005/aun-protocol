"""Deterministic generator for test-vectors/card-v1.json (format: FORMAT below).

Usage:
  python tools/make_card_vectors.py           write the file
  python tools/make_card_vectors.py --check   replay the file through the reference node
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
    CARD_MAX_BYTES,
    CARD_VERSION,
    PROTOCOL,
    Node,
    VerificationError,
    encode_card,
    parse_time,
    sign_card,
)
from make_examples import TEST_ONLY_NOTE, _node  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = "test-vectors/card-v1.json"

JST = timezone(timedelta(hours=9))
T0 = datetime(2099, 1, 1, 9, 0, tzinfo=JST)
LATER = T0 + timedelta(minutes=10)
MINUTE = timedelta(seconds=60)

KEYS = {label: _node(label, f"agent-{label}") for label in "abc"}
ROLES = {"a": "card owner", "b": "receiver", "c": "other node"}
FORMAT = [
    "Agent card cases for SPEC section 11, for an implementation in any language.",
    "Each case starts a fresh node B that has stored no card and trusts no one.",
    "Its steps run in order. A step gives the card bytes `card` (Base64), B's clock",
    "`now`, `in_person` (the card came through the in-person step) and `expect`:",
    "trusted for a first card, updated for a later card, or the code of the refusal.",
    "A refusal changes nothing. After the last step, `final` is the `issued_at` of the",
    "card B stores for node A, as written in that card, or null when B stores none.",
]


# ---- cards ------------------------------------------------------------------


def fields(who: str = "a", issued_at: datetime | str = T0, **override: Any) -> dict[str, Any]:
    """The nine fields minus `signature`. `override` replaces a field; None drops it."""
    node = KEYS[who]
    when = issued_at if isinstance(issued_at, str) else issued_at.isoformat()
    result = {
        "version": CARD_VERSION,
        "node_id": node["node_id"],
        "agent_id": node["personal_agent_id"],
        "public_key": node["public_key"],
        "display_name": f"Node {who.upper()}",
        "protocol_versions": [PROTOCOL],
        "relay_endpoint": f"https://relay.example/aun/{who}",
        "issued_at": when,
    }
    result.update(override)
    return {k: v for k, v in result.items() if v is not None}


def card(who: str = "a", issued_at: datetime | str = T0, *, signer: str | None = None,
         **override: Any) -> bytes:
    """A card signed by `signer` (default: `who`). It is not checked at all."""
    unsigned = fields(who, issued_at, **override)
    return encode_card(sign_card(unsigned, KEYS[signer or who]["private"]))


def a0() -> bytes:
    return card("a", T0)


def a1() -> bytes:
    return card("a", LATER, display_name="Node A (new)",
                relay_endpoint="https://relay.example/aun/a2")


def tampered(data: bytes, **change: Any) -> bytes:
    """Change fields after signing, so the signature no longer matches."""
    parsed = json.loads(data)
    parsed.update(change)
    return encode_card(parsed)


def padded(data: bytes, total: int) -> bytes:
    """`data` with spaces after `{`, `total` bytes long."""
    assert len(data) <= total
    return b"{" + b" " * (total - len(data)) + data[1:]


def raw(data: bytes, old: bytes, new: bytes) -> bytes:
    assert data.count(old) == 1
    return data.replace(old, new)


def spare_bits_key() -> str:
    """The same key with the last data character moved: another spelling of the bytes."""
    key = KEYS["a"]["public_key"]
    assert key[-1] == "="
    return key[:-2] + chr(ord(key[-2]) + 1) + "="


def spare_bits_signature(data: bytes) -> str:
    signature = json.loads(data)["signature"]
    return signature[:-3] + chr(ord(signature[-3]) + 1) + "=="


# ---- cases ------------------------------------------------------------------


def step(data: bytes, expect: str, in_person: bool = False,
         now: datetime | None = None) -> dict[str, Any]:
    """B's clock is one minute after `issued_at` unless `now` is given."""
    if now is None:
        try:
            now = parse_time(json.loads(data)["issued_at"]) + MINUTE
        except (ValueError, KeyError, TypeError):
            now = T0 + MINUTE
    return {"card": base64.b64encode(data).decode("ascii"),
            "now": now.astimezone(JST).isoformat(), "in_person": in_person, "expect": expect}


def build_cases() -> dict[str, dict[str, Any]]:
    schema, mismatch = "CARD_SCHEMA_INVALID", "CARD_IDENTITY_MISMATCH"
    bad_sig, stale = "CARD_SIGNATURE_INVALID", "CARD_STALE"
    not_yet, no_version = "CARD_NOT_YET_VALID", "CARD_VERSION_UNSUPPORTED"
    too_large, not_trusted = "CARD_TOO_LARGE", "CARD_PEER_NOT_TRUSTED"
    t0, t1 = T0.isoformat(), LATER.isoformat()
    cases: dict[str, tuple[list[dict], str | None]] = {}

    def single(name: str, data: bytes, expect: str, now: datetime | None = None,
               final: str | None = None) -> None:
        """One step, in person. A card that is refused stores nothing."""
        cases[name] = ([step(data, expect, True, now)], final)

    # The update rule (section 11.2 step 8, section 11.3).
    cases["first_in_person"] = ([step(a0(), "trusted", True)], t0)
    cases["first_via_relay"] = ([step(a0(), not_trusted)], None)
    cases["later_update"] = ([step(a0(), "trusted", True), step(a1(), "updated")], t1)
    cases["identical_resend"] = ([step(a0(), "trusted", True), step(a0(), stale)], t0)
    cases["in_person_resend"] = ([step(a0(), "trusted", True), step(a0(), stale, True)], t0)
    cases["same_instant_other_offset"] = ([
        step(a0(), "trusted", True),
        step(card("a", "2099-01-01T00:00:00Z"), stale)], t0)
    cases["older_card"] = ([
        step(a1(), "trusted", True), step(a0(), stale, now=LATER + MINUTE)], t1)
    cases["agent_id_changed"] = ([
        step(a0(), "trusted", True),
        step(card("a", LATER, agent_id="agent-x"), mismatch)], t0)
    cases["failed_update_then_good"] = ([
        step(a0(), "trusted", True),
        step(tampered(a1(), display_name="Changed"), bad_sig),
        step(a1(), "updated")], t1)
    cases["far_future_then_good"] = ([
        step(a0(), "trusted", True),
        step(card("a", "2100-01-01T00:00:00Z"), not_yet, now=LATER + MINUTE),
        step(a1(), "updated")], t1)
    cases["other_peer_update"] = ([
        step(a0(), "trusted", True),
        step(card("c", T0), "trusted", True),
        step(card("c", LATER, display_name="Node C (new)"), "updated")], t0)

    # Identity and signature (steps 4 and 5).
    single("node_id_not_derived", card("c", T0, node_id=KEYS["a"]["node_id"]), mismatch)
    single("signed_by_other_key", card("a", T0, signer="c"), bad_sig)
    single("tampered_after_signing", tampered(a0(), display_name="Changed"), bad_sig)

    # Version and clock (steps 6 and 7).
    single("version_only_0_2", card("a", T0, protocol_versions=["aun/0.2"]), no_version)
    single("version_unknown_extra",
           card("a", T0, protocol_versions=[PROTOCOL, "aun/9.9"]), "trusted", final=t0)
    single("clock_301_ahead", a0(), not_yet, now=T0 - timedelta(seconds=301))
    single("clock_300_ahead", a0(), "trusted", now=T0 - timedelta(seconds=300), final=t0)
    single("one_year_old", a0(), "trusted", now=T0 + timedelta(days=365), final=t0)

    # Size (step 1).
    single("size_2049", padded(a0(), CARD_MAX_BYTES + 1), too_large)
    single("size_2048", padded(a0(), CARD_MAX_BYTES), "trusted", final=t0)

    # Schema and strict JSON (steps 2 and 3).
    single("extra_field", card("a", T0, extra="x"), schema)
    single("missing_relay_endpoint", card("a", T0, relay_endpoint=None), schema)
    single("empty_display_name", card("a", T0, display_name=""), schema)
    single("display_name_101_code_points", card("a", T0, display_name="あ" * 101), schema)
    single("display_name_100_code_points", card("a", T0, display_name="あ" * 100),
           "trusted", final=t0)
    single("http_endpoint", card("a", T0, relay_endpoint="http://relay.example/aun/a"), schema)
    single("space_in_endpoint", card("a", T0, relay_endpoint="https://relay.example/a un"),
           schema)
    single("empty_versions", card("a", T0, protocol_versions=[]), schema)
    single("duplicate_versions", card("a", T0, protocol_versions=[PROTOCOL, PROTOCOL]), schema)
    single("version_aun_card_2", card("a", T0, version="aun-card/2"), schema)
    single("public_key_spare_bits", card("a", T0, public_key=spare_bits_key()), schema)
    single("signature_spare_bits", tampered(a0(), signature=spare_bits_signature(a0())), schema)
    single("february_30", card("a", "2099-02-30T09:00:00+09:00"), schema)
    single("duplicate_json_key",
           raw(a0(), b'"agent_id": "agent-a"', b'"agent_id": "agent-a",\n  "agent_id": "agent-a"'),
           schema)
    single("byte_order_mark", b"\xef\xbb\xbf" + a0(), schema)
    single("float_value", raw(a0(), b'"aun/0.3"', b"1.0"), schema)
    single("not_an_object", encode_card([json.loads(a0())]), schema)  # type: ignore[arg-type]

    # Order of the checks: each case breaks two, and the earlier one is reported.
    single("too_large_and_bad_schema",
           padded(card("a", T0, extra="x"), CARD_MAX_BYTES + 1), too_large)
    single("bad_node_id_and_bad_signature",
           card("a", T0, signer="c", node_id=KEYS["c"]["node_id"]), mismatch)
    single("bad_signature_and_bad_version",
           card("a", T0, signer="c", protocol_versions=["aun/0.2"]), bad_sig)
    single("bad_version_and_future", card("a", T0, protocol_versions=["aun/0.2"]), no_version,
           now=T0 - timedelta(hours=1))
    cases["future_and_not_in_person"] = ([
        step(a0(), not_yet, False, T0 - timedelta(hours=1))], None)

    # Free text is data: a name that is only an ideographic space is still a name.
    single("ideographic_space_name", card("a", T0, display_name="　"), "trusted", final=t0)

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
    return Node(KEYS["b"]["personal_agent_id"], KEYS["b"]["private"])


def run_case(case: dict[str, Any]) -> tuple[list[str], str | None]:
    """Each step's result through a fresh reference node B, and the final `issued_at`."""
    node = fresh_receiver()
    results = []
    for entry in case["steps"]:
        data = base64.b64decode(entry["card"])
        now = datetime.fromisoformat(entry["now"])
        before = copy.deepcopy((node.cards, node.trusted, node.sessions, node.seen, node.nonces))
        try:
            results.append(node.accept_card(data, now, entry["in_person"]))
        except VerificationError as exc:
            after = (node.cards, node.trusted, node.sessions, node.seen, node.nonces)
            results.append(exc.code + (" (state changed)" if after != before else ""))
    stored = node.cards.get(KEYS["a"]["node_id"])
    return results, stored["issued_at"] if stored else None


def check(path: Path) -> int:
    failures = 0
    for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
        expected = ([entry["expect"] for entry in case["steps"]], case["final"])
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
