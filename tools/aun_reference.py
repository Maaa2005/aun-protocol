"""Small reference implementation of AUN Protocol 0.2 signing and verification.

Implements SPEC.md section 7 (signing), the schema check, the time window of
section 8 step 5, and the node ID rule of section 1. It does not implement
session state, replay detection or peer trust (the rest of section 8).

Usage:
    python tools/aun_reference.py verify <envelope.json> --public-key <base64>
        [--no-time-check]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator

PROTOCOL = "aun/0.2"
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "negotiation-message.schema.json"
)


class VerificationError(Exception):
    """Raised when an envelope fails a check. `code` follows SPEC section 8."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical(obj: Any) -> bytes:
    """RFC 8785 (JCS) serialization."""
    return rfc8785.dumps(obj)


def node_id_from_public_key(raw32: bytes) -> str:
    """SPEC section 1: `agt_` + first 16 hex chars of SHA-256 of the raw key."""
    if len(raw32) != 32:
        raise ValueError("public key must be 32 raw bytes")
    return "agt_" + hashlib.sha256(raw32).hexdigest()[:16]


def compute_payload_hash(payload: dict[str, Any], delta: dict[str, Any]) -> str:
    """SPEC section 7 step 1."""
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


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _parse_created_at(envelope: dict[str, Any]) -> datetime:
    try:
        created_at = datetime.fromisoformat(str(envelope["created_at"]))
    except (KeyError, ValueError) as exc:
        raise VerificationError("MESSAGE_SCHEMA_INVALID", "created_at is invalid") from exc
    if created_at.tzinfo is None:
        raise VerificationError(
            "MESSAGE_SCHEMA_INVALID", "created_at needs a timezone offset"
        )
    return created_at


def validate_schema(envelope: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(envelope), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "(root)"
        raise VerificationError("MESSAGE_SCHEMA_INVALID", f"{where}: {first.message}")
    _parse_created_at(envelope)


def verify_envelope(
    envelope: dict[str, Any],
    public_key: str | bytes,
    now: datetime | None = None,
    window_seconds: int = 300,
) -> None:
    """Verify schema, signature, payload hash and time window.

    `public_key` is the Base64 string (or raw 32 bytes) of the sender's key.
    Pass `window_seconds=None` to skip the time check. Raises
    VerificationError with code MESSAGE_SCHEMA_INVALID,
    MESSAGE_SIGNATURE_INVALID or MESSAGE_EXPIRED.
    """
    validate_schema(envelope)

    try:
        raw_key = (
            public_key
            if isinstance(public_key, bytes)
            else base64.b64decode(public_key, validate=True)
        )
        key = Ed25519PublicKey.from_public_bytes(raw_key)
        signature = base64.b64decode(envelope["signature"], validate=True)
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

    if window_seconds is not None:
        current = now or datetime.now(timezone.utc)
        age = abs((current - _parse_created_at(envelope)).total_seconds())
        if age > window_seconds:
            raise VerificationError(
                "MESSAGE_EXPIRED", f"created_at is {age:.0f}s from now"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AUN Protocol 0.2 reference tool")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify one envelope file")
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--public-key", required=True, help="Base64 raw Ed25519 key")
    verify.add_argument(
        "--no-time-check", action="store_true", help="skip the 300 second window"
    )
    args = parser.parse_args(argv)

    envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
    try:
        verify_envelope(
            envelope,
            args.public_key,
            window_seconds=None if args.no_time_check else 300,
        )
        expected = node_id_from_public_key(base64.b64decode(args.public_key))
        if envelope["sender_node_id"] != expected:
            raise VerificationError(
                "AGENT_IDENTITY_MISMATCH",
                f"sender_node_id is not {expected} for this public key",
            )
    except (VerificationError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(
        f"OK {envelope['message_type']} seq={envelope['sequence']} "
        f"from {envelope['sender_node_id']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
