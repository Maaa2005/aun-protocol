# Design note: AUN 0.4, the fixes from the 2026-11-02 review

Status: draft, after research and one review with a second AI. The rules are in
[SPEC.md](../SPEC.md). This note keeps why each was chosen and what was not.

## Why break compatibility now

The node ID and `session_version` cannot be fixed compatibly. A search of GitHub
on 2026-11-04 found no implementation outside this repository, and the spec is
a 0.x draft, so this is the cheapest moment. Keeping the name 0.3 would make two
incompatible things with one name. Migration is short: 0.3 is frozen by a tag,
nodes make new cards, and sessions do not carry over.

## 1. Small-order keys

Measured with `cryptography` 50.0.2: every small-order public key in both sign
bits, and the non-canonical `eeff...7f`, accepted a signature made without a
private key. RFC 8032 and FIPS 186-5 do not refuse such keys, and Go, BoringSSL
and OpenSSL do not either, so the spec has to.

- **Chosen:** refuse by comparing integers (section 8), which works in every
  language. It covers the same points as the libsodium 1.0.18 list. R gets the
  same check, only to reduce differences between libraries.
- **Not chosen:** multiplying by 8, because some libraries, including
  `cryptography`, offer no point operation.
- **Not chosen:** a full order check to refuse mixed-order keys. It is costly and
  rarely offered, and only the holder can make such a key. The remaining
  differences between libraries are stated in the spec.
- **Not chosen:** fixing the verification equation as ZIP-215 does. It suits a
  consensus system, and common libraries give no choice of equation.

## 2. IDs and free text

Machine IDs are ASCII in most comparable systems (Matrix, AT Protocol, DIDComm),
and RFC 8264 and RFC 8265 separate IDs from display text. Tag characters and
variation selectors are invisible to people and read by language models. The
signature forbids editing text in transit, so a receiver can only refuse it or
handle it at display.

- **Chosen:** an ASCII pattern for IDs, and a table of refused code points for
  free text, fixed by number and outside the schema.
- **Not chosen:** the PRECIS FreeformClass, which needs derived tables that move
  with the Unicode version.
- **Not chosen:** display handling only. A model reading the text is the main
  case here, and marking characters on a screen does not reach it.
- **Cost, accepted:** tag-sequence flags, Japanese ideographic variation
  sequences (they use the supplementary selectors), some old Hangul, and line
  breaks in `topic`. The Mongolian selectors stay allowed because the script
  needs them.

## 3. Node ID of 128 bits

A truncated hash gives half its length against collisions and its full length
against second preimages (SP 800-107r1). RFC 6920 limits names under 100 bits.
Comparable systems use the whole key (Tor v3, did:key, Iroh), 256 bits (Syncthing)
or 120 bits (did:plc). A relay routes by node ID, so a 64-bit collision could
misroute messages even though signatures hold.

- **Not chosen:** the whole key, which appears twice per message for little gain.
- **Not chosen:** 64 bits with an explanation, which leaves the routing problem.

## 4. Late messages and a lost ACCEPT

In 0.3 the 300 second window on every message meant that an `ACCEPT` resent later
was dropped, leaving one side agreed and the other expired. Time limits at set-up
with state afterwards are common (Kerberos, TLS 0-RTT, AS4 with identical resends
and ID checks, RFC 4130).

- **Chosen:** no past limit at step 6 for any type, including `REQUEST`, which can
  also wait at a relay. Section 5.3 limits lateness to the deadline. State stops
  copies. The review changed this: the first draft kept 300 seconds for `REQUEST`,
  which would lose ordinary stored-and-forwarded requests.
- **Not chosen:** signing again with a new time, because two different `ACCEPT`
  messages could then exist.
- **Not chosen:** an acknowledgement message, which needs its own acknowledgement
  and more state.
- **Not chosen:** a status query, which adds a second interface and authentication.
- **Cost, accepted:** a node that loses its records can accept a copy of a
  `REQUEST` for about 7 days, where 0.3 limited this to 300 seconds. The spec says
  so and asks such a node to wait. Without a third party the two sides cannot be
  made certain of each other, so the unknown outcome remains and is shown.

## 5. `session_version`

Senders always wrote 1 and receivers took 1 to 1000, a design no comparable
protocol has. `protocol` already identifies the version on each signed message.
RFC 9170 describes unused version fields as a failure.

- **Not chosen:** a constant 1, because it is a signed field with no meaning. TLS
  keeps `legacy_version` for middleboxes, and AUN has none.
- **Not chosen:** defining a meaning, because nothing needs one.

## 6. Delivery

Only the hand-over to the other side's endpoint has to be shared. The nearest
models are DIDComm over HTTPS and Matrix transactions. RFC 9110 says 202 is
noncommittal, so the sender is told a deposit, not a receipt. Mastodon's repeated
SSRF bypasses are the reason for checking the real connection and IPv4 inside IPv6.

- **Not chosen:** a Mediator with acknowledged pickup, which would bind the
  receiver's internals. It can be added later.
- **Not chosen:** RFC 9421 HTTP signatures, because the body is already signed, and
  ActivityPub shows how implementations of them diverge.
- **Not chosen:** several transports, which would split implementations.
- **Not chosen:** leaving it unspecified, which does not interoperate.
