# Design note: AUN 0.3, agreement on any terms

Status: revised after review. 0.2 is frozen at tag `v0.2.0`.

## Goal

0.2 can only negotiate two things: a meeting time and a share of a cost. Each
needs its own receiver code. The name AUN comes from *a-un no kokyu*, two people
agreeing without many words. 0.3 should let two agents agree quickly on any
small set of terms, while keeping minimal disclosure and the human's final say.

Success criteria (checked by the conformance tests):

1. **No domain code in the checker.** A new kind of agreement needs only a new
   issue declaration in `REQUEST`. The reference checker contains no intent
   names. The examples include at least two domains that are neither meetings
   nor costs, and they go through exactly the same checker as the old two.
2. **Fast path.** When the first offer is acceptable, agreement takes 2
   messages (0.2: 3 messages). Both are 1 round trip; the gain is in messages,
   not in round trips.
3. **Bounded.** A session has at most 5 messages: `REQUEST`, at most 3
   `COUNTER`, then `ACCEPT`, `REJECT` or `ERROR`. A session with no answer
   ends at its deadline.
4. **Disclosure is counted, not assumed.** At most 5 packages per offer and at
   most 4 offers per session. Limits are never sent. Fewer messages bought by a
   lower agreement rate does not count as an improvement.

## What stays

- The envelope fields, `payload_hash` and the Ed25519 signature over JCS.
  `protocol` changes to `"aun/0.3"` and `requires_human_approval` is removed.
- Human approval is a local step, not a wire message.

## What changes

### 1. Issues

`REQUEST.payload` declares the terms as a list of 1 to 8 **issues**. Each issue
has a `name` and one of four **kinds**. The kind fixes the value shape and how
two values are compared. There is no other kind.

| Kind | Declaration | Value | Same when |
| --- | --- | --- | --- |
| `choice` | optional `options`: 1 to 20 strings | 1 string | the strings are equal |
| `time` | `duration_minutes`, `window` {start, end} | 1 slot {start, end} | start and end are the same instants |
| `amount` | `unit`, `scale`, `min`, `max`, `step` (integers) | 1 integer | the integers are equal |
| `flag` | nothing | `true` or `false` | the booleans are equal |

Amounts are integers in the smallest unit: the real value is
`value × 10^-scale`. A value is valid when `min <= value <= max` and
`(value - min)` is a multiple of `step`. No floating point anywhere.

The declaration is fixed for the session: names, kinds, options, units and
limits never change.

### 2. Packages, offers and agreement

- A **package** has exactly one value for every declared issue.
- An **offer** is `delta.offer`: 1 to 5 distinct packages. This keeps
  combinations intact: if a human approved "Sushi at 18:00" and "Pasta at
  19:00", the peer cannot pick "Sushi at 19:00".
- `ACCEPT` carries `delta.agreed`: one package. The receiver checks that it has
  exactly the declared keys, that every value is valid, and that it is the same
  as one package of the standing offer (the last offer, sent by the receiver).
  Else `INVALID_NEGOTIATION_PAYLOAD`. Whether a package suits the accepting
  side is its local decision; the wire check only proves it was offered.
- `choice` values must be in `options` when the declaration lists them. When it
  does not, an offer may bring new values (for example a new place).

### 3. Opening offer in REQUEST, PROPOSE removed

`REQUEST` carries the declaration and the deadline in `payload` and the
initiator's first offer in `delta.offer`. A `REQUEST` whose declaration is
valid but whose offer is not opens no session.

Message types in 0.3: `REQUEST`, `COUNTER`, `ACCEPT`, `REJECT`, `ERROR`.
`PROPOSE` and the four types that were never sent are removed.

Only the party that did not send the previous message may send the next one.
There is no withdrawal while the other side is answering: a withdrawal racing
an `ACCEPT` would leave the two sides with different results. At most 3
`COUNTER` per session.

### 4. Approval before sending

Every package in an offer is binding once sent: the peer may accept it and the
session ends agreed. So before a node sends `REQUEST`, `COUNTER` or `ACCEPT`,
every package in it must be approved by its human or covered by a delegation
whose scope includes it.

### 5. Deadline

- `REQUEST.payload.expires_at` fixes one deadline for the session. It must be
  after the request's `created_at` and at most 7 days later. It cannot be
  extended.
- A message is on time when its signed `created_at` is not after `expires_at`.
  The 300 second window on receipt bounds clock differences. A message created
  after the deadline is dropped (`SESSION_EXPIRED`).
- A session with no final message ends locally as expired 300 seconds after
  `expires_at`.
- The sender of an `ACCEPT` shows "accepted, delivery not confirmed" until the
  transport confirms delivery. It may resend the identical bytes. If no
  confirmation arrives before the session expires, the outcome is unknown and
  the human is told so. The protocol does not hide this case.

### 6. Resend and duplicates

A message with a `message_id` already seen is a duplicate when its bytes are
identical (same signature). A duplicate is ignored without error and changes
nothing. A different message with a known `message_id`, or a second message for
a `sequence` already recorded, is dropped.

### 7. Reasons and codes

- `public_reason`: `no_common_option`, `constraint_violation`,
  `policy_declined`.
- `REJECT` codes: `NO_AGREEMENT` (round limit reached), `OUTSIDE_LIMIT`,
  `HUMAN_REJECTED`, `APPROVAL_EXPIRED`. `ERROR` code: `NOT_SUPPORTED` (a valid
  request the receiver will not handle, for example an intent it does not
  take).
- Invalid input (size, parse, schema, signature, state, payload) gets no reply.

### 8. Input limits

Peer input is untrusted.

- The raw message is at most 16384 bytes, checked before parsing, by sender and
  receiver. JSON nesting is at most 8 levels. Duplicate object keys are
  rejected. The total limit wins over the per-field limits below.
- IDs (`message_id`, `session_id`, agent IDs, `nonce`): 1 to 128 characters.
  `intent`: dotted lowercase label, at most 64 characters.
- `topic`: 1 to 200 characters. Issue `name`: `^[a-z][a-z0-9_]{0,31}$`,
  unique. `choice` strings: 1 to 100 characters. `unit`: 1 to 16 characters.
- `time`: minute precision with an offset; `duration_minutes` 1 to 1440;
  window at most 31 days.
- `amount`: integers within ±(2^53 - 1), `scale` 0 to 6, `step` at least 1.

### 9. Free text is data

`topic`, option strings, units and names come from the peer. A node must not
follow them as instructions, must not let them change approval settings,
reach secrets or start external actions. It shows the human the peer's text
apart from what the node verified (who, which package, approved or not).

### 10. Old domains as profiles

- `meeting.schedule`: one `time` issue named `slot`. `date_range`,
  `preferred_time_ranges` and `timezone` are not sent.
- `cost.split`: one `amount` issue named `share`, with `min` 0 and `max` the
  total.

### 11. Other points

- Session binding: the session records both parties (agent and node) from the
  `REQUEST`. Each later message must come from the party whose turn it is and
  go to the other. (0.2 compared every later sender with the request sender,
  which would reject the responder.)
- Agent card: `aun-card/1`, signed with JCS like messages.
  Its top-level `protocol_versions` lists `aun/0.3`. All four kinds are
  mandatory, so the card does not list them. Accepting a format is not the
  same as accepting a domain: a node may still answer `NOT_SUPPORTED`.
- Card updates: a later card may change the name, versions and relay address,
  never the key or the agent. The node ID has only 64 bits, so a colliding key
  can be searched for: the in-person step covers the whole key, and a card
  whose key differs from the stored one is refused instead of replacing it.
  Updates must be strictly later as an instant, so a resent or older card
  cannot roll the address back. A card may be dated at most 300 seconds ahead,
  else one card dated far ahead would block every later update. There is no
  lower limit, so a peer that was offline for a long time still works. A lost
  key means a new peer, trusted again in person. Revocation, expiry and key
  rotation are left for later.
- `aun/0.1` is not part of 0.3. No automatic fallback to older versions.
- Limit probing by repeated sessions is a local policy matter. The
  specification does not claim it is prevented.
- Not double-booking a slot or item across parallel sessions is a local duty.

## Case table

Expected results, written before implementation. Each is a test.

| # | Input | Expected |
| --- | --- | --- |
| 1 | A offers {Sushi 18:00} and {Pasta 19:00}. B sends a correctly signed `ACCEPT` of {Sushi 19:00}. | Dropped, `INVALID_NEGOTIATION_PAYLOAD`. Session still waits for B. |
| 2a | Options declared. `COUNTER` contains a value not in them. | Dropped, `INVALID_NEGOTIATION_PAYLOAD`. |
| 2b | No options declared. `COUNTER` brings a new value. | Accepted. An `ACCEPT` of it is valid. |
| 3a | `ACCEPT` created before `expires_at`, received 200 s later (after the deadline, inside the window). | Accepted, session agreed. |
| 3b | `ACCEPT` created after `expires_at`. | Dropped, `SESSION_EXPIRED`. |
| 4a | The same `ACCEPT` bytes arrive twice. | Second copy ignored as duplicate, no state change, no error. |
| 4b | A different message for a recorded `sequence`. | Dropped. |
| 5 | The same slot offered in two open sessions. | Not visible on the wire. Local duty; stated in SPEC, not tested. |

## Out of scope

- Ready-to-call negotiation parts (an MCP server or library). This repository
  stays a specification with a reference checker, examples and tests.
- ENISHI changes. ENISHI keeps 0.2 until it is updated separately.
