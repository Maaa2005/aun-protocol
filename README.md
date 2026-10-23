# AUN Protocol

AUN is a signed message protocol for personal AI agents that agree on terms on
behalf of their owners: a time, a place, an amount, a yes or no, or any mix of
them. The name comes from *a-un no kokyu*, two people who agree without many
words. When the first offer suits the other side, agreement takes 2 messages.
Each agent discloses only the options its human approved, and the human keeps
the final say.

- Specification: [SPEC.md](SPEC.md) (version `aun/0.3`)
- JSON Schema: [schemas/negotiation-message.schema.json](schemas/negotiation-message.schema.json)
- Reference checker: [tools/aun_reference.py](tools/aun_reference.py)
- Canonicalization (RFC 8785) test vectors: [test-vectors/jcs-v0.2.json](test-vectors/jcs-v0.2.json)
- Design note for 0.3: [docs/design-0.3.md](docs/design-0.3.md)

A request declares the terms as a list of issues of four kinds (`choice`,
`time`, `amount`, `flag`). A new kind of agreement is a new list of issues, not
new code. The examples include meetings, cost shares, a dinner plan, a favour
and a shared gift, all checked by the same code.

The 0.2 specification is frozen at tag
[`v0.2.0`](https://github.com/Maaa2005/aun-protocol/tree/v0.2.0).

## Quick start

```sh
pip install -r requirements.txt && pytest -q
python tools/aun_reference.py verify examples/meeting-schedule/02-accept.json \
  --public-key ny9olPZA86PrrqKq4Zfafzj4/p1/+6DGKmrCIPKzFg0= --no-time-check
python tools/aun_reference.py check-session examples/dinner-plan \
  --keys examples/keys.json
```

The keys in `examples/keys.json` are for tests only.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The license does not grant permission to use the ENISHI or AUN Protocol names
or branding as a trademark or endorsement.
