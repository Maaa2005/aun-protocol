# AUN Protocol

AUN is a signed message protocol for personal AI agents that negotiate on
behalf of their owners, such as scheduling a meeting or splitting a cost. Each
agent discloses only what the other side needs, and a human makes the final
decision when the agent should not decide alone.

- Specification: [SPEC.md](SPEC.md) (version `aun/0.2`)
- JSON Schema: [schemas/negotiation-message.schema.json](schemas/negotiation-message.schema.json)
- Canonicalization (RFC 8785) test vectors: [test-vectors/jcs-v0.2.json](test-vectors/jcs-v0.2.json)

The reference implementation is ENISHI Local Core. ENISHI product code is not
part of this repository and is not covered by its license.

## Quick start

```sh
pip install -r requirements.txt && pytest -q
python tools/aun_reference.py verify examples/meeting-schedule/03-accept.json \
  --public-key ny9olPZA86PrrqKq4Zfafzj4/p1/+6DGKmrCIPKzFg0= --no-time-check
```

Set `ENISHI_LOCAL_CORE` to `services/local-core` to also cross-check the
examples against the reference implementation.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The license does not grant permission to use the ENISHI or AUN Protocol names
or branding as a trademark or endorsement.
