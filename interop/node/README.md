# Node implementation

A second implementation of the AUN 0.4 checks, first written from SPEC.md alone,
without reading the Python reference. It uses no npm packages. It shows that the
spec can be implemented without the reference, and it catches a spec change that
makes the two give different answers.

    node interop/node/run.js

This needs Node 24. It exits 0 only when every case in `test-vectors/` matches.

It covers the receiver checks of sections 4 to 9 and the card checks of section
11.2. It is not a usable node: it has no keys, no delivery and no durable storage.

When the two implementations disagree, SPEC.md decides. Fix the one that is wrong
and add a case to the vectors, so the split cannot come back unnoticed. If the spec
does not decide, fix the spec first.
