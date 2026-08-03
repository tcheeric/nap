# NAP v2 official test vectors

RFC §20.3. These are the shared conformance fixtures for **every** NAP
implementation — the TypeScript packages in this repo and the JVM ones in
`nap-java`. They are the thing that makes "wire-compatible" checkable rather than
asserted.

Regenerate with:

```bash
npx tsx packages/nap-core/scripts/generate-test-vectors.ts
```

Every input is fixed — keys, timestamps, challenge strings — so regenerating
produces a byte-identical tree unless behaviour changed. **A diff here is a
protocol change**: land the matching change in the other implementation, or
interop breaks.

## Files

| File | Covers |
|---|---|
| `index.json` | Manifest: the two principals' keys, and which file covers which §20.3 case. |
| `payload-hash.json` | Payload hash generation. |
| `nip98.json` | Exact URL matching, payload mismatch, duplicate tag rejection. Decidable by the NIP-98 header validator alone. |
| `flow.json` | Expired challenge rejection, retrying the same valid completion, pubkey/npub mismatch. Needs a seeded challenge store and a controllable clock. |

The private keys in `index.json` are test fixtures published in a public
repository. They are not secrets and must never be used for anything.

## Consuming them

`payload-hash.json` — hash the UTF-8 bytes of `body`, hex-encode, compare to
`sha256`.

`nip98.json` — for each case, feed `authorization`, `request.method`,
`request.url`, the UTF-8 bytes of `request.body`, and `now` to the header
validator. Expect success, or failure with exactly `expect.code`.

`flow.json` — for each case, seed a challenge store with `challenge`, then run
`steps` in order against **one** server instance with the clock pinned to each
step's `now`. `expect.same_session_as_step` means the session returned must be
the one an earlier step returned; that is the retry-safety guarantee (RFC §13.3),
and returning a second distinct session fails the vector just as an error would.

Consumers in this repo: `packages/nap-core/test/vectors.test.ts` (the first two
files) and `packages/nap-server/test/vectors.test.ts` (`flow.json`).

## Adding a case

Add it to the generator, regenerate, and update **both** implementations'
consumers. A vector no implementation runs is decoration.

Error codes are part of the vector. If an implementation returns a different
code for the same input, that is a divergence to fix or to specify — not a
mapping to paper over in the consumer.
