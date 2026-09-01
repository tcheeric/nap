# Integration tests against real infrastructure

`packages/nap-voucher/test/integration.test.ts` runs NAP's voucher verification
against the **actual Cashu mint image and a real Nostr relay**, started with
[testcontainers](https://node.testcontainers.org/).

```bash
npm run test:integration     # needs Docker
npm test                     # skips them; no Docker required
```

## Why, given there is already an end-to-end test

`endToEnd.test.ts` drives a complete NAP login — real NIP-98, real Express
adapter, real `createNapServer` — but **the mint in it is one this repo wrote.**
It serves the keyset shape we believed the mint serves, so it can only confirm
our own assumptions. If `parseKeysets()` disagreed with the real `/v1/keys`
payload, or `proofY()` derived a `Y` the mint had never heard of, that test
would still pass and every real deployment would fail.

The two are complementary and neither replaces the other:

| | `endToEnd.test.ts` | `integration.test.ts` |
| --- | --- | --- |
| Mint | hand-written, real BDHKE/DLEQ | the real `cashu-mint-rest` image |
| Covers | the whole login, all denial paths, §7.3, §6.1 | that our parsing matches what the mint actually sends |
| Needs Docker | no | yes |
| Runtime | ~1s | ~8s after images are pulled |

The contract this file pins is narrow on purpose: **the wire shape of
`GET /v1/keys`**, because that is what the auth path consumes and the one thing
a self-written mint cannot vouch for.

## What it checks

- The real keyset payload parses, and `getKey()` returns the same key the mint
  published for that amount.
- Every published key is a compressed secp256k1 point the DLEQ code can parse.
  A key the curve library refused would fail every verification with
  `NAP_VOUCHER_DLEQ_INVALID` and read as a bad proof rather than a parsing
  mismatch.
- An unpublished keyset id is refused as `unknown_keyset`.
- An unroutable mint reports `unavailable` against a real socket, not a
  synthetic stub error. §7.3 hangs off that distinction.
- A real relay accepts a websocket connection and completes a `REQ`/`EOSE`
  handshake, which is the subscription shape the §7.1 revocation watcher will
  need.

Mutation-checked: changing `parseKeysets()` to expect a field the mint does not
send fails three of these tests.

## Requirements

- **Docker.**
- **The `cashu-mint` sibling checkout**, for
  `~/IdeaProjects/cashu-mint/scripts/preload-test-data.json`. The mint reads its
  dev keyset from that file; without it `/v1/keys` answers
  `500 Preload configuration could not be read`. When the file is missing the
  tests skip with a warning rather than failing, since a missing sibling repo is
  a setup gap rather than a defect here.
- **testcontainers 10.x, not 12.x.** Version 12 requires Node >= 22.22 and this
  repo runs Node 20; on 12 the failure is an opaque
  `webidl.util.markAsUncloneable is not a function` at import time.

## Running the mint standalone: what it takes

Non-obvious, and worth recording since the compose stack runs eight services:

| Setting | Why |
| --- | --- |
| `MINT_PRELOAD_ENABLED=true` | Serves a fixed dev keyset instead of reading a HashiCorp vault, which would drag in the vault, its database, and the gateway. |
| `MINT_PRELOAD_JSON_INPUT=file:/app/scripts/preload-test-data.json` plus a bind mount | Where that keyset comes from. |
| `MINT_WEBHOOK_SECRET` | Refused at startup in any non-local profile, whether or not webhooks are used. |
| `VAULT_BACKEND=DATABASE`, `VAULT_HASHI_ENABLED=false` | Keeps HashiCorp out of the picture. |

With those, the mint starts in about 3.5 seconds and serves `/v1/keys`.

## Known limits

Two things could not be exercised, both upstream rather than in NAP.

### `POST /v1/checkstate` needs a database

The NUT-07 endpoint answers `500` on a mint with no datastore, so the liveness
check is covered by `mintClient.test.ts` (unit) and `endToEnd.test.ts` (against
a mint that answers from live state) rather than here. Wiring the real vault
database would mean adding Postgres, Flyway migrations, and the vault service —
a fair amount of stack for one endpoint whose contract is three enum values.

### Voucher issuance is blocked by a packaging bug in the mint

`POST /v1/vouchers` cannot be reached in the published image. Enabling the
voucher profile fails at startup:

```
Failed to instantiate [xyz.tcheeric.cashu.voucher.app.ports.VoucherLedgerPort]:
  Factory method 'voucherLedgerPort' threw exception with message:
  org/apache/commons/lang3/StringUtils
Caused by: java.lang.NoClassDefFoundError: org/apache/commons/lang3/StringUtils
```

`cashu-mint-rest/pom.xml` declares `commons-lang3` with `<scope>test</scope>`,
so it is absent from the runtime image while the voucher ledger path needs it.
Reaching that error also requires `SPRING_PROFILES_ACTIVE` to include `voucher`
(the issuer key properties are only bound in `application-voucher.yml`),
`MINT_VOUCHER_ISSUER_PRIVKEY` / `_PUBKEY`, a reachable relay, and HTTP Basic
credentials, since `/v1/vouchers/**` is `hasRole("ADMIN")`.

Filed upstream as [398ja/cashu-mint#405](https://github.com/398ja/cashu-mint/issues/405).
Until it is fixed an issued voucher cannot be obtained from the real mint, so
the voucher lifecycle stays covered by `endToEnd.test.ts`, which mints its own
with genuine BDHKE and a genuine DLEQ.

Two adjacent gotchas, also recorded on that issue: the issuer key properties
only bind under the `voucher` profile (they live in `application-voucher.yml`,
so setting them with `dev` alone silently fails), and `/v1/vouchers/**` is
`hasRole("ADMIN")`, so it needs HTTP Basic plus a configured admin password.

## Adding to CI

Keep them off the default `npm test`. They need a Docker daemon and pull two
images, so a run that cannot reach a registry should not turn the whole suite
red. If a job does have Docker, run `npm run test:integration` as a separate
step so its failures are legible as infrastructure problems rather than as unit
regressions.
