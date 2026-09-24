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

One thing still cannot be exercised here, and one that could not be has since
been fixed.

### `POST /v1/checkstate` needs a vault service

The NUT-07 endpoint answers `500` because the mint calls a separate vault
service on port 3333 (`KeySetVaultClient`, `VaultClient`), which is not running:

```
Caused by: java.net.ConnectException: Connection refused
```

Standing it up means Postgres, Flyway migrations, HashiCorp Vault and the vault
service itself, per `docker-compose.dev.yml` — a large stack for one endpoint
whose contract is three enum values. The liveness check stays covered by
`mintClient.test.ts` (unit, including the `SPENT`/`PENDING`/`UNSPENT` mapping)
and by the resolver tests. The real-mint login block stubs **only** `checkState`
and takes every key from the live mint, so the substitution is visible and
narrow.

### Voucher issuance: the packaging bug is fixed, the relay config is not

[398ja/cashu-mint#405](https://github.com/398ja/cashu-mint/issues/405) is fixed:
`commons-lang3` is no longer stripped from the runtime image, the voucher
profile starts, and `POST /v1/vouchers` reaches the ledger publish step instead
of 404ing.

Issuance still cannot complete in a container, for a different reason. The relay
list in `application-voucher.yml` is hardcoded:

```yaml
relays:
  - wss://relay.damus.io
  - wss://relay.cashu.xyz
```

Unlike the issuer keys beside it, it carries no `${...}` placeholder, and a YAML
list cannot be replaced from outside: an indexed override adds to the list, and
`SPRING_APPLICATION_JSON`, an external `application.properties`, a
profile-specific external file and a `--voucher.nostr.relays[0]` argument were
all tried and all lost to the hardcoded value.

Chasing that turned out to be the wrong diagnosis, and the real one is worse:
**`application-voucher.yml` is not read at all.** Editing `publishTimeoutMs` in
the file directly and rebuilding changed nothing, and the logged
`queryTimeout=5000` matches neither the file (`10000`) nor the Java default
(`10000`). `VoucherConfiguration` constructs the ledger repository with a
two-argument constructor that hardcodes both timeouts, so the configured values
are read and then discarded. Filed as
[398ja/cashu-mint#407](https://github.com/398ja/cashu-mint/issues/407).

The practical consequence is that a mint cannot be pointed at a private relay,
so issuance fails with `VoucherNostrException: Not connected to any relay`.

**This does not block NAP's coverage**, which is why it is recorded rather than
worked around. NAP never calls `POST /v1/vouchers` — a holder obtains a voucher
out of band and presents it. What NAP consumes is `GET /v1/keys`, and that is
now exercised end to end: `integration.test.ts` builds a proof against the
mint's *own* published key and drives a complete voucher-bound login through it.

Three configuration gotchas, all recorded on that issue and all costly to
rediscover. The issuer key properties only bind under the `voucher` profile
(they live in `application-voucher.yml`, so setting them with `dev` alone
silently fails). `/v1/vouchers/**` is `hasRole("ADMIN")`, so it needs HTTP Basic
plus a configured admin password. And the webhook secret is
`cashu.mint.webhook.shared-secret`, required in non-local profiles — a missing
one fails startup before the voucher beans are reached, which looks like a
voucher problem and is not.

## Adding to CI

Keep them off the default `npm test`. They need a Docker daemon and pull two
images, so a run that cannot reach a registry should not turn the whole suite
red. If a job does have Docker, run `npm run test:integration` as a separate
step so its failures are legible as infrastructure problems rather than as unit
regressions.
