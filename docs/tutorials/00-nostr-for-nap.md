# Nostr for NAP

**Already know Nostr?** Skip this page. You want [integration guide §1–§3](../NAP-INTEGRATION-GUIDE.md#1-what-nap-is-and-the-problem-it-solves)
— what NAP is, the protocol walkthrough, and the authorisation model — then start at
[tutorial 01](./01-a-server-you-can-curl.md).

Everyone else: this page is the vocabulary the rest of the series assumes. There is no code
to run here. It takes about ten minutes and it is the only place these concepts are
explained, so later tutorials link back rather than repeating themselves.

---

## The one-sentence version

NAP logs a user in by asking them to **sign a short-lived challenge with a key they already
control**, instead of asking them for a password you would then have to store.

Everything below is the detail behind that sentence.

## <a id="keys"></a>Keys and npub

A Nostr identity is a **secp256k1 keypair**. That is the same curve Bitcoin uses, and the
same one behind most of what you already trust on the web.

- The **private key** is the identity. Whoever holds it *is* the user. There is no reset
  link, no support desk, no recovery flow — this is the part that makes key handling a
  serious topic rather than a detail.
- The **public key** is derived from it and is safe to publish. It is what your server
  stores as "who this user is."

Both show up in two encodings, and the series uses both, so it is worth fixing the
difference now:

| Form | Looks like | Where you see it |
| --- | --- | --- |
| **hex pubkey** | `3bf0c63f…` (64 hex characters) | Inside signed events, in your database, in `principal.pubkey` |
| **npub** | `npub1w4uswf…` (bech32, human-facing) | What a user copies and pastes, what NAP's `/auth/init` takes |

They are the same 32 bytes in different clothes. `npub` exists because bech32 has a
checksum, so a typo is caught rather than silently becoming a different valid identity.

The private key has the same pair: raw hex, and a bech32 form prefixed `nsec`. **An `nsec`
is a password that cannot be changed.** When you see it in the wild, treat it accordingly.

> **The mental shift.** In password auth, the server holds a secret derived from something
> the user knows, and proves identity by comparing. In NAP, the server holds *nothing
> secret at all*. It holds a public key and checks a signature. A database breach leaks a
> list of public keys, which were already public.

## <a id="signers"></a>Signers: who actually holds the key

Your application should never see a private key if it can avoid it. A **signer** is
whatever holds the key and produces signatures on request.

NAP's `SessionSigner` interface has exactly two methods — "who are you?" and "sign this" —
and **the server cannot tell which kind of signer produced a proof.** They are
interchangeable at the wire. That is what makes the choice reversible in code, even though
it is not reversible in product terms.

There are three, and picking one is the first real decision you make ([guide §0.1](../NAP-INTEGRATION-GUIDE.md#01-the-decision-that-shapes-everything-else)):

### <a id="nip07"></a>NIP-07 — a browser extension

The user installs an extension (Alby, nos2x, and others). It injects `window.nostr` into
your page. Your code calls it; the extension prompts the user; you get a signature back.
**The key never enters your page.**

This is the default recommendation and what tutorials 01–06 use.

The cost is real but small: the user needs an extension installed. That failure mode is
distinguishable from every other one, and NAP gives you four separate error codes so
"install an extension" never has to render as "login failed":

| Code | What happened |
| --- | --- |
| `NOT_AVAILABLE` | No extension appeared. Not an error — an onboarding step. |
| `DECLINED` | The user said no. Offer to retry; don't alarm them. |
| `TIMEOUT` | The prompt was never answered. Probably behind another window. |
| `PROVIDER_ERROR` | Anything else, including a locked extension. |

### <a id="nip46"></a>NIP-46 — a remote signer

The key lives somewhere else entirely — typically a phone app or a self-hosted "bunker" —
and your page talks to it over **Nostr relays**. The user approves on the other device.

The page and the signer find each other through a pairing step: one side produces a
`bunker://` or `nostrconnect://` URI containing a relay, a pubkey, and a secret, and the
other reads it. From then on they exchange encrypted messages through the relay.

Two consequences worth knowing before [tutorial 07](./07-nip46.md):

- **Every signature is a network round trip.** Signing is meaningfully slower than an
  extension, and it can fail for network reasons rather than user reasons.
- **The relay is not trusted, but it is in the path.** The messages are encrypted, but the
  relay sees who is talking to whom, and it can drop traffic.

### <a id="inpage"></a>An in-page key

Your application holds the key itself, encrypted at rest, decrypted in memory when needed.

This is the option with the most power and the most obligation. You own encryption,
passphrase UX, eviction on idle, and the honest conversation with yourself about what it
can and cannot protect. NAP ships a WebCrypto key store so you are not writing the
cryptography, but **the responsibility does not ship with it.**

[Tutorial 08](./08-in-page-keys.md) covers it, and it is deliberately last in
the series.

> **The ceiling, stated once.** If hostile script runs on your origin, no key-custody
> scheme in a browser saves you — your own code must be able to decrypt the key, so
> anything running as your code can too. That is a reason to prefer NIP-07 or NIP-46, and
> it is *not* a reason to skip encryption when you do hold a key. See RFC §28.5.

## <a id="nip98"></a>NIP-98: what actually gets signed

NIP-98 is the piece that turns "I have a key" into "I am authorising *this specific
request*."

The user signs a small structured event — a **Nostr event** is just a JSON object with a
pubkey, a timestamp, a kind number, some tags, and a signature over all of it. For NIP-98
the tags are what matter:

| Tag | Carries | Why it is there |
| --- | --- | --- |
| `u` | The full URL being called | So a proof for one endpoint cannot be replayed at another |
| `method` | `POST`, `GET`, … | So a read proof cannot authorise a write |
| `payload` | `sha256` of the **raw request body** | So the body cannot be altered in transit |

Plus the event's own `created_at`, which the server checks against a tolerance window so an
old proof cannot be replayed forever.

Two things follow from this that will bite you if you do not know them now:

**The `u` tag is checked against a value your server decides.** That value is the
**audience**. If your server thinks it is `https://api.example.com` and the client signed
`https://api.example.org`, the proof is rejected. Getting the audience wrong makes *every*
login fail as an indistinguishable 401. This is why the audience is configured explicitly
and why deriving it from a request header requires an allowlist —
[guide §9.4](../NAP-INTEGRATION-GUIDE.md#9-security-considerations-and-operational-notes).

**The `payload` tag hashes the raw bytes.** Any middleware that parses JSON and
re-serialises it changes the bytes, changes the hash, and breaks every login. This is the
single most common integration failure, and [tutorial 01](./01-a-server-you-can-curl.md)
puts the fix in front of you before you can hit it.

## <a id="flow"></a>How NAP puts it together

Four steps. You will run all of them by hand in tutorial 01.

1. **`POST /auth/init`** — the client says "I am this npub." The server issues a
   short-lived, single-use **challenge**.
2. **The client signs** a NIP-98 event over the completion request, with the challenge
   inside it. This is the step the signer performs, and the only step the user sees.
3. **`POST /auth/complete`** — the client sends the signed proof. The server verifies the
   signature, the audience, the method, the body hash, the timestamp, and that the
   challenge is still unredeemed.
4. **A session exists.** The server returns a session and — in the cookie mode the browser
   packages use — sets an `HttpOnly` cookie. Subsequent requests carry the cookie; nothing
   is signed again until the session expires.

That last point is worth dwelling on, because it is where NAP's ergonomics live: **the
signature happens once per session, not once per request.** A reload does not re-prompt,
because the cookie outlives the page. The key is only needed again when the session ends.

## <a id="notauth"></a>What a signature proves — and what it does not

The series returns to this repeatedly, so here it is up front.

A valid NIP-98 proof shows that **something with access to the private key signed this
request, recently.** That is all.

It does **not** prove a human was present. A NIP-46 bunker with pre-granted permissions
signs without prompting anyone. An extension can be configured to auto-approve. There is no
signed "the user touched the device" bit the way WebAuthn has one.

So: use signatures to establish *who*, and never to establish *consent*. If you need a
human to have agreed to something, build that agreement into your own UI. Tutorial 06
covers step-up authentication and makes the same point where it matters most.

## Where to go next

[Tutorial 01 — a NAP server you can `curl`](./01-a-server-you-can-curl.md). No browser, no
frontend, no extension. Just the exchange above, by hand, so you can see it work.

For depth on anything here: the [integration guide](../NAP-INTEGRATION-GUIDE.md) is the
reference, and [the RFC](../NAP-v2-RFC.md) is the authority on protocol behaviour.
