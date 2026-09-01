# NAP tutorials

A step-by-step series that starts with an empty directory and ends with an
Express + React application doing NIP-07, NIP-46 and in-page-key logins, roles
and permissions, Postgres-backed sessions, refresh tokens, step-up, and the caps
a deployment needs.

Everything is built up in one place — **`examples/merchant-app`**, a workspace
package covered by `npm run typecheck` and an integration test in CI, so a
breaking change to the libraries fails the build rather than quietly making a
tutorial wrong.

**Already know Nostr?** Skip tutorial 00. Read
[integration guide §1–§3](../NAP-INTEGRATION-GUIDE.md#1-what-nap-is-and-the-problem-it-solves)
— what NAP is, the protocol walkthrough, and the authorisation model — then start
at [tutorial 01](./01-a-server-you-can-curl.md).

---

## The series

Read in order. Each tutorial names the one before it as a prerequisite, but every
one from 05 onward also works against any finished copy of the example app.

| # | Tutorial | What you have when you finish |
| --- | --- | --- |
| 00 | [Nostr for NAP](./00-nostr-for-nap.md) | The vocabulary the rest of the series assumes: keys, npubs, events, signers, and what a signature does *not* prove. No code. |
| 01 | [A NAP server you can `curl`](./01-a-server-you-can-curl.md) | A running Express server issuing challenges and verifying completions, driven entirely by hand from a terminal. No browser, no extension, no frontend. |
| 02 | [Logging in from a browser](./02-logging-in-from-a-browser.md) | A React frontend that signs in with a NIP-07 extension, signs out, and survives a page reload without asking for a signature. |
| 03 | [Roles and permissions](./03-roles-and-permissions.md) | Guarded routes that refuse the wrong caller, a registry that turns a typo into a boot failure, and a UI that stops offering buttons it knows will fail. |
| 04 | [Sessions that survive a restart](./04-postgres.md) | The same app backed by Postgres, so restarting the server no longer logs everybody out. Needs Docker. |
| 05 | [Refresh tokens](./05-refresh-tokens.md) | A session that outlives its access token — including the client-side rotation, because nothing in NAP does it for you. |
| 06 | [Step-up for destructive actions](./06-step-up.md) | An endpoint a valid session is not enough to reach: it wants a signature made just now. |
| 07 | [Remote signers with NIP-46](./07-nip46.md) | A login that works with no browser extension at all, against a key that stays on the user's phone. |
| 08 | [Holding a key in the page](./08-in-page-keys.md) | An nsec typed once, encrypted at rest, evicted when the tab goes idle, and brought back with a passphrase. |
| 09 | [Before you ship](./09-before-you-ship.md) | The caps, the audience rule and the cookie attributes a deployment needs — plus a clear-eyed list of what the example still is not. |

**On Fastify:** the series is written against Express. If your backend is
Fastify 5, read [the appendix](./appendix-fastify.md) — the whole substitution in
one place, cross-referenced to the tutorial each line belongs to. There is no
second example app, on purpose.

---

## Where the series stops

It gets you to a working, sensibly configured integration. It does **not** get
you to a production system: tutorial 09 §8 lists what is still missing from the
example, and §11 of the integration guide catalogues what is RFC-specified but
unimplemented in the libraries themselves.

For depth on anything the tutorials touch:

- [`docs/NAP-v2-RFC.md`](../NAP-v2-RFC.md) — the protocol specification. Any
  behaviour question is settled here.
- [`docs/NAP-INTEGRATION-GUIDE.md`](../NAP-INTEGRATION-GUIDE.md) — the full
  integration surface, including the Java implementation and where each side
  diverges from the RFC.
- [`docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md`](../NAP-IMPLEMENTATION-BEST-PRACTICES.md)
  — operational guidance.

## Placing NAP against something you already know

- [NAP and WebAuthn](../comparisons/webauthn.md) — the precedent NAP follows, and the three places it is permanently weaker.
- [NAP and OAuth 2.0](../comparisons/oauth.md) — which question each protocol answers, and what adopting NAP looks like when OAuth is already running.
