# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`nap` is the TypeScript monorepo for the NAP v2 packages — Nostr-native
authentication (NIP-98 proof over an HTTP challenge/response) and authorisation
(a role/permission ACL layer) for web applications.

`nap-java` (sibling repo, `xyz.tcheeric:nap-*`) is the JVM implementation of the
same protocol. The two must stay wire-compatible: **a protocol change here needs
the matching change there, or interop breaks.**

## Build Commands

```bash
npm test        # vitest run
npm run typecheck
```

There is **no build step.** Every package points `exports` and `types` at
`./src/index.ts`, so there is no `dist/` and nothing to compile. Don't go looking
for a `build` script — it doesn't exist, and the packages are not
npm-publishable in this state.

## Repository Structure

```text
nap/
├── packages/*      8 workspaces — see README.md for the list
├── docs/           RFC, integration guide, best practices
└── specs/          feature specs (untracked)
```

## Key Documents

- `docs/NAP-v2-RFC.md` — the protocol specification. **The authority.** Any
  behaviour question is settled here, not by the code.
- `docs/NAP-INTEGRATION-GUIDE.md` — how the protocol works end to end and how to
  integrate it. Also records, section by section, where the code diverges from
  the RFC.
- `docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md` — operational guidance.

## Design Notes

- Keep protocol types portable across browser and server runtimes.
- Preserve package boundaries inside `packages/*`.
- Favor additive protocol changes and cross-package compatibility.

## Traps

These have each cost real debugging time. Check them before changing the
relevant area.

- **Never reserialize the request body.** The NIP-98 `payload` tag is
  `sha256(rawBody)`. A global `express.json()` running before the NAP router, or
  any middleware that re-stringifies JSON, breaks every completion with
  `NAP_COMPLETE_PAYLOAD_MISMATCH`. The adapters capture raw bytes deliberately.
- **`getExternalBaseUrl` is required and security-relevant.** It sets the NIP-98
  audience. `createRequestDerivedBaseUrlResolver()` derives it from the request
  and contains **no trust policy** — prefer a pinned constant or a Host
  allowlist. See §9.4 of the integration guide.
- **Dedupe `nostr-tools`.** Four packages depend on it. Version skew between the
  app's copy and NAP's surfaces as confusing `verifyEvent` failures.
- **Every auth failure is an identical 401.** That is deliberate. Debugging is
  impossible without wiring an `AuditLogger` and reading the `code`.
- **Rate limiting is not implemented.** `/auth/init` is unauthenticated and
  writes a row per call. Anything production-facing needs a limiter in front.

## Known Gaps

The integration guide's §11 lists what is RFC-specified but unimplemented, and
what is implemented but incomplete. These are tracked as cards on the `nap`
kan board. Prefer updating both when closing one.
