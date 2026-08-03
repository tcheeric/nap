# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All packages in this workspace share a single version.

## [Unreleased]

## [0.3.0] - 2026-08-03

### Added

- `GET /auth/session` and `POST /auth/logout` on both the Express and Fastify adapters.
  `nap-client-web` already called both, so two of seven `NapSession` methods —
  `resume()` and `logout()` — were dead against a stock mount. Handlers are also
  exported individually (`createNapExpressSessionHandler`, `createNapExpressLogoutHandler`,
  and the Fastify equivalents) for callers wiring routes by hand.
- `toPublicSessionView()` in `@imani/nap-server`, rendering a session without credential
  fields.
- `onLogin` on `NapClientOptions`, fired by `login()` and by a `resume()` that restores a
  session. `useNapCallbacks()` returned an `onLogin` the options type did not accept, so
  the hook's `isAuthenticated` never became true.
- `requireRole(role | role[], options)` on both adapters, with any-of semantics.
  Registered role keys are checked against the registry by `validatePermissions()`, so a
  typo fails at startup rather than silently returning 403 forever.
- `EvictableSigner` and `isEvictableSigner()` in `@imani/nap-client-web`.
- `docs/NAP-INTEGRATION-GUIDE.md`, documenting the protocol and both implementations
  against their source, including where each diverges from the RFC.
- RFC §15.1 (Guarding On Permissions, Not Roles), §28 (Client Key Custody), and
  Appendix D (NAP vs OAuth 2.0).

### Changed

- **`createTrustedProxyAwareBaseUrlResolver()` renamed to
  `createRequestDerivedBaseUrlResolver()`.** The old name advertised a trust policy the
  function does not contain: it reads `Host` raw and delegates the `X-Forwarded-Proto`
  question entirely to the framework's trust-proxy setting. Behaviour is unchanged.
- **`session.logout()` now zeroes the private key** (RFC §28.3). A later `login()`
  requires the key to be supplied again, via `reunlock(passphrase)` or a fresh signer.
  Applications that logged out and back in with the same in-memory signer must adapt.
- `createPrivateKeySessionSigner()` returns `EvictableSigner` rather than `SessionSigner`.
  This widens the type; existing callers are unaffected.
- New adapter options: `cookieName` and `clearCookieOptions`. The latter must match the
  attributes the cookie was set with, or the browser keeps it after logout.

### Fixed

- Corrected nine of the integration guide's 39 RFC line citations. Six pointed at blank
  lines and three at unrelated content, having been written against a file that was being
  edited concurrently. All 39 are now verified to resolve to the claim they support.

### Security

- **`session.lock()` now evicts key material** rather than only marking session state
  (RFC §28.6). Previously the `KeyHolder` passed to `reunlock()` only flipped booleans —
  `setKey(key)` ignored its argument — while the signer closure retained the private key
  for the life of the session, so script in the page could still sign after an idle lock.
  Eviction now fires on `lock()`, the idle timeout, `shutdown()`, `logout()`, `destroy()`,
  and an incoming lock/shutdown/logout broadcast from another tab.

  This bounds the exposure window to the idle timeout. It does not defend a key that is
  unlocked while hostile script runs, since the client must be able to decrypt it, and
  only the `Uint8Array` is zeroed — the hex string passed in is an immutable JS string
  beyond this library's reach until garbage collection.
- `setKey()` rejects a key deriving a different pubkey, so a wrong re-unlock cannot
  silently swap the signing account while `getNpub()` reports the old identity.
- `GET /auth/session` omits `access_token` and the step-up fields. In cookie mode the
  token is HttpOnly; echoing it into a JSON body would hand a working bearer credential
  to any script on the page.

## [0.2.0] - 2026-03-21

The v2 package set: `nap-core`, `nap-server`, `nap-client-http`, `nap-client-web`,
`nap-react`, `nap-adapter-express`, `nap-adapter-fastify`, and `nap-store-postgres`,
with the ACL layer and the NAP v2 RFC.

[Unreleased]: https://github.com/tcheeric/nap/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tcheeric/nap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tcheeric/nap/releases/tag/v0.2.0
