# @imani/nap-react

React bindings for the [Nostr Auth Protocol (NAP)](../../README.md) client. Provides hooks and a context provider for managing NAP session state in React applications.

## Installation

```bash
npm install @imani/nap-react @imani/nap-client-web react
```

`react` (>=18) is a peer dependency.

## Overview

`nap-react` bridges the imperative `NapSession` from `@imani/nap-client-web` into React's declarative model. It provides:

- **`NapProvider`** — Context provider that exposes session state to the component tree
- **`useNapSession()`** — Hook to read session state (authenticated, locked, shutdown, identity, roles/permissions)
- **`useReunlock()`** — Hook for the unlock flow (prompt, guard, cancel)
- **`useNapCallbacks()`** — Hook to create state-syncing callbacks for `NapClientOptions`
- **`useNip07()`** — Hook to detect a browser extension, as a tri-state
- **`useSignerPreference()`** — Hook to remember which signer to rebuild after a reload
- **`useStoredConnection()`** — Hook to drive a passphrase-gated restore of a stored pairing

It is signer-agnostic, and the two places that stops being automatic are worth
knowing up front: **how a lock clears** depends on whether the signer holds a key
in the page, and **an identity change** only reaches React if you wire its
callback. Both are covered below.

## Three-State Session Model

NAP sessions have three states:

| State | Condition | User Experience |
|-------|-----------|-----------------|
| **Open** | Authenticated, key usable | Normal operation — signing works |
| **Locked** | Authenticated, key evicted (5 min idle) | Lock icon shown, unlock on save |
| **Shutdown** | Authenticated, key evicted (15 min idle) | Full-screen overlay |

Transitions:
```
Open ---(5 min idle)---> Locked ---(10 more min idle)---> Shutdown
  ^                        |                                 |
  |      (unlock)          |            (unlock)             |
  +------------------------+                                 |
  +----------------------------------------------------------+
```

### How a lock clears depends on the signer

**Read this before building any unlock UI.** There are three ways out of a lock,
and they are not interchangeable:

| Setup | `lockRecovery` | Way out | Why |
|---|---|---|---|
| NIP-07 extension | `'unlock'` | `session.unlock()` | The key never left the extension. Nothing was evicted, so there is nothing to decrypt. |
| NIP-46 bunker | `'unlock'` | `session.unlock()` | Same — the key is on the remote signer. |
| In-page key + `keyStore` | `'passphrase'` | `session.reunlock(passphrase)` | The key was zeroed. Decrypting it back out of the store needs the passphrase. |
| In-page key, no `keyStore` | `'reauthenticate'` | build a fresh signer, `login()` again | The key was zeroed and nothing can restore it. `unlock()` would report a session that still cannot sign. |

**The signer decides; the `keyStore` only breaks the tie for signers that hold a
key here.** An app offering both nsec and extension login passes one store to
`createNapSession`, and that store must not drag an extension user into a
passphrase prompt for a key they never had.

Per RFC §28.6(4), a signer of your own that holds a key *without* implementing
`EvictableSigner` reports `'unlock'` too — it owns its own eviction, and the
session genuinely cannot tell it apart from a NIP-07 one.

Branch your unlock UI on `lockRecovery` from `useNapSession()`. It was a boolean
once; that was a two-way answer to a three-way question, and each arm it failed
to model stranded somebody.

A key-holding signer with **no** `keyStore` has no way back from its own first
lock. `createNapSession()` therefore throws when `autoLock` is enabled — a timer
that zeroes the key with no way back, minutes after a call that returned cleanly,
is a wiring error. But `lock()` and `shutdown()` still lock: zeroing the key is
the point of RFC §28.6, and a user who explicitly asks for it must get it. Making
them sign in again is a far better trade than leaving a live nsec in the page.

Locking a session **nobody has logged into yet is a no-op.** The idle timer
starts when the session is built, so a login page left open past `timeoutMs`
would otherwise lock itself — and since `locked` gates authentication, it would
then refuse the very login that clears it. The same applies after `logout()` and
after an identity change, both of which leave the timer running and need a fresh
login to recover.

A `resume()` does **not** clear a lock. Restoring the server session says nothing
about the key: for an in-page key it is still evicted, and reporting unlocked
would skip the passphrase prompt and then fail the signature.

`useReunlock().withSigningGuard()` routes all of this for you: it prompts when a
passphrase can help, and otherwise refuses with a `ReunlockCancelledError` whose
`reason` names what to render — `locked`, `shutdown`, or
`reauthenticate_required`.

**It will not unlock on the user's behalf.** An earlier version called
`session.unlock()` for key-free signers, on the theory that the extension or
bunker would prompt for its own approval anyway. It does not always: a NIP-46
bunker with pre-granted permissions signs silently, so a background autosave
cleared the lock in every tab and signed with nobody at the machine. A lock any
timer can clear is not a lock. Render an unlock affordance and let the click call
`session.unlock()`.

## Quick Start

### 1. Create the session and wire callbacks

```tsx
import { useMemo } from 'react';
import { createNapSession } from '@imani/nap-client-web';
import { NapProvider, useNapCallbacks } from '@imani/nap-react';

function App() {
  const [napState, callbacks] = useNapCallbacks();

  const session = useMemo(() => createNapSession({
    baseUrl: '/api/v1',
    signer: mySigner,
    autoLock: {
      enabled: true,
      timeoutMs: 5 * 60 * 1000,         // Lock after 5 min
      shutdownTimeoutMs: 15 * 60 * 1000, // Shutdown after 15 min
    },
    broadcast: { enabled: true },
    keyStore: myKeyStore,   // in-page keys only; omit for NIP-07 / NIP-46
    ...callbacks,
  }), [callbacks]);

  return (
    <NapProvider session={session} identityChange={napState.identityChange}>
      <Router>
        <Routes />
      </Router>
      <ShutdownOverlay />
    </NapProvider>
  );
}
```

**Spread `...callbacks` — do not list them by hand.** Naming four of them drops
`onIdentityChanged`, and that one is not recoverable from anywhere else: from
outside the session, an account switch and a logout are the same object state.
`identityChange` has to be threaded into the provider for the same reason.

### 2. Read session state in components

```tsx
import { useNapSession } from '@imani/nap-react';

function Header() {
  const { isAuthenticated, isLocked, isShutdown } = useNapSession();

  if (!isAuthenticated) return null;

  return (
    <header>
      <LockIcon locked={isLocked} />
      {isShutdown && <span>Session expired</span>}
    </header>
  );
}
```

### 3. Guard save operations with re-unlock

```tsx
import { useReunlock, ReunlockCancelledError } from '@imani/nap-react';

function SettingsForm() {
  const reunlock = useReunlock();

  const handleSave = async () => {
    try {
      await reunlock.withSigningGuard(async () => {
        const signed = signEvent(myData);
        await api.saveSettings(signed);
      });
    } catch (err) {
      if (err instanceof ReunlockCancelledError) return; // User cancelled
      showError(err);
    }
  };

  return (
    <>
      <button onClick={handleSave}>Save</button>
      {reunlock.isPrompting && (
        <ReunlockModal
          onSuccess={reunlock.handleSuccess}
          onCancel={reunlock.cancel}
        />
      )}
    </>
  );
}
```

`isPrompting` never goes true for a NIP-07 or NIP-46 session: there is no
passphrase to collect, so `withSigningGuard` rejects with `reason: 'locked'`
instead. Handle that alongside the modal — show an Unlock button whose click
calls `session.unlock()`. The same component works for every signer.

### 4. Build a shutdown overlay

The overlay has to branch on `lockRecovery`. A NIP-46 user given a passphrase
field has no way out of this screen.

```tsx
import { useNapSession } from '@imani/nap-react';
import { ReunlockError } from '@imani/nap-client-web';

function ShutdownOverlay() {
  const { session, isShutdown, lockRecovery } = useNapSession();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  if (!isShutdown) return null;

  // NIP-07 / NIP-46: nothing to restore, so nothing to ask for. The signer's
  // own approval on the next signature is the re-authorization.
  if (lockRecovery === 'reauthenticate') {
    // The key was zeroed and nothing can restore it. Only a fresh signer helps.
    return (
      <div className="shutdown-overlay">
        <h2>Sign In Again</h2>
        <button onClick={startFreshLogin}>Sign in</button>
      </div>
    );
  }

  if (lockRecovery === 'unlock') {
    return (
      <div className="shutdown-overlay">
        <h2>Session Paused</h2>
        <p>Your signer will ask you to approve the next action.</p>
        <button onClick={() => session.unlock()}>Resume</button>
      </div>
    );
  }

  const handleSubmit = async () => {
    try {
      await session.reunlock(password);
      // Session is restored — isShutdown becomes false, overlay disappears
    } catch (err) {
      if (err instanceof ReunlockError && err.code === 'INVALID_PASSPHRASE') {
        setError('Incorrect passphrase');
      }
    }
  };

  return (
    <div className="shutdown-overlay">
      <h2>Session Expired</h2>
      <p>Enter your passphrase to continue.</p>
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
      {error && <p className="error">{error}</p>}
      <button onClick={handleSubmit}>Continue</button>
    </div>
  );
}
```

## API Reference

### `<NapProvider>`

Context provider. Wrap your app (or authenticated section) with this.

| Prop | Type | Description |
|------|------|-------------|
| `session` | `NapSession` | A session created via `createNapSession()` |
| `identityChange` | `IdentityChangedDetail \| null` | From `useNapCallbacks()`. Required — pass `null` only to opt out deliberately, since without it the tree cannot tell an account switch from a logout. |
| `children` | `ReactNode` | Child components |

### `useNapSession()`

Returns the current session state. Must be used inside a `<NapProvider>`.

```typescript
interface NapSessionState {
  session: NapSession;    // The underlying session instance
  isAuthenticated: boolean;
  isLocked: boolean;
  isShutdown: boolean;
  lockRecovery: LockRecovery;  // 'unlock' | 'passphrase' | 'reauthenticate'
  identityChange: IdentityChangedDetail | null; // signer became someone else
  roles: readonly string[];                     // [] when unauthenticated
  permissions: readonly string[];               // [] when unauthenticated
  hasRole: (role: string) => boolean;           // UI affordance, not enforcement
  hasPermission: (permission: string) => boolean;
}
```

`roles`, `permissions` and the two predicates are for deciding what to render —
see [Roles and Permissions](#roles-and-permissions). The authorization boundary
is the server's guards.

### `useNapCallbacks()`

Creates state-tracking callbacks to pass to `createNapSession()`. Returns a tuple of `[state, callbacks]`.

```typescript
const [state, callbacks] = useNapCallbacks();
// state: { isAuthenticated, isLocked, isShutdown, identityChange }
// callbacks: { onLock, onUnlock, onShutdown, onLogout, onLogin,
//              onSessionExpired, onIdentityChanged }
```

Spread `...callbacks` into `NapClientOptions`. `onIdentityChanged` is the one
that carries information nothing else can recover — see
[Handling an identity change](#handling-an-identity-change).

### `useReunlock(isKeyAvailable?)`

Hook for managing unlock prompts and signing guards.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `isKeyAvailable` | `() => boolean` | `() => !session.isLocked()` | Synchronous check for key availability |

Returns:

```typescript
interface UseReunlockReturn {
  isPrompting: boolean;                              // Modal should be visible
  promptReunlock: () => Promise<void>;               // Show modal, resolves on unlock
  withSigningGuard: <T>(fn: () => Promise<T>) => Promise<T>;  // Guard async fn
  cancel: () => void;                                // Dismiss modal
  handleSuccess: () => void;                         // Called on successful unlock
}
```

`withSigningGuard` picks the right path per signer: it runs `fn` directly if the
key is available, calls `session.unlock()` for a key-free signer, and only
prompts when a passphrase is genuinely required.

### `useNip07(options?)`

Detects a NIP-07 provider. `options` is `Nip07DetectOptions` from
`@imani/nap-client-web` (`timeoutMs`, `pollIntervalMs`, `window`) and is read
once per attempt, so passing it inline is safe.

```typescript
interface Nip07Detection {
  status: 'detecting' | 'present' | 'absent';
  provider: Nip07Provider | null;  // non-null exactly when status is 'present'
  retry: () => void;
}
```

### `useSignerPreference(storageKey?, options?)`

Remembers which signer to rebuild after a reload. Defaults to the
`nap-signer-preference` key in `localStorage`.

```typescript
interface UseSignerPreferenceReturn {
  preference: { kind: 'nip07' | 'nip46' | 'key'; npub: string; savedAt: number } | null;
  remember: (kind: SignerKind, npub: string) => void;  // after login(), not before
  forget: () => void;                                   // on logout and identity change
}
```

Reads and writes never throw — a denied or absent `localStorage` (SSR, private
mode, a partitioned frame) reads as "no preference", which costs one click
rather than the login screen. Corrupt or unrecognised records read the same way.

### `useStoredConnection(source)`

Drives a passphrase-gated restore. `source` is `{ has(), restore(passphrase) }`;
`restore` returns `null` for a wrong passphrase or an unreadable record.

```typescript
interface UseStoredConnectionReturn<T> {
  status: 'checking' | 'none' | 'available' | 'restoring' | 'restored' | 'unavailable';
  value: T | null;                                   // non-null when 'restored'
  restore: (passphrase: string) => Promise<T | null>;
  reset: () => void;                                 // back to 'available' to retype
}
```

### `acquireSigningAccess(deps)`

The branch `withSigningGuard` runs, exported on its own for state layers that
are not this one. Takes
`{ isKeyAvailable, identityChanged, isShutdown, lockRecovery, prompt }` and
resolves once signing is permitted, or throws a `ReunlockCancelledError` naming
what the caller has to do instead. Total over `LockRecovery`, deliberately.

### `ReunlockCancelledError`

Thrown when an unlock prompt is interrupted.

```typescript
class ReunlockCancelledError extends Error {
  reason: 'user_cancelled' | 'session_expired' | 'logout' | 'unmounted'
        | 'identity_changed' | 'shutdown' | 'locked' | 'reauthenticate_required';
}
```

`identity_changed` is not a retryable failure — see below.

The last three all mean "the guard cannot get you signing; render something":

| `reason` | What to render |
|---|---|
| `locked` | An Unlock button whose click calls `session.unlock()` |
| `shutdown` | The full-screen shutdown overlay, with the same Unlock action |
| `reauthenticate_required` | A sign-in prompt — the key is gone and nothing restores it |

None of them clears the lock on its own, deliberately. `unlock()` broadcasts, so
a background save that called it would dismiss the lock, and the shutdown
overlay, in every tab with nobody having touched anything.

## Handling an Identity Change

Switching accounts in a NIP-07 extension, or re-pairing a bunker at a different
key, means the next `login()` would silently authenticate as someone else.
`nap-client-web` refuses: it terminates the session and throws
`IdentityMismatchError` rather than carrying the old session's roles across.

React only learns about it if you wired `onIdentityChanged`, because polling the
session cannot distinguish a terminated-for-identity session from a logged-out
one. Once wired:

```tsx
function IdentityBanner() {
  const { identityChange } = useNapSession();
  if (!identityChange) return null;

  return (
    <div role="alert">
      Your signer switched accounts. Please sign in again.
    </div>
  );
}
```

Prompt for a fresh login. Do not retry `login()` on a timer — the guard exists
because a silent re-login is a privilege transfer nobody asked for. While it is
set, `withSigningGuard` and `promptReunlock` reject immediately with
`identity_changed` rather than opening a modal over a dead session.

It clears on logout, and on a successful `login()` — **not** on a `resume()`.
`onLogin` carries a `via: 'login' | 'resume'` for exactly this: a `login()` is a
fresh signature, so whoever holds the signer has just proved who they are, while
a `resume()` proves only that a cookie is still valid. The identity guard sends
no `/auth/logout`, so the terminated identity's cookie is very much still valid
— clearing on any `onLogin` would drop the banner precisely when the page is
authenticated as somebody the signer is not.

Note this resolves in both directions: if the user switches to B, sees the
banner, switches *back* to A and logs in, the banner clears. Keying it on "the
session pubkey matches the new identity" would leave it stuck forever, and with
it every passphrase prompt, since a set `identityChange` makes `promptReunlock`
reject.

## Providing Your Own Modal

`nap-react` is headless — it manages state, not UI. You provide the modal component. The contract:

```tsx
interface YourModalProps {
  onSuccess: () => void;  // Call after successful session.reunlock(passphrase)
  onCancel: () => void;   // Call when user dismisses
}
```

Wire it to the hook:

```tsx
{reunlock.isPrompting && (
  <YourModal onSuccess={reunlock.handleSuccess} onCancel={reunlock.cancel} />
)}
```

Inside your modal, call `session.reunlock(passphrase)` from `@imani/nap-client-web`. On success, call `onSuccess()`. On cancel, call `onCancel()`. Error handling (wrong passphrase, etc.) stays in the modal.

## Cross-Tab Behavior

When one tab locks or shuts down, all tabs receive the broadcast:

- **Lock broadcast**: Other tabs evict their own key copy and update the indicator
- **Shutdown broadcast**: Other tabs show the shutdown overlay
- **Unlock broadcast**: an in-page-key tab does NOT restore its key — it needs its own passphrase entry, because the passphrase never leaves the tab where it was typed. A key-free tab (NIP-07 / NIP-46) *does* unlock: it has no key of its own to restore, and leaving it locked would strand it.
- **Identity-changed broadcast**: every tab drops the session. It is the same session everywhere, so an account switch invalidates all of them.

`NapProvider` polls the session every 500ms, so broadcast-driven changes show up
within that window without any extra wiring — except `identityChange`, which
arrives through the callback.

## Roles and Permissions

The session body carries `roles` and `permissions`, and `useNapSession()` keeps
them in sync so a render can branch on them:

```tsx
function Toolbar() {
  const { hasPermission, roles } = useNapSession();

  return (
    <>
      {hasPermission('voucher:create') && <NewVoucherButton />}
      {roles.includes('admin') && <AdminLink />}
    </>
  );
}
```

Both are empty arrays when unauthenticated, never null, so you do not have to
check `isAuthenticated` first.

> **This decides what the UI offers. It does not decide what the user may do.**
>
> The authorization boundary is the server: `requirePermission`, `requireRole`
> and `requireSession` in `@imani/nap-adapter-express` / `-fastify`. Hiding a
> button changes nothing about what a request is allowed to do — anyone can call
> the endpoint anyway. If a check exists only here, it does not exist.

Use `hasPermission` from the hook rather than `session.hasPermission()`. The
method on the session reads its closure directly, so it returns a correct answer
without ever telling React to render it; the hook's version is derived from
provider state and re-renders when the grants actually change.

### They are a snapshot, not a live feed

The arrays are what the server sent at login. A permission revoked mid-session
stays listed until the session is renewed. The server behaves the same way — its
guards use the login-time ACL snapshot unless you pass `aclResolver` — so the
client is not uniquely stale, but neither is live. Treat a 401 or 403 on a
request as the authoritative answer, not a surprise.

## Surviving a Reload

A reload keeps the session and loses the signer. The session id is an `HttpOnly`
cookie the browser re-attaches on its own, and `resume()` never invokes the
signer — so returning to a live session costs no prompt. But `createNapSession()`
needs a `SessionSigner` *before* `resume()` can be called, and that object died
with the page.

So the question a reloaded page has to answer is which signer to rebuild:

| Signer | What it needs to come back | Prompt? |
|---|---|---|
| NIP-07 | `window.nostr`, once the extension injects it | No |
| NIP-46 | the stored pairing record, decrypted | Passphrase |
| In-page key | the encrypted key from the `keyStore` | Passphrase |

`useSignerPreference()` records the answer — a `'nip07' \| 'nip46' \| 'key'`
discriminator plus the npub, both public. **No key material, ever**: RFC §1181
forbids plaintext key material at rest, `localStorage` included. Keys go in
`createWebCryptoKeyStore()` (in-page) or a `SecretStore` (NIP-46), encrypted with
PBKDF2 + AES-GCM.

```tsx
function Boot() {
  const { preference, remember, forget } = useSignerPreference();
  const { status, provider } = useNip07();

  // Prompt-free path: extension already present, and it is the one last used.
  // verifyIdentity is not optional here in spirit — the cookie outlived the
  // page, the signer did not, and the user may have switched accounts in the
  // extension while you were gone. Without it resume() restores the previous
  // account's roles under a signer that is now somebody else.
  useEffect(() => {
    if (preference?.kind === 'nip07' && provider) {
      void session.resume({ verifyIdentity: true }).catch(handleIdentityMismatch);
    }
  }, [preference, provider]);

  // Record only after login() actually succeeded — a remembered choice that
  // fails sends the next visit down a path the user cannot complete.
  const signIn = async () => {
    const { principal } = await session.login();
    remember('nip07', principal.npub);
  };

  // And drop it when the identity is no longer theirs.
  const { identityChange } = useNapSession();
  useEffect(() => { if (identityChange) forget(); }, [identityChange, forget]);
}
```

`createNapSession({ signerPreference })` clears the stored record itself on a
terminal login failure and on an identity change — see the `nap-client-web`
changelog. Keep the `forget()` above anyway if you wire it: this hook's
`preference` is a snapshot taken on mount, and nothing tells it the session
cleared the underlying storage. `forget()` is idempotent, so doing both is fine.

Call `forget()` on logout and on an identity change. A preference pointing at an
account the user has left is a login attempt that will fail the identity guard.

### Detecting the extension

`window.nostr` is injected on the extension's schedule, not yours, so a component
that checks once on mount tells users who have an extension that they don't.
`useNip07()` gives you the tri-state to render against:

```tsx
const { status, provider, retry } = useNip07();     // 'detecting' | 'present' | 'absent'
```

Render nothing or a spinner while `detecting` — showing "install an extension"
and then swapping it for a login button is the flicker this exists to prevent.
`retry()` re-runs detection, for after the user installs one and comes back.

### Restoring a NIP-46 pairing

`useStoredConnection()` drives the passphrase gate over an encrypted pairing
record. It takes the two operations rather than importing them, so `nap-react`
still has no dependency on `@imani/nap-client-nip46`:

```tsx
const source = useMemo(() => ({
  has: () => store.has(),
  restore: async (passphrase: string) => {
    const record = await loadConnection(store, passphrase);
    return record ? createNip46Signer({ ...record }) : null;
  },
}), [store]);

const { status, value: signer, restore, reset } = useStoredConnection(source);
```

`status` runs `checking → none | available → restoring → restored | unavailable`.
A wrong passphrase and an unreadable record both land on `unavailable` and are
deliberately indistinguishable — offer "try again" and "pair from scratch"
together, because a forgotten passphrase must not be a dead app.

## NIP-46 Connection Status

A bunker's relay connection can drop while the session is otherwise fine, and
that is a different condition from locked — the user needs "reconnecting", not
"unlock". `nap-react` deliberately ships no hook for it: it would mean depending
on `@imani/nap-client-nip46`, which would break that package's opt-in isolation
for every app that does not use it.

You already hold the signer, so read it directly:

```tsx
const [status, setStatus] = useState(signer.getStatus());
useEffect(() => {
  const id = setInterval(() => setStatus(signer.getStatus()), 2000);
  return () => clearInterval(id);
}, [signer]);
```

`Nip46Signer` also exposes `ping()`, `connect()`, and `disconnect()`.
