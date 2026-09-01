# 08 — Holding a key in the page

**You build:** login for a user with no extension and no second device — an nsec
typed once, encrypted at rest, evicted when the tab goes idle, and brought back
with a passphrase.

**You need:** tutorial 07 finished, or any working copy of `examples/merchant-app`.
An nsec you do not mind putting in a browser. Generate a throwaway one rather
than pasting your real key into a tutorial app.

**On transcripts.** Like tutorial 07, this one is not curl-able. Locking, idle
timers and cross-tab broadcast all live in the browser, so the sequences below
are described and the code is quoted from the example app, which typechecks in
CI. Where a constant is quoted, the file it comes from is named.

---

## 1. Why this is the last one

You have now watched three tutorials of session machinery work against signers
that hold no key: an extension in 02, a bunker in 07. Everything — `login()`,
`resume()`, `stepUp()`, the identity guard, the lock — was written against
`SessionSigner` and none of it knew which kind it had.

An in-page key is substitutable at that seam too. It is *not* substitutable at
the security boundary, and it is last in this series because the honest order
to meet the three options in is the order of what they cost:

| Signer | Where the key lives | What a hostile script on your origin gets |
| --- | --- | --- |
| NIP-07 extension | Extension storage, separate origin | A signature, if the user approves it |
| NIP-46 bunker | The user's other device | A signature, if the user approves it |
| In-page key | This page's memory | The key |

That last cell does not have a fix. It has mitigations, and this tutorial wires
all of them, and §8 is about the part they do not reach. RFC §28.2 prefers the
first two for exactly this reason.

Ship it anyway when "install an extension first" is not a viable first screen
for your product. The realistic alternative is not that users go and install
one — it is that somebody writes `localStorage.setItem('nsec', nsec)`, which
RFC §1181 forbids outright and which this tutorial exists to displace.

---

## 2. Encrypt before you store, and store the ciphertext

`nap-client-web` ships the store. You do not write the crypto.

```ts
// examples/merchant-app/src/web/storage.ts
import { createWebCryptoKeyStore } from '@imani/nap-client-web';

export const keyStore = createWebCryptoKeyStore('merchant.key');
```

One instance, exported, imported by both the enrolment screen and the session.
Two calls with the same storage key would in fact agree — the record lives in
`localStorage` under that name, not in the object — but the *name* is what has
to match between whoever enrols and whoever re-unlocks, and a constant nobody
retypes is the cheapest way to keep it matching.

> **If you read guide §0.1 and came away thinking you had to implement
> `KeyStore` yourself:** that text was stale and is now fixed. `KeyStore` was
> published as an interface with no implementation, which left every app that
> needed one writing its own crypto. This is the reference answer.

What lands in storage, from `packages/nap-client-web/src/webCryptoSecretStore.ts`:
an envelope containing an AES-GCM ciphertext, a fresh 16-byte salt and 12-byte
IV per write, and the PBKDF2 iteration count — **310,000**, SHA-256 — recorded
alongside so a record written today stays readable when the constant is raised
tomorrow. The count is bounded on the way *in* as well as on the way out, so a
tampered `iterations: 2e9` cannot hang the tab inside `deriveKey`.

Enrolment is one call:

```ts
// examples/merchant-app/src/web/KeyLogin.tsx
const hex = /* nip19.decode(nsec).data as hex */;
await keyStore.save(hex, passphrase);
onSigner(createPrivateKeySessionSigner(hex), { verifyIdentity: true });
```

The passphrase is an argument. The store never holds it, and nothing writes it
anywhere. What the store can do is decrypt on demand, given it again.

**One thing the library cannot do for you.** `createPrivateKeySessionSigner`
zeroes its `Uint8Array` on eviction, but the hex *string* you passed in is an
immutable JS string and lingers until garbage collection, out of reach. Keep
the window short: read it from the store straight into the signer, and do not
park it in application state on the way past.

---

## 3. Wire the store into the session — and meet the throw that saves you

```ts
// examples/merchant-app/src/web/useNapBootstrap.ts
createNapSession({
  baseUrl: window.location.origin,
  signer,
  keyStore,
  autoLock: {
    enabled: true,
    timeoutMs: 60_000, // short so the tutorial is watchable; the default is 15 minutes
  },
  ...callbacks,
});
```

`keyStore` is passed for **every** signer kind, not only the key one. For
NIP-07 and NIP-46 it is inert: `lockRecovery()` asks the signer first and only
consults the store for a signer that holds a key here, so wiring one store for
your nsec users does not drag your extension users into a passphrase prompt
they cannot answer.

Now delete the `keyStore` line and reload with the key signer. You get:

```
Error: autoLock with a key-holding signer requires a keyStore: the lock evicts
the key and reunlock() is the only way back
```

That throw is deliberate, and it is the same principle as the adapter wiring
checks in tutorial 02: **fail while building, not at request time.** Without
it, the call returns cleanly, the app works, and then sixty seconds of
inactivity later the timer evicts the key, `reunlock()` throws for the missing
store, `unlock()` throws because this session holds a key of its own, and the
session is bricked. The user's only way out is a page reload they have no
reason to think of. Inert-but-quiet is the failure mode being designed
against.

Note what it does *not* refuse: `autoLock` only. An explicit `lock()` with no
store is allowed, and §5 covers why.

---

## 4. A lock clears three different ways, and you must ask before it locks

Here is the part that generates bugs.

```ts
type LockRecovery = 'unlock' | 'passphrase' | 'reauthenticate';
```

- **`'unlock'`** — nothing was evicted, because the key was never in the page.
  NIP-07, NIP-46. `session.unlock()` clears the flag; there is no passphrase
  because there is nothing to decrypt. Per RFC §28.6(4) a signer you supply
  that holds a key *without* implementing `EvictableSigner` also lands here —
  it owns its own eviction and the session cannot tell it from an extension.
- **`'passphrase'`** — an `EvictableSigner` plus a `keyStore`.
  `session.reunlock(passphrase)`.
- **`'reauthenticate'`** — an `EvictableSigner` with no `keyStore`. The lock
  zeroed the key and nothing restores it. Not `unlock()`, which would clear the
  flag and hand back a session that still cannot sign. Not `reunlock()`, which
  has no store to read. A fresh signer and a fresh login is the only way on.

`session.lockRecovery()` answers, it mutates nothing, and it is **constant for
the session's lifetime** — so read it whenever you like, including while still
unlocked, to decide what your overlay is going to say. The alternative is
asking `unlock()`, which answers by succeeding or throwing, which is too late:
by then you have already rendered a field the user cannot fill.

The example app's whole overlay is a switch over it:

```tsx
// examples/merchant-app/src/web/LockScreen.tsx
switch (lockRecovery) {
  case 'unlock':          return /* an Unlock button */;
  case 'passphrase':      return /* a passphrase field */;
  case 'reauthenticate':  return /* "sign in again" */;
}
```

No `default`. The switch is total over the union on purpose: adding a fourth
recovery mode to the library should break your build here rather than fall
through to a silent nothing. `nap-react`'s own `acquireSigningAccess` is
written the same way.

> **This was a `requiresPassphrase(): boolean` for one release.** A two-way
> answer to a three-way question, and it produced a bug in each arm it could
> not express, in both directions: NIP-07 users sent to a passphrase modal
> they could never satisfy, and unrecoverable sessions sent to an `unlock()`
> that throws. Don't collapse it back.

---

## 5. Nothing unlocks on the user's behalf

The temptation, when a background autosave hits a locked session, is to call
`unlock()` and carry on. Do not.

`nap-react`'s `acquireSigningAccess` refuses instead — `locked`, `shutdown`, or
`reauthenticate_required` — and leaves the gesture to the UI. Two reasons, and
the second is the one that surprises people:

1. `unlock()` clears the lock **and** a shutdown **and** broadcasts to every
   other tab. A background caller therefore dismisses the overlay on a machine
   with nobody in front of it.
2. "The signer will re-prompt anyway" is false. A NIP-46 bunker that
   pre-granted `sign_event:27235` signs silently, and so does an in-page key
   that was never evicted. A lock any timer can clear is not a lock.

The `'passphrase'` arm is the exception, and it is not really an exception:
typing the passphrase *is* the user gesture. That is why it is the one arm
allowed to prompt from inside a guard.

The mirror of this rule is that `lock()` and `shutdown()` **always** evict,
even when recovery is awkward — even in the `'reauthenticate'` arm where the
key is simply gone. Zeroing the key is the point (RFC §28.6). Refusing a user's
explicit lock to spare them an awkward recovery leaves a live nsec in the page,
which is the worse trade every time. Only `autoLock` is refused up front, at
wiring time, and only because a timer has no user intent behind it.

---

## 6. Remembering the signer across a reload — and the check that has to come with it

Tutorial 02 left this open: the session id is an `HttpOnly` cookie and survives
a reload, but the signer is a JavaScript object and does not, and
`createNapSession()` needs one before `resume()` can be called at all. So every
reload asked the user to pick a signer again. Time to close it.

```ts
// examples/merchant-app/src/web/storage.ts
export const signerPreference = createSignerPreferenceStore();
```

What it holds is a `'nip07' | 'nip46' | 'key'` discriminator and an npub. Both
public — the npub *is* the identity, not a credential — so nothing here needs
encrypting, and nothing here may ever become the place somebody puts an nsec.
Reads and writes never throw: Safari's private mode has historically thrown on
`setItem`, an embedded frame can be denied storage access outright, and there
is no `localStorage` at all during SSR. Every one of those means the same thing
to you — no remembered preference, ask the user — and none is worth taking the
login screen down for.

Three rules for using it.

**Write after the login, not on the click that starts one.**

```tsx
// examples/merchant-app/src/web/App.tsx
const success = await session.login();
refresh.arm(success);
if (signerKind) {
  remember(signerKind, success.principal.npub);
}
```

Recording a choice that then fails sends the next visit down a path the user
cannot complete.

**Hand it to the session too, so the session can clear it.**

```ts
createNapSession({ /* … */ signerPreference });
```

It is never *written* there — only the app knows which kind of signer it built
— but the session clears it on a terminal `/auth/init` or `/auth/complete`
failure and when the identity guard terminates. Omit it and a login the server
has stopped accepting stays on the screen, offered on every reload, failing
every time.

**Only one kind can restore itself unattended.**

```tsx
// examples/merchant-app/src/web/SignerPicker.tsx
useEffect(() => {
  if (preference?.kind !== 'nip07' || !provider) return;
  onSigner({ signer: createNip07Signer(provider), kind: 'nip07', verifyIdentity: true });
}, [preference, provider, onSigner]);
```

A stored bunker pairing and a stored key are both ciphertext, and the
passphrase that opens them is the user's. For those two the preference store
buys something smaller but still real: the app knows which screen to render, so
the user meets an unlock field rather than a menu.

### And now the check

Every path above rebuilds a signer from storage, and `resume()` never invokes
the signer. That is exactly what makes a reload prompt-free (FR-024) and
exactly what makes it unable to notice the signer is now somebody else. The
cookie outlived the page; the signer did not.

For an in-page key the gap is easy to hit on purpose: enrol a second nsec over
the first while the old session cookie is still live. A plain `resume()`
restores the previous account's principal, roles and permissions under a signer
who is a different person.

So the screen that rebuilt the signer is the one that asks for the check —
which is why it travels in the same object as the signer, where the two cannot
drift apart:

```ts
export interface SignerChoice {
  signer: SessionSigner;
  kind: SignerKind;
  verifyIdentity: boolean;
}
```

```ts
await session.resume({ verifyIdentity: options.verifyIdentity ?? false });
```

`true` on all three restore paths, `false` on a freshly-clicked extension login
where there is nothing to verify against. It is opt-in rather than always-on
because verifying costs a `getNpub()`, which is a relay round trip on NIP-46
and would tax the prompt-free reload the mechanism exists to protect. For an
in-page key it is a local computation and free.

When it trips you get `IdentityMismatchError` and the session is terminated:
state cleared, other tabs told. Not migrated — a new identity is a new login,
and carrying the old session's roles across would be a privilege transfer
nobody asked for. Handle it through `onIdentityChanged` and resolve it **by
pubkey**, never by treating the next `onLogin` as resolution: that callback
fires for `resume()` too, and because the guard deliberately sends no
`/auth/logout`, the terminated identity's cookie still works.

---

## 7. Two tabs must not disagree

Open the merchant app in two tabs, sign in with the key signer in one, and:

- Press **Lock now** in tab A. Tab B locks too.
- Unlock tab B with the passphrase. Tab A unlocks.
- Sign out in either. Both return to the picker.

That is `BroadcastChannel`, on by default, named `nap-session`. You wired
nothing for it.

Two details worth knowing before you trust it:

**A lock only means something for an authenticated session.** A tab still on
its login screen that took the flag from a sibling has no unlock affordance to
clear it with — and because `locked` gates `authenticate()`, the lock refuses
the login that would clear it. The example app renders the overlay *before* the
authentication branch for this reason:

```tsx
// examples/merchant-app/src/web/App.tsx — in Account()
if (isLocked || isShutdown) {
  return <LockScreen />;
}

if (!isAuthenticated) { /* … sign-in screen … */ }
```

**An incoming lock is not re-broadcast**, or two tabs would ping-pong. And the
handler for a broadcast lock no-ops on an unauthenticated tab — when it does,
it rearms the idle timer, because `createActivityLock`'s timers are one-shot
and returning without a `touch()` would disarm autoLock for the life of the
page.

Also: `session.destroy()` closes the channel and stops the timer. The example
app calls it in its effect cleanup, and without it a hot reload leaves a fleet
of orphaned sessions racing each other.

---

## 8. The ceiling

Everything above is real and worth doing. None of it survives a hostile script
running on your origin.

The reason is structural, not a gap to patch: your own code must be able to
decrypt the key in order to sign with it, so anything running as your code can
do the same. A script on your origin can read the passphrase out of the input
event, call `keyStore.loadKey` itself, or simply wait for the user to unlock
and read the signer's memory. Encryption at rest defends against a stolen
laptop, a shared browser profile, and an extension reading `localStorage` — not
against XSS on your own page.

So the honest statement of what this chapter buys:

| Threat | Extension / bunker | In-page key, wired as above |
| --- | --- | --- |
| Someone reads `localStorage` | No key there | Ciphertext only |
| Laptop stolen, tab left open | Nothing to take | Key evicted by the idle timer |
| Server compromised | Key never left the device | Key never left the browser |
| XSS on your origin | A signature, on approval | **The key** |

That is a ceiling, not a reason to skip the layers beneath it — an attacker who
has to land XSS is a strictly harder problem than one who only has to read a
`localStorage` entry. But it does mean your CSP, your dependency hygiene and
your `nostr-tools` dedupe are load-bearing security controls for this signer in
a way they are not for the other two. Tutorial 09 is where that gets a
checklist.

And it means the offer matters. The example app lists all three signers and
puts this one last, which is the correct default: a user who *can* use an
extension should not be quietly given the option that costs them the most.

---

## Try it

1. Run the app (`npm start` and `npm run dev:web`). Scroll past the extension
   and remote-signer options to **Sign in with a key**.
2. Paste a throwaway nsec and a passphrase. You are signed in, and
   `localStorage` under `merchant.key` holds an envelope — open devtools and
   confirm there is no nsec in it.
3. Leave the tab alone for 60 seconds. The overlay appears and the key is gone.
   Return with the passphrase.
4. Type the wrong passphrase. You get "Wrong passphrase", not
   "Unable to access storage" — the store throws those two apart precisely so
   the retryable case can say so.
5. Delete `keyStore` from `createNapSession` and reload. Read the throw in §3.
6. Put it back, sign in with an **extension** instead, and lock. You get an
   Unlock button and no passphrase field. Same overlay component, different
   arm of the switch.
7. Two tabs. Lock in one, unlock in the other, sign out in either.
8. Sign in with an extension, then reload. You are not asked to pick a signer:
   the preference store rebuilt it and `resume()` restored the session with no
   prompt at all. Sign out and reload again — now you are asked, because a
   deliberate sign-out forgets the choice.
9. Sign in with key A, then press **Forget this key**, enrol key B, and reload.
   `verifyIdentity` terminates the session instead of handing you A's roles.

---

## Where this leaves you

Three signer kinds, one `SessionSigner` interface, and an app that branches on
which kind it has in exactly two places — the lock overlay and the reload
restore. Both are places where the kinds genuinely differ, and in both the
library hands you a closed set of cases so the branch can be made total rather
than guessed at.

**Next:** [09 — Before you ship](./09-before-you-ship.md) — the rate limiter
that counts per process, the audit log without which every 401 is identical,
and the rest of what production wants.
