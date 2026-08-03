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
- **`useNapSession()`** — Hook to read session state (authenticated, locked, shutdown)
- **`useReunlock()`** — Hook for the re-unlock flow (prompt, guard, cancel)
- **`useNapCallbacks()`** — Hook to create state-syncing callbacks for `NapClientOptions`

## Three-State Session Model

NAP sessions have three states:

| State | Condition | User Experience |
|-------|-----------|-----------------|
| **Open** | Authenticated, key in memory | Normal operation — signing works |
| **Locked** | Authenticated, key cleared (5 min idle) | Lock icon shown, re-unlock modal on save |
| **Shutdown** | Authenticated, key cleared (15 min idle) | Full-screen overlay, passphrase required |

Transitions:
```
Open ---(5 min idle)---> Locked ---(10 more min idle)---> Shutdown
  ^                        |                                 |
  |    (passphrase)        |          (passphrase)           |
  +------------------------+                                 |
  +----------------------------------------------------------+
```

## Quick Start

### 1. Create the session and wire callbacks

```tsx
import { useMemo } from 'react';
import { createNapSession } from '@imani/nap-client-web';
import { NapProvider, useNapCallbacks } from '@imani/nap-react';

function App() {
  const [state, callbacks] = useNapCallbacks();

  const session = useMemo(() => createNapSession({
    baseUrl: '/api/v1',
    signer: mySigner,
    autoLock: {
      enabled: true,
      timeoutMs: 5 * 60 * 1000,         // Lock after 5 min
      shutdownTimeoutMs: 15 * 60 * 1000, // Shutdown after 15 min
    },
    broadcast: { enabled: true },
    keyStore: myKeyStore,
    onLock: callbacks.onLock,
    onUnlock: callbacks.onUnlock,
    onShutdown: callbacks.onShutdown,
    onLogout: callbacks.onLogout,
  }), [callbacks]);

  return (
    <NapProvider session={session}>
      <Router>
        <Routes />
      </Router>
      <ShutdownOverlay />
    </NapProvider>
  );
}
```

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

### 4. Build a shutdown overlay

```tsx
import { useNapSession } from '@imani/nap-react';
import { ReunlockError } from '@imani/nap-client-web';

function ShutdownOverlay() {
  const { session, isShutdown } = useNapSession();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  if (!isShutdown) return null;

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
| `children` | `ReactNode` | Child components |

### `useNapSession()`

Returns the current session state. Must be used inside a `<NapProvider>`.

```typescript
interface NapSessionState {
  session: NapSession;    // The underlying session instance
  isAuthenticated: boolean;
  isLocked: boolean;
  isShutdown: boolean;
}
```

### `useNapCallbacks()`

Creates state-tracking callbacks to pass to `createNapSession()`. Returns a tuple of `[state, callbacks]`.

```typescript
const [state, callbacks] = useNapCallbacks();
// state: { isAuthenticated, isLocked, isShutdown }
// callbacks: { onLock, onUnlock, onShutdown, onLogout, onLogin }
```

Use `callbacks` in the `NapClientOptions` so React state stays in sync with imperative session changes.

### `useReunlock(isKeyAvailable?)`

Hook for managing re-unlock prompts and signing guards.

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

### `ReunlockCancelledError`

Thrown when a re-unlock prompt is interrupted.

```typescript
class ReunlockCancelledError extends Error {
  reason: 'user_cancelled' | 'session_expired' | 'logout' | 'unmounted';
}
```

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

- **Lock broadcast**: Other tabs update their lock indicator
- **Shutdown broadcast**: Other tabs show the shutdown overlay
- **Unlock broadcast**: Other tabs can update UI (e.g., "Unlocked in another tab") but do NOT automatically restore the key — each tab requires its own passphrase entry

This is by design: the passphrase never leaves the tab where it was entered.
