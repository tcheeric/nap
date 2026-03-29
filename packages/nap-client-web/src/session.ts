import { buildAuthCompleteRequest } from '@imani/nap-client-http';
import type { AuthSuccessResponse } from '@imani/nap-core';
import { createActivityLock } from './activityLock.js';
import { createBroadcastBus } from './broadcast.js';
import { fetchJson } from './httpClient.js';
import { reunlock as reunlockCore } from './reunlock.js';
import type { KeyHolder } from './keyStore.js';
import type { NapClientOptions, NapSession, SessionState } from './types.js';

function normalizeBaseUrl(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function sessionPath(baseUrl: string, path: string): string {
  return `${normalizeBaseUrl(baseUrl)}/auth/${path}`;
}

function toSessionState(response: AuthSuccessResponse): SessionState {
  return {
    pubkey: response.principal.pubkey,
    npub: response.principal.npub,
    roles: response.roles ?? [],
    permissions: response.permissions ?? [],
    expiresAt: response.expires_at,
  };
}

export function createNapSession(options: NapClientOptions): NapSession {
  const fetchImpl = options.fetch ?? fetch;
  let sessionState: SessionState | null = null;
  let locked = false;
  let shutdownState = false;

  const publishLock = (): void => {
    locked = true;
    options.onLock?.();
    broadcast.publish('lock');
  };

  const publishShutdown = (): void => {
    locked = true;
    shutdownState = true;
    options.onShutdown?.();
    broadcast.publish('shutdown');
  };

  const broadcast = createBroadcastBus(
    options.broadcast?.enabled ?? true,
    options.broadcast?.channelName ?? 'nap-session',
    (type) => {
      if (type === 'logout') {
        sessionState = null;
        locked = false;
        shutdownState = false;
        options.onLogout?.();
        return;
      }

      if (type === 'unlock') {
        options.onUnlock?.();
        return;
      }

      if (type === 'shutdown') {
        locked = true;
        shutdownState = true;
        options.onShutdown?.();
        return;
      }

      // Handle incoming lock from another tab without re-broadcasting
      // to avoid ping-pong between tabs.
      if (type === 'lock') {
        locked = true;
        options.onLock?.();
        return;
      }
    }
  );

  const activityLock = createActivityLock(
    options.autoLock?.enabled ?? false,
    options.autoLock?.timeoutMs ?? 15 * 60 * 1000,
    publishLock,
    options.autoLock?.shutdownTimeoutMs,
    publishShutdown
  );

  async function authenticate(stepUp = false): Promise<AuthSuccessResponse> {
    locked = false;
    shutdownState = false;
    activityLock.touch();

    const initResponse = await fetchJson<{ challenge_id: string; challenge: string; auth_url: string; auth_method: 'POST'; issued_at: number; expires_at: number }>(
      fetchImpl,
      sessionPath(options.baseUrl, 'init'),
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          npub: await options.signer.getNpub(),
        }),
      }
    );

    if (initResponse.status !== 200 || !initResponse.body) {
      throw new Error(`NAP init failed with status ${initResponse.status}`);
    }

    const completion = await buildAuthCompleteRequest({
      challenge: initResponse.body,
      signer: options.signer,
    });
    const completeResponse = await fetchJson<AuthSuccessResponse>(
      fetchImpl,
      `${sessionPath(options.baseUrl, 'complete')}${stepUp ? '?step_up=true' : ''}`,
      {
        method: 'POST',
        headers: {
          authorization: completion.authorization,
          'content-type': 'application/json',
        },
        body: new TextDecoder().decode(completion.rawBody),
      }
    );

    if (completeResponse.status !== 200 || !completeResponse.body) {
      throw new Error(`NAP completion failed with status ${completeResponse.status}`);
    }

    sessionState = toSessionState(completeResponse.body);
    return completeResponse.body;
  }

  return {
    login(): Promise<AuthSuccessResponse> {
      return authenticate(false);
    },
    async logout(): Promise<void> {
      await fetchJson(fetchImpl, sessionPath(options.baseUrl, 'logout'), {
        method: 'POST',
      });
      sessionState = null;
      locked = false;
      shutdownState = false;
      options.onLogout?.();
      broadcast.publish('logout');
    },
    async resume(): Promise<AuthSuccessResponse | null> {
      const response = await fetchJson<AuthSuccessResponse>(
        fetchImpl,
        sessionPath(options.baseUrl, 'session'),
        { method: 'GET' }
      );

      if (response.status === 401) {
        sessionState = null;
        options.onSessionExpired?.();
        return null;
      }

      if (response.status !== 200 || !response.body) {
        throw new Error(`NAP session lookup failed with status ${response.status}`);
      }

      sessionState = toSessionState(response.body);
      return response.body;
    },
    async stepUp(): Promise<string> {
      const response = await authenticate(true);

      if (!response.step_up_token) {
        throw new Error('NAP step-up response did not include a step-up token');
      }

      return response.step_up_token;
    },
    isAuthenticated(): boolean {
      return sessionState !== null;
    },
    getSession(): SessionState | null {
      return sessionState;
    },
    hasPermission(permission: string): boolean {
      return sessionState?.permissions.includes(permission) ?? false;
    },
    hasRole(role: string): boolean {
      return sessionState?.roles.includes(role) ?? false;
    },
    lock(): void {
      publishLock();
    },
    isLocked(): boolean {
      return locked;
    },
    shutdown(): void {
      publishShutdown();
    },
    isShutdown(): boolean {
      return shutdownState;
    },
    async reunlock(passphrase: string): Promise<void> {
      if (!options.keyStore) {
        throw new Error('keyStore is required for reunlock');
      }

      const holder: KeyHolder = {
        setKey() {
          locked = false;
          shutdownState = false;
        },
        clearKey() {
          locked = true;
        },
        hasKey() {
          return !locked;
        },
      };

      await reunlockCore(passphrase, options.keyStore, holder, {
        onTimerReset: () => activityLock.touch(),
        onBroadcast: () => broadcast.publish('unlock'),
      });
    },
    destroy(): void {
      activityLock.stop();
      broadcast.close();
    },
  };
}
