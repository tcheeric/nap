import type { AuthSuccessResponse } from '@imani/nap-core';

/**
 * Keeps a cookie-mode session alive without asking the signer again.
 *
 * None of this comes from the library. `nap-client-web` does not store the
 * refresh token, does not call `/auth/refresh`, and does not know this loop
 * exists — the server-side capability is complete and the client half is the
 * integrator's. Tutorial 05 explains the wiring; this is it.
 */
export interface RefreshLoop {
  /** Arm from a `login()` response. A body with no `refresh_token` disarms. */
  arm(auth: AuthSuccessResponse): void;
  disarm(): void;
}

export interface RefreshLoopOptions {
  baseUrl: string;
  /**
   * Called when the loop gives up. The session may or may not be gone — ask the
   * server rather than assuming, because the failure could have been the
   * network.
   */
  onLost: () => void;
  /** How long before expiry to refresh. */
  leadSeconds?: number;
}

export function createRefreshLoop({
  baseUrl,
  onLost,
  leadSeconds = 60,
}: RefreshLoopOptions): RefreshLoop {
  // Memory only, and deliberately. This is a week-long credential; putting it
  // in localStorage makes it readable by any script that gets into the page,
  // and it does not expire when the tab closes. The cost is that a reload
  // loses it — see tutorial 05 §6.
  let refreshToken: string | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const arm = (auth: AuthSuccessResponse) => {
    clearTimeout(timer);
    refreshToken = auth.refresh_token;

    if (!refreshToken) {
      // The server was not configured with refreshTtlSeconds. Nothing to do,
      // and nothing broken: the session simply ends at expires_at.
      return;
    }

    const fireAt = (auth.expires_at - leadSeconds) * 1000;
    timer = setTimeout(refresh, Math.max(0, fireAt - Date.now()));
  };

  const refresh = async () => {
    // Read before the await. The rotation retires this token the moment the
    // server sees it, so it must not still be reachable if anything re-enters.
    const spending = refreshToken;
    refreshToken = undefined;

    let response: Response;

    try {
      response = await fetch(`${baseUrl}/auth/refresh`, {
        method: 'POST',
        // The header, never a cookie: the browser attaches a cookie to every
        // request to the origin, which is the last thing a week-long
        // credential should do. The server reads Authorization: Bearer.
        headers: { authorization: `Bearer ${spending}` },
        // The rotation mints a new access token, and in cookie mode that
        // arrives as a Set-Cookie the response must be allowed to write.
        credentials: 'include',
      });
    } catch {
      onLost();
      return;
    }

    if (!response.ok) {
      onLost();
      return;
    }

    // Rotation, so the response carries the *next* token. There is no retry
    // path here on purpose: if a refresh fails after the server rotated —
    // a dropped response, a timeout — the token we hold is already retired,
    // and presenting it again is precisely what the server reads as a stolen
    // token. It revokes the whole session. One attempt, then ask.
    arm((await response.json()) as AuthSuccessResponse);
  };

  return {
    arm,
    disarm() {
      clearTimeout(timer);
      refreshToken = undefined;
    },
  };
}
