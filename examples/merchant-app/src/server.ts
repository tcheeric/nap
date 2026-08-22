import { createMerchantApp } from './app.js';
import { createStores, startChallengeSweeper } from './stores.js';

const port = Number(process.env.PORT ?? 3000);

// The audience is a pinned constant and it is security-relevant: it is the value
// every NIP-98 `u` tag is compared against. If this does not match the URL the
// client actually calls, every login fails with an indistinguishable 401 — so
// set it deliberately rather than deriving it from whatever the request claims.
const baseUrl = process.env.NAP_BASE_URL ?? `http://localhost:${port}`;

const mode = process.env.NAP_MODE === 'bearer' ? 'bearer' : 'cookie';

// Off unless you set it, and the default session TTL is 900 seconds — so
// without this a NIP-07 user signs a fresh challenge four times an hour. Any
// positive value registers POST /auth/refresh and starts minting a rotating
// refresh token. Set NAP_REFRESH_TTL=0 to watch the 900-second wall arrive.
// Nothing in the client packages calls that endpoint; tutorial 05 wires it.
const refreshTtlSeconds = Number(process.env.NAP_REFRESH_TTL ?? 7 * 24 * 60 * 60);

// 900 is the default and production has no reason to change it — a short access
// token is the point. Overridable here only so tutorial 05 can watch a session
// expire without waiting a quarter of an hour for it.
const sessionTtlSeconds = Number(process.env.NAP_SESSION_TTL ?? 900);

const stores = createStores();
const backend = process.env.DATABASE_URL ? 'postgres' : 'in-memory';

const { app } = createMerchantApp({
  baseUrl,
  mode,
  secureCookies: baseUrl.startsWith('https://'),
  challengeStore: stores.challengeStore,
  sessionStore: stores.sessionStore,
  aclStore: stores.aclStore,
  server: {
    sessionTtlSeconds,
    ...(refreshTtlSeconds > 0 ? { refreshTtlSeconds } : {}),
  },
});

startChallengeSweeper(stores.challengeStore);

app.listen(port, () => {
  console.log(`merchant-app listening on ${baseUrl} (${mode} mode, ${backend} stores, session ${sessionTtlSeconds}s, refresh ${refreshTtlSeconds > 0 ? `${refreshTtlSeconds}s` : 'off'})`);
});
