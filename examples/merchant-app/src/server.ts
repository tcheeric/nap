import { createMerchantApp } from './app.js';

const port = Number(process.env.PORT ?? 3000);

// The audience is a pinned constant and it is security-relevant: it is the value
// every NIP-98 `u` tag is compared against. If this does not match the URL the
// client actually calls, every login fails with an indistinguishable 401 — so
// set it deliberately rather than deriving it from whatever the request claims.
const baseUrl = process.env.NAP_BASE_URL ?? `http://localhost:${port}`;

const mode = process.env.NAP_MODE === 'bearer' ? 'bearer' : 'cookie';

const { app } = createMerchantApp({
  baseUrl,
  mode,
  secureCookies: baseUrl.startsWith('https://'),
});

app.listen(port, () => {
  console.log(`merchant-app listening on ${baseUrl} (${mode} mode)`);
});
