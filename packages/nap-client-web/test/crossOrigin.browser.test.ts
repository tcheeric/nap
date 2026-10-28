/**
 * Extension 0002 in a real browser, across two real origins.
 *
 * Opt-in: `NAP_BROWSER=1 npm test -- crossOrigin.browser`. Needs a Playwright
 * Chromium (`npx playwright-core install chromium`). The fake windows in
 * `crossOrigin.test.ts` model the browser; this checks the model against one,
 * for the three things only a browser can say:
 *
 * - `event.origin` really is the sender's origin, and a page cannot choose it;
 * - `postMessage(msg, origin)` really is dropped when the receiver is another origin;
 * - `window.opener`, `window.open` and `top !== self` behave as the code assumes.
 *
 * `127.0.0.1` and `localhost` on one port are two origins, which is all this needs.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { build } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const enabled = process.env.NAP_BROWSER === '1';

const ENTRY = `
import { generateSecretKey } from 'nostr-tools';
import { bytesToHex } from '@imani/nap-core';
import { connectCrossOrigin, mountCrossOriginSigner, createPrivateKeySessionSigner } from '@imani/nap-client-web';

const params = new URLSearchParams(location.search);
window.__nap = { connectCrossOrigin };

if (location.pathname === '/nap/signer') {
  const relying = params.get('relying') ?? document.documentElement.dataset.relying;
  const key = bytesToHex(generateSecretKey());
  window.__handle = mountCrossOriginSigner({
    policy: { [relying]: { kinds: [27235], audiences: [relying] } },
    signer: createPrivateKeySessionSigner(key),
    onConsent: async (request) => { window.__consent = request; return true; },
  });
}
`;

describe.skipIf(!enabled)('extension 0002 in Chromium', () => {
  let server: Server;
  let port: number;
  let browser: import('playwright-core').Browser;
  let bundle = '';

  const relyingOrigin = () => `http://127.0.0.1:${port}`;
  const keyOrigin = () => `http://localhost:${port}`;

  beforeAll(async () => {
    const result = await build({
      stdin: { contents: ENTRY, resolveDir: process.cwd(), loader: 'ts' },
      bundle: true,
      format: 'esm',
      platform: 'browser',
      conditions: ['nap-source'],
      write: false,
    });
    bundle = result.outputFiles[0].text;

    server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://x');
      if (url.pathname === '/bundle.js') {
        res.writeHead(200, { 'content-type': 'text/javascript' });
        res.end(bundle);
        return;
      }
      const relying = `http://127.0.0.1:${port}`;
      const coop = url.searchParams.get('coop');
      res.writeHead(200, { 'content-type': 'text/html', ...(coop ? { 'cross-origin-opener-policy': coop } : {}) });
      res.end(`<!doctype html><html data-relying="${relying}"><body><button id="go">go</button><script type="module" src="/bundle.js"></script></body></html>`);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;

    const { chromium } = await import('playwright-core');
    browser = await chromium.launch();
  });

  afterAll(async () => {
    await browser?.close();
    await new Promise((resolve) => server?.close(resolve));
  });

  async function relyingPage() {
    const context = await browser.newContext();
    const page = await context.newPage();
    // localhost resolves to 127.0.0.1 here, but it is a different origin.
    await page.goto(`${relyingOrigin()}/app`);
    await page.waitForFunction(() => (window as unknown as { __nap?: unknown }).__nap);
    return { context, page };
  }

  it('connects and signs across two real origins, and the event carries a valid signature', async () => {
    const { context, page } = await relyingPage();
    const popupPromise = context.waitForEvent('page');

    const result = page.evaluate(async ({ key, relying }) => {
      const { connectCrossOrigin } = (window as unknown as { __nap: typeof import('../src/crossOriginClient.js') }).__nap;
      const grant = await connectCrossOrigin({ keyOrigin: key, kinds: [27235], audiences: [relying] });
      const event = await grant.signer.signEvent({
        kind: 27235,
        created_at: Math.floor(Date.now() / 1000),
        content: '',
        tags: [['u', `${relying}/auth/complete`], ['method', 'POST']],
      });
      let refused = '';
      try {
        await grant.signer.signEvent({
          kind: 27235,
          created_at: Math.floor(Date.now() / 1000),
          content: '',
          tags: [['u', 'https://gateway.example/auth/complete'], ['method', 'POST']],
        });
      } catch (error) {
        refused = (error as { code?: string }).code ?? String(error);
      }
      return { pubkey: grant.info.pubkey, event, refused };
    }, { key: keyOrigin(), relying: relyingOrigin() });

    const popup = await popupPromise;
    expect(new URL(popup.url()).origin).toBe(keyOrigin());

    const { pubkey, event, refused } = await result;
    expect(event.pubkey).toBe(pubkey);
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(refused).toBe('REFUSED');

    const consent = await popup.evaluate(() => (window as unknown as { __consent: { origin: string } }).__consent);
    // The origin the signer saw is the browser's, not anything the page sent.
    expect(consent.origin).toBe(relyingOrigin());
    await context.close();
  });

  it('a page on an origin outside the policy gets no answer at all', async () => {
    const context = await browser.newContext();
    const page = await context.newPage();
    // The key origin itself, opening the signer page: not in the policy, which names only 127.0.0.1.
    await page.goto(`${keyOrigin()}/app`);
    await page.waitForFunction(() => (window as unknown as { __nap?: unknown }).__nap);

    const code = await page.evaluate(async (key) => {
      const { connectCrossOrigin } = (window as unknown as { __nap: typeof import('../src/crossOriginClient.js') }).__nap;
      try {
        await connectCrossOrigin({ keyOrigin: key, kinds: [27235], audiences: [key], readyTimeoutMs: 1500 });
        return 'connected';
      } catch (error) {
        return (error as { code?: string }).code ?? String(error);
      }
    }, keyOrigin());
    expect(code).toBe('NOT_AVAILABLE');
    await context.close();
  });

  it('COOP: same-origin on the signer page severs the opener, so the handshake cannot happen', async () => {
    const outcome = async (coop: string) => {
      const { context, page } = await relyingPage();
      const code = await page.evaluate(async ({ key, relying, coop }) => {
        const { connectCrossOrigin } = (window as unknown as { __nap: typeof import('../src/crossOriginClient.js') }).__nap;
        try {
          await connectCrossOrigin({
            keyOrigin: key,
            kinds: [27235],
            audiences: [relying],
            signerPath: `/nap/signer?coop=${coop}`,
            readyTimeoutMs: 1500,
          });
          return 'connected';
        } catch (error) {
          return (error as { code?: string }).code ?? String(error);
        }
      }, { key: keyOrigin(), relying: relyingOrigin(), coop });
      await context.close();
      return code;
    };

    // Recorded in the extension doc: the signer page must not send COOP same-origin.
    expect(await outcome('same-origin')).not.toBe('connected');
    expect(await outcome('same-origin-allow-popups')).not.toBe('connected');
    expect(await outcome('unsafe-none')).toBe('connected');
  });

  it('COOP on the relying page: same-origin-allow-popups works, same-origin does not', async () => {
    const outcome = async (coop: string) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(`${relyingOrigin()}/app?coop=${coop}`);
      await page.waitForFunction(() => (window as unknown as { __nap?: unknown }).__nap);
      const code = await page.evaluate(async ({ key, relying }) => {
        const { connectCrossOrigin } = (window as unknown as { __nap: typeof import('../src/crossOriginClient.js') }).__nap;
        try {
          await connectCrossOrigin({ keyOrigin: key, kinds: [27235], audiences: [relying], readyTimeoutMs: 1500 });
          return 'connected';
        } catch (error) {
          return (error as { code?: string }).code ?? String(error);
        }
      }, { key: keyOrigin(), relying: relyingOrigin() });
      await context.close();
      return code;
    };

    expect(await outcome('same-origin')).not.toBe('connected');
    expect(await outcome('same-origin-allow-popups')).toBe('connected');
  });

  it('a signer page inside an iframe stays silent', async () => {
    const { context, page } = await relyingPage();
    const framed = await page.evaluate(async (key) => {
      const frame = document.createElement('iframe');
      frame.src = `${key}/nap/signer`;
      document.body.append(frame);
      const heard: unknown[] = [];
      addEventListener('message', (event) => heard.push(event.data));
      await new Promise((resolve) => frame.addEventListener('load', resolve));
      await new Promise((resolve) => setTimeout(resolve, 500));
      return heard.length;
    }, keyOrigin());
    expect(framed).toBe(0);
    await context.close();
  });
});
