import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, type EventTemplate } from 'nostr-tools';
import { bytesToHex, utf8Bytes } from '@imani/nap-core';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  issueChallenge,
  toPublicAuthSuccess,
  verifyCompletion,
  type NapServerOptions,
} from '@imani/nap-server';
import { connectCrossOrigin, type CrossOriginGrant } from '../src/crossOriginClient.js';
import {
  CROSS_ORIGIN_PROTOCOL,
  CrossOriginSignerError,
  audienceOf,
  normalizeOrigin,
  parseMessage,
} from '../src/crossOriginProtocol.js';
import {
  createStorageConsentStore,
  mountCrossOriginSigner,
  type CrossOriginSignerHandle,
  type CrossOriginSignerOptions,
  type SignRequest,
} from '../src/crossOriginSigner.js';
import { createNapSession } from '../src/session.js';
import { createPrivateKeySessionSigner } from '../src/signers.js';
import type { SessionSigner } from '../src/types.js';
import { FakeWindow, flush, link, type WindowHandle } from './fakeWindows.js';
import { runSignerConformance } from './signerConformance.js';

const SHOP = 'https://shop.example';
const WALLET = 'https://wallet.example';
const EVIL = 'https://evil.example';

const KEY = generateSecretKey();
const PUBKEY = getPublicKey(KEY);
const NPUB = nip19.npubEncode(PUBKEY);

const POLICY = {
  [SHOP]: { kinds: [27235], audiences: [SHOP] },
};

interface World {
  relying: FakeWindow;
  wallet: FakeWindow;
  popup: WindowHandle;
  opener: WindowHandle;
  handle: () => CrossOriginSignerHandle;
  connect: (extra?: Partial<Parameters<typeof connectCrossOrigin>[0]>) => Promise<CrossOriginGrant>;
  signer: SessionSigner;
  onConsent: ReturnType<typeof vi.fn>;
}

/**
 * A relying page on SHOP opening the wallet's signer page on WALLET. The signer page mounts on
 * the tick after `window.open`, the way a real popup loads after the call returns.
 */
function world(
  overrides: Partial<CrossOriginSignerOptions> = {},
  signer: SessionSigner = createPrivateKeySessionSigner(bytesToHex(KEY)),
  relyingOrigin = SHOP
): World {
  const relying = new FakeWindow(relyingOrigin);
  const wallet = new FakeWindow(WALLET);
  const { forward: popup, back: opener } = link(relying, wallet);
  const onConsent = vi.fn(async () => true);
  let mounted: CrossOriginSignerHandle | undefined;

  const mount = () => {
    mounted = mountCrossOriginSigner({
      policy: POLICY,
      signer,
      onConsent,
      opener,
      target: wallet,
      isFramed: false,
      sessionChannel: false,
      ...overrides,
    });
  };

  return {
    relying,
    wallet,
    popup,
    opener,
    signer,
    onConsent,
    handle: () => mounted!,
    connect: (extra = {}) =>
      connectCrossOrigin({
        keyOrigin: WALLET,
        kinds: [27235],
        audiences: [relyingOrigin],
        target: relying,
        closedPollMs: 5,
        readyTimeoutMs: 200,
        open: (url) => {
          expect(url).toBe(`${WALLET}/nap/signer`);
          setTimeout(mount, 0);
          return popup;
        },
        ...extra,
      }),
  };
}

function template(overrides: Partial<EventTemplate> = {}, u = `${SHOP}/auth/complete`): EventTemplate {
  return {
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    content: '',
    tags: [
      ['u', u],
      ['method', 'POST'],
    ],
    ...overrides,
  };
}

function completionTemplate(u = `${SHOP}/auth/complete`): EventTemplate {
  return {
    ...template({}, u),
    tags: [
      ['u', u],
      ['method', 'POST'],
      ['payload', 'p'],
      ['challenge', 'c'],
      ['challenge_id', 'id'],
    ],
  };
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as CrossOriginSignerError).code;
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe('protocol', () => {
  it('ignores anything that is not exactly a message of this protocol', () => {
    expect(parseMessage(null)).toBeNull();
    expect(parseMessage('ready')).toBeNull();
    expect(parseMessage({ type: 'ready' })).toBeNull();
    expect(parseMessage({ nap: 'nap-cross-origin-signer/2', type: 'ready' })).toBeNull();
    expect(parseMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'connect', id: 'x', kinds: [], audiences: [SHOP] })).toBeNull();
    expect(parseMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'error', code: 'MADE_UP' })).toBeNull();
    expect(
      parseMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'sign', id: 'x', grantId: 'g', template: { kind: 1, tags: 'no', content: '', created_at: 1 } })
    ).toBeNull();
    const hostile = {
      nap: CROSS_ORIGIN_PROTOCOL,
      get type() {
        throw new Error('boom');
      },
    };
    expect(parseMessage(hostile)).toBeNull();
  });

  it('copies what it parses instead of holding the sender’s objects', () => {
    const tags = [['u', `${SHOP}/x`]];
    const parsed = parseMessage({
      nap: CROSS_ORIGIN_PROTOCOL,
      type: 'sign',
      id: 'x',
      grantId: 'g',
      template: { kind: 27235, created_at: 1, content: '', tags, extra: 'dropped' },
    });
    expect(parsed?.type).toBe('sign');
    if (parsed?.type !== 'sign') return;
    expect(parsed.template.tags).not.toBe(tags);
    expect(parsed.template.tags[0]).not.toBe(tags[0]);
    expect('extra' in parsed.template).toBe(false);
  });

  it('accepts only canonical bare origins', () => {
    expect(normalizeOrigin('https://shop.example')).toBe('https://shop.example');
    expect(normalizeOrigin('https://shop.example/')).toBe('https://shop.example');
    expect(() => normalizeOrigin('https://shop.example/path')).toThrow();
    expect(() => normalizeOrigin('https://SHOP.example')).toThrow(/canonical/);
    expect(() => normalizeOrigin('https://user@shop.example')).toThrow();
    expect(() => normalizeOrigin('ftp://shop.example')).toThrow();
    expect(() => normalizeOrigin('shop.example')).toThrow();
  });

  it('reads the audience from exactly one u tag', () => {
    expect(audienceOf(template())).toBe(SHOP);
    expect(audienceOf({ ...template(), tags: [['method', 'POST']] })).toBeNull();
    expect(audienceOf({ ...template(), tags: [['u', `${SHOP}/a`], ['u', `${EVIL}/b`]] })).toBeNull();
    expect(audienceOf({ ...template(), tags: [['u', 'javascript:alert(1)']] })).toBeNull();
    expect(audienceOf({ ...template(), tags: [['u', `https://x@${SHOP.slice(8)}/`]] })).toBeNull();
  });
});

describe('policy validation', () => {
  const base = { signer: createPrivateKeySessionSigner(bytesToHex(KEY)), onConsent: async () => true, opener: null, isFramed: false, sessionChannel: false as const };

  it('refuses an empty policy rather than allowing everyone', () => {
    expect(() => mountCrossOriginSigner({ ...base, policy: {} })).toThrow(/at least one/);
  });

  it('refuses entries that would not match what they look like', () => {
    expect(() => mountCrossOriginSigner({ ...base, policy: { 'https://shop.example/app': POLICY[SHOP] } })).toThrow();
    expect(() => mountCrossOriginSigner({ ...base, policy: { [SHOP]: { kinds: [], audiences: [SHOP] } } })).toThrow();
    expect(() => mountCrossOriginSigner({ ...base, policy: { [SHOP]: { kinds: [27235], audiences: [] } } })).toThrow();
    expect(() => mountCrossOriginSigner({ ...base, policy: { [SHOP]: { kinds: [27235], audiences: [SHOP], maxTtlSeconds: 3600 } } })).toThrow();
  });
});

describe('connect', () => {
  it('connects, asks for consent once, and gets a grant scoped to what it asked for', async () => {
    const w = world();
    const grant = await w.connect();

    expect(grant.info.pubkey).toBe(PUBKEY);
    expect(grant.info.kinds).toEqual([27235]);
    expect(grant.info.audiences).toEqual([SHOP]);
    expect(grant.isActive()).toBe(true);
    expect(await grant.signer.getNpub()).toBe(NPUB);
    expect(w.onConsent).toHaveBeenCalledTimes(1);
    expect(w.onConsent.mock.calls[0][0]).toMatchObject({ origin: SHOP, pubkey: PUBKEY, npub: NPUB, kinds: [27235], audiences: [SHOP] });
    expect(w.handle().grants()).toHaveLength(1);
  });

  it('never posts with a wildcard target origin', async () => {
    const w = world();
    const grant = await w.connect();
    await grant.signer.signEvent(template());

    expect(w.opener.targetOrigins.every((origin) => origin === SHOP)).toBe(true);
    expect(w.popup.targetOrigins.every((origin) => origin === WALLET)).toBe(true);
  });

  it('asks again only when there is nothing remembered', async () => {
    const memory = new Map<string, string>();
    const storage = { getItem: (k: string) => memory.get(k) ?? null, setItem: (k: string, v: string) => void memory.set(k, v) };
    const consentStore = createStorageConsentStore(storage);

    const first = world({ consentStore });
    await first.connect();
    expect(first.onConsent).toHaveBeenCalledTimes(1);

    const second = world({ consentStore });
    await second.connect();
    expect(second.onConsent).not.toHaveBeenCalled();

    // A wider scope is a new question.
    const widened = world({ consentStore, policy: { [SHOP]: { kinds: [27235, 1], audiences: [SHOP] } } });
    await widened.connect({ kinds: [27235, 1] });
    expect(widened.onConsent).toHaveBeenCalledTimes(1);

    await consentStore.forget(SHOP);
    expect(await consentStore.list()).toEqual([]);
  });

  it('reports a declined consent as DECLINED and closes the popup', async () => {
    const w = world({ onConsent: async () => false });
    expect(await codeOf(w.connect())).toBe('DECLINED');
    expect(w.popup.closed).toBe(true);
    expect(w.handle().grants()).toHaveLength(0);
  });

  it('refuses kinds or audiences the policy does not give this origin', async () => {
    expect(await codeOf(world().connect({ kinds: [27235, 4] }))).toBe('REFUSED');
    expect(await codeOf(world().connect({ audiences: [SHOP, EVIL] }))).toBe('REFUSED');
  });

  it('unlocks before asking for consent, and a refused unlock is DECLINED', async () => {
    const order: string[] = [];
    const ok = world({
      ensureUnlocked: async () => void order.push('unlock'),
      onConsent: async () => (order.push('consent'), true),
    });
    await ok.connect();
    expect(order).toEqual(['unlock', 'consent']);

    const refused = world({ ensureUnlocked: async () => { throw new Error('cancelled'); } });
    expect(await codeOf(refused.connect())).toBe('DECLINED');
    expect(refused.onConsent).not.toHaveBeenCalled();
  });

  it('will not connect as someone other than the expected identity', async () => {
    const someoneElse = getPublicKey(generateSecretKey());
    const w = world();
    expect(await codeOf(w.connect({ expectedPubkey: someoneElse }))).toBe('REFUSED');
    expect(w.onConsent.mock.calls[0][0]).toMatchObject({ expectedPubkey: someoneElse, pubkey: PUBKEY });
    expect(w.handle().grants()).toHaveLength(0);

    const matching = world();
    const grant = await matching.connect({ expectedPubkey: PUBKEY });
    expect(grant.info.pubkey).toBe(PUBKEY);
  });

  it('reports a blocked popup without waiting', async () => {
    const relying = new FakeWindow(SHOP);
    const code = await codeOf(
      connectCrossOrigin({ keyOrigin: WALLET, kinds: [27235], audiences: [SHOP], target: relying, open: () => null })
    );
    expect(code).toBe('POPUP_BLOCKED');
  });

  it('gives up with NOT_AVAILABLE when nothing answers', async () => {
    const relying = new FakeWindow(SHOP);
    const wallet = new FakeWindow(WALLET);
    const { forward } = link(relying, wallet);
    const code = await codeOf(
      connectCrossOrigin({ keyOrigin: WALLET, kinds: [27235], audiences: [SHOP], target: relying, readyTimeoutMs: 30, open: () => forward })
    );
    expect(code).toBe('NOT_AVAILABLE');
  });

  it('gives up with CHANNEL_CLOSED when the user closes the popup mid-consent', async () => {
    let release!: (value: boolean) => void;
    const w = world({ onConsent: () => new Promise<boolean>((resolve) => (release = resolve)) });
    const pending = w.connect();
    await flush();
    w.popup.close();
    expect(await codeOf(pending)).toBe('CHANNEL_CLOSED');
    release(true);
  });
});

describe('who may talk to the signer page', () => {
  it('a stranger who opens the signer page hears nothing, not even that it exists', async () => {
    const evil = new FakeWindow(EVIL);
    const wallet = new FakeWindow(WALLET);
    const { forward, back } = link(evil, wallet);
    const onConsent = vi.fn(async () => true);
    const signer = createPrivateKeySessionSigner(bytesToHex(KEY));

    mountCrossOriginSigner({ policy: POLICY, signer, onConsent, opener: back, target: wallet, isFramed: false, sessionChannel: false });
    forward.postMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'connect', id: 'x', kinds: [27235], audiences: [SHOP] }, WALLET);
    forward.postMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'connect', id: 'y', kinds: [27235], audiences: [EVIL] }, WALLET);
    await flush();

    expect(evil.received).toEqual([]);
    expect(onConsent).not.toHaveBeenCalled();
  });

  it('ignores an allowed origin that is not the opener', async () => {
    const w = world();
    const grant = await w.connect();

    // A second shop.example window (another tab) messaging the same signer page.
    const otherTab = new FakeWindow(SHOP);
    const { forward } = link(otherTab, w.wallet);
    forward.postMessage(
      { nap: CROSS_ORIGIN_PROTOCOL, type: 'sign', id: 'z', grantId: grant.info.grantId, template: template() },
      WALLET
    );
    await flush();
    expect(otherTab.received).toEqual([]);
  });

  it('a framed signer page answers nothing, because consent in a frame can be clickjacked', async () => {
    const w = world({ isFramed: true });
    expect(await codeOf(w.connect())).toBe('NOT_AVAILABLE');
    expect(w.onConsent).not.toHaveBeenCalled();
  });

  it('a signer page opened directly, with no opener, answers nothing', () => {
    const handle = mountCrossOriginSigner({
      policy: POLICY,
      signer: createPrivateKeySessionSigner(bytesToHex(KEY)),
      onConsent: async () => true,
      opener: null,
      target: new FakeWindow(WALLET),
      isFramed: false,
      sessionChannel: false,
    });
    expect(handle.grants()).toEqual([]);
  });

  it('the relying page ignores messages from anything but the popup it opened', async () => {
    const w = world();
    const grant = await w.connect();
    const impostor = new FakeWindow(WALLET);
    const { forward } = link(impostor, w.relying);
    forward.postMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'revoked', grantId: grant.info.grantId }, SHOP);
    await flush();
    expect(grant.isActive()).toBe(true);
  });
});

describe('signing inside a grant', () => {
  it('signs a request addressed to an allowed audience, and the event verifies', async () => {
    const w = world();
    const grant = await w.connect();
    const event = await grant.signer.signEvent(template());

    expect(event.pubkey).toBe(PUBKEY);
    expect(event.tags).toEqual(template().tags);
  });

  it('refuses a u tag outside the grant: the §7.1 origin-substitution attack', async () => {
    const w = world();
    const grant = await w.connect();

    expect(await codeOf(grant.signer.signEvent(template({}, 'https://gateway.example/auth/complete')))).toBe('REFUSED');
    expect(await codeOf(grant.signer.signEvent({ ...template(), tags: [['method', 'POST']] }))).toBe('REFUSED');
    expect(await codeOf(grant.signer.signEvent({ ...template(), tags: [['u', `${SHOP}/a`], ['u', `${EVIL}/b`]] }))).toBe('REFUSED');
    // Still usable for what it is for.
    await expect(grant.signer.signEvent(template())).resolves.toBeTruthy();
  });

  it('refuses a kind outside the grant', async () => {
    const grant = await world().connect();
    expect(await codeOf(grant.signer.signEvent(template({ kind: 1 })))).toBe('REFUSED');
  });

  it('refuses a created_at far from now, so a grant cannot pre-sign proofs for later', async () => {
    const grant = await world().connect();
    const future = Math.floor(Date.now() / 1000) + 3600;
    expect(await codeOf(grant.signer.signEvent(template({ created_at: future })))).toBe('REFUSED');
  });

  it('refuses a grant id it did not issue, the same way as a revoked one', async () => {
    const w = world();
    await w.connect();
    w.popup.postMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'sign', id: 'q', grantId: 'forged', template: template() }, WALLET);
    await flush();
    const reply = w.relying.received.map((event) => parseMessage(event.data)).find((message) => message?.type === 'error');
    expect(reply).toMatchObject({ type: 'error', id: 'q', code: 'REVOKED' });
  });

  it('the first completion proof rides the consent, the second needs a prompt (step-up, §10.3)', async () => {
    const noPrompt = await world().connect();
    await expect(noPrompt.signer.signEvent(completionTemplate())).resolves.toBeTruthy();
    expect(await codeOf(noPrompt.signer.signEvent(completionTemplate()))).toBe('REFUSED');

    const onSign = vi.fn(async (_request: SignRequest) => true);
    const prompted = await world({ onSign }).connect();
    await prompted.signer.signEvent(completionTemplate());
    await prompted.signer.signEvent(completionTemplate());
    expect(onSign.mock.calls.map(([request]) => request.reason)).toEqual(['request', 'completion']);

    const declined = await world({ onSign: async (request) => request.reason !== 'completion' }).connect();
    await declined.signer.signEvent(completionTemplate());
    expect(await codeOf(declined.signer.signEvent(completionTemplate()))).toBe('DECLINED');
  });

  it('rejects an event the signer page returns that is not what was asked for', async () => {
    const honest = createPrivateKeySessionSigner(bytesToHex(KEY));
    const tampering: SessionSigner = {
      getNpub: () => honest.getNpub(),
      signEvent: async (event) => honest.signEvent({ ...event, content: 'swapped' }),
    };
    const grant = await world({}, tampering).connect();
    expect(await codeOf(grant.signer.signEvent(template()))).toBe('SIGNER_ERROR');
  });

  it('the relying page verifies the signature itself', async () => {
    const w = world();
    const grant = await w.connect();
    // Answer the next sign request with a forged signature, ahead of the real signer page.
    const real = w.popup.postMessage.bind(w.popup);
    w.popup.postMessage = (message: unknown, origin: string) => {
      const parsed = parseMessage(message);
      if (parsed?.type === 'sign') {
        const forged = { ...finalizeEvent(parsed.template, KEY), sig: '0'.repeat(128) };
        setTimeout(() => w.relying.deliver({ origin: WALLET, source: w.popup, data: { nap: CROSS_ORIGIN_PROTOCOL, type: 'signed', id: parsed.id, event: forged } }), 0);
        return;
      }
      real(message, origin);
    };
    expect(await codeOf(grant.signer.signEvent(template()))).toBe('SIGNER_ERROR');
  });
});

describe('ending a grant', () => {
  it('revokeAll (the key origin locked or logged out) ends it on both sides', async () => {
    const w = world();
    const grant = await w.connect();
    const ended = vi.fn();
    grant.onEnd(ended);

    w.handle().revokeAll('lock');
    await flush();

    expect(grant.isActive()).toBe(false);
    expect(ended).toHaveBeenCalledWith('REVOKED');
    expect(w.handle().grants()).toEqual([]);
    expect(await codeOf(grant.signer.signEvent(template()))).toBe('REVOKED');
  });

  it('a lock broadcast by the key origin’s own session reaches the popup', async () => {
    const channel = `nap-test-${Math.random()}`;
    const w = world({ sessionChannel: channel });
    const grant = await w.connect();

    const tab = new BroadcastChannel(channel);
    tab.postMessage('lock');
    await vi.waitFor(() => expect(grant.isActive()).toBe(false));
    tab.close();
    w.handle().close();
  });

  it('revoke by origin, for a "Connected sites" screen', async () => {
    const changes: number[] = [];
    const w = world({ onGrantsChanged: (grants) => changes.push(grants.length) });
    const grant = await w.connect();
    w.handle().revoke(SHOP);
    await flush();
    expect(grant.isActive()).toBe(false);
    expect(changes).toEqual([1, 0]);
  });

  it('expires at the TTL without the key origin saying anything', async () => {
    let clock = Math.floor(Date.now() / 1000);
    const w = world({ now: () => clock, policy: { [SHOP]: { kinds: [27235], audiences: [SHOP], maxTtlSeconds: 60 } } });
    const grant = await w.connect({ now: () => clock });
    expect(grant.info.expiresAt).toBe(clock + 60);

    clock += 61;
    expect(grant.isActive()).toBe(false);
    expect(await codeOf(grant.signer.signEvent(template({ created_at: clock })))).toBe('GRANT_EXPIRED');
    expect(() => grant.signer.getNpub()).toThrow(CrossOriginSignerError);
  });

  it('the key origin enforces the TTL even against a relying page that ignores it', async () => {
    let clock = Math.floor(Date.now() / 1000);
    const w = world({ now: () => clock, policy: { [SHOP]: { kinds: [27235], audiences: [SHOP], maxTtlSeconds: 60 } } });
    // The relying page's clock never moves, so it keeps believing the grant is live.
    const grant = await w.connect({ now: () => Math.floor(Date.now() / 1000) - 3600 });
    clock += 61;
    expect(await codeOf(grant.signer.signEvent(template({ created_at: clock })))).toBe('GRANT_EXPIRED');
    expect(w.handle().grants()).toEqual([]);
  });

  it('disconnect tells the key origin and closes the popup', async () => {
    const w = world();
    const grant = await w.connect();
    const sent: unknown[] = [];
    const real = w.popup.postMessage.bind(w.popup);
    w.popup.postMessage = (message: unknown, origin: string) => {
      sent.push(message);
      real(message, origin);
    };
    grant.disconnect();
    expect(sent.map((message) => parseMessage(message)?.type)).toEqual(['disconnect']);
    expect(w.popup.closed).toBe(true);
    expect(grant.isActive()).toBe(false);
  });

  it('a disconnect message drops the grant on the key origin', async () => {
    const w = world();
    const grant = await w.connect();
    w.popup.postMessage({ nap: CROSS_ORIGIN_PROTOCOL, type: 'disconnect', grantId: grant.info.grantId }, WALLET);
    await flush();
    expect(w.handle().grants()).toEqual([]);
  });

  it('closing the popup ends the grant', async () => {
    const w = world();
    const grant = await w.connect();
    w.popup.close();
    await vi.waitFor(() => expect(grant.isActive()).toBe(false));
    expect(await codeOf(grant.signer.signEvent(template()))).toBe('CHANNEL_CLOSED');
  });

  it('an identity change behind the signer ends every grant', async () => {
    const other = generateSecretKey();
    let current = KEY;
    const switching: SessionSigner = {
      getNpub: () => nip19.npubEncode(getPublicKey(current)),
      signEvent: async (event) => finalizeEvent(event, current),
    };
    const w = world({}, switching);
    const grant = await w.connect();
    current = other;
    expect(await codeOf(grant.signer.signEvent(template()))).toBe('REVOKED');
    await flush();
    expect(grant.isActive()).toBe(false);
    expect(w.handle().grants()).toEqual([]);
  });
});

describe('a real NAP server cannot tell the difference', () => {
  it('logs in end to end through the cross-origin signer, with core NAP unchanged', async () => {
    const serverOptions: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore: new InMemorySessionStore(),
      aclResolver: { resolve: async () => ({ allowed: true, roles: ['merchant'], permissions: ['subscription:buy'] }) },
      minAuthResponseMillis: 0,
    };
    const authUrl = `${SHOP}/auth/complete`;
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      if (url === `${SHOP}/auth/init`) {
        const { npub } = JSON.parse(String(init?.body)) as { npub: string };
        const result = await issueChallenge({ npub, authUrl }, serverOptions);
        return new Response(JSON.stringify(result.ok ? result.value : {}), { status: result.ok ? 200 : 401 });
      }
      if (url === authUrl) {
        const headers = init?.headers as Record<string, string>;
        const rawBody = utf8Bytes(String(init?.body));
        const result = await verifyCompletion({ authorization: headers.authorization, method: 'POST', url: authUrl, rawBody }, serverOptions);
        return new Response(JSON.stringify(result.ok ? toPublicAuthSuccess(result.session) : {}), { status: result.ok ? 200 : 401 });
      }
      return new Response('', { status: 404 });
    });

    const grant = await world().connect();
    const session = createNapSession({ baseUrl: SHOP, signer: grant.signer, fetch: fetchImpl, broadcast: { enabled: false } });
    const response = await session.login();

    expect(response.principal.pubkey).toBe(PUBKEY);
    expect(response.permissions).toEqual(['subscription:buy']);
  });
});

// The grant's signer is a SessionSigner like any other. No rotateIdentity: a grant names one
// identity for its whole life, and a change behind it ends the grant (tested above) rather
// than letting the npub drift.
runSignerConformance({
  name: 'cross-origin signer (extension 0002)',
  keyFree: true,
  create: async () => {
    // The conformance stub server lives on merchant.example.com and signs fixed timestamps.
    const merchant = 'https://merchant.example.com';
    const w = world(
      { createdAtSkewSeconds: Number.POSITIVE_INFINITY, policy: { [merchant]: { kinds: [27235], audiences: [merchant] } } },
      undefined,
      merchant
    );
    return (await w.connect()).signer;
  },
});
