import { describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import { createNapSession } from '../src/session.js';
import { SessionLockedError } from '../src/httpClient.js';
import { isEvictableSigner } from '../src/types.js';
import type { SessionSigner } from '../src/types.js';

export interface SignerConformanceCase {
  name: string;
  create(): SessionSigner | Promise<SessionSigner>;
  /**
   * True for signers that hold no key in the page (NIP-07, NIP-46). They must
   * not implement `EvictableSigner` — there is nothing in reach to evict — but
   * `lock()` must still lock the session (FR-023).
   */
  keyFree: boolean;
  /**
   * Change the identity behind a signer, the way an extension account switch or
   * a re-paired bunker does, and resolve once it has taken effect.
   *
   * Omit only for signers whose identity genuinely cannot change — the in-page
   * private key signer refuses `setKey` for a different key by design, so there
   * is no such transition to test.
   */
  rotateIdentity?(signer: SessionSigner): void | Promise<void>;
}

function pubkeyOf(npub: string): string {
  const decoded = nip19.decode(npub);
  expect(decoded.type).toBe('npub');
  return decoded.data as string;
}

function stubServer(npub: string, pubkey: string): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);

    if (url.endsWith('/auth/init')) {
      return new Response(JSON.stringify({
        challenge_id: 'challenge-1',
        challenge: 'challenge',
        auth_url: 'https://merchant.example.com/auth/complete',
        auth_method: 'POST',
        issued_at: 1_710_000_000,
        expires_at: 1_710_000_060,
      }), { status: 200 });
    }

    return new Response(JSON.stringify({
      status: 'ok',
      expires_at: 1_710_000_900,
      principal: { npub, pubkey },
      roles: ['merchant'],
      permissions: ['voucher:create'],
    }), { status: 200 });
  });
}

/**
 * The contract every signer must satisfy, run identically against all three.
 *
 * This is what makes "signers are interchangeable" a checked claim rather than a
 * documented intention (FR-010, FR-023, SC-006, SC-011).
 */
export function runSignerConformance(testCase: SignerConformanceCase): void {
  describe(`SessionSigner conformance: ${testCase.name}`, () => {
    it('reports a valid, stable npub', async () => {
      const signer = await testCase.create();

      const first = await signer.getNpub();
      const second = await signer.getNpub();

      expect(first).toMatch(/^npub1/);
      expect(() => nip19.decode(first)).not.toThrow();
      expect(second).toBe(first);
    });

    if (testCase.rotateIdentity) {
      it('re-reads its identity instead of serving a cached npub', async () => {
        const signer = await testCase.create();
        const before = await signer.getNpub();

        await testCase.rotateIdentity!(signer);

        // Stability above is necessary but not sufficient: a signer that cached
        // its first answer passes it too, and then reports the old identity
        // forever. `session.ts` calls getNpub() before every login precisely to
        // catch this transition — a cache turns that guard into a no-op (FR-021).
        expect(await signer.getNpub()).not.toBe(before);
      });
    }

    it('signs an event whose pubkey matches its npub', async () => {
      const signer = await testCase.create();
      const npub = await signer.getNpub();

      const event = await signer.signEvent({
        kind: 27235,
        tags: [['u', 'https://merchant.example.com/auth/complete'], ['method', 'POST']],
        content: '',
        created_at: 1_710_000_000,
      });

      expect(event.kind).toBe(27235);
      expect(event.pubkey).toBe(pubkeyOf(npub));
      expect(event.sig).toBeTruthy();
    });

    it('completes login() against a stub server with the same request shape', async () => {
      const signer = await testCase.create();
      const npub = await signer.getNpub();
      const fetchMock = stubServer(npub, pubkeyOf(npub));

      const session = createNapSession({
        baseUrl: 'https://merchant.example.com',
        signer,
        fetch: fetchMock,
      });

      const response = await session.login();

      expect(response.principal.npub).toBe(npub);
      expect(session.isAuthenticated()).toBe(true);

      // SC-011: the server sees the same two requests regardless of who signed.
      const [initUrl, initInit] = fetchMock.mock.calls[0];
      expect(String(initUrl)).toBe('https://merchant.example.com/auth/init');
      expect(JSON.parse(String(initInit?.body))).toEqual({ npub });

      const [completeUrl, completeInit] = fetchMock.mock.calls[1];
      expect(String(completeUrl)).toBe('https://merchant.example.com/auth/complete');
      const authorization = (completeInit?.headers as Record<string, string>).authorization;
      expect(authorization.startsWith('Nostr ')).toBe(true);
    });

    if (testCase.keyFree) {
      it('holds no key in the page, yet still locks', async () => {
        const signer = await testCase.create();

        // Nothing in reach to evict, so it must not claim to be evictable.
        expect(isEvictableSigner(signer)).toBe(false);

        const session = createNapSession({
          baseUrl: 'https://merchant.example.com',
          signer,
          fetch: vi.fn<typeof fetch>(),
        });

        expect(() => session.lock()).not.toThrow();
        expect(session.isLocked()).toBe(true);

        expect(() => session.shutdown()).not.toThrow();
        expect(session.isShutdown()).toBe(true);
      });

      it('refuses to authenticate while locked', async () => {
        const signer = await testCase.create();
        const fetchMock = vi.fn<typeof fetch>();

        const session = createNapSession({
          baseUrl: 'https://merchant.example.com',
          signer,
          fetch: fetchMock,
        });

        session.lock();

        await expect(session.login()).rejects.toThrow(SessionLockedError);
        expect(fetchMock).not.toHaveBeenCalled();
      });
    }
  });
}
