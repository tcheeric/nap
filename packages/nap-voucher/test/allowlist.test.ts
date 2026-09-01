import { describe, expect, it } from 'vitest';
import {
  canonicalizeMintUrl,
  createIssuerAllowlist,
  createMintAllowlist,
} from '../src/index.js';

const MINT = 'https://mint.example.com';
const ISSUER = 'a'.repeat(64);

function allowlist(mints: string[] = [MINT]) {
  return createMintAllowlist(mints);
}

describe('mint allowlist (extension 0001 §4.3)', () => {
  describe('construction fails at wiring time, not request time', () => {
    it('rejects an empty list with no escape hatch', () => {
      // The whole point: "any mint" must be unrepresentable. Any mint can sign
      // a voucher claiming any role, so a permissive default is a privilege
      // escalation with a config file in front of it.
      expect(() => createMintAllowlist([])).toThrow(/non-empty mint allowlist/);
    });

    it('rejects a missing list', () => {
      expect(() => createMintAllowlist(undefined as unknown as string[])).toThrow(
        /non-empty mint allowlist/
      );
    });

    it.each([
      ['', /empty entry/],
      ['   ', /empty entry/],
      ['mint.example.com', /not an absolute URL/],
      ['//mint.example.com', /not an absolute URL/],
      ['ftp://mint.example.com', /must use https/],
      ['https://user:pw@mint.example.com', /userinfo/],
      ['https://mint.example.com/v1', /bare origin/],
      ['https://mint.example.com/?a=b', /bare origin/],
      ['https://mint.example.com/#frag', /bare origin/],
      ['https://*.example.com', /wildcards/],
    ])('rejects %s', (entry, expected) => {
      expect(() => createMintAllowlist([entry])).toThrow(expected);
    });

    it('rejects http even though the audience allowlist permits it', () => {
      // Not an inconsistency. The audience may legitimately be plaintext on a
      // trusted internal hop behind TLS termination. This is an outbound call
      // to a third party carrying a credential, whose answer decides an
      // authorization: over plaintext anyone on the path forges UNSPENT.
      expect(() => createMintAllowlist(['http://mint.example.com'])).toThrow(/must use https/);
    });

    it('rejects duplicates that differ only by normalization', () => {
      // Always means the operator believes two entries differ when they do not.
      expect(() =>
        createMintAllowlist(['https://mint.example.com', 'https://mint.example.com/'])
      ).toThrow(/duplicate origins/);
    });
  });

  describe('matching is exact', () => {
    it('accepts the configured origin', () => {
      expect(allowlist().resolve(MINT)).toBe(MINT);
    });

    it('accepts a trailing slash, which is the same origin', () => {
      expect(allowlist().resolve('https://mint.example.com/')).toBe(MINT);
    });

    it('is case-insensitive on the host, as DNS is', () => {
      expect(allowlist().resolve('https://MINT.EXAMPLE.COM')).toBe(MINT);
    });

    it.each([
      ['a different host', 'https://evil.example.com'],
      ['a subdomain', 'https://a.mint.example.com'],
      ['a suffix extension', 'https://mint.example.com.evil.com'],
      ['a prefix', 'https://notmint.example.com'],
      ['a different scheme', 'http://mint.example.com'],
      ['an explicit non-default port', 'https://mint.example.com:8443'],
      ['userinfo pointing elsewhere', 'https://mint.example.com@evil.com'],
      ['a path traversal attempt', 'https://evil.com/https://mint.example.com'],
      ['not a URL at all', 'mint.example.com'],
      ['empty', ''],
    ])('rejects %s', (_label, candidate) => {
      expect(allowlist().resolve(candidate)).toBeNull();
    });

    it('treats an explicit default port as the same origin', () => {
      expect(allowlist().resolve('https://mint.example.com:443')).toBe(MINT);
    });

    it('distinguishes ports when the entry pins one', () => {
      const pinned = createMintAllowlist(['https://mint.example.com:8443']);

      expect(pinned.resolve('https://mint.example.com:8443')).toBe('https://mint.example.com:8443');
      expect(pinned.resolve(MINT)).toBeNull();
    });

    it('returns the configured origin rather than the caller-supplied string', () => {
      // Nothing downstream should ever hold a value that arrived in the
      // request. The two are equal here, which is exactly why the property has
      // to be asserted rather than observed.
      const list = allowlist();
      const resolved = list.resolve('https://MINT.EXAMPLE.COM/');

      expect(resolved).toBe(list.origins[0]);
    });

    it('never throws on a malformed mint_url', () => {
      // A malformed credential must produce the same generic 401 as every other
      // voucher failure. An exception distinguishes itself by shape and timing.
      for (const bad of ['', '   ', 'not a url', '://', 'https://', '\u0000']) {
        expect(() => allowlist().resolve(bad)).not.toThrow();
        expect(allowlist().resolve(bad)).toBeNull();
      }
    });
  });

  it('canonicalizeMintUrl agrees with the allowlist on what is well-formed', () => {
    expect(canonicalizeMintUrl('https://MINT.example.com/')).toBe(MINT);
    expect(canonicalizeMintUrl('http://mint.example.com')).toBeNull();
    expect(canonicalizeMintUrl('nonsense')).toBeNull();
  });
});

describe('issuer allowlist', () => {
  it('rejects an empty list at construction', () => {
    expect(() => createIssuerAllowlist([], allowlist())).toThrow(/non-empty issuer allowlist/);
  });

  it('rejects an issuer pinned to a mint that is not allowlisted', () => {
    // Dead configuration that reads as though it grants something. Worse, if
    // the mint is removed later the operator believes the pair still constrains
    // something.
    expect(() =>
      createIssuerAllowlist([{ mint: 'https://other.example.com', issuerPubkey: ISSUER }], allowlist())
    ).toThrow(/not in the mint allowlist/);
  });

  it.each([
    ['too short', 'abc'],
    ['not hex', 'z'.repeat(64)],
    ['uppercase-only nonsense', 'X'.repeat(64)],
    ['empty', ''],
    ['65 chars', 'a'.repeat(65)],
  ])('rejects an issuer pubkey that is %s', (_label, issuerPubkey) => {
    expect(() => createIssuerAllowlist([{ mint: MINT, issuerPubkey }], allowlist())).toThrow(
      /lowercase hex/
    );
  });

  it('rejects duplicate pairs', () => {
    expect(() =>
      createIssuerAllowlist(
        [
          { mint: MINT, issuerPubkey: ISSUER },
          { mint: `${MINT}/`, issuerPubkey: ISSUER.toUpperCase() },
        ],
        allowlist()
      )
    ).toThrow(/duplicate/);
  });

  it('allows the configured pair and nothing else', () => {
    const mints = allowlist([MINT, 'https://second.example.com']);
    const issuers = createIssuerAllowlist([{ mint: MINT, issuerPubkey: ISSUER }], mints);

    expect(issuers.allows(MINT, ISSUER)).toBe(true);
    expect(issuers.allows(MINT, 'b'.repeat(64))).toBe(false);
    // Keyed on the pair: trusting a mint is not trusting everyone who ever used
    // it, and an issuer trusted on one mint is not trusted on another.
    expect(issuers.allows('https://second.example.com', ISSUER)).toBe(false);
  });

  it('normalizes case on both sides of the pair', () => {
    const issuers = createIssuerAllowlist(
      [{ mint: 'https://MINT.example.com', issuerPubkey: ISSUER.toUpperCase() }],
      allowlist()
    );

    expect(issuers.allows(MINT, ISSUER)).toBe(true);
  });

  it('returns false rather than throwing on non-string input', () => {
    const issuers = createIssuerAllowlist([{ mint: MINT, issuerPubkey: ISSUER }], allowlist());

    expect(issuers.allows(undefined as unknown as string, ISSUER)).toBe(false);
    expect(issuers.allows(MINT, null as unknown as string)).toBe(false);
  });
});

describe('SSRF: an unvetted URL is never reached', () => {
  it('resolves without performing any network call', async () => {
    // §6 ordering note: step (a) comes before everything, so a non-allowlisted
    // mint_url must be refused without an outbound request. Assert the
    // allowlist itself is inert by failing the test if anything calls fetch.
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      calls.push(String(input));
      throw new Error('no network expected');
    }) as typeof fetch;

    try {
      const list = allowlist();

      expect(list.resolve('https://169.254.169.254')).toBeNull();
      expect(list.resolve('https://localhost')).toBeNull();
      expect(list.resolve('https://evil.example.com')).toBeNull();
      expect(list.resolve(MINT)).toBe(MINT);
      expect(calls).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('rejects the cloud metadata endpoint and loopback unless explicitly configured', () => {
    // Not special-cased, and deliberately not: the allowlist is exact, so these
    // are refused for the same reason every other unlisted host is. Asserted so
    // the classic SSRF targets are covered by name.
    const list = allowlist();

    for (const target of [
      'https://169.254.169.254/latest/meta-data/',
      'https://127.0.0.1',
      'https://[::1]',
      'https://metadata.google.internal',
    ]) {
      expect(list.resolve(target)).toBeNull();
    }
  });
});
