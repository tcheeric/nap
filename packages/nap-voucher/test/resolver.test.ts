import { describe, expect, it, vi } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createIssuerAllowlist, createMintAllowlist } from '../src/allowlist.js';
import { createMintAvailabilityPolicy } from '../src/availability.js';
import { MintUnavailableError, type MintClient } from '../src/mintClient.js';
import { voucherCanonicalBytes, parseVoucherSecret, VOUCHER_TAGS } from '../src/secret.js';
import { createVoucherAclResolver, VOUCHER_DENIAL_CODES } from '../src/resolver.js';

/**
 * §6 steps (a)-(i). Each step gets a negative test asserting the documented
 * audit code, because the codes are the only place the distinctions survive:
 * the client sees an identical 401 either way, so a step silently not running
 * would be invisible from the outside.
 */

const MINT = 'https://mint.example.com';
const ISSUER_PRIVATE = hexToBytes('11'.repeat(32));
const ISSUER_PUBKEY = bytesToHex(schnorr.getPublicKey(ISSUER_PRIVATE));
const HOLDER_PRIVATE = hexToBytes('22'.repeat(32));
const HOLDER_PUBKEY = bytesToHex(schnorr.getPublicKey(HOLDER_PRIVATE));
const NPUB = 'npub1holder';
const NOW = 1_710_000_000;

/** Builds a genuinely issuer-signed P2PK_VOUCHER secret. */
function signedSecret(
  overrides: {
    lockedTo?: string;
    lockPrefix?: string;
    expiresAt?: number | null;
    issuerPrivate?: Uint8Array;
    issuerPubkey?: string;
    kind?: 'VOUCHER' | 'P2PK_VOUCHER';
    tamperAfterSigning?: boolean;
  } = {}
): string {
  const kind = overrides.kind ?? 'P2PK_VOUCHER';
  const expiresAt = overrides.expiresAt === undefined ? NOW + 3600 : overrides.expiresAt;
  const tags: string[][] = [
    [VOUCHER_TAGS.VOUCHER_ID, 'v-123'],
    [VOUCHER_TAGS.ISSUER, 'imani'],
    [VOUCHER_TAGS.UNIT, 'sat'],
    [VOUCHER_TAGS.FACE_VALUE, '1000'],
  ];

  if (expiresAt !== null) {
    tags.push([VOUCHER_TAGS.EXPIRES_AT, String(expiresAt)]);
  }

  const body = {
    nonce: '0123456789abcdef',
    data: `${overrides.lockPrefix ?? '02'}${overrides.lockedTo ?? HOLDER_PUBKEY}`,
    tags,
  };
  const unsigned = parseVoucherSecret(JSON.stringify([kind, body]))!;
  const sig = bytesToHex(
    schnorr.sign(sha256(voucherCanonicalBytes(unsigned)), overrides.issuerPrivate ?? ISSUER_PRIVATE)
  );

  if (overrides.tamperAfterSigning) {
    // Change a covered tag after signing: the signature is over the old bytes.
    tags[3] = [VOUCHER_TAGS.FACE_VALUE, '999999'];
  }

  return JSON.stringify([
    kind,
    {
      ...body,
      tags: [
        ...tags,
        [VOUCHER_TAGS.ISSUER_PUBKEY, overrides.issuerPubkey ?? ISSUER_PUBKEY],
        [VOUCHER_TAGS.ISSUER_SIG, sig],
      ],
    },
  ]);
}

function credential(overrides: Record<string, unknown> = {}) {
  return {
    mint_url: MINT,
    keyset_id: '00882760bfa2eb41',
    secret: signedSecret(),
    signature: '02'.padEnd(66, 'a'),
    amount: 8,
    dleq: { e: 'e'.repeat(64), s: 's'.padEnd(64, '0'), r: 'r'.padEnd(64, '0') },
    ...overrides,
  };
}

function harness(
  overrides: {
    mintClient?: Partial<MintClient>;
    dleqValid?: boolean;
    availability?: ReturnType<typeof createMintAvailabilityPolicy>;
    fallback?: Parameters<typeof createVoucherAclResolver>[0]['fallback'];
  } = {}
) {
  const logged: Array<{ code: string; outcome: string }> = [];
  const getKey = vi.fn(async () => '02'.padEnd(66, 'b'));
  const checkState = vi.fn(async () => 'UNSPENT' as const);

  const resolver = createVoucherAclResolver({
    mintAllowlist: createMintAllowlist([MINT]),
    issuerAllowlist: createIssuerAllowlist(
      [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
      createMintAllowlist([MINT])
    ),
    mintClient: { getKey, checkState, clearCache: () => {}, ...overrides.mintClient } as MintClient,
    availability: overrides.availability ?? createMintAvailabilityPolicy(),
    grant: () => ({ roles: ['voucher-holder'], permissions: ['voucher:view'] }),
    clock: { nowUnix: () => NOW },
    auditLogger: { log: (event) => void logged.push({ code: event.code, outcome: event.outcome }) },
    ...(overrides.fallback ? { fallback: overrides.fallback } : {}),
  });

  return { resolver, logged, getKey, checkState };
}

// The DLEQ maths is verified in dleq.test.ts against the official spec vectors.
// Here it is stubbed so each step can be isolated: a test for step (f) must not
// fail because a hand-built DLEQ was wrong.
vi.mock('../src/dleq.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/dleq.js')>();
  return { ...actual, verifyProofDleq: vi.fn(() => true) };
});

const { verifyProofDleq } = await import('../src/dleq.js');

describe('wiring mistakes fail at construction', () => {
  const valid = () => ({
    mintAllowlist: createMintAllowlist([MINT]),
    issuerAllowlist: createIssuerAllowlist(
      [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
      createMintAllowlist([MINT])
    ),
    mintClient: {
      getKey: async () => '02'.padEnd(66, 'b'),
      checkState: async () => 'UNSPENT' as const,
      clearCache: () => {},
    } as MintClient,
    availability: createMintAvailabilityPolicy(),
    grant: () => ({ roles: [], permissions: [] }),
  });

  it.each(['mintAllowlist', 'issuerAllowlist', 'mintClient', 'availability', 'grant'])(
    'rejects a missing %s',
    (key) => {
      const options = { ...valid(), [key]: undefined };

      expect(() => createVoucherAclResolver(options as never)).toThrow(key);
    }
  );

  it('rejects a grant that is present but not callable', () => {
    // Found in review: presence was checked, callability was not, so this
    // constructed happily and threw on the first login presenting a voucher.
    // Every other wiring mistake here fails at construction; this one waited
    // for a user.
    const options = { ...valid(), grant: 'not a function' };

    expect(() => createVoucherAclResolver(options as never)).toThrow(/must be a function/);
  });
});

describe('the happy path', () => {
  it('accepts a bound, signed, unspent voucher and grants what the policy says', async () => {
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision).toMatchObject({
      allowed: true,
      roles: ['voucher-holder'],
      permissions: ['voucher:view'],
    });
    expect(logged).toContainEqual({ code: 'NAP_VOUCHER_ACCEPTED', outcome: 'success' });
  });
});

describe('step (a): the mint allowlist', () => {
  it('denies an unlisted mint', async () => {
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ mint_url: 'https://evil.example.com' }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.MINT_NOT_ALLOWED);
  });

  it('never contacts an unlisted mint, because the URL comes from the request', async () => {
    // SSRF. The check has to precede the fetch, not accompany it.
    const { resolver, getKey, checkState } = harness();

    await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ mint_url: 'http://169.254.169.254/latest/meta-data' }),
      now: NOW,
    });

    expect(getKey).not.toHaveBeenCalled();
    expect(checkState).not.toHaveBeenCalled();
  });
});

describe('step (d): the binding to the login key', () => {
  it('denies a voucher locked to somebody else', async () => {
    // The stolen-credential case: a valid, unspent, issuer-signed voucher
    // presented by someone who is not the key it is locked to.
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ lockedTo: 'cc'.repeat(32) }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.BINDING_MISMATCH);
  });

  it('denies an unlocked VOUCHER, where possession alone would suffice', async () => {
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ kind: 'VOUCHER' }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.BINDING_MISMATCH);
  });

  it('checks the binding before reaching the mint', async () => {
    // Local and free, so it runs first: no round trip, and the mint is not told
    // that someone is probing this proof.
    const { resolver, getKey, checkState } = harness();

    await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ lockedTo: 'cc'.repeat(32) }) }),
      now: NOW,
    });

    expect(getKey).not.toHaveBeenCalled();
    expect(checkState).not.toHaveBeenCalled();
  });

  it('accepts either compressed parity, which the signature cannot distinguish', async () => {
    // 02X and 03X have private keys d and n-d; whoever holds one computes the
    // other. Rejecting one parity would deny honest holders without stopping an
    // attacker.
    const { resolver } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ lockPrefix: '03' }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(true);
  });
});

describe('step (g): expiry', () => {
  it('denies an expired voucher against the injected clock', async () => {
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ expiresAt: NOW - 1 }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.EXPIRED);
  });

  it('uses the context clock rather than the wall clock', async () => {
    // The same voucher, judged by two different notions of now. If this read
    // Date.now() the second call would still pass.
    const { resolver } = harness();
    const voucher = credential({ secret: signedSecret({ expiresAt: NOW + 10 }) });

    expect((await resolver.resolve(NPUB, HOLDER_PUBKEY, { voucher, now: NOW })).allowed).toBe(true);
    expect((await resolver.resolve(NPUB, HOLDER_PUBKEY, { voucher, now: NOW + 11 })).allowed).toBe(
      false
    );
  });
});

describe('steps (e) and (f): the issuer', () => {
  it('denies a forged issuer signature', async () => {
    const { resolver, logged } = harness();
    const forged = JSON.parse(signedSecret());
    forged[1].tags = forged[1].tags.map((tag: string[]) =>
      tag[0] === VOUCHER_TAGS.ISSUER_SIG ? [tag[0], 'ab'.repeat(64)] : tag
    );

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: JSON.stringify(forged) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED);
  });

  it('denies a voucher whose covered tags were edited after signing', async () => {
    // The point of signing the canonical bytes: raising face_value from 1000 to
    // 999999 after the issuer signed must not verify.
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ tamperAfterSigning: true }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED);
  });

  it('denies a valid signature from an issuer this server does not honour', async () => {
    // Correctly signed, just not by anyone trusted. Trusting the mint is not
    // trusting everyone who ever issued on it.
    const other = hexToBytes('33'.repeat(32));
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({
        secret: signedSecret({
          issuerPrivate: other,
          issuerPubkey: bytesToHex(schnorr.getPublicKey(other)),
        }),
      }),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED);
  });
});

describe('step (b): DLEQ', () => {
  it('denies a proof the mint did not sign', async () => {
    vi.mocked(verifyProofDleq).mockReturnValueOnce(false);
    const { resolver, logged } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.DLEQ_INVALID);
  });
});

describe('step (h): the NUT-07 state check', () => {
  it.each(['SPENT', 'PENDING'] as const)('denies a %s proof', async (state) => {
    const { resolver, logged } = harness({ mintClient: { checkState: async () => state } });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.SPENT);
  });

  it('checks the state exactly once, and only through the read-only client', async () => {
    // §6.1: login must not spend. The strong form of that -- the client exposes
    // no spending operation, its source names no spending endpoint, and it
    // issues only GET /v1/keys and POST /v1/checkstate -- lives in
    // `noSpend.test.ts`, which inspects the mint client itself.
    //
    // This asserts the resolver's part: one state check per resolution, no
    // retry loop, nothing else. An earlier version of this test also asserted
    // `Object.keys(resolver)`, which describes the *resolver* and would pass
    // however the mint client changed. It looked like a second safeguard and
    // was none.
    const { resolver, checkState, getKey } = harness();

    await resolver.resolve(NPUB, HOLDER_PUBKEY, { voucher: credential(), now: NOW });

    expect(checkState).toHaveBeenCalledTimes(1);
    expect(getKey).toHaveBeenCalledTimes(1);
  });
});

describe('mint availability', () => {
  it('denies by default when the mint is unreachable', async () => {
    const { resolver, logged } = harness({
      mintClient: {
        getKey: async () => {
          throw new MintUnavailableError('unavailable', 'connection refused');
        },
      },
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE);
  });

  it('grants only the reduced set when degrading, never the policy grant', async () => {
    const { resolver } = harness({
      mintClient: {
        checkState: async () => {
          throw new MintUnavailableError('unavailable', 'timeout');
        },
      },
      availability: createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: { roles: [], permissions: ['voucher:view'] },
        destructivePermissions: ['voucher:redeem'],
      }),
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision).toMatchObject({ allowed: true, roles: [], permissions: ['voucher:view'] });
  });

  it('applies the registry check to the degraded grant too', async () => {
    // Found in review: the degraded path returned early, before the check ADR
    // 0004 added. A typo here is likelier than in `grant()`, not less --
    // degraded mode is the branch an operator writes once and exercises only
    // during an outage, which is the worst moment to find the session grants
    // nothing.
    const logged: Array<{ code: string; details?: Record<string, unknown> }> = [];
    const resolver = createVoucherAclResolver({
      mintAllowlist: createMintAllowlist([MINT]),
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
        createMintAllowlist([MINT])
      ),
      mintClient: {
        getKey: async () => {
          throw new MintUnavailableError('unavailable', 'timeout');
        },
        checkState: async () => 'UNSPENT' as const,
        clearCache: () => {},
      } as MintClient,
      availability: createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: { roles: [], permissions: ['voucher:veiw'] },
      }),
      permissionRegistry: { permissions: [{ key: 'voucher:view' }], roles: [] },
      grant: () => ({ roles: [], permissions: ['voucher:view'] }),
      auditLogger: {
        log: (event) => void logged.push({ code: event.code, details: event.details }),
      },
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]).toMatchObject({
      code: VOUCHER_DENIAL_CODES.GRANT_NOT_IN_REGISTRY,
      details: { unknown: ['voucher:veiw'], degraded: true },
    });
    // And no success line ahead of the denial: an audit trail reading
    // "degraded, succeeded" followed by a denial describes a sequence that
    // never happened.
    expect(logged.map((entry) => entry.code)).not.toContain(
      VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE
    );
  });

  it('still bounds a degraded session by the voucher expiry', async () => {
    // Liveness being unknown is a reason to grant less, not to grant it for
    // longer than the credential itself lasts.
    const { resolver } = harness({
      mintClient: {
        checkState: async () => {
          throw new MintUnavailableError('unavailable', 'timeout');
        },
      },
      availability: createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: { roles: [], permissions: ['voucher:view'] },
      }),
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ expiresAt: NOW + 60 }) }),
      now: NOW,
    });

    expect(decision).toMatchObject({ allowed: true, expires_at: NOW + 60 });
  });

  it('does not degrade on a definite refusal from a reachable mint', async () => {
    // An unknown keyset is an answer, not a blip. Degrading here would treat a
    // clear "no" as a network problem.
    const { resolver, logged } = harness({
      mintClient: {
        getKey: async () => {
          throw new MintUnavailableError('unknown_keyset', 'no such keyset');
        },
      },
      availability: createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: { roles: [], permissions: ['voucher:view'] },
      }),
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.code).toBe(VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE);
  });
});

describe('when no voucher is presented', () => {
  it('denies rather than allowing a credential-free login', async () => {
    const { resolver } = harness();

    expect((await resolver.resolve(NPUB, HOLDER_PUBKEY, { now: NOW })).allowed).toBe(false);
  });

  it('delegates to a fallback when one is wired', async () => {
    const fallback = {
      resolve: async () => ({ allowed: true, roles: ['stored'], permissions: ['p'] }),
    };
    const { resolver, getKey } = harness({ fallback });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, { now: NOW });

    expect(decision.roles).toEqual(['stored']);
    expect(getKey).not.toHaveBeenCalled();
  });
});

describe('denials are indistinguishable to the client', () => {
  it('never carries roles, permissions, or a session revocation', async () => {
    // A bad voucher denies this login. It says nothing about the principal's
    // other sessions, which may rest on a stored ACL or a different voucher.
    const { resolver } = harness();

    for (const voucher of [
      credential({ mint_url: 'https://evil.example.com' }),
      credential({ secret: signedSecret({ lockedTo: 'cc'.repeat(32) }) }),
      credential({ secret: signedSecret({ expiresAt: NOW - 1 }) }),
      credential({ secret: 'not-a-secret' }),
    ]) {
      const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, { voucher, now: NOW });

      expect(decision.allowed).toBe(false);
      expect(decision.roles).toEqual([]);
      expect(decision.permissions).toEqual([]);
      expect(decision.revoke_sessions).toBeUndefined();
    }
  });

  it('rejects a hostile credential without throwing', async () => {
    const { resolver } = harness();

    for (const voucher of [
      {},
      { mint_url: MINT },
      { mint_url: MINT, keyset_id: 1, secret: 's', signature: 'c', amount: 8 },
      credential({ dleq: null }),
      credential({ amount: 'eight' }),
    ]) {
      await expect(
        resolver.resolve(NPUB, HOLDER_PUBKEY, { voucher, now: NOW })
      ).resolves.toMatchObject({ allowed: false });
    }
  });
});

/**
 * #17: `grant()` output against the `PermissionRegistry`.
 *
 * The decision is grant-time validation, not wiring-time. The signature forces
 * it: `grant()` takes a verified voucher, so a policy keyed on the voucher's
 * own tags has no output until a real voucher arrives. See the option's doc
 * comment for why probing with a synthetic voucher would be worse than nothing.
 */
describe('grant() is checked against the registry', () => {
  const registry = {
    permissions: [{ key: 'voucher:view' }],
    roles: [{ key: 'voucher-holder' }],
  };

  const withGrant = (granted: { roles: string[]; permissions: string[] }) => {
    const logged: Array<{ code: string; details?: Record<string, unknown> }> = [];
    const resolver = createVoucherAclResolver({
      mintAllowlist: createMintAllowlist([MINT]),
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
        createMintAllowlist([MINT])
      ),
      mintClient: {
        getKey: async () => '02'.padEnd(66, 'b'),
        checkState: async () => 'UNSPENT' as const,
        clearCache: () => {},
      } as MintClient,
      availability: createMintAvailabilityPolicy(),
      grant: () => granted,
      permissionRegistry: registry,
      auditLogger: {
        log: (event) => void logged.push({ code: event.code, details: event.details }),
      },
    });

    return { resolver, logged };
  };

  it('accepts a grant the registry declares', async () => {
    const { resolver } = withGrant({ roles: ['voucher-holder'], permissions: ['voucher:view'] });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(true);
  });

  it('denies a typo, rather than granting a session that quietly does nothing', async () => {
    // Today this is silent: the session is issued carrying a key no guard will
    // ever match, and the denial surfaces later at some unrelated route with no
    // record of the cause.
    const { resolver, logged } = withGrant({
      roles: ['voucher-holder'],
      permissions: ['voucher:veiw'],
    });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]).toMatchObject({
      code: VOUCHER_DENIAL_CODES.GRANT_NOT_IN_REGISTRY,
      details: { unknown: ['voucher:veiw'] },
    });
  });

  it('denies an undeclared role, which expands to nothing downstream', async () => {
    // Checking permissions alone would miss this: roles expand into permissions
    // in createRegistryAclResolver, so an undeclared role is an empty grant
    // wearing the name of a real one.
    const { resolver, logged } = withGrant({ roles: ['admn'], permissions: ['voucher:view'] });

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(logged[0]?.details).toMatchObject({ unknown: ['admn'] });
  });

  it('is optional: without a registry the policy is trusted as before', async () => {
    // Additive. An application that has no registry, or validates elsewhere,
    // keeps working unchanged.
    const { resolver } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential(),
      now: NOW,
    });

    expect(decision.allowed).toBe(true);
  });
});

/**
 * #24, third acceptance criterion: the codes must be visible from guard
 * re-resolution too.
 *
 * Checking that surfaced a footgun rather than a missing log line.
 * `resolveEffectiveAcl` re-resolves per guarded request but holds only a
 * session -- the credential lived in the login body and is gone. So a voucher
 * resolver wired as a guard's `aclResolver` denied *every* guarded request, and
 * logged nothing at all: login succeeded, then the session could do nothing,
 * with no record of why.
 */
describe('guard re-resolution, which never carries a credential', () => {
  const session = { roles: ['voucher-holder'], permissions: ['voucher:view'] };

  const build = (onMissingCredential?: 'deny' | 'trust-session') => {
    const logged: Array<{ code: string; details?: Record<string, unknown> }> = [];
    const resolver = createVoucherAclResolver({
      mintAllowlist: createMintAllowlist([MINT]),
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
        createMintAllowlist([MINT])
      ),
      mintClient: {
        getKey: async () => '02'.padEnd(66, 'b'),
        checkState: async () => 'UNSPENT' as const,
        clearCache: () => {},
      } as MintClient,
      availability: createMintAvailabilityPolicy(),
      grant: () => ({ roles: ['r'], permissions: ['p'] }),
      ...(onMissingCredential ? { onMissingCredential } : {}),
      auditLogger: {
        log: (event) => void logged.push({ code: event.code, details: event.details }),
      },
    });

    return { resolver, logged };
  };

  it('audits the denial instead of failing silently', async () => {
    const { resolver, logged } = build();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, { now: NOW, session });

    expect(decision.allowed).toBe(false);
    // The note names the footgun. Without it an operator sees a wall of
    // identical denials and has to infer the cause.
    expect(logged[0]).toMatchObject({
      code: VOUCHER_DENIAL_CODES.ABSENT,
      details: { note: expect.stringContaining('onMissingCredential') },
    });
  });

  it("honours the session's snapshot under 'trust-session'", async () => {
    const { resolver } = build('trust-session');

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, { now: NOW, session });

    expect(decision).toMatchObject({ allowed: true, ...session });
  });

  it("still denies a credential-free LOGIN under 'trust-session'", async () => {
    // The load-bearing half. `trust-session` must not weaken login: a login
    // carries no `session`, so the two cases stay distinguishable and the
    // credential remains mandatory to obtain a session in the first place.
    const { resolver } = build('trust-session');

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, { now: NOW });

    expect(decision.allowed).toBe(false);
  });
});

/**
 * The resolver reports the voucher's expiry so the server can clamp the session
 * to it (#27). Without this the fact is unreachable: it lives inside the
 * secret, which the server never sees again once login is over.
 */
describe('the decision carries the voucher expiry', () => {
  it('reports expires_at from the secret', async () => {
    const { resolver } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ expiresAt: NOW + 300 }) }),
      now: NOW,
    });

    expect(decision).toMatchObject({ allowed: true, expires_at: NOW + 300 });
  });

  it('omits it for a voucher that does not expire', async () => {
    // Absent rather than 0 or Infinity: the server treats absence as "no bound"
    // and uses its configured TTL, which is the correct answer here.
    const { resolver } = harness();

    const decision = await resolver.resolve(NPUB, HOLDER_PUBKEY, {
      voucher: credential({ secret: signedSecret({ expiresAt: null }) }),
      now: NOW,
    });

    expect(decision.allowed).toBe(true);
    expect(decision.expires_at).toBeUndefined();
  });
});
