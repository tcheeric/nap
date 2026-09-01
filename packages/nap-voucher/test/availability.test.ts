import { describe, expect, it } from 'vitest';
import { createMintAvailabilityPolicy, type MintFailureReason } from '../src/index.js';

const REDUCED = { roles: ['voucher-holder'], permissions: ['voucher:view'] };

describe('default is deny (§7.3)', () => {
  it('denies when the option is omitted entirely', () => {
    // The central requirement of #26. Degraded mode accepts an already-spent
    // voucher, so it must never be reachable by forgetting to configure.
    const policy = createMintAvailabilityPolicy();

    expect(policy.mode).toBe('deny');
    expect(policy.decide('unavailable')).toEqual({ outcome: 'deny', reason: 'unavailable' });
  });

  it('denies when options are passed but the mode is not set', () => {
    expect(createMintAvailabilityPolicy({}).mode).toBe('deny');
  });

  it.each(['unavailable', 'mint_not_allowed', 'unknown_keyset', 'malformed_response'] as const)(
    'denies %s in deny mode',
    (reason) => {
      expect(createMintAvailabilityPolicy({ onMintUnavailable: 'deny' }).decide(reason)).toEqual({
        outcome: 'deny',
        reason,
      });
    }
  );

  it('rejects a degradedGrant that could never be used', () => {
    // Means the operator believes degraded mode is on when it is not. Better to
    // find out at wiring time than during an outage.
    expect(() =>
      createMintAvailabilityPolicy({ onMintUnavailable: 'deny', degradedGrant: REDUCED })
    ).toThrow(/would never be used/);
  });

  it('rejects an unrecognised mode rather than falling back', () => {
    expect(() =>
      createMintAvailabilityPolicy({ onMintUnavailable: 'allow' as 'deny' })
    ).toThrow(/must be 'deny' or 'degrade'/);
  });
});

describe('degrade requires an explicit grant', () => {
  it('refuses to build without one', () => {
    // No sensible default exists: "the full grant" is the vulnerability, and
    // "nothing" is a session that silently does nothing while reading as though
    // it works.
    expect(() => createMintAvailabilityPolicy({ onMintUnavailable: 'degrade' })).toThrow(
      /requires an explicit degradedGrant/
    );
  });

  it.each([
    ['a non-array roles', { roles: 'admin', permissions: [] }],
    ['a non-array permissions', { roles: [], permissions: 'all' }],
    ['an empty object', {}],
  ])('refuses to build with %s', (_label, degradedGrant) => {
    expect(() =>
      createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: degradedGrant as never,
      })
    ).toThrow(/requires an explicit degradedGrant/);
  });

  it('rejects a grant carrying a destructive permission', () => {
    // The only mechanical check that "reduced" is true. Without it the failure
    // is silent: a degraded session quietly carrying voucher:redeem is exactly
    // what §7.3 forbids.
    expect(() =>
      createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: { roles: [], permissions: ['voucher:view', 'voucher:redeem'] },
        destructivePermissions: ['voucher:redeem', 'stripe:manage'],
      })
    ).toThrow(/destructive permissions: voucher:redeem/);
  });

  it('accepts a genuinely reduced grant', () => {
    expect(() =>
      createMintAvailabilityPolicy({
        onMintUnavailable: 'degrade',
        degradedGrant: REDUCED,
        destructivePermissions: ['voucher:redeem'],
      })
    ).not.toThrow();
  });
});

describe('degrade fires only on unavailable', () => {
  const policy = () =>
    createMintAvailabilityPolicy({
      onMintUnavailable: 'degrade',
      degradedGrant: REDUCED,
      destructivePermissions: ['voucher:redeem'],
    });

  it('degrades when the mint did not answer', () => {
    expect(policy().decide('unavailable')).toEqual({ outcome: 'degrade', grant: REDUCED });
  });

  it.each(['mint_not_allowed', 'unknown_keyset', 'malformed_response'] as const)(
    'denies %s even in degrade mode',
    (reason) => {
      // These are a mint that answered clearly. Degrading on them would treat a
      // definite refusal as a network blip.
      expect(policy().decide(reason)).toEqual({ outcome: 'deny', reason });
    }
  );

  it('never grants a destructive permission when degrading', () => {
    const decision = policy().decide('unavailable');

    expect(decision.outcome).toBe('degrade');
    if (decision.outcome === 'degrade') {
      expect(decision.grant.permissions).not.toContain('voucher:redeem');
      expect(decision.grant.permissions).toEqual(['voucher:view']);
    }
  });

  it('hands out a frozen grant that callers cannot widen', () => {
    // The grant crosses into the resolver and becomes an AclDecision. A caller
    // that mutated it would widen every subsequent degraded session.
    const decision = policy().decide('unavailable');

    if (decision.outcome === 'degrade') {
      expect(() => decision.grant.permissions.push('voucher:redeem')).toThrow();
      expect(policy().decide('unavailable')).toEqual({ outcome: 'degrade', grant: REDUCED });
    }
  });

  it('is unaffected by later mutation of the caller original options object', () => {
    const mutable = { roles: ['a'], permissions: ['voucher:view'] };
    const built = createMintAvailabilityPolicy({
      onMintUnavailable: 'degrade',
      degradedGrant: mutable,
    });

    mutable.permissions.push('voucher:redeem');
    const decision = built.decide('unavailable');

    if (decision.outcome === 'degrade') {
      expect(decision.grant.permissions).toEqual(['voucher:view']);
    }
  });
});

describe('every MintFailureReason is handled', () => {
  it('returns a decision for each reason with no fallthrough', () => {
    // Guards against a new reason being added to the client and silently
    // taking whichever branch happens to be last.
    const reasons: MintFailureReason[] = [
      'mint_not_allowed',
      'unavailable',
      'malformed_response',
      'unknown_keyset',
    ];
    const policy = createMintAvailabilityPolicy();

    for (const reason of reasons) {
      expect(policy.decide(reason).outcome).toBe('deny');
    }
  });
});
