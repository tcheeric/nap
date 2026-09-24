/**
 * The wiring example from the `@imani/nap-voucher` README, executed.
 *
 * Extension 0001 #30: "wiring example compiles and is exercised by a test". A
 * documented snippet that has never run is a liability — it is the first thing
 * an integrator copies, and the failure lands on them rather than on us. So the
 * README's example lives here, compiled by `tsc` with the rest of the workspace
 * and run by the suite.
 *
 * Only the parts whose shape is settled. The resolver and the completion-body
 * field are #23 and #22, blocked on decision #13.
 */

import { describe, expect, it } from 'vitest';
import {
  createIssuerAllowlist,
  createMintAllowlist,
  createMintAvailabilityPolicy,
  createMintClient,
} from '../src/index.js';

const ISSUER_PUBKEY = 'a'.repeat(64);

describe('README wiring example', () => {
  it('compiles and builds a working set of allowlists', () => {
    // --- README: "Why there are two allowlists" ---
    const mints = createMintAllowlist(['https://mint.example.com']);
    const issuers = createIssuerAllowlist(
      [{ mint: 'https://mint.example.com', issuerPubkey: ISSUER_PUBKEY }],
      mints
    );

    // Returns the *configured* origin, or null. Never throws, never fetches.
    const mint = mints.resolve('https://mint.example.com');

    expect(mint).toBe('https://mint.example.com');
    expect(issuers.allows(mint!, ISSUER_PUBKEY)).toBe(true);
    expect(mints.resolve('https://evil.example.com')).toBeNull();
  });

  it('compiles and builds the mint client from the allowlist', () => {
    const mints = createMintAllowlist(['https://mint.example.com']);

    // --- README: "DLEQ and the state check" ---
    const mint = createMintClient({ allowlist: mints, keysetCacheTtlSeconds: 3600 });

    expect(typeof mint.getKey).toBe('function');
    expect(typeof mint.checkState).toBe('function');
  });

  it('compiles and builds both availability policies', () => {
    // --- README: "Mint availability (§7.3)" ---
    const strict = createMintAvailabilityPolicy();
    const lenient = createMintAvailabilityPolicy({
      onMintUnavailable: 'degrade',
      degradedGrant: { roles: ['voucher-holder'], permissions: ['voucher:view'] },
      destructivePermissions: ['voucher:redeem'],
    });

    expect(strict.mode).toBe('deny');
    expect(lenient.mode).toBe('degrade');
    expect(strict.decide('unavailable').outcome).toBe('deny');
    expect(lenient.decide('unavailable').outcome).toBe('degrade');
  });

  it('produces the construction-time errors the guide documents', () => {
    // The exact messages an operator hits when they get the wiring wrong, so
    // the guide's claims about them cannot drift from the code.
    expect(() => createMintAllowlist([])).toThrow(/non-empty mint allowlist/);
    expect(() => createMintAllowlist(['http://mint.example.com'])).toThrow(/must use https/);
    expect(() => createMintAllowlist(['https://*.example.com'])).toThrow(/wildcards/);
    expect(() =>
      createIssuerAllowlist([], createMintAllowlist(['https://mint.example.com']))
    ).toThrow(/non-empty issuer allowlist/);
    expect(() => createMintAvailabilityPolicy({ onMintUnavailable: 'degrade' })).toThrow(
      /requires an explicit degradedGrant/
    );
  });
});
