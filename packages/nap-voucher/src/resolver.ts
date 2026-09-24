/**
 * The voucher ACL resolver: extension 0001 §6, RFC §12 step 13.
 *
 * Composes the pieces that already exist — the mint and issuer allowlists
 * (`allowlist.ts`), DLEQ verification and the mint client (`dleq.ts`,
 * `mintClient.ts`), and the availability policy (`availability.ts`) — into the
 * ordered procedure the extension specifies.
 *
 * ## The order is the security property
 *
 * Steps (a) through (i) are not interchangeable:
 *
 * - **(a) first, always.** `mint_url` arrives in the request. Contacting it
 *   before checking the allowlist is SSRF: an attacker picks the URL, and the
 *   server makes the request from inside the network perimeter.
 * - **(d) before (h).** The binding check is local and free. Running the
 *   network round trip first would leak to a mint that someone is probing a
 *   proof, and would spend a round trip on a credential already known bad.
 * - **All of it after RFC steps 1–12.** This resolver only ever runs from a
 *   completion that has already proven key control. Otherwise `/auth/complete`
 *   is a free oracle for state-checking arbitrary proofs against a mint the
 *   caller does not control. That ordering lives in `server.ts` rather than
 *   here, so it is pinned by a test that drives the real endpoint.
 *
 * ## Every failure is the same 401 to the client
 *
 * The codes below exist only in the audit log. A caller learning *why* their
 * voucher was refused learns whether a mint is allowlisted, whether an issuer
 * is trusted, and whether a proof is spent — an oracle assembled from error
 * messages. `AclDecision.reason` is audit-facing for the same reason.
 */

import type { IssuerAllowlist, MintAllowlist } from './allowlist.js';
import type { MintAvailabilityPolicy } from './availability.js';
import { verifyProofDleq } from './dleq.js';
import { MintUnavailableError, type Clock, type MintClient } from './mintClient.js';
import { parseVoucherSecret, voucherCanonicalBytes, type ParsedVoucherSecret } from './secret.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Audit codes, per §6.2.
 *
 * Distinctions the operator needs and the client must never see.
 */
export const VOUCHER_DENIAL_CODES = {
  /** `mint_url` is not in the allowlist. Nothing was contacted. */
  MINT_NOT_ALLOWED: 'NAP_VOUCHER_MINT_NOT_ALLOWED',
  /** The credential or its NUT-10 secret would not parse. */
  MALFORMED: 'NAP_VOUCHER_MALFORMED',
  /** NUT-12 DLEQ verification failed: the mint did not sign this proof. */
  DLEQ_INVALID: 'NAP_VOUCHER_DLEQ_INVALID',
  /** The P2PK lock key is not the key that signed the completion (§3.1). */
  BINDING_MISMATCH: 'NAP_VOUCHER_BINDING_MISMATCH',
  /** The issuer signature is invalid, or the pair is not allowlisted. */
  ISSUER_UNTRUSTED: 'NAP_VOUCHER_ISSUER_UNTRUSTED',
  /** `expires_at` is in the past, per the server's clock. */
  EXPIRED: 'NAP_VOUCHER_EXPIRED',
  /** NUT-07 returned SPENT or PENDING. */
  SPENT: 'NAP_VOUCHER_SPENT',
  /** The mint could not be reached and the mode is `deny`. */
  MINT_UNAVAILABLE: 'NAP_VOUCHER_MINT_UNAVAILABLE',
  /**
   * No credential was presented, and no `fallback` was wired.
   *
   * On login this is a client that simply did not send one. On *guard
   * re-resolution* it is something else entirely: `resolveEffectiveAcl` never
   * has the credential — it holds a session, not a request body — so a voucher
   * resolver wired as a guard's `aclResolver` sees this on every guarded
   * request. See `onMissingCredential`.
   */
  ABSENT: 'NAP_VOUCHER_ABSENT',
  /**
   * `grant()` returned a role or permission the registry does not declare
   * (#17).
   *
   * Almost always a typo. It denies rather than granting the rest, because a
   * partially-applied policy is one nobody wrote: the operator meant the login
   * to carry `voucher:view`, and a session carrying everything *except* that is
   * not a safer version of their intent.
   */
  GRANT_NOT_IN_REGISTRY: 'NAP_VOUCHER_GRANT_NOT_IN_REGISTRY',
} as const;

export type VoucherDenialCode = (typeof VOUCHER_DENIAL_CODES)[keyof typeof VOUCHER_DENIAL_CODES];

/** The verified voucher handed to `grant()`. */
export interface VerifiedVoucher {
  /** Canonical mint origin, as the allowlist matched it — not the raw input. */
  mintUrl: string;
  issuerPubkey: string;
  voucherId: string | null;
  issuer: string | null;
  unit: string | null;
  faceValue: number | null;
  expiresAt: number | null;
  /** The pubkey the voucher is locked to, which is also the session's. */
  lockedTo: string;
  /** The full parsed secret, for policies keyed on a tag not surfaced above. */
  secret: ParsedVoucherSecret;
}

export interface VoucherGrant {
  roles: string[];
  permissions: string[];
}

export interface VoucherAuditLogger {
  log(event: {
    code: string;
    npub?: string;
    pubkey?: string;
    outcome: 'success' | 'failure';
    details?: Record<string, unknown>;
  }): Promise<void> | void;
}

export interface VoucherAclResolverOptions {
  mintAllowlist: MintAllowlist;
  issuerAllowlist: IssuerAllowlist;
  mintClient: MintClient;
  availability: MintAvailabilityPolicy;
  /**
   * Maps a verified voucher to roles and permissions.
   *
   * The application's policy, deliberately outside the library: what a
   * `unit: 'sat'` voucher of face value 1000 is *worth* is not something a
   * protocol library can know.
   */
  grant(voucher: VerifiedVoucher): VoucherGrant;
  /**
   * The permission registry `grant()` output is checked against (#17).
   *
   * Optional, and checked at **grant time** rather than at wiring time. That is
   * forced by the signature: `grant()` takes a verified voucher, so a policy
   * deriving a key from the voucher's own tags -- `voucher:view:${unit}` -- has
   * no output at all until a real voucher arrives. Calling it at construction
   * with a synthetic voucher would enumerate keys like `voucher:view:PROBE:0`
   * and validate a set the application never grants, which is worse than not
   * checking: it would report success for a policy that fails on every real
   * login. See ADR 0004.
   *
   * So this does not give the wiring-time guarantee the adapters'
   * `validatePermissions` gives. What it gives is the conversion of a *silent*
   * failure into a loud and audited one: a typo'd key today grants nothing and
   * denies at some guard far away, with no record of why.
   */
  permissionRegistry?: PermissionRegistryLike;
  clock?: Clock;
  auditLogger?: VoucherAuditLogger;
  /**
   * What to answer when no voucher was presented.
   *
   * Defaults to denying. A resolver wired for voucher authorization that
   * silently allowed credential-free logins would make the credential
   * optional, which is the whole property inverted. Supply a delegate to fall
   * through to a stored ACL instead.
   */
  fallback?: AclResolverLike;
  /**
   * What a *guarded request* means when there is no credential to re-check.
   *
   * This exists because the two callers are not alike, and treating them alike
   * breaks one of them. `resolveEffectiveAcl` re-resolves per guarded request
   * (§7.2) but holds only a session — the credential lived in the login body
   * and is gone. So a resolver that denies whenever a credential is missing
   * denies **every guarded request**, and the operator sees a login that
   * succeeds followed by a session that can do nothing.
   *
   * - `'deny'` (default) keeps login strict: no credential, no session.
   * - `'trust-session'` additionally accepts a request that already carries a
   *   session's snapshot, which is what re-resolution is.
   *
   * `'trust-session'` is not a weakening of login. `AclResolutionContext` marks
   * re-resolution explicitly rather than inferring it from the credential's
   * absence, so a credential-free *login* is still denied under either
   * setting. What it does mean is that a session's authorization is only as
   * fresh as its TTL, which is §7.1's staleness question and is why this is an
   * explicit choice rather than a default.
   */
  onMissingCredential?: 'deny' | 'trust-session';
}

/**
 * The parts of `PermissionRegistry` this needs, structurally.
 *
 * Structural rather than imported so `@imani/nap-voucher` does not depend on
 * `@imani/nap-server` for a type. The registry an application already passes to
 * `validatePermissions()` satisfies it.
 */
export interface PermissionRegistryLike {
  permissions: ReadonlyArray<{ key: string }>;
  roles: ReadonlyArray<{ key: string }>;
}

/** The shape of `AclResolver` from `@imani/nap-server`, structurally. */
export interface AclResolverLike {
  resolve(
    npub: string,
    pubkey: string,
    context?: {
      voucher?: unknown;
      now: number;
      /** Present on re-resolution and refresh, never on login. */
      session?: { roles: string[]; permissions: string[] };
    }
  ): Promise<{
    allowed: boolean;
    roles: string[];
    permissions: string[];
    reason?: string;
    revoke_sessions?: boolean;
    expires_at?: number;
  }>;
}

const DENY = (reason: string) => ({
  allowed: false,
  roles: [] as string[],
  permissions: [] as string[],
  reason,
  // Deliberately never `revoke_sessions`. A bad voucher denies this login; it
  // says nothing about the principal's other sessions, which may rest on a
  // stored ACL or on a different, perfectly good voucher.
});

/**
 * Compares a NUT-11 lock key to the Nostr pubkey that signed the completion.
 *
 * The two encodings differ: NUT-11 keys are 33-byte compressed (`02`/`03`
 * prefix), Nostr pubkeys are 32-byte x-only. So the comparison is on the
 * x-coordinate.
 *
 * Dropping the prefix is safe here, and that is worth stating because it looks
 * like weakening a check. A BIP-340 signature for x-only key `X` proves control
 * of the private key `d` with `x(dG) = X`. The two compressed keys sharing that
 * x-coordinate, `02X` and `03X`, have private keys `d` and `n - d`, and anyone
 * holding one trivially computes the other. So a caller who can produce the
 * NIP-98 signature can spend against either, and treating them as distinct
 * would reject valid vouchers without denying an attacker anything.
 */
function lockKeyMatchesPubkey(lockKey: string, pubkey: string): boolean {
  if (typeof lockKey !== 'string' || typeof pubkey !== 'string') {
    return false;
  }

  const lock = lockKey.trim().toLowerCase();
  const signer = pubkey.trim().toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(signer)) {
    return false;
  }

  if (/^0[23][0-9a-f]{64}$/.test(lock)) {
    return lock.slice(2) === signer;
  }

  // An x-only lock key is accepted so a secret written in either encoding
  // works, but a malformed one never falls through to a match.
  return /^[0-9a-f]{64}$/.test(lock) && lock === signer;
}

function verifyIssuerSignature(secret: ParsedVoucherSecret): boolean {
  const { issuerSig, issuerPubkey } = secret;

  if (!issuerSig || !issuerPubkey) {
    return false;
  }

  // The issuer key is x-only for BIP-340, but may be written compressed. Accept
  // both and normalise, rather than failing on an encoding difference.
  const key = /^0[23][0-9a-f]{64}$/i.test(issuerPubkey) ? issuerPubkey.slice(2) : issuerPubkey;

  if (!/^[0-9a-f]{64}$/i.test(key) || !/^[0-9a-f]{128}$/i.test(issuerSig)) {
    return false;
  }

  try {
    // Signed over the SHA-256 of the canonical bytes, matching
    // VoucherSignatureService in cashu-voucher.
    return schnorr.verify(hexToBytes(issuerSig), sha256(voucherCanonicalBytes(secret)), hexToBytes(key));
  } catch {
    // A malformed point or signature throws rather than returning false. It is
    // a denial either way, and letting it escape would be a 500 on hostile
    // input.
    return false;
  }
}

/**
 * Builds the resolver.
 *
 * Every dependency is injected rather than constructed here. The allowlists in
 * particular throw when empty, and that construction-time failure belongs to
 * the operator wiring the server, not to the first login that happens to
 * present a voucher.
 */
export function createVoucherAclResolver(options: VoucherAclResolverOptions): AclResolverLike {
  const required = ['mintAllowlist', 'issuerAllowlist', 'mintClient', 'availability', 'grant'] as const;

  for (const key of required) {
    if (!options?.[key]) {
      throw new Error(
        `NAP voucher resolver requires '${key}'. Every one of these is load-bearing: without it the resolver would either skip a check the extension requires or reach the network unguarded.`
      );
    }
  }

  // Presence is not enough for the callables. A `grant` that is present but not
  // a function passed the check above and then threw on the first login that
  // presented a voucher -- turning a wiring mistake into a runtime failure for a
  // user, when every other mistake in this package fails at construction.
  for (const key of ['grant'] as const) {
    if (typeof options[key] !== 'function') {
      throw new Error(
        `NAP voucher resolver option '${key}' must be a function, got ${typeof options[key]}.`
      );
    }
  }

  const { mintAllowlist, issuerAllowlist, mintClient, availability, grant } = options;
  const audit = options.auditLogger;

  /**
   * Roles and permissions the registry does not declare, or `[]` when there is
   * no registry.
   *
   * Extracted so the degraded path uses the same check as the normal one. It
   * did not, and a typo'd `degradedGrant` sailed through — the exact mistake
   * ADR 0004 exists to catch, on the configuration an operator exercises least
   * and can least afford to get wrong.
   *
   * Roles are checked alongside permissions because a role expands into
   * permissions downstream, so an undeclared role is an empty grant wearing the
   * name of a real one.
   */
  const undeclaredKeys = (granted: VoucherGrant | null | undefined): string[] => {
    const registry = options.permissionRegistry;

    if (!registry) {
      return [];
    }

    const declaredPermissions = new Set(registry.permissions.map((entry) => entry.key));
    const declaredRoles = new Set(registry.roles.map((entry) => entry.key));

    return [
      ...(granted?.permissions ?? []).filter((key) => !declaredPermissions.has(key)),
      ...(granted?.roles ?? []).filter((key) => !declaredRoles.has(key)),
    ];
  };

  const deny = async (
    code: VoucherDenialCode,
    npub: string,
    pubkey: string,
    details?: Record<string, unknown>
  ) => {
    await audit?.log({ code, npub, pubkey, outcome: 'failure', ...(details ? { details } : {}) });
    // The code goes to the audit log; the caller gets an undifferentiated
    // denial, and the adapter turns it into the same 401 as every other
    // failure.
    return DENY(code);
  };

  return {
    async resolve(npub, pubkey, context) {
      const credential = context?.voucher as
        | {
            mint_url?: unknown;
            keyset_id?: unknown;
            secret?: unknown;
            signature?: unknown;
            amount?: unknown;
            dleq?: { e?: unknown; s?: unknown; r?: unknown };
          }
        | undefined;

      if (!credential) {
        if (options.fallback) {
          return options.fallback.resolve(npub, pubkey, context);
        }

        // Re-resolution never carries a credential, so denying here would deny
        // every guarded request. Trusting the session's snapshot is the only
        // other honest answer; which one applies is the operator's call.
        const session = context?.session;

        if (options.onMissingCredential === 'trust-session' && session) {
          return {
            allowed: true,
            roles: [...(session.roles ?? [])],
            permissions: [...(session.permissions ?? [])],
          };
        }

        return deny(VOUCHER_DENIAL_CODES.ABSENT, npub, pubkey, {
          // Names the footgun in the audit log rather than leaving an operator
          // to infer it from a wall of identical denials.
          ...(session ? { note: 'guard re-resolution has no credential; see onMissingCredential' } : {}),
        });
      }

      const now = context?.now ?? options.clock?.nowUnix() ?? Math.floor(Date.now() / 1000);

      // (a) The allowlist, before anything reaches the network. SSRF.
      const mintUrl =
        typeof credential.mint_url === 'string' ? mintAllowlist.resolve(credential.mint_url) : null;

      if (!mintUrl) {
        return deny(VOUCHER_DENIAL_CODES.MINT_NOT_ALLOWED, npub, pubkey);
      }

      if (
        typeof credential.secret !== 'string' ||
        typeof credential.signature !== 'string' ||
        typeof credential.keyset_id !== 'string' ||
        typeof credential.amount !== 'number'
      ) {
        return deny(VOUCHER_DENIAL_CODES.MALFORMED, npub, pubkey);
      }

      // (c) Parse first, because (d) needs the lock key and is local.
      const secret = parseVoucherSecret(credential.secret);

      if (!secret) {
        return deny(VOUCHER_DENIAL_CODES.MALFORMED, npub, pubkey);
      }

      // (d) The binding, §3.1 — before any network call, so a stolen credential
      // is refused without telling the mint anything.
      //
      // Only P2PK_VOUCHER can satisfy this: an unlocked VOUCHER has no lock
      // key, and accepting one would make possession alone sufficient, which is
      // exactly what this extension exists to prevent.
      if (!secret.lockKey || !lockKeyMatchesPubkey(secret.lockKey, pubkey)) {
        return deny(VOUCHER_DENIAL_CODES.BINDING_MISMATCH, npub, pubkey, { kind: secret.kind });
      }

      // (g) Expiry, also local and free, against the server's clock rather than
      // the wall clock.
      if (secret.expiresAt !== null && secret.expiresAt <= now) {
        return deny(VOUCHER_DENIAL_CODES.EXPIRED, npub, pubkey, { expires_at: secret.expiresAt });
      }

      // (e) The issuer signature, and (f) the pair. Both local. Verifying the
      // signature before checking the allowlist means an unallowlisted issuer's
      // forgery is still recorded as untrusted rather than as a bad signature.
      if (!verifyIssuerSignature(secret) || !secret.issuerPubkey) {
        return deny(VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED, npub, pubkey);
      }

      if (!issuerAllowlist.allows(mintUrl, secret.issuerPubkey)) {
        return deny(VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED, npub, pubkey, {
          issuer_pubkey: secret.issuerPubkey,
        });
      }

      // (b) DLEQ and (h) the state check both need the mint. Everything local
      // has now passed, so this is the first outbound request.
      try {
        const A = await mintClient.getKey(mintUrl, credential.keyset_id, credential.amount);
        const dleq = credential.dleq;

        if (
          !dleq ||
          typeof dleq.e !== 'string' ||
          typeof dleq.s !== 'string' ||
          typeof dleq.r !== 'string'
        ) {
          return deny(VOUCHER_DENIAL_CODES.MALFORMED, npub, pubkey);
        }

        // (b) The mint really signed this proof.
        if (
          !verifyProofDleq({
            A,
            secret: credential.secret,
            C: credential.signature,
            dleq: { e: dleq.e, s: dleq.s, r: dleq.r },
          })
        ) {
          return deny(VOUCHER_DENIAL_CODES.DLEQ_INVALID, npub, pubkey);
        }

        // (h) Read-only. Login must never spend (§6.1).
        const state = await mintClient.checkState(mintUrl, credential.secret);

        if (state !== 'UNSPENT') {
          return deny(VOUCHER_DENIAL_CODES.SPENT, npub, pubkey, { state });
        }
      } catch (error) {
        if (!(error instanceof MintUnavailableError)) {
          throw error;
        }

        // Only a genuine liveness failure may degrade; a mint that answered
        // clearly is a definite refusal. The policy owns that distinction.
        const decision = availability.decide(error.reason);

        if (decision.outcome === 'deny') {
          return deny(VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE, npub, pubkey, { reason: error.reason });
        }

        // The degraded grant, not `grant()`. The voucher's liveness is unknown,
        // so the operator's reduced set is what a login is worth.
        //
        // It goes through the same registry check as a normal grant. A typo here
        // is likelier than in `grant()`, not less: degraded mode is the branch an
        // operator writes once and exercises only during an outage, which is the
        // worst moment to discover the session grants nothing.
        //
        // Checked *before* the degraded-success line is logged, so a login that
        // ends in a denial does not leave a success record ahead of it. An audit
        // trail reading "degraded, succeeded" followed by a denial describes a
        // sequence that never happened.
        const degradedUnknown = undeclaredKeys(decision.grant);

        if (degradedUnknown.length > 0) {
          return deny(VOUCHER_DENIAL_CODES.GRANT_NOT_IN_REGISTRY, npub, pubkey, {
            unknown: degradedUnknown,
            degraded: true,
          });
        }

        await audit?.log({
          code: VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE,
          npub,
          pubkey,
          outcome: 'success',
          details: { reason: error.reason, degraded: true },
        });

        return {
          allowed: true,
          roles: [...decision.grant.roles],
          permissions: [...decision.grant.permissions],
          reason: 'NAP_VOUCHER_DEGRADED',
          // The voucher's own expiry still bounds the session. Liveness being
          // unknown is a reason to grant less, not a reason to grant it for
          // longer than the credential itself lasts.
          ...(secret.expiresAt !== null ? { expires_at: secret.expiresAt } : {}),
        };
      }

      // (i) Policy decides what a verified voucher is worth.
      const verified: VerifiedVoucher = {
        mintUrl,
        issuerPubkey: secret.issuerPubkey,
        voucherId: secret.voucherId,
        issuer: secret.issuer,
        unit: secret.unit,
        faceValue: secret.faceValue,
        expiresAt: secret.expiresAt,
        lockedTo: pubkey,
        secret,
      };

      const granted = grant(verified);

      // (i continued) The registry check, when one is wired.
      const unknown = undeclaredKeys(granted);

      if (unknown.length > 0) {
        return deny(VOUCHER_DENIAL_CODES.GRANT_NOT_IN_REGISTRY, npub, pubkey, { unknown });
      }

      await audit?.log({
        code: 'NAP_VOUCHER_ACCEPTED',
        npub,
        pubkey,
        outcome: 'success',
        details: { mint_url: mintUrl, voucher_id: secret.voucherId, issuer: secret.issuer },
      });

      return {
        allowed: true,
        roles: [...(granted?.roles ?? [])],
        permissions: [...(granted?.permissions ?? [])],
        // The server clamps the session to this, so a voucher expiring in five
        // minutes cannot mint a fifteen-minute session. The resolver is the only
        // party that knows the expiry -- it is inside the secret, which the
        // server never sees again after login.
        ...(secret.expiresAt !== null ? { expires_at: secret.expiresAt } : {}),
      };
    },
  };
}
