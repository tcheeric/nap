/**
 * What to do when the mint does not answer (extension 0001 §7.3).
 *
 * The problem this exists for: making the mint mandatory (§4) makes it an
 * availability dependency of *login*. If the mint is down, nobody logs in.
 * That is a real regression against today's behaviour, where login depends
 * only on the app's own store.
 *
 * `degrade` is the escape hatch: issue a session on DLEQ alone — which does
 * prove the mint signed this proof — with a **reduced** permission set that
 * excludes anything destructive or value-bearing.
 *
 * The default is `deny`, and that is not a stylistic choice. Degraded mode
 * accepts an already-spent voucher, because DLEQ cannot tell a live proof from
 * a burned one (§4.2). Only the NUT-07 check can, and it is precisely the check
 * that is unavailable. So `degrade` trades a real security property for
 * availability, and a trade like that has to be made deliberately, in writing,
 * by the operator.
 */

import type { MintFailureReason } from './mintClient.js';

export interface DegradedGrant {
  roles: string[];
  permissions: string[];
}

export type AvailabilityDecision =
  | { outcome: 'deny'; reason: MintFailureReason }
  | { outcome: 'degrade'; grant: DegradedGrant };

export interface MintAvailabilityPolicyOptions {
  /** Default `'deny'`. See the module note on why. */
  onMintUnavailable?: 'deny' | 'degrade';
  /**
   * The reduced set to grant when degrading. REQUIRED when the mode is
   * `degrade`, with no default.
   *
   * There is no sensible default here. A default of "the full grant" is the
   * vulnerability; a default of "nothing" is a session that silently does
   * nothing and reads as though it works. Either way the operator has to say
   * what a login is worth when liveness is unknown.
   */
  degradedGrant?: DegradedGrant;
  /**
   * Permissions that must never appear in `degradedGrant` — the destructive or
   * value-bearing ones.
   *
   * Optional, but strongly encouraged: it is the only mechanical check that
   * `degradedGrant` actually is reduced. Without it "reduced" is a promise in a
   * comment, and the failure mode is silent — a degraded session quietly
   * carrying `voucher:redeem` is exactly the outcome §7.3 forbids, and nothing
   * would catch it. Overlap throws at wiring time.
   */
  destructivePermissions?: readonly string[];
  /**
   * Roles that must never appear in `degradedGrant`.
   *
   * Checking `permissions` alone is not enough. Roles expand into permissions
   * downstream — `createRegistryAclResolver` returns `role.permissions`
   * (`packages/nap-server/src/acl.ts`) — so a `degradedGrant` listing only
   * `voucher:view` but carrying `roles: ['admin']` can still hand a degraded
   * session everything that role grants. The permission check would pass and
   * the guarantee would be void.
   *
   * Supply the roles that carry anything destructive, alongside
   * `destructivePermissions`.
   */
  destructiveRoles?: readonly string[];
}

export interface MintAvailabilityPolicy {
  /**
   * Decide what a mint failure means.
   *
   * Only `unavailable` can ever degrade. Every other reason is a mint that
   * answered clearly — `mint_not_allowed`, `unknown_keyset`, and
   * `malformed_response` are all definite refusals — and degrading on those
   * would be treating a clear "no" as a network blip.
   */
  decide(reason: MintFailureReason): AvailabilityDecision;
  readonly mode: 'deny' | 'degrade';
}

export function createMintAvailabilityPolicy(
  options: MintAvailabilityPolicyOptions = {}
): MintAvailabilityPolicy {
  const mode = options.onMintUnavailable ?? 'deny';

  if (mode !== 'deny' && mode !== 'degrade') {
    throw new Error(
      `NAP voucher onMintUnavailable must be 'deny' or 'degrade', got '${String(mode)}'`
    );
  }

  if (mode === 'deny') {
    if (options.degradedGrant) {
      // A grant that will never be used means the operator believes degraded
      // mode is on when it is not. Failing here is the difference between
      // finding out now and finding out during an outage.
      throw new Error(
        "NAP voucher degradedGrant was supplied but onMintUnavailable is 'deny', so it would never be used"
      );
    }

    return { mode, decide: (reason) => ({ outcome: 'deny', reason }) };
  }

  const grant = options.degradedGrant;

  if (!grant || !Array.isArray(grant.roles) || !Array.isArray(grant.permissions)) {
    throw new Error(
      "NAP voucher onMintUnavailable: 'degrade' requires an explicit degradedGrant { roles, permissions }. Degraded mode accepts an already-spent voucher, so what it is worth must be stated rather than defaulted."
    );
  }

  const destructive = new Set(options.destructivePermissions ?? []);
  const overlap = grant.permissions.filter((permission) => destructive.has(permission));

  if (overlap.length > 0) {
    throw new Error(
      `NAP voucher degradedGrant includes destructive permissions: ${overlap.join(', ')}. Degraded mode runs without a liveness check, so an already-spent voucher would carry them.`
    );
  }

  // Roles are checked too, because they expand into permissions downstream: a
  // grant listing only harmless permissions but carrying a privileged role
  // hands that role's permissions to a degraded session, and the permission
  // check above would not see it.
  const destructiveRoles = new Set(options.destructiveRoles ?? []);
  const roleOverlap = grant.roles.filter((role) => destructiveRoles.has(role));

  if (roleOverlap.length > 0) {
    throw new Error(
      `NAP voucher degradedGrant includes destructive roles: ${roleOverlap.join(', ')}. Roles expand into permissions, so a degraded session would carry whatever they grant.`
    );
  }

  const frozen: DegradedGrant = Object.freeze({
    roles: Object.freeze([...grant.roles]) as string[],
    permissions: Object.freeze([...grant.permissions]) as string[],
  });

  return {
    mode,
    decide(reason: MintFailureReason): AvailabilityDecision {
      return reason === 'unavailable'
        ? { outcome: 'degrade', grant: frozen }
        : { outcome: 'deny', reason };
    },
  };
}
