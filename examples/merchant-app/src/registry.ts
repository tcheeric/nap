import type { PermissionRegistry } from '@imani/nap-server';

/**
 * The whole authorisation vocabulary of this app, in one object.
 *
 * `validatePermissionRegistry()` runs over this at boot and refuses a role that
 * references a permission that is not declared, so a typo here is a startup
 * failure rather than a route that silently never matches.
 */
export const REGISTRY: PermissionRegistry = {
  appId: 'merchant-app',
  permissions: [
    { key: 'merchant:read', description: 'Read vouchers and merchant profile', stepUp: false },
    { key: 'voucher:create', description: 'Issue a new voucher', stepUp: false },
    // stepUp: true — a valid session is not enough. The caller must also present
    // an X-Step-Up-Token minted by a *fresh* signature. See tutorial 06.
    { key: 'stripe:manage', description: 'Change payout settings', stepUp: true },
  ],
  roles: [
    {
      key: 'viewer',
      description: 'Can look, cannot touch',
      permissions: ['merchant:read'],
    },
    {
      key: 'merchant',
      description: 'Runs a shop',
      permissions: ['merchant:read', 'voucher:create'],
    },
    {
      key: 'owner',
      description: 'Runs a shop and owns the money',
      permissions: ['merchant:read', 'voucher:create', 'stripe:manage'],
    },
    {
      key: 'support',
      description: 'Staff. Can look up a merchant, and nothing this app offers',
      // Deliberately empty. Support is not part of the merchant vocabulary —
      // there is no permission that means "is staff", and inventing one would
      // put a key in the registry that no merchant role should ever hold.
      // This is the case `requireRole()` exists for; see tutorial 03.
      permissions: [],
    },
  ],
  // Every principal with no ACL row lands here. Make it the least you are
  // willing to hand a stranger who can produce a valid signature.
  defaultRole: 'merchant',
};
