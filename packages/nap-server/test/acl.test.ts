import { describe, expect, it } from 'vitest';
import {
  createRegistryAclResolver,
  InMemoryAclStore,
  validatePermissionRegistry,
  type PermissionRegistry,
} from '../src/index.js';

function buildRegistry(): PermissionRegistry {
  return {
    appId: 'possa-merchant',
    permissions: [
      { key: 'merchant:read', description: 'Read merchant settings', stepUp: false },
      { key: 'voucher:create', description: 'Create vouchers', stepUp: false },
      { key: 'stripe:manage', description: 'Manage Stripe settings', stepUp: true },
    ],
    roles: [
      {
        key: 'merchant',
        description: 'Full merchant access',
        permissions: ['merchant:read', 'voucher:create', 'stripe:manage'],
      },
      {
        key: 'readonly',
        description: 'Read-only access',
        permissions: ['merchant:read'],
      },
    ],
    defaultRole: 'merchant',
  };
}

describe('registry ACL support', () => {
  it('auto-provisions the default role and resolves permissions', async () => {
    const aclStore = new InMemoryAclStore();
    const resolver = createRegistryAclResolver(buildRegistry(), aclStore);

    const decision = await resolver.resolve('npub1example', 'pubkey-1');

    expect(decision).toEqual({
      allowed: true,
      roles: ['merchant'],
      permissions: ['merchant:read', 'stripe:manage', 'voucher:create'],
    });
  });

  it('applies permission overrides with deny precedence', async () => {
    const aclStore = new InMemoryAclStore();
    await aclStore.upsert({
      principal_pubkey: 'pubkey-2',
      app_id: 'possa-merchant',
      role: 'readonly',
      permission_overrides: [
        { action: 'grant', permission: 'voucher:create' },
        { action: 'grant', permission: 'stripe:manage' },
        { action: 'deny', permission: 'stripe:manage' },
      ],
      suspended: false,
    });

    const resolver = createRegistryAclResolver(buildRegistry(), aclStore, {
      autoProvision: false,
    });

    const decision = await resolver.resolve('npub1example', 'pubkey-2');

    expect(decision).toEqual({
      allowed: true,
      roles: ['readonly'],
      permissions: ['merchant:read', 'voucher:create'],
    });
  });

  it('denies suspended principals', async () => {
    const aclStore = new InMemoryAclStore();
    await aclStore.upsert({
      principal_pubkey: 'pubkey-3',
      app_id: 'possa-merchant',
      role: 'merchant',
      permission_overrides: [],
      suspended: true,
    });
    const resolver = createRegistryAclResolver(buildRegistry(), aclStore, {
      autoProvision: false,
    });

    await expect(resolver.resolve('npub1example', 'pubkey-3')).resolves.toEqual({
      allowed: false,
      roles: [],
      permissions: [],
      reason: 'suspended',
      // The only deny certain enough to end the principal's sessions.
      revoke_sessions: true,
    });
  });

  it('rejects invalid registries at startup', () => {
    const invalidRegistry: PermissionRegistry = {
      appId: 'possa-merchant',
      permissions: [
        { key: 'merchant:read', description: 'Read merchant settings', stepUp: false },
      ],
      roles: [
        {
          key: 'merchant',
          description: 'Full merchant access',
          permissions: ['voucher:create'],
        },
      ],
      defaultRole: 'merchant',
    };

    expect(() => validatePermissionRegistry(invalidRegistry)).toThrow(
      "PermissionRegistry role 'merchant' references unknown permission 'voucher:create'"
    );
  });
});
