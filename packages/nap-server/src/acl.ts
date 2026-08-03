import type { AclDecision } from '@imani/nap-core';
import type {
  AclRecord,
  AclStore,
  Clock,
  PermissionRegistry,
  PermissionOverride,
  RoleDefinition,
  AclResolver,
  SessionStore,
} from './types.js';

export interface RegistryAclResolverOptions {
  autoProvision?: boolean;
  logger?: Pick<Console, 'info' | 'warn'>;
}

function validateUniqueKeys(values: string[], label: string): void {
  const seen = new Set<string>();

  for (const value of values) {
    if (seen.has(value)) {
      throw new Error(`PermissionRegistry contains duplicate ${label} key '${value}'`);
    }

    seen.add(value);
  }
}

function validateRolePermissions(
  registry: PermissionRegistry,
  role: RoleDefinition,
  knownPermissions: ReadonlySet<string>
): void {
  for (const permission of role.permissions) {
    if (!knownPermissions.has(permission)) {
      throw new Error(
        `PermissionRegistry role '${role.key}' references unknown permission '${permission}'`
      );
    }
  }
}

export function validatePermissionRegistry(registry: PermissionRegistry): void {
  validateUniqueKeys(
    registry.permissions.map((permission) => permission.key),
    'permission'
  );
  validateUniqueKeys(
    registry.roles.map((role) => role.key),
    'role'
  );

  const knownPermissions = new Set(
    registry.permissions.map((permission) => permission.key)
  );
  const knownRoles = new Set(registry.roles.map((role) => role.key));

  if (!knownRoles.has(registry.defaultRole)) {
    throw new Error(
      `PermissionRegistry defaultRole '${registry.defaultRole}' is not declared in roles`
    );
  }

  for (const role of registry.roles) {
    validateRolePermissions(registry, role, knownPermissions);
  }
}

function applyOverrides(
  basePermissions: string[],
  overrides: PermissionOverride[]
): string[] {
  const granted = new Set(basePermissions);
  const denied = new Set<string>();

  for (const override of overrides) {
    if (override.action === 'grant') {
      granted.add(override.permission);
      continue;
    }

    denied.add(override.permission);
  }

  return Array.from(granted).filter((permission) => !denied.has(permission)).sort();
}

function denied(reason: string): AclDecision {
  return {
    allowed: false,
    roles: [],
    permissions: [],
    reason,
  };
}

function allowed(role: string, permissions: string[]): AclDecision {
  return {
    allowed: true,
    roles: [role],
    permissions,
  };
}

function buildAutoProvisionRecord(registry: PermissionRegistry, pubkey: string): AclRecord {
  return {
    principal_pubkey: pubkey,
    app_id: registry.appId,
    role: registry.defaultRole,
    permission_overrides: [],
    suspended: false,
  };
}

async function resolveAclRecord(
  registry: PermissionRegistry,
  aclStore: AclStore,
  pubkey: string,
  options: Required<RegistryAclResolverOptions>
): Promise<AclRecord | null> {
  const existing = await aclStore.get(pubkey, registry.appId);

  if (existing) {
    return existing;
  }

  if (!options.autoProvision) {
    return null;
  }

  const record = buildAutoProvisionRecord(registry, pubkey);
  await aclStore.upsert(record);
  options.logger.info('nap.acl.auto_provisioned', {
    pubkey,
    app_id: registry.appId,
    role: registry.defaultRole,
  });
  return aclStore.get(pubkey, registry.appId);
}

export function createRegistryAclResolver(
  registry: PermissionRegistry,
  aclStore: AclStore,
  options: RegistryAclResolverOptions = {}
): AclResolver {
  validatePermissionRegistry(registry);

  const resolvedOptions: Required<RegistryAclResolverOptions> = {
    autoProvision: options.autoProvision ?? true,
    logger: options.logger ?? console,
  };

  return {
    async resolve(_npub: string, pubkey: string): Promise<AclDecision> {
      const record = await resolveAclRecord(
        registry,
        aclStore,
        pubkey,
        resolvedOptions
      );

      if (!record) {
        return denied('no_acl_record');
      }

      if (record.suspended) {
        return denied('suspended');
      }

      const role = registry.roles.find(
        (candidate) => candidate.key === record.role
      );

      if (!role) {
        resolvedOptions.logger.warn(
          `PermissionRegistry role '${record.role}' is missing for pubkey '${pubkey}'`
        );
        return denied('unknown_role');
      }

      return allowed(
        role.key,
        applyOverrides(role.permissions, record.permission_overrides)
      );
    },
  };
}

/**
 * Wrap an `AclStore` so that losing access also ends the sessions that access
 * was granted to (RFC §15 rule 2).
 *
 * Without this, `suspend()` marks the row and the suspended principal keeps
 * working until their session TTL runs out — up to 15 minutes of continued
 * access after you revoked it, which is the wrong answer for the case you
 * suspend someone in a hurry.
 *
 * Only suspension and a role change revoke. Permission-override edits do not:
 * those are picked up on the next request by guards configured with an
 * `aclResolver`, and revoking a session for a routine grant would log everyone
 * out for a permission being *added*.
 *
 * ```ts
 * const aclStore = createRevokingAclStore(
 *   new PostgresAclStore(pool),
 *   sessionStore
 * );
 * ```
 */
export function createRevokingAclStore(
  aclStore: AclStore,
  sessionStore: SessionStore,
  clock: Clock = { nowUnix: () => Math.floor(Date.now() / 1000) }
): AclStore {
  return {
    get(pubkey: string, appId: string) {
      return aclStore.get(pubkey, appId);
    },

    async upsert(record: AclRecord): Promise<void> {
      const previous = await aclStore.get(record.principal_pubkey, record.app_id);
      await aclStore.upsert(record);

      if ((previous && previous.role !== record.role) || record.suspended) {
        await sessionStore.revokeByPrincipal(record.principal_pubkey, clock.nowUnix());
      }
    },

    async suspend(pubkey: string, appId: string, reason?: string): Promise<void> {
      await aclStore.suspend(pubkey, appId, reason);
      await sessionStore.revokeByPrincipal(pubkey, clock.nowUnix());
    },

    unsuspend(pubkey: string, appId: string) {
      return aclStore.unsuspend(pubkey, appId);
    },
  };
}
