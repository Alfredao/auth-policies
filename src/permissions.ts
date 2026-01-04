import type { BaseUser, RoleDefinition, RolePermissions, TenantUser } from './types'

/**
 * Error thrown when circular inheritance is detected
 */
export class CircularInheritanceError extends Error {
  constructor(public readonly cycle: string[]) {
    super(`Circular role inheritance detected: ${cycle.join(' -> ')}`)
    this.name = 'CircularInheritanceError'
  }
}

/**
 * Check if a role definition uses inheritance
 */
function isInheritedRole<TRole extends string>(
  definition: RoleDefinition<TRole>
): definition is { inherits: TRole | TRole[]; permissions: string[] } {
  return (
    typeof definition === 'object' &&
    !Array.isArray(definition) &&
    'inherits' in definition
  )
}

/**
 * Resolve all permissions for a role, including inherited permissions
 *
 * @throws {CircularInheritanceError} If circular inheritance is detected
 */
function resolveRolePermissions<TRole extends string>(
  role: TRole,
  rolePermissions: RolePermissions<TRole>,
  visited: Set<TRole> = new Set(),
  path: TRole[] = []
): string[] {
  // Check for circular inheritance
  if (visited.has(role)) {
    throw new CircularInheritanceError([...path, role])
  }

  const definition = rolePermissions[role]
  if (!definition) {
    return []
  }

  // Simple array - no inheritance
  if (Array.isArray(definition)) {
    return [...definition]
  }

  // Has inheritance
  if (isInheritedRole(definition)) {
    visited.add(role)
    path.push(role)

    const inheritedRoles = Array.isArray(definition.inherits)
      ? definition.inherits
      : [definition.inherits]

    const inheritedPermissions = new Set<string>()

    // Collect permissions from all inherited roles
    for (const inheritedRole of inheritedRoles) {
      const permissions = resolveRolePermissions(
        inheritedRole,
        rolePermissions,
        new Set(visited),
        [...path]
      )
      for (const permission of permissions) {
        inheritedPermissions.add(permission)
      }
    }

    // Add own permissions
    for (const permission of definition.permissions) {
      inheritedPermissions.add(permission)
    }

    return [...inheritedPermissions]
  }

  return []
}

/**
 * Resolve all role permissions, flattening inheritance hierarchies
 *
 * @example
 * ```typescript
 * const rolePermissions = {
 *   VIEWER: ['view.user'],
 *   ADMIN: { inherits: 'VIEWER', permissions: ['delete.user'] },
 * }
 *
 * const resolved = resolvePermissions(rolePermissions)
 * // { VIEWER: ['view.user'], ADMIN: ['view.user', 'delete.user'] }
 * ```
 *
 * @throws {CircularInheritanceError} If circular inheritance is detected
 */
export function resolvePermissions<TRole extends string>(
  rolePermissions: RolePermissions<TRole>
): Record<TRole, string[]> {
  const resolved = {} as Record<TRole, string[]>

  for (const role of Object.keys(rolePermissions) as TRole[]) {
    resolved[role] = resolveRolePermissions(role, rolePermissions)
  }

  return resolved
}

/**
 * Create permission checking utilities for a specific role-permission configuration
 *
 * Supports both flat permission arrays and hierarchical inheritance:
 *
 * @example
 * ```typescript
 * // Flat permissions
 * const checker = createPermissionChecker({
 *   ADMIN: ['view.user', 'delete.user'],
 *   USER: ['view.user'],
 * })
 *
 * // With inheritance
 * const checker = createPermissionChecker({
 *   VIEWER: ['view.user', 'view.post'],
 *   EDITOR: { inherits: 'VIEWER', permissions: ['create.post', 'update.post'] },
 *   ADMIN: { inherits: 'EDITOR', permissions: ['delete.post', 'delete.user'] },
 * })
 * ```
 *
 * @throws {CircularInheritanceError} If circular inheritance is detected
 */
export function createPermissionChecker<
  TUser extends BaseUser<TRole>,
  TRole extends string = string
>(rolePermissions: RolePermissions<TRole>) {
  // Resolve all permissions upfront (also validates for circular dependencies)
  const resolvedPermissions = resolvePermissions(rolePermissions)

  /**
   * Get all roles for a user (combines role + roles)
   * Supports backwards compatibility with single role
   */
  function getUserRoles(user: TUser): TRole[] {
    const roles: TRole[] = []

    // Add single role if present
    if (user.role) {
      roles.push(user.role as TRole)
    }

    // Add multiple roles if present
    if (user.roles && Array.isArray(user.roles)) {
      for (const role of user.roles) {
        if (!roles.includes(role as TRole)) {
          roles.push(role as TRole)
        }
      }
    }

    return roles
  }

  /**
   * Get all permissions for a user (from all their roles)
   * Merges and deduplicates permissions from all roles
   */
  function getPermissions(user: TUser): string[] {
    const roles = getUserRoles(user)
    const permissionSet = new Set<string>()

    for (const role of roles) {
      const rolePerms = resolvedPermissions[role]
      if (rolePerms) {
        for (const perm of rolePerms) {
          permissionSet.add(perm)
        }
      }
    }

    return [...permissionSet]
  }

  /**
   * Check if a user has a specific permission
   * Checks against all of the user's roles
   */
  function hasPermission(user: TUser, permission: string): boolean {
    const roles = getUserRoles(user)

    for (const role of roles) {
      const permissions = resolvedPermissions[role]
      if (permissions?.includes(permission)) {
        return true
      }
    }

    return false
  }

  /**
   * Check if a user has any of the specified permissions
   */
  function hasAnyPermission(user: TUser, permissions: string[]): boolean {
    return permissions.some((permission) => hasPermission(user, permission))
  }

  /**
   * Check if a user has all of the specified permissions
   */
  function hasAllPermissions(user: TUser, permissions: string[]): boolean {
    return permissions.every((permission) => hasPermission(user, permission))
  }

  /**
   * Get all roles for a user
   */
  function getRoles(user: TUser): TRole[] {
    return getUserRoles(user)
  }

  /**
   * Get the resolved permissions map (for debugging/testing)
   */
  function getResolvedPermissions(): Record<TRole, string[]> {
    return { ...resolvedPermissions }
  }

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getPermissions,
    getRoles,
    getResolvedPermissions,
  }
}

/**
 * Get tenant-specific roles for a user in a specific tenant
 *
 * @example
 * ```typescript
 * const user = {
 *   id: '1',
 *   role: 'USER',
 *   tenantRoles: { 'business-1': 'OWNER', 'business-2': ['ADMIN', 'BILLING'] }
 * }
 *
 * getTenantRoles(user, 'business-1') // ['OWNER']
 * getTenantRoles(user, 'business-2') // ['ADMIN', 'BILLING']
 * getTenantRoles(user, 'business-3') // []
 * ```
 */
export function getTenantRoles<TTenantRole extends string>(
  user: TenantUser<string, TTenantRole, string>,
  tenantId: string
): TTenantRole[] {
  if (!user.tenantRoles || !tenantId) {
    return []
  }

  const tenantRole = user.tenantRoles[tenantId]
  if (!tenantRole) {
    return []
  }

  if (Array.isArray(tenantRole)) {
    return tenantRole
  }

  return [tenantRole]
}

/**
 * Create a tenant-aware permission checker that combines system and tenant permissions
 *
 * @example
 * ```typescript
 * const checker = createTenantPermissionChecker({
 *   systemRolePermissions: {
 *     SUPER_ADMIN: ['*'],
 *     USER: ['view.profile'],
 *   },
 *   tenantRolePermissions: {
 *     OWNER: ['manage.business', 'view.reports', 'manage.staff'],
 *     ADMIN: ['view.reports', 'manage.staff'],
 *     MEMBER: ['view.reports'],
 *   },
 * })
 *
 * // User with system role 'USER' and tenant role 'OWNER' in 'business-1'
 * const user = {
 *   id: '1',
 *   role: 'USER',
 *   tenantRoles: { 'business-1': 'OWNER' },
 * }
 *
 * // Combined permissions in tenant context
 * checker.getPermissions(user, 'business-1')
 * // ['view.profile', 'manage.business', 'view.reports', 'manage.staff']
 *
 * // Only system permissions without tenant context
 * checker.getPermissions(user, null)
 * // ['view.profile']
 * ```
 */
export function createTenantPermissionChecker<
  TSystemRole extends string = string,
  TTenantRole extends string = string
>(config: {
  systemRolePermissions: RolePermissions<TSystemRole>
  tenantRolePermissions: RolePermissions<TTenantRole>
}) {
  const { systemRolePermissions, tenantRolePermissions } = config

  // Resolve permissions upfront
  const resolvedSystemPermissions = resolvePermissions(systemRolePermissions)
  const resolvedTenantPermissions = resolvePermissions(tenantRolePermissions)

  /**
   * Get system-level roles for a user
   */
  function getSystemRoles<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser
  ): TSystemRole[] {
    const roles: TSystemRole[] = []

    if (user.role) {
      roles.push(user.role as TSystemRole)
    }

    if (user.roles && Array.isArray(user.roles)) {
      for (const role of user.roles) {
        if (!roles.includes(role as TSystemRole)) {
          roles.push(role as TSystemRole)
        }
      }
    }

    return roles
  }

  /**
   * Get system-level permissions for a user
   */
  function getSystemPermissions<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser
  ): string[] {
    const roles = getSystemRoles(user)
    const permissions = new Set<string>()

    for (const role of roles) {
      const rolePerms = resolvedSystemPermissions[role]
      if (rolePerms) {
        for (const perm of rolePerms) {
          permissions.add(perm)
        }
      }
    }

    return [...permissions]
  }

  /**
   * Get tenant-level permissions for a user in a specific tenant
   */
  function getTenantPermissions<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    tenantId: string | null
  ): string[] {
    if (!tenantId) {
      return []
    }

    const roles = getTenantRoles<TTenantRole>(user, tenantId)
    const permissions = new Set<string>()

    for (const role of roles) {
      const rolePerms = resolvedTenantPermissions[role]
      if (rolePerms) {
        for (const perm of rolePerms) {
          permissions.add(perm)
        }
      }
    }

    return [...permissions]
  }

  /**
   * Get all permissions for a user (system + tenant)
   * If tenantId is null, only system permissions are returned
   */
  function getPermissions<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    tenantId: string | null
  ): string[] {
    const systemPerms = getSystemPermissions(user)
    const tenantPerms = getTenantPermissions(user, tenantId)

    // Merge and deduplicate
    const allPerms = new Set<string>([...systemPerms, ...tenantPerms])
    return [...allPerms]
  }

  /**
   * Check if a user has a specific permission (system or tenant level)
   */
  function hasPermission<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    permission: string,
    tenantId: string | null
  ): boolean {
    // Check system permissions first
    const systemRoles = getSystemRoles(user)
    for (const role of systemRoles) {
      const permissions = resolvedSystemPermissions[role]
      if (permissions?.includes(permission)) {
        return true
      }
    }

    // Check tenant permissions if tenant context provided
    if (tenantId) {
      const tenantRoles = getTenantRoles<TTenantRole>(user, tenantId)
      for (const role of tenantRoles) {
        const permissions = resolvedTenantPermissions[role]
        if (permissions?.includes(permission)) {
          return true
        }
      }
    }

    return false
  }

  /**
   * Check if a user has any of the specified permissions
   */
  function hasAnyPermission<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    permissions: string[],
    tenantId: string | null
  ): boolean {
    return permissions.some((permission) => hasPermission(user, permission, tenantId))
  }

  /**
   * Check if a user has all of the specified permissions
   */
  function hasAllPermissions<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    permissions: string[],
    tenantId: string | null
  ): boolean {
    return permissions.every((permission) => hasPermission(user, permission, tenantId))
  }

  /**
   * Get all roles for a user (system + tenant)
   */
  function getRoles<TUser extends TenantUser<TSystemRole, TTenantRole>>(
    user: TUser,
    tenantId: string | null
  ): { system: TSystemRole[]; tenant: TTenantRole[] } {
    return {
      system: getSystemRoles(user),
      tenant: tenantId ? getTenantRoles<TTenantRole>(user, tenantId) : [],
    }
  }

  return {
    getSystemRoles,
    getSystemPermissions,
    getTenantRoles: <TUser extends TenantUser<TSystemRole, TTenantRole>>(
      user: TUser,
      tenantId: string
    ) => getTenantRoles<TTenantRole>(user, tenantId),
    getTenantPermissions,
    getPermissions,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getRoles,
    getResolvedSystemPermissions: () => ({ ...resolvedSystemPermissions }),
    getResolvedTenantPermissions: () => ({ ...resolvedTenantPermissions }),
  }
}
