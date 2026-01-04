import type { BaseUser, RoleDefinition, RolePermissions } from './types'

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
   * Check if a user has a specific permission
   */
  function hasPermission(user: TUser, permission: string): boolean {
    const permissions = resolvedPermissions[user.role as TRole]
    if (!permissions) return false
    return permissions.includes(permission)
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
   * Get all permissions for a user's role (including inherited)
   */
  function getPermissions(user: TUser): string[] {
    return resolvedPermissions[user.role as TRole] || []
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
    getResolvedPermissions,
  }
}
