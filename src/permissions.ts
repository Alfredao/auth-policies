import type { BaseUser } from './types'

/**
 * Create permission checking utilities for a specific role-permission configuration
 */
export function createPermissionChecker<
  TUser extends BaseUser<TRole>,
  TRole extends string = string
>(rolePermissions: Record<TRole, string[]>) {
  /**
   * Check if a user has a specific permission
   */
  function hasPermission(user: TUser, permission: string): boolean {
    const permissions = rolePermissions[user.role as TRole]
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
   * Get all permissions for a user's role
   */
  function getPermissions(user: TUser): string[] {
    return rolePermissions[user.role as TRole] || []
  }

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getPermissions,
  }
}
