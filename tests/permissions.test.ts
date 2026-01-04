import { describe, it, expect } from 'vitest'
import { createPermissionChecker, resolvePermissions, CircularInheritanceError } from '../src/permissions'
import type { BaseUser, RolePermissions } from '../src/types'

// Test types
type TestRole = 'ADMIN' | 'EDITOR' | 'VIEWER'

interface TestUser extends BaseUser<TestRole> {
  id: string
  role: TestRole
  email: string
}

// Test data
const rolePermissions: Record<TestRole, string[]> = {
  ADMIN: [
    'view.user',
    'create.user',
    'update.user',
    'delete.user',
    'view.post',
    'create.post',
    'update.post',
    'delete.post',
  ],
  EDITOR: ['view.user', 'view.post', 'create.post', 'update.post'],
  VIEWER: ['view.user', 'view.post'],
}

const adminUser: TestUser = { id: '1', role: 'ADMIN', email: 'admin@test.com' }
const editorUser: TestUser = { id: '2', role: 'EDITOR', email: 'editor@test.com' }
const viewerUser: TestUser = { id: '3', role: 'VIEWER', email: 'viewer@test.com' }

describe('createPermissionChecker', () => {
  const checker = createPermissionChecker<TestUser, TestRole>(rolePermissions)

  describe('hasPermission', () => {
    it('should return true when user has the permission', () => {
      expect(checker.hasPermission(adminUser, 'delete.user')).toBe(true)
      expect(checker.hasPermission(editorUser, 'view.post')).toBe(true)
      expect(checker.hasPermission(viewerUser, 'view.user')).toBe(true)
    })

    it('should return false when user does not have the permission', () => {
      expect(checker.hasPermission(viewerUser, 'delete.user')).toBe(false)
      expect(checker.hasPermission(editorUser, 'delete.post')).toBe(false)
      expect(checker.hasPermission(viewerUser, 'create.post')).toBe(false)
    })

    it('should return false for non-existent permissions', () => {
      expect(checker.hasPermission(adminUser, 'non.existent')).toBe(false)
    })

    it('should handle all permissions for admin', () => {
      const allPermissions = [
        'view.user',
        'create.user',
        'update.user',
        'delete.user',
        'view.post',
        'create.post',
        'update.post',
        'delete.post',
      ]

      allPermissions.forEach((permission) => {
        expect(checker.hasPermission(adminUser, permission)).toBe(true)
      })
    })
  })

  describe('hasAnyPermission', () => {
    it('should return true when user has at least one permission', () => {
      expect(
        checker.hasAnyPermission(viewerUser, ['delete.user', 'view.user'])
      ).toBe(true)

      expect(
        checker.hasAnyPermission(editorUser, ['delete.post', 'create.post'])
      ).toBe(true)
    })

    it('should return false when user has none of the permissions', () => {
      expect(
        checker.hasAnyPermission(viewerUser, ['delete.user', 'create.user'])
      ).toBe(false)

      expect(
        checker.hasAnyPermission(viewerUser, ['delete.post', 'update.post'])
      ).toBe(false)
    })

    it('should return false for empty permissions array', () => {
      expect(checker.hasAnyPermission(adminUser, [])).toBe(false)
    })

    it('should return true if user has all permissions', () => {
      expect(
        checker.hasAnyPermission(adminUser, ['view.user', 'create.user'])
      ).toBe(true)
    })
  })

  describe('hasAllPermissions', () => {
    it('should return true when user has all permissions', () => {
      expect(
        checker.hasAllPermissions(adminUser, ['view.user', 'delete.user'])
      ).toBe(true)

      expect(
        checker.hasAllPermissions(editorUser, ['view.post', 'create.post'])
      ).toBe(true)
    })

    it('should return false when user is missing at least one permission', () => {
      expect(
        checker.hasAllPermissions(viewerUser, ['view.user', 'delete.user'])
      ).toBe(false)

      expect(
        checker.hasAllPermissions(editorUser, ['view.post', 'delete.post'])
      ).toBe(false)
    })

    it('should return true for empty permissions array', () => {
      expect(checker.hasAllPermissions(viewerUser, [])).toBe(true)
    })

    it('should return false when user has only some permissions', () => {
      expect(
        checker.hasAllPermissions(editorUser, [
          'view.post',
          'create.post',
          'delete.post',
        ])
      ).toBe(false)
    })
  })

  describe('getPermissions', () => {
    it('should return all permissions for a role', () => {
      const adminPermissions = checker.getPermissions(adminUser)

      expect(adminPermissions).toContain('view.user')
      expect(adminPermissions).toContain('delete.user')
      expect(adminPermissions).toHaveLength(8)
    })

    it('should return correct permissions for each role', () => {
      expect(checker.getPermissions(adminUser)).toHaveLength(8)
      expect(checker.getPermissions(editorUser)).toHaveLength(4)
      expect(checker.getPermissions(viewerUser)).toHaveLength(2)
    })

    it('should return empty array for unknown role', () => {
      const unknownUser = { id: '4', role: 'UNKNOWN' as TestRole, email: 'test@test.com' }
      expect(checker.getPermissions(unknownUser)).toEqual([])
    })
  })
})

describe('createPermissionChecker with empty config', () => {
  const emptyChecker = createPermissionChecker<TestUser, TestRole>({} as Record<TestRole, string[]>)

  it('should return false for hasPermission with no roles configured', () => {
    expect(emptyChecker.hasPermission(adminUser, 'view.user')).toBe(false)
  })

  it('should return empty array for getPermissions with no roles configured', () => {
    expect(emptyChecker.getPermissions(adminUser)).toEqual([])
  })
})

// ============================================
// Permission Inheritance Tests
// ============================================

describe('resolvePermissions', () => {
  it('should resolve flat permissions unchanged', () => {
    const permissions: RolePermissions<'ADMIN' | 'USER'> = {
      ADMIN: ['view.user', 'delete.user'],
      USER: ['view.user'],
    }

    const resolved = resolvePermissions(permissions)

    expect(resolved.ADMIN).toEqual(['view.user', 'delete.user'])
    expect(resolved.USER).toEqual(['view.user'])
  })

  it('should resolve single inheritance', () => {
    const permissions: RolePermissions<'VIEWER' | 'EDITOR'> = {
      VIEWER: ['view.user', 'view.post'],
      EDITOR: {
        inherits: 'VIEWER',
        permissions: ['create.post', 'update.post'],
      },
    }

    const resolved = resolvePermissions(permissions)

    expect(resolved.VIEWER).toEqual(['view.user', 'view.post'])
    expect(resolved.EDITOR).toContain('view.user')
    expect(resolved.EDITOR).toContain('view.post')
    expect(resolved.EDITOR).toContain('create.post')
    expect(resolved.EDITOR).toContain('update.post')
    expect(resolved.EDITOR).toHaveLength(4)
  })

  it('should resolve multi-level inheritance', () => {
    const permissions: RolePermissions<'VIEWER' | 'EDITOR' | 'ADMIN'> = {
      VIEWER: ['view.user'],
      EDITOR: {
        inherits: 'VIEWER',
        permissions: ['create.post'],
      },
      ADMIN: {
        inherits: 'EDITOR',
        permissions: ['delete.user'],
      },
    }

    const resolved = resolvePermissions(permissions)

    expect(resolved.VIEWER).toEqual(['view.user'])
    expect(resolved.EDITOR).toEqual(expect.arrayContaining(['view.user', 'create.post']))
    expect(resolved.ADMIN).toEqual(expect.arrayContaining(['view.user', 'create.post', 'delete.user']))
    expect(resolved.ADMIN).toHaveLength(3)
  })

  it('should resolve multiple inheritance (diamond pattern)', () => {
    const permissions: RolePermissions<'BASE' | 'BILLING' | 'SUPPORT' | 'MANAGER'> = {
      BASE: ['view.dashboard'],
      BILLING: {
        inherits: 'BASE',
        permissions: ['view.invoice', 'create.invoice'],
      },
      SUPPORT: {
        inherits: 'BASE',
        permissions: ['view.ticket', 'update.ticket'],
      },
      MANAGER: {
        inherits: ['BILLING', 'SUPPORT'],
        permissions: ['delete.user'],
      },
    }

    const resolved = resolvePermissions(permissions)

    expect(resolved.BASE).toEqual(['view.dashboard'])
    expect(resolved.BILLING).toHaveLength(3)
    expect(resolved.SUPPORT).toHaveLength(3)
    // Manager should have all permissions from both BILLING and SUPPORT
    expect(resolved.MANAGER).toContain('view.dashboard')
    expect(resolved.MANAGER).toContain('view.invoice')
    expect(resolved.MANAGER).toContain('create.invoice')
    expect(resolved.MANAGER).toContain('view.ticket')
    expect(resolved.MANAGER).toContain('update.ticket')
    expect(resolved.MANAGER).toContain('delete.user')
    expect(resolved.MANAGER).toHaveLength(6)
  })

  it('should deduplicate permissions', () => {
    const permissions: RolePermissions<'A' | 'B' | 'C'> = {
      A: ['view.user'],
      B: ['view.user', 'create.user'],
      C: {
        inherits: ['A', 'B'],
        permissions: ['view.user', 'delete.user'], // view.user is duplicated
      },
    }

    const resolved = resolvePermissions(permissions)

    expect(resolved.C).toContain('view.user')
    expect(resolved.C).toContain('create.user')
    expect(resolved.C).toContain('delete.user')
    expect(resolved.C).toHaveLength(3) // No duplicates
  })

  it('should throw CircularInheritanceError for direct cycle', () => {
    const permissions = {
      A: { inherits: 'B', permissions: ['a'] },
      B: { inherits: 'A', permissions: ['b'] },
    } as RolePermissions<'A' | 'B'>

    expect(() => resolvePermissions(permissions)).toThrow(CircularInheritanceError)
  })

  it('should throw CircularInheritanceError for indirect cycle', () => {
    const permissions = {
      A: { inherits: 'B', permissions: ['a'] },
      B: { inherits: 'C', permissions: ['b'] },
      C: { inherits: 'A', permissions: ['c'] },
    } as RolePermissions<'A' | 'B' | 'C'>

    expect(() => resolvePermissions(permissions)).toThrow(CircularInheritanceError)
  })

  it('should throw CircularInheritanceError for self-reference', () => {
    const permissions = {
      A: { inherits: 'A', permissions: ['a'] },
    } as RolePermissions<'A'>

    expect(() => resolvePermissions(permissions)).toThrow(CircularInheritanceError)
  })

  it('should include cycle path in error', () => {
    const permissions = {
      A: { inherits: 'B', permissions: ['a'] },
      B: { inherits: 'C', permissions: ['b'] },
      C: { inherits: 'A', permissions: ['c'] },
    } as RolePermissions<'A' | 'B' | 'C'>

    try {
      resolvePermissions(permissions)
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(CircularInheritanceError)
      expect((error as CircularInheritanceError).cycle).toContain('A')
    }
  })
})

describe('createPermissionChecker with inheritance', () => {
  type HierarchicalRole = 'VIEWER' | 'EDITOR' | 'ADMIN' | 'SUPER_ADMIN'

  interface HierarchicalUser extends BaseUser<HierarchicalRole> {
    id: string
    role: HierarchicalRole
  }

  const hierarchicalPermissions: RolePermissions<HierarchicalRole> = {
    VIEWER: ['view.user', 'view.post'],
    EDITOR: {
      inherits: 'VIEWER',
      permissions: ['create.post', 'update.post'],
    },
    ADMIN: {
      inherits: 'EDITOR',
      permissions: ['delete.post', 'create.user', 'update.user'],
    },
    SUPER_ADMIN: {
      inherits: 'ADMIN',
      permissions: ['delete.user', 'manage.system'],
    },
  }

  const checker = createPermissionChecker<HierarchicalUser, HierarchicalRole>(hierarchicalPermissions)

  const viewer: HierarchicalUser = { id: '1', role: 'VIEWER' }
  const editor: HierarchicalUser = { id: '2', role: 'EDITOR' }
  const admin: HierarchicalUser = { id: '3', role: 'ADMIN' }
  const superAdmin: HierarchicalUser = { id: '4', role: 'SUPER_ADMIN' }

  describe('hasPermission with inheritance', () => {
    it('should check own permissions', () => {
      expect(checker.hasPermission(viewer, 'view.user')).toBe(true)
      expect(checker.hasPermission(viewer, 'view.post')).toBe(true)
    })

    it('should check inherited permissions', () => {
      // Editor inherits from Viewer
      expect(checker.hasPermission(editor, 'view.user')).toBe(true)
      expect(checker.hasPermission(editor, 'view.post')).toBe(true)
      expect(checker.hasPermission(editor, 'create.post')).toBe(true)

      // Admin inherits from Editor (and transitively from Viewer)
      expect(checker.hasPermission(admin, 'view.user')).toBe(true)
      expect(checker.hasPermission(admin, 'create.post')).toBe(true)
      expect(checker.hasPermission(admin, 'delete.post')).toBe(true)
    })

    it('should check multi-level inherited permissions', () => {
      // Super Admin inherits everything
      expect(checker.hasPermission(superAdmin, 'view.user')).toBe(true)
      expect(checker.hasPermission(superAdmin, 'create.post')).toBe(true)
      expect(checker.hasPermission(superAdmin, 'delete.post')).toBe(true)
      expect(checker.hasPermission(superAdmin, 'delete.user')).toBe(true)
      expect(checker.hasPermission(superAdmin, 'manage.system')).toBe(true)
    })

    it('should deny permissions not in hierarchy', () => {
      expect(checker.hasPermission(viewer, 'delete.user')).toBe(false)
      expect(checker.hasPermission(editor, 'delete.user')).toBe(false)
      expect(checker.hasPermission(admin, 'delete.user')).toBe(false)
      expect(checker.hasPermission(admin, 'manage.system')).toBe(false)
    })
  })

  describe('getPermissions with inheritance', () => {
    it('should return all permissions including inherited', () => {
      expect(checker.getPermissions(viewer)).toHaveLength(2)
      expect(checker.getPermissions(editor)).toHaveLength(4)
      expect(checker.getPermissions(admin)).toHaveLength(7)
      expect(checker.getPermissions(superAdmin)).toHaveLength(9)
    })
  })

  describe('getResolvedPermissions', () => {
    it('should return the resolved permissions map', () => {
      const resolved = checker.getResolvedPermissions()

      expect(resolved.VIEWER).toHaveLength(2)
      expect(resolved.EDITOR).toHaveLength(4)
      expect(resolved.ADMIN).toHaveLength(7)
      expect(resolved.SUPER_ADMIN).toHaveLength(9)
    })
  })
})

describe('createAuth with inherited permissions', () => {
  // This test verifies that createAuth works correctly with inherited permissions
  // The actual test is in create-auth.test.ts, but we verify the integration here
  it('should work with createPermissionChecker in createAuth context', () => {
    type Role = 'USER' | 'ADMIN'

    const rolePermissions: RolePermissions<Role> = {
      USER: ['view.resource'],
      ADMIN: {
        inherits: 'USER',
        permissions: ['delete.resource'],
      },
    }

    const checker = createPermissionChecker<BaseUser<Role>, Role>(rolePermissions)
    const adminUser: BaseUser<Role> = { id: '1', role: 'ADMIN' }

    // Admin should have both inherited and own permissions
    expect(checker.hasPermission(adminUser, 'view.resource')).toBe(true)
    expect(checker.hasPermission(adminUser, 'delete.resource')).toBe(true)
  })
})

// ============================================
// Multiple Roles Tests
// ============================================

describe('createPermissionChecker with multiple roles', () => {
  type Role = 'VIEWER' | 'EDITOR' | 'BILLING' | 'SUPPORT'

  const rolePermissions: RolePermissions<Role> = {
    VIEWER: ['view.dashboard', 'view.profile'],
    EDITOR: ['view.dashboard', 'create.post', 'update.post'],
    BILLING: ['view.invoice', 'create.invoice', 'manage.subscription'],
    SUPPORT: ['view.ticket', 'update.ticket', 'close.ticket'],
  }

  const checker = createPermissionChecker<BaseUser<Role>, Role>(rolePermissions)

  describe('users with roles[] array', () => {
    it('should get permissions from multiple roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['VIEWER', 'BILLING'],
      }

      expect(checker.hasPermission(user, 'view.dashboard')).toBe(true)
      expect(checker.hasPermission(user, 'view.invoice')).toBe(true)
      expect(checker.hasPermission(user, 'create.invoice')).toBe(true)
      expect(checker.hasPermission(user, 'create.post')).toBe(false) // EDITOR only
    })

    it('should merge permissions from all roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['EDITOR', 'SUPPORT'],
      }

      const permissions = checker.getPermissions(user)

      expect(permissions).toContain('view.dashboard')
      expect(permissions).toContain('create.post')
      expect(permissions).toContain('update.post')
      expect(permissions).toContain('view.ticket')
      expect(permissions).toContain('update.ticket')
      expect(permissions).toContain('close.ticket')
      expect(permissions).toHaveLength(6)
    })

    it('should deduplicate permissions across roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['VIEWER', 'EDITOR'], // Both have view.dashboard
      }

      const permissions = checker.getPermissions(user)
      const dashboardCount = permissions.filter(p => p === 'view.dashboard').length

      expect(dashboardCount).toBe(1) // Should only appear once
    })

    it('should return all roles for a user', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['VIEWER', 'BILLING', 'SUPPORT'],
      }

      const roles = checker.getRoles(user)

      expect(roles).toContain('VIEWER')
      expect(roles).toContain('BILLING')
      expect(roles).toContain('SUPPORT')
      expect(roles).toHaveLength(3)
    })

    it('should handle empty roles array', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: [],
      }

      expect(checker.hasPermission(user, 'view.dashboard')).toBe(false)
      expect(checker.getPermissions(user)).toEqual([])
      expect(checker.getRoles(user)).toEqual([])
    })
  })

  describe('users with both role and roles', () => {
    it('should combine single role with roles array', () => {
      const user: BaseUser<Role> = {
        id: '1',
        role: 'VIEWER',
        roles: ['BILLING'],
      }

      expect(checker.hasPermission(user, 'view.dashboard')).toBe(true) // from role
      expect(checker.hasPermission(user, 'view.invoice')).toBe(true) // from roles
      expect(checker.hasPermission(user, 'create.post')).toBe(false) // neither
    })

    it('should deduplicate when same role in both role and roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        role: 'VIEWER',
        roles: ['VIEWER', 'BILLING'],
      }

      const roles = checker.getRoles(user)

      expect(roles.filter(r => r === 'VIEWER')).toHaveLength(1) // No duplicates
      expect(roles).toHaveLength(2) // VIEWER + BILLING
    })

    it('should get permissions from combined roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        role: 'EDITOR',
        roles: ['SUPPORT'],
      }

      const permissions = checker.getPermissions(user)

      expect(permissions).toContain('view.dashboard') // EDITOR
      expect(permissions).toContain('create.post') // EDITOR
      expect(permissions).toContain('view.ticket') // SUPPORT
      expect(permissions).toContain('close.ticket') // SUPPORT
    })
  })

  describe('hasAnyPermission with multiple roles', () => {
    it('should return true if any permission matches across roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['VIEWER', 'BILLING'],
      }

      expect(checker.hasAnyPermission(user, ['create.post', 'view.invoice'])).toBe(true)
      expect(checker.hasAnyPermission(user, ['create.post', 'close.ticket'])).toBe(false)
    })
  })

  describe('hasAllPermissions with multiple roles', () => {
    it('should return true if user has all permissions across roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
        roles: ['VIEWER', 'BILLING'],
      }

      expect(checker.hasAllPermissions(user, ['view.dashboard', 'view.invoice'])).toBe(true)
      expect(checker.hasAllPermissions(user, ['view.dashboard', 'create.post'])).toBe(false)
    })
  })

  describe('backwards compatibility', () => {
    it('should still work with single role only', () => {
      const user: BaseUser<Role> = {
        id: '1',
        role: 'EDITOR',
      }

      expect(checker.hasPermission(user, 'create.post')).toBe(true)
      expect(checker.hasPermission(user, 'view.invoice')).toBe(false)
      expect(checker.getRoles(user)).toEqual(['EDITOR'])
    })

    it('should handle user with neither role nor roles', () => {
      const user: BaseUser<Role> = {
        id: '1',
      }

      expect(checker.hasPermission(user, 'view.dashboard')).toBe(false)
      expect(checker.getPermissions(user)).toEqual([])
      expect(checker.getRoles(user)).toEqual([])
    })
  })
})

describe('createAuth with multiple roles', () => {
  it('should work with users having multiple roles', async () => {
    type Role = 'VIEWER' | 'ADMIN'

    const rolePermissions: RolePermissions<Role> = {
      VIEWER: ['view.post'],
      ADMIN: ['view.post', 'delete.post'],
    }

    const PostPolicy = {
      view: async () => true,
      delete: async (user: BaseUser<Role>) => {
        const checker = createPermissionChecker<BaseUser<Role>, Role>(rolePermissions)
        return checker.hasPermission(user, 'delete.post')
      },
    }

    const { createAuth } = await import('../src/create-auth')

    const multiRoleUser: BaseUser<Role> = {
      id: '1',
      roles: ['VIEWER', 'ADMIN'],
    }

    const auth = createAuth<BaseUser<Role>, Role, 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => multiRoleUser,
    })

    // User has delete.post permission through ADMIN role
    expect(auth.hasPermission(multiRoleUser, 'delete.post')).toBe(true)
    expect(auth.getRoles(multiRoleUser)).toEqual(['VIEWER', 'ADMIN'])
  })
})
