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
