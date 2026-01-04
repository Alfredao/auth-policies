import { describe, it, expect } from 'vitest'
import { createPermissionChecker } from '../src/permissions'
import type { BaseUser } from '../src/types'

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
