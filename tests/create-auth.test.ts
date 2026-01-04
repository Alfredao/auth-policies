import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createAuth } from '../src/create-auth'
import {
  UnauthorizedException,
  UnauthenticatedException,
  PolicyConfigurationException,
  AuthErrorCode,
} from '../src/exceptions'
import type { BaseUser, Policy } from '../src/types'

// Test types
type TestRole = 'ADMIN' | 'USER'
type TestResource = 'Post' | 'Comment'

interface TestUser extends BaseUser<TestRole> {
  id: string
  role: TestRole
  email: string
}

interface Post {
  id: string
  authorId: string
  title: string
}

// Test data
const adminUser: TestUser = { id: '1', role: 'ADMIN', email: 'admin@test.com' }
const regularUser: TestUser = { id: '2', role: 'USER', email: 'user@test.com' }

const rolePermissions: Record<TestRole, string[]> = {
  ADMIN: ['view.post', 'create.post', 'update.post', 'delete.post', 'view.comment', 'delete.comment'],
  USER: ['view.post', 'create.post', 'view.comment'],
}

// Test policies
const PostPolicy: Policy<TestUser> = {
  view: async (user) => true,
  viewAll: async (user) => true,
  create: async (user) => rolePermissions[user.role].includes('create.post'),
  update: async (user, resource?: unknown) => {
    const post = resource as Post | undefined
    // Users can only update their own posts
    if (user.role === 'USER' && post && post.authorId !== user.id) {
      return false
    }
    return rolePermissions[user.role].includes('update.post')
  },
  delete: async (user) => rolePermissions[user.role].includes('delete.post'),
}

const CommentPolicy: Policy<TestUser> = {
  view: async (user) => true,
  delete: async (user) => rolePermissions[user.role].includes('delete.comment'),
}

describe('createAuth', () => {
  let mockGetUser: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockGetUser = vi.fn()
  })

  const createTestAuth = (user: TestUser | null = adminUser, debug = false) => {
    mockGetUser.mockResolvedValue(user)

    return createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: {
        Post: PostPolicy,
        Comment: CommentPolicy,
      },
      getUser: mockGetUser,
      debug,
    })
  }

  describe('checkPermission', () => {
    it('should return true when user has permission via policy', async () => {
      const auth = createTestAuth(adminUser)

      const result = await auth.checkPermission('delete', 'Post')
      expect(result).toBe(true)
    })

    it('should return false when user lacks permission', async () => {
      const auth = createTestAuth(regularUser)

      const result = await auth.checkPermission('delete', 'Post')
      expect(result).toBe(false)
    })

    it('should return false when user is not authenticated', async () => {
      const auth = createTestAuth(null)

      const result = await auth.checkPermission('view', 'Post')
      expect(result).toBe(false)
    })

    it('should return false for non-existent resource type', async () => {
      const auth = createTestAuth(adminUser)

      const result = await auth.checkPermission('view', 'NonExistent' as TestResource)
      expect(result).toBe(false)
    })

    it('should return false for non-existent action', async () => {
      const auth = createTestAuth(adminUser)

      const result = await auth.checkPermission('nonexistent' as 'view', 'Post')
      expect(result).toBe(false)
    })

    it('should pass resource to policy for context-aware checks', async () => {
      const auth = createTestAuth(regularUser)
      const ownPost: Post = { id: '1', authorId: '2', title: 'My Post' }
      const otherPost: Post = { id: '2', authorId: '1', title: 'Other Post' }

      // User can't update posts (no permission), so both should be false
      expect(await auth.checkPermission('update', 'Post', { resource: ownPost })).toBe(false)
      expect(await auth.checkPermission('update', 'Post', { resource: otherPost })).toBe(false)
    })
  })

  describe('canApi', () => {
    it('should return true when authorized', async () => {
      const auth = createTestAuth(adminUser)

      const result = await auth.canApi('view', 'Post')
      expect(result).toBe(true)
    })

    it('should throw UnauthorizedException with context when not authorized', async () => {
      const auth = createTestAuth(regularUser)

      try {
        await auth.canApi('delete', 'Post')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException)
        const authError = error as UnauthorizedException
        expect(authError.code).toBe(AuthErrorCode.POLICY_DENIED)
        expect(authError.context?.action).toBe('delete')
        expect(authError.context?.resourceType).toBe('Post')
        expect(authError.context?.role).toBe('USER')
        expect(authError.context?.userId).toBe('2')
      }
    })

    it('should throw UnauthenticatedException when not authenticated', async () => {
      const auth = createTestAuth(null)

      await expect(auth.canApi('view', 'Post')).rejects.toThrow(UnauthenticatedException)
    })

    it('should throw PolicyConfigurationException for non-existent policy', async () => {
      const auth = createTestAuth(adminUser)

      try {
        await auth.canApi('view', 'NonExistent' as TestResource)
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyConfigurationException)
        const configError = error as PolicyConfigurationException
        expect(configError.code).toBe(AuthErrorCode.POLICY_NOT_FOUND)
        expect(configError.message).toContain('NonExistent')
        expect(configError.message).toContain('Available types:')
      }
    })

    it('should throw PolicyConfigurationException for non-existent action', async () => {
      const auth = createTestAuth(adminUser)

      try {
        await auth.canApi('nonexistent' as 'view', 'Post')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyConfigurationException)
        const configError = error as PolicyConfigurationException
        expect(configError.code).toBe(AuthErrorCode.ACTION_NOT_FOUND)
        expect(configError.message).toContain('nonexistent')
        expect(configError.message).toContain('Available actions:')
      }
    })

    it('should include role in error message', async () => {
      const auth = createTestAuth(regularUser)

      try {
        await auth.canApi('delete', 'Post')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException)
        expect((error as UnauthorizedException).message).toContain('USER')
      }
    })

    it('should pass resource to policy', async () => {
      const auth = createTestAuth(adminUser)
      const post: Post = { id: '1', authorId: '1', title: 'Test' }

      const result = await auth.canApi('update', 'Post', { resource: post })
      expect(result).toBe(true)
    })
  })

  describe('can', () => {
    it('should return true when authorized', async () => {
      const auth = createTestAuth(adminUser)

      const result = await auth.can('view', 'Post')
      expect(result).toBe(true)
    })

    it('should throw UnauthorizedException when not authorized (no redirect handler)', async () => {
      const auth = createTestAuth(regularUser)

      await expect(auth.can('delete', 'Post')).rejects.toThrow(UnauthorizedException)
    })

    it('should call redirect handler when provided and not authorized', async () => {
      const mockRedirect = vi.fn(() => {
        throw new Error('Redirected')
      }) as unknown as () => never

      mockGetUser.mockResolvedValue(regularUser)

      const auth = createAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy, Comment: CommentPolicy },
        getUser: mockGetUser,
        handlers: {
          onUnauthorizedRedirect: mockRedirect,
        },
      })

      await expect(auth.can('delete', 'Post')).rejects.toThrow('Redirected')
      expect(mockRedirect).toHaveBeenCalled()
    })
  })

  describe('requireUser', () => {
    it('should return user when authenticated', async () => {
      const auth = createTestAuth(adminUser)

      const user = await auth.requireUser()
      expect(user).toEqual(adminUser)
    })

    it('should throw UnauthenticatedException when not authenticated', async () => {
      const auth = createTestAuth(null)

      await expect(auth.requireUser()).rejects.toThrow(UnauthenticatedException)
    })
  })

  describe('getUser', () => {
    it('should return user when authenticated', async () => {
      const auth = createTestAuth(adminUser)

      const user = await auth.getUser()
      expect(user).toEqual(adminUser)
    })

    it('should return null when not authenticated', async () => {
      const auth = createTestAuth(null)

      const user = await auth.getUser()
      expect(user).toBeNull()
    })
  })

  describe('permission utilities', () => {
    it('hasPermission should check role permissions', () => {
      const auth = createTestAuth()

      expect(auth.hasPermission(adminUser, 'delete.post')).toBe(true)
      expect(auth.hasPermission(regularUser, 'delete.post')).toBe(false)
    })

    it('hasAnyPermission should check multiple permissions', () => {
      const auth = createTestAuth()

      expect(auth.hasAnyPermission(regularUser, ['delete.post', 'view.post'])).toBe(true)
      expect(auth.hasAnyPermission(regularUser, ['delete.post', 'update.post'])).toBe(false)
    })

    it('hasAllPermissions should require all permissions', () => {
      const auth = createTestAuth()

      expect(auth.hasAllPermissions(adminUser, ['view.post', 'delete.post'])).toBe(true)
      expect(auth.hasAllPermissions(regularUser, ['view.post', 'delete.post'])).toBe(false)
    })

    it('getPermissions should return all user permissions', () => {
      const auth = createTestAuth()

      const adminPerms = auth.getPermissions(adminUser)
      expect(adminPerms).toContain('delete.post')
      expect(adminPerms).toHaveLength(6)

      const userPerms = auth.getPermissions(regularUser)
      expect(userPerms).not.toContain('delete.post')
      expect(userPerms).toHaveLength(3)
    })
  })

  describe('config access', () => {
    it('should expose rolePermissions in config', () => {
      const auth = createTestAuth()

      expect(auth.config.rolePermissions).toEqual(rolePermissions)
    })

    it('should expose policies in config', () => {
      const auth = createTestAuth()

      expect(auth.config.policies.Post).toBeDefined()
      expect(auth.config.policies.Comment).toBeDefined()
    })

    it('should expose debug setting in config', () => {
      const authNoDebug = createTestAuth(adminUser, false)
      const authWithDebug = createTestAuth(adminUser, true)

      expect(authNoDebug.config.debug).toBe(false)
      expect(authWithDebug.config.debug).toBe(true)
    })
  })

  describe('custom handlers', () => {
    it('should use custom throw handler for canApi', async () => {
      const customError = new Error('Custom error')
      const mockThrowHandler = vi.fn(() => {
        throw customError
      }) as unknown as () => never

      mockGetUser.mockResolvedValue(regularUser)

      const auth = createAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy, Comment: CommentPolicy },
        getUser: mockGetUser,
        handlers: {
          onUnauthorizedThrow: mockThrowHandler,
        },
      })

      await expect(auth.canApi('delete', 'Post')).rejects.toThrow('Custom error')
      expect(mockThrowHandler).toHaveBeenCalled()
    })
  })

  describe('debug mode', () => {
    it('should log when debug is enabled', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const auth = createTestAuth(adminUser, true)

      await auth.checkPermission('view', 'Post')

      expect(consoleSpy).toHaveBeenCalled()
      expect(consoleSpy.mock.calls.some((call) => call[0].includes('[auth-policies]'))).toBe(true)

      consoleSpy.mockRestore()
    })

    it('should not log when debug is disabled', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const auth = createTestAuth(adminUser, false)

      await auth.checkPermission('view', 'Post')

      const authPoliciesLogs = consoleSpy.mock.calls.filter((call) =>
        call[0]?.includes?.('[auth-policies]')
      )
      expect(authPoliciesLogs).toHaveLength(0)

      consoleSpy.mockRestore()
    })
  })
})

describe('createAuth with async policies', () => {
  it('should handle async policy methods correctly', async () => {
    const mockGetUser = vi.fn().mockResolvedValue({ id: '1', role: 'ADMIN' })

    const asyncPolicy: Policy<BaseUser<'ADMIN'>> = {
      view: async () => {
        // Simulate async operation
        await new Promise((resolve) => setTimeout(resolve, 10))
        return true
      },
    }

    const auth = createAuth({
      rolePermissions: { ADMIN: ['view.item'] },
      policies: { Item: asyncPolicy },
      getUser: mockGetUser,
    })

    const result = await auth.checkPermission('view', 'Item')
    expect(result).toBe(true)
  })
})

describe('error message formatting', () => {
  it('should include action and resource type in unauthorized message', async () => {
    const mockGetUser = vi.fn().mockResolvedValue({ id: '1', role: 'VIEWER' })

    const policy: Policy<BaseUser<'VIEWER'>> = {
      delete: async () => false,
    }

    const auth = createAuth({
      rolePermissions: { VIEWER: [] },
      policies: { Document: policy },
      getUser: mockGetUser,
    })

    try {
      await auth.canApi('delete', 'Document')
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(UnauthorizedException)
      const authError = error as UnauthorizedException
      expect(authError.message).toContain('delete')
      expect(authError.message).toContain('Document')
      expect(authError.message).toContain('VIEWER')
    }
  })
})
