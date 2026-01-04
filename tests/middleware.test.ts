import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  createAuthMiddleware,
  createPermissionMiddleware,
  createExpressAuth,
} from '../src/middleware'
import type { BaseUser, Policy } from '../src/types'

// Test types
type TestRole = 'ADMIN' | 'USER'
type TestResource = 'Post'

interface TestUser extends BaseUser<TestRole> {
  id: string
  role: TestRole
}

// Test data
const adminUser: TestUser = { id: '1', role: 'ADMIN' }
const regularUser: TestUser = { id: '2', role: 'USER' }

const rolePermissions: Record<TestRole, string[]> = {
  ADMIN: ['delete.post'],
  USER: ['view.post'],
}

const PostPolicy: Policy<TestUser> = {
  view: () => true,
  delete: (user) => user.role === 'ADMIN',
}

describe('createAuthMiddleware', () => {
  describe('withAuth wrapper', () => {
    it('should allow authorized requests', async () => {
      const withAuth = createAuthMiddleware<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: async () => adminUser,
      })

      const handler = vi.fn().mockResolvedValue(Response.json({ success: true }))
      const wrapped = withAuth(handler, { action: 'delete', type: 'Post' })

      const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
      const response = await wrapped(request, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).toBe(200)
    })

    it('should return 401 when not authenticated', async () => {
      const withAuth = createAuthMiddleware<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: async () => null,
      })

      const handler = vi.fn()
      const wrapped = withAuth(handler, { action: 'delete', type: 'Post' })

      const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
      const response = await wrapped(request, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(401)

      const body = await response.json()
      expect(body.error).toBe('UnauthenticatedException')
      expect(body.code).toBe('UNAUTHENTICATED')
    })

    it('should return 403 when not authorized', async () => {
      const withAuth = createAuthMiddleware<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: async () => regularUser,
      })

      const handler = vi.fn()
      const wrapped = withAuth(handler, { action: 'delete', type: 'Post' })

      const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
      const response = await wrapped(request, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(403)

      const body = await response.json()
      expect(body.error).toBe('UnauthorizedException')
      expect(body.code).toBe('POLICY_DENIED')
    })

    it('should pass resource to policy when getResource provided', async () => {
      const policySpy = vi.fn().mockReturnValue(true)
      const policies = {
        Post: {
          delete: policySpy,
        },
      }

      const withAuth = createAuthMiddleware<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies,
        getUser: async () => adminUser,
      })

      const mockResource = { id: '123', title: 'Test Post' }
      const handler = vi.fn().mockResolvedValue(Response.json({ success: true }))
      const wrapped = withAuth(handler, {
        action: 'delete',
        type: 'Post',
        getResource: async () => mockResource,
      })

      const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
      await wrapped(request, {})

      expect(policySpy).toHaveBeenCalledWith(adminUser, mockResource)
    })
  })
})

describe('createPermissionMiddleware', () => {
  it('should allow when user has permission', async () => {
    const requirePermission = createPermissionMiddleware<TestUser, TestRole>({
      rolePermissions,
      getUser: async () => adminUser,
    })

    const handler = vi.fn().mockResolvedValue(Response.json({ success: true }))
    const wrapped = requirePermission(handler, { permission: 'delete.post' })

    const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
    const response = await wrapped(request, {})

    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })

  it('should return 401 when not authenticated', async () => {
    const requirePermission = createPermissionMiddleware<TestUser, TestRole>({
      rolePermissions,
      getUser: async () => null,
    })

    const handler = vi.fn()
    const wrapped = requirePermission(handler, { permission: 'delete.post' })

    const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
    const response = await wrapped(request, {})

    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(401)
  })

  it('should return 403 when lacking permission', async () => {
    const requirePermission = createPermissionMiddleware<TestUser, TestRole>({
      rolePermissions,
      getUser: async () => regularUser,
    })

    const handler = vi.fn()
    const wrapped = requirePermission(handler, { permission: 'delete.post' })

    const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
    const response = await wrapped(request, {})

    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(403)

    const body = await response.json()
    expect(body.message).toContain('delete.post')
  })

  it('should use custom error message', async () => {
    const requirePermission = createPermissionMiddleware<TestUser, TestRole>({
      rolePermissions,
      getUser: async () => regularUser,
    })

    const handler = vi.fn()
    const wrapped = requirePermission(handler, {
      permission: 'delete.post',
      message: 'Only admins can delete posts',
    })

    const request = new Request('http://localhost/api/posts/1', { method: 'DELETE' })
    const response = await wrapped(request, {})

    const body = await response.json()
    expect(body.message).toBe('Only admins can delete posts')
  })
})

describe('createExpressAuth', () => {
  let mockRes: {
    status: ReturnType<typeof vi.fn>
    json: ReturnType<typeof vi.fn>
  }
  let mockNext: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    }
    mockNext = vi.fn()
  })

  describe('requireAuth', () => {
    it('should call next when authenticated', async () => {
      const { requireAuth } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => adminUser,
      })

      const req = {} as any
      await requireAuth(req, mockRes as any, mockNext)

      expect(mockNext).toHaveBeenCalledWith()
      expect(req.user).toEqual(adminUser)
    })

    it('should return 401 when not authenticated', async () => {
      const { requireAuth } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => null,
      })

      const req = {} as any
      await requireAuth(req, mockRes as any, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'UnauthenticatedException',
          statusCode: 401,
        })
      )
    })
  })

  describe('protect', () => {
    it('should call next when authorized', async () => {
      const { protect } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => adminUser,
      })

      const middleware = protect({ action: 'delete', type: 'Post' })
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockNext).toHaveBeenCalledWith()
      expect(req.user).toEqual(adminUser)
    })

    it('should return 403 when not authorized', async () => {
      const { protect } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => regularUser,
      })

      const middleware = protect({ action: 'delete', type: 'Post' })
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockNext).not.toHaveBeenCalled()
      expect(mockRes.status).toHaveBeenCalledWith(403)
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'UnauthorizedException',
          code: 'POLICY_DENIED',
          statusCode: 403,
        })
      )
    })

    it('should return 500 for missing policy', async () => {
      const { protect } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: {},
        getUser: () => adminUser,
      })

      const middleware = protect({ action: 'delete', type: 'Post' })
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(500)
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'PolicyConfigurationException',
          code: 'POLICY_NOT_FOUND',
        })
      )
    })

    it('should return 500 for missing action', async () => {
      const { protect } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: { view: () => true } },
        getUser: () => adminUser,
      })

      const middleware = protect({ action: 'delete', type: 'Post' })
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(500)
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'PolicyConfigurationException',
          code: 'ACTION_NOT_FOUND',
        })
      )
    })
  })

  describe('requirePermission', () => {
    it('should call next when has permission', async () => {
      const { requirePermission } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => adminUser,
      })

      const middleware = requirePermission('delete.post')
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockNext).toHaveBeenCalledWith()
    })

    it('should return 403 when lacks permission', async () => {
      const { requirePermission } = createExpressAuth<TestUser, TestRole, TestResource>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: () => regularUser,
      })

      const middleware = requirePermission('delete.post')
      const req = {} as any
      await middleware(req, mockRes as any, mockNext)

      expect(mockRes.status).toHaveBeenCalledWith(403)
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'UnauthorizedException',
          message: "Permission 'delete.post' required",
        })
      )
    })
  })
})
