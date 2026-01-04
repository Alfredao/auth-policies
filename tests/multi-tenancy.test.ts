import { describe, it, expect, vi } from 'vitest'
import {
  createAuth,
  createTenantPermissionChecker,
  getTenantRoles,
  type TenantUser,
  type RolePermissions,
  type Policy,
} from '../src/index'

// Define types for testing
type SystemRole = 'SUPER_ADMIN' | 'USER'
type TenantRole = 'OWNER' | 'ADMIN' | 'MEMBER'

interface TestUser extends TenantUser<SystemRole, TenantRole> {
  id: string
  email: string
  role: SystemRole
  tenantRoles?: Record<string, TenantRole | TenantRole[]>
}

const systemRolePermissions: RolePermissions<SystemRole> = {
  SUPER_ADMIN: ['*'],
  USER: ['view.profile'],
}

const tenantRolePermissions: RolePermissions<TenantRole> = {
  OWNER: ['manage.business', 'view.reports', 'manage.staff', 'view.appointments'],
  ADMIN: ['view.reports', 'manage.staff', 'view.appointments'],
  MEMBER: ['view.appointments'],
}

describe('getTenantRoles', () => {
  it('should return tenant roles for a user in a specific tenant', () => {
    const user: TestUser = {
      id: '1',
      email: 'user@example.com',
      role: 'USER',
      tenantRoles: {
        'business-1': 'OWNER',
        'business-2': 'MEMBER',
      },
    }

    expect(getTenantRoles(user, 'business-1')).toEqual(['OWNER'])
    expect(getTenantRoles(user, 'business-2')).toEqual(['MEMBER'])
    expect(getTenantRoles(user, 'business-3')).toEqual([])
  })

  it('should handle multiple roles per tenant', () => {
    const user: TestUser = {
      id: '1',
      email: 'user@example.com',
      role: 'USER',
      tenantRoles: {
        'business-1': ['ADMIN', 'MEMBER'],
      },
    }

    expect(getTenantRoles(user, 'business-1')).toEqual(['ADMIN', 'MEMBER'])
  })

  it('should return empty array when user has no tenantRoles', () => {
    const user: TestUser = {
      id: '1',
      email: 'user@example.com',
      role: 'USER',
    }

    expect(getTenantRoles(user, 'business-1')).toEqual([])
  })

  it('should return empty array for empty tenantId', () => {
    const user: TestUser = {
      id: '1',
      email: 'user@example.com',
      role: 'USER',
      tenantRoles: { 'business-1': 'OWNER' },
    }

    expect(getTenantRoles(user, '')).toEqual([])
  })
})

describe('createTenantPermissionChecker', () => {
  const checker = createTenantPermissionChecker<SystemRole, TenantRole>({
    systemRolePermissions,
    tenantRolePermissions,
  })

  const user: TestUser = {
    id: '1',
    email: 'user@example.com',
    role: 'USER',
    tenantRoles: {
      'business-1': 'OWNER',
      'business-2': 'MEMBER',
    },
  }

  const superAdmin: TestUser = {
    id: '2',
    email: 'admin@example.com',
    role: 'SUPER_ADMIN',
  }

  describe('getSystemRoles', () => {
    it('should return system roles', () => {
      expect(checker.getSystemRoles(user)).toEqual(['USER'])
      expect(checker.getSystemRoles(superAdmin)).toEqual(['SUPER_ADMIN'])
    })
  })

  describe('getSystemPermissions', () => {
    it('should return system-level permissions', () => {
      expect(checker.getSystemPermissions(user)).toEqual(['view.profile'])
      expect(checker.getSystemPermissions(superAdmin)).toEqual(['*'])
    })
  })

  describe('getTenantPermissions', () => {
    it('should return tenant-level permissions for a specific tenant', () => {
      const perms = checker.getTenantPermissions(user, 'business-1')
      expect(perms).toContain('manage.business')
      expect(perms).toContain('view.reports')
      expect(perms).toContain('manage.staff')
    })

    it('should return empty array for null tenant', () => {
      expect(checker.getTenantPermissions(user, null)).toEqual([])
    })

    it('should return empty array for tenant user is not part of', () => {
      expect(checker.getTenantPermissions(user, 'business-3')).toEqual([])
    })
  })

  describe('getPermissions', () => {
    it('should combine system and tenant permissions', () => {
      const perms = checker.getPermissions(user, 'business-1')
      // System permissions
      expect(perms).toContain('view.profile')
      // Tenant permissions
      expect(perms).toContain('manage.business')
      expect(perms).toContain('view.reports')
    })

    it('should return only system permissions when tenantId is null', () => {
      const perms = checker.getPermissions(user, null)
      expect(perms).toEqual(['view.profile'])
    })
  })

  describe('hasPermission', () => {
    it('should check system permissions without tenant context', () => {
      expect(checker.hasPermission(user, 'view.profile', null)).toBe(true)
      expect(checker.hasPermission(user, 'manage.business', null)).toBe(false)
    })

    it('should check tenant permissions with tenant context', () => {
      expect(checker.hasPermission(user, 'manage.business', 'business-1')).toBe(true)
      expect(checker.hasPermission(user, 'manage.business', 'business-2')).toBe(false)
      expect(checker.hasPermission(user, 'view.appointments', 'business-2')).toBe(true)
    })

    it('should allow system permissions in any tenant context', () => {
      expect(checker.hasPermission(user, 'view.profile', 'business-1')).toBe(true)
      expect(checker.hasPermission(user, 'view.profile', 'business-2')).toBe(true)
    })
  })

  describe('hasAnyPermission', () => {
    it('should check if user has any of the permissions', () => {
      expect(
        checker.hasAnyPermission(user, ['manage.business', 'delete.user'], 'business-1')
      ).toBe(true)
      expect(
        checker.hasAnyPermission(user, ['delete.user', 'create.user'], 'business-1')
      ).toBe(false)
    })
  })

  describe('hasAllPermissions', () => {
    it('should check if user has all permissions', () => {
      expect(
        checker.hasAllPermissions(user, ['manage.business', 'view.reports'], 'business-1')
      ).toBe(true)
      expect(
        checker.hasAllPermissions(user, ['manage.business', 'delete.user'], 'business-1')
      ).toBe(false)
    })
  })

  describe('getRoles', () => {
    it('should return both system and tenant roles', () => {
      const roles = checker.getRoles(user, 'business-1')
      expect(roles.system).toEqual(['USER'])
      expect(roles.tenant).toEqual(['OWNER'])
    })

    it('should return empty tenant roles when tenantId is null', () => {
      const roles = checker.getRoles(user, null)
      expect(roles.system).toEqual(['USER'])
      expect(roles.tenant).toEqual([])
    })
  })
})

describe('createAuth with tenant config', () => {
  const AppointmentPolicy: Policy<TestUser> = {
    view: (user, _resource, tenantId) => {
      // SUPER_ADMIN can view all
      if (user.role === 'SUPER_ADMIN') return true
      // Check tenant role
      if (!tenantId) return false
      const tenantRoles = getTenantRoles<TenantRole>(user, tenantId)
      return tenantRoles.length > 0
    },
    manage: (user, _resource, tenantId) => {
      if (user.role === 'SUPER_ADMIN') return true
      if (!tenantId) return false
      const tenantRoles = getTenantRoles<TenantRole>(user, tenantId)
      return tenantRoles.includes('OWNER') || tenantRoles.includes('ADMIN')
    },
  }

  const user: TestUser = {
    id: '1',
    email: 'user@example.com',
    role: 'USER',
    tenantRoles: {
      'business-1': 'OWNER',
      'business-2': 'MEMBER',
    },
  }

  const superAdmin: TestUser = {
    id: '2',
    email: 'admin@example.com',
    role: 'SUPER_ADMIN',
  }

  it('should check permissions with tenant context from options', async () => {
    let currentUser: TestUser | null = user

    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => currentUser,
      tenant: {
        rolePermissions: tenantRolePermissions,
        getTenantId: async () => null, // No default tenant
      },
    })

    // Without tenant context - should deny
    const canViewWithoutTenant = await auth.checkPermission('view', 'Appointment')
    expect(canViewWithoutTenant).toBe(false)

    // With tenant context where user is OWNER - should allow
    const canViewWithTenant = await auth.checkPermission('view', 'Appointment', {
      tenantId: 'business-1',
    })
    expect(canViewWithTenant).toBe(true)

    // With tenant context where user is MEMBER - should allow view
    const canViewAsMember = await auth.checkPermission('view', 'Appointment', {
      tenantId: 'business-2',
    })
    expect(canViewAsMember).toBe(true)

    // MEMBER cannot manage
    const canManageAsMember = await auth.checkPermission('manage', 'Appointment', {
      tenantId: 'business-2',
    })
    expect(canManageAsMember).toBe(false)

    // OWNER can manage
    const canManageAsOwner = await auth.checkPermission('manage', 'Appointment', {
      tenantId: 'business-1',
    })
    expect(canManageAsOwner).toBe(true)
  })

  it('should check permissions with tenant context from config', async () => {
    let activeTenantId: string | null = 'business-1'
    let currentUser: TestUser | null = user

    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => currentUser,
      tenant: {
        rolePermissions: tenantRolePermissions,
        getTenantId: async () => activeTenantId,
      },
    })

    // Uses tenant from config
    const canView = await auth.checkPermission('view', 'Appointment')
    expect(canView).toBe(true)

    // Change active tenant
    activeTenantId = 'business-2'
    const canManage = await auth.checkPermission('manage', 'Appointment')
    expect(canManage).toBe(false) // MEMBER cannot manage
  })

  it('should expose tenant utilities', async () => {
    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => user,
      tenant: {
        rolePermissions: tenantRolePermissions,
        getTenantId: async () => 'business-1',
      },
    })

    expect(auth.tenant).not.toBeNull()
    expect(auth.tenant?.getTenantRoles(user, 'business-1')).toEqual(['OWNER'])
    expect(auth.tenant?.hasPermission(user, 'manage.business', 'business-1')).toBe(true)
  })

  it('should include tenantEnabled in config', async () => {
    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => user,
      tenant: {
        rolePermissions: tenantRolePermissions,
        getTenantId: async () => 'business-1',
      },
    })

    expect(auth.config.tenantEnabled).toBe(true)
  })

  it('should pass tenantId to audit logger', async () => {
    const mockAudit = vi.fn()

    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => user,
      tenant: {
        rolePermissions: tenantRolePermissions,
        getTenantId: async () => null,
      },
      onAudit: mockAudit,
    })

    await auth.checkPermission('view', 'Appointment', { tenantId: 'business-1' })

    expect(mockAudit).toHaveBeenCalled()
    expect(mockAudit.mock.calls[0][0].tenantId).toBe('business-1')
  })

  it('should work without tenant config (backwards compatible)', async () => {
    const auth = createAuth<TestUser, SystemRole, 'Appointment'>({
      rolePermissions: systemRolePermissions,
      policies: {
        Appointment: AppointmentPolicy,
      },
      getUser: async () => superAdmin,
    })

    expect(auth.tenant).toBeNull()
    expect(auth.config.tenantEnabled).toBe(false)

    // SUPER_ADMIN can still access via policy logic
    const canView = await auth.checkPermission('view', 'Appointment')
    expect(canView).toBe(true)
  })
})

describe('cache with tenantId', () => {
  it('should cache results per tenant', async () => {
    const policySpy = vi.fn().mockReturnValue(true)

    const auth = createAuth({
      rolePermissions: { ADMIN: ['view.all'] },
      policies: {
        Resource: {
          view: policySpy,
        },
      },
      getUser: async () => ({ id: '1', role: 'ADMIN' }),
      cache: {
        enabled: true,
        ttl: 60000,
      },
    })

    // First call - should execute policy
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-1' })
    expect(policySpy).toHaveBeenCalledTimes(1)

    // Second call with same tenant - should use cache
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-1' })
    expect(policySpy).toHaveBeenCalledTimes(1)

    // Third call with different tenant - should execute policy again
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-2' })
    expect(policySpy).toHaveBeenCalledTimes(2)
  })

  it('should invalidate tenant-specific cache entries', async () => {
    const policySpy = vi.fn().mockReturnValue(true)

    const auth = createAuth({
      rolePermissions: { ADMIN: ['view.all'] },
      policies: {
        Resource: {
          view: policySpy,
        },
      },
      getUser: async () => ({ id: '1', role: 'ADMIN' }),
      cache: {
        enabled: true,
        ttl: 60000,
      },
    })

    // Populate cache for two tenants
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-1' })
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-2' })
    expect(policySpy).toHaveBeenCalledTimes(2)

    // Invalidate tenant-1
    auth.cache?.invalidateTenant('tenant-1')

    // tenant-1 should re-execute
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-1' })
    expect(policySpy).toHaveBeenCalledTimes(3)

    // tenant-2 should still use cache
    await auth.checkPermission('view', 'Resource', { tenantId: 'tenant-2' })
    expect(policySpy).toHaveBeenCalledTimes(3)
  })
})
