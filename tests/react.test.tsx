/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { createAuth } from '../src/create-auth'
import {
  AuthProvider,
  useAuth,
  useUser,
  usePermission,
  Can,
  Cannot,
} from '../src/react'
import type { BaseUser, Policy } from '../src/types'

// Test types
type TestRole = 'ADMIN' | 'USER'
type TestResource = 'Post'

interface TestUser extends BaseUser<TestRole> {
  id: string
  role: TestRole
  email: string
}

// Test data
const adminUser: TestUser = { id: '1', role: 'ADMIN', email: 'admin@test.com' }
const regularUser: TestUser = { id: '2', role: 'USER', email: 'user@test.com' }

const rolePermissions: Record<TestRole, string[]> = {
  ADMIN: ['delete.post'],
  USER: ['view.post'],
}

// Synchronous policy for faster tests
const PostPolicy: Policy<TestUser> = {
  view: (user) => true,
  delete: (user) => user.role === 'ADMIN',
}

describe('AuthProvider', () => {
  const createTestAuth = (user: TestUser | null) => {
    return createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => user,
    })
  }

  it('should provide auth context with initialUser', () => {
    const auth = createTestAuth(adminUser)

    function TestComponent() {
      const { user, isAuthenticated, isLoading } = useAuth<TestUser>()
      return (
        <div>
          <span data-testid="loading">{isLoading ? 'yes' : 'no'}</span>
          <span data-testid="auth">{isAuthenticated ? 'yes' : 'no'}</span>
          <span data-testid="email">{user?.email || 'none'}</span>
        </div>
      )
    }

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <TestComponent />
      </AuthProvider>
    )

    expect(screen.getByTestId('loading').textContent).toBe('no')
    expect(screen.getByTestId('auth').textContent).toBe('yes')
    expect(screen.getByTestId('email').textContent).toBe('admin@test.com')
  })

  it('should show loading state when no initialUser', () => {
    const auth = createTestAuth(adminUser)

    function TestComponent() {
      const { isLoading } = useAuth()
      return <span data-testid="loading">{isLoading ? 'yes' : 'no'}</span>
    }

    render(
      <AuthProvider auth={auth}>
        <TestComponent />
      </AuthProvider>
    )

    expect(screen.getByTestId('loading').textContent).toBe('yes')
  })

  it('should throw error when useAuth is used outside provider', () => {
    function TestComponent() {
      useAuth()
      return null
    }

    expect(() => render(<TestComponent />)).toThrow(
      'useAuth must be used within an AuthProvider'
    )
  })
})

describe('useUser', () => {
  it('should return user data with initialUser', () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    function TestComponent() {
      const { user, isAuthenticated } = useUser<TestUser>()
      return (
        <span data-testid="result">
          {isAuthenticated ? user?.email : 'not auth'}
        </span>
      )
    }

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <TestComponent />
      </AuthProvider>
    )

    expect(screen.getByTestId('result').textContent).toBe('admin@test.com')
  })

  it('should show not authenticated when initialUser is null', () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => null,
    })

    function TestComponent() {
      const { isAuthenticated } = useUser()
      return (
        <span data-testid="result">{isAuthenticated ? 'auth' : 'not auth'}</span>
      )
    }

    render(
      <AuthProvider auth={auth} initialUser={null}>
        <TestComponent />
      </AuthProvider>
    )

    expect(screen.getByTestId('result').textContent).toBe('not auth')
  })
})

describe('usePermission', () => {
  it('should show loading initially', () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    function TestComponent() {
      const { isLoading } = usePermission('delete', 'Post')
      return <span data-testid="loading">{isLoading ? 'yes' : 'no'}</span>
    }

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <TestComponent />
      </AuthProvider>
    )

    expect(screen.getByTestId('loading').textContent).toBe('yes')
  })

  it('should resolve to allowed for admin', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    function TestComponent() {
      const { allowed, isLoading } = usePermission('delete', 'Post')
      return (
        <span data-testid="result">
          {isLoading ? 'loading' : allowed ? 'allowed' : 'denied'}
        </span>
      )
    }

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <TestComponent />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('result').textContent).toBe('allowed')
    }, { timeout: 1000 })
  })

  it('should resolve to denied for regular user', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => regularUser,
    })

    function TestComponent() {
      const { allowed, isLoading } = usePermission('delete', 'Post')
      return (
        <span data-testid="result">
          {isLoading ? 'loading' : allowed ? 'allowed' : 'denied'}
        </span>
      )
    }

    render(
      <AuthProvider auth={auth} initialUser={regularUser}>
        <TestComponent />
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByTestId('result').textContent).toBe('denied')
    }, { timeout: 1000 })
  })
})

describe('Can component', () => {
  it('should render loading state initially', () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <Can action="delete" resourceType="Post" loading={<span>Loading...</span>}>
          <button>Delete</button>
        </Can>
      </AuthProvider>
    )

    expect(screen.getByText('Loading...')).toBeDefined()
  })

  it('should render children when allowed', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <Can action="delete" resourceType="Post">
          <button>Delete</button>
        </Can>
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('Delete')).toBeDefined()
    }, { timeout: 1000 })
  })

  it('should render fallback when denied', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => regularUser,
    })

    render(
      <AuthProvider auth={auth} initialUser={regularUser}>
        <Can action="delete" resourceType="Post" fallback={<span>No access</span>}>
          <button>Delete</button>
        </Can>
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('No access')).toBeDefined()
    }, { timeout: 1000 })
  })
})

describe('Cannot component', () => {
  it('should render children when NOT allowed', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => regularUser,
    })

    render(
      <AuthProvider auth={auth} initialUser={regularUser}>
        <Cannot action="delete" resourceType="Post">
          <span>You cannot delete</span>
        </Cannot>
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('You cannot delete')).toBeDefined()
    }, { timeout: 1000 })
  })

  it('should not render when allowed', async () => {
    const auth = createAuth<TestUser, TestRole, TestResource>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => adminUser,
    })

    render(
      <AuthProvider auth={auth} initialUser={adminUser}>
        <Cannot action="delete" resourceType="Post">
          <span>You cannot delete</span>
        </Cannot>
        <span>Other content</span>
      </AuthProvider>
    )

    await waitFor(() => {
      expect(screen.queryByText('You cannot delete')).toBeNull()
    }, { timeout: 1000 })
  })
})
