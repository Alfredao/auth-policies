import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createAuth, createPolicyCache, PolicyCache } from '../src/index'

describe('PolicyCache', () => {
  describe('basic operations', () => {
    it('should create a cache with default config', () => {
      const cache = createPolicyCache()
      const stats = cache.stats()
      expect(stats.maxSize).toBe(1000)
      expect(stats.ttl).toBe(60000)
      expect(stats.size).toBe(0)
    })

    it('should create a cache with custom config', () => {
      const cache = createPolicyCache({
        ttl: 30000,
        maxSize: 500,
      })
      const stats = cache.stats()
      expect(stats.maxSize).toBe(500)
      expect(stats.ttl).toBe(30000)
    })

    it('should set and get values', () => {
      const cache = new PolicyCache()
      cache.set('key1', true)
      cache.set('key2', false)

      expect(cache.get('key1')).toBe(true)
      expect(cache.get('key2')).toBe(false)
      expect(cache.get('key3')).toBeUndefined()
    })

    it('should generate correct cache keys', () => {
      const cache = new PolicyCache()

      const key1 = cache.generateKey('view', 'User', 'user-123')
      expect(key1).toBe('view:User:user-123:no-resource')

      const key2 = cache.generateKey('update', 'Post', 'user-456', { id: 'post-789' })
      expect(key2).toBe('update:Post:user-456:post-789')

      const key3 = cache.generateKey('delete', 'Comment', 'user-789', { id: 123 })
      expect(key3).toBe('delete:Comment:user-789:123')
    })

    it('should use custom getResourceKey function', () => {
      const cache = new PolicyCache({
        getResourceKey: (resource) => {
          if (resource && typeof resource === 'object' && 'uuid' in resource) {
            return String((resource as { uuid: string }).uuid)
          }
          return undefined
        },
      })

      const key = cache.generateKey('view', 'User', 'user-123', { uuid: 'custom-uuid' })
      expect(key).toBe('view:User:user-123:custom-uuid')
    })
  })

  describe('TTL expiration', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('should expire entries after TTL', () => {
      const cache = new PolicyCache({ ttl: 1000 })
      cache.set('key1', true)

      expect(cache.get('key1')).toBe(true)

      // Advance time by 500ms - still valid
      vi.advanceTimersByTime(500)
      expect(cache.get('key1')).toBe(true)

      // Advance time by 600ms more (1100ms total) - expired
      vi.advanceTimersByTime(600)
      expect(cache.get('key1')).toBeUndefined()
    })

    it('should not expire entries when TTL is 0', () => {
      const cache = new PolicyCache({ ttl: 0 })
      cache.set('key1', true)

      vi.advanceTimersByTime(999999999)
      expect(cache.get('key1')).toBe(true)
    })

    it('should cleanup expired entries', () => {
      const cache = new PolicyCache({ ttl: 1000 })
      cache.set('key1', true)
      cache.set('key2', false)

      vi.advanceTimersByTime(1100)
      const cleaned = cache.cleanup()

      expect(cleaned).toBe(2)
      expect(cache.stats().size).toBe(0)
    })
  })

  describe('LRU eviction', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('should evict least recently used entry when at max size', () => {
      const cache = new PolicyCache({ maxSize: 3, ttl: 0 })

      cache.set('key1', true)
      vi.advanceTimersByTime(10)
      cache.set('key2', true)
      vi.advanceTimersByTime(10)
      cache.set('key3', true)
      vi.advanceTimersByTime(10)

      expect(cache.stats().size).toBe(3)

      // Access key1 and key3 to make them recently used
      cache.get('key1')
      vi.advanceTimersByTime(10)
      cache.get('key3')
      vi.advanceTimersByTime(10)

      // Add key4 - should evict key2 (least recently used)
      cache.set('key4', true)

      expect(cache.stats().size).toBe(3)
      expect(cache.get('key1')).toBe(true)
      expect(cache.get('key2')).toBeUndefined() // evicted
      expect(cache.get('key3')).toBe(true)
      expect(cache.get('key4')).toBe(true)
    })
  })

  describe('invalidation', () => {
    it('should invalidate a specific key', () => {
      const cache = new PolicyCache()
      cache.set('key1', true)
      cache.set('key2', true)

      const result = cache.invalidate('key1')

      expect(result).toBe(true)
      expect(cache.get('key1')).toBeUndefined()
      expect(cache.get('key2')).toBe(true)
    })

    it('should invalidate all entries for a user', () => {
      const cache = new PolicyCache()
      cache.set('view:User:user-123:no-resource', true)
      cache.set('update:User:user-123:post-1', true)
      cache.set('delete:User:user-456:no-resource', true)

      const count = cache.invalidateUser('user-123')

      expect(count).toBe(2)
      expect(cache.get('view:User:user-123:no-resource')).toBeUndefined()
      expect(cache.get('update:User:user-123:post-1')).toBeUndefined()
      expect(cache.get('delete:User:user-456:no-resource')).toBe(true)
    })

    it('should invalidate all entries for a resource type', () => {
      const cache = new PolicyCache()
      cache.set('view:Post:user-123:no-resource', true)
      cache.set('update:Post:user-456:post-1', true)
      cache.set('delete:User:user-123:no-resource', true)

      const count = cache.invalidateResourceType('Post')

      expect(count).toBe(2)
      expect(cache.get('view:Post:user-123:no-resource')).toBeUndefined()
      expect(cache.get('update:Post:user-456:post-1')).toBeUndefined()
      expect(cache.get('delete:User:user-123:no-resource')).toBe(true)
    })

    it('should invalidate all entries for a specific resource', () => {
      const cache = new PolicyCache()
      cache.set('view:Post:user-123:post-1', true)
      cache.set('update:Post:user-456:post-1', true)
      cache.set('delete:Post:user-123:post-2', true)

      const count = cache.invalidateResource('Post', 'post-1')

      expect(count).toBe(2)
      expect(cache.get('view:Post:user-123:post-1')).toBeUndefined()
      expect(cache.get('update:Post:user-456:post-1')).toBeUndefined()
      expect(cache.get('delete:Post:user-123:post-2')).toBe(true)
    })

    it('should clear all entries', () => {
      const cache = new PolicyCache()
      cache.set('key1', true)
      cache.set('key2', true)
      cache.set('key3', true)

      cache.clear()

      expect(cache.stats().size).toBe(0)
    })
  })
})

describe('createAuth with caching', () => {
  const rolePermissions = {
    ADMIN: ['view.post', 'create.post', 'update.post', 'delete.post'],
    USER: ['view.post'],
  }

  interface TestUser {
    id: string
    role: 'ADMIN' | 'USER'
  }

  interface Post {
    id: string
    title: string
    authorId: string
  }

  let policyCallCount: number

  beforeEach(() => {
    policyCallCount = 0
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const createTestPolicy = () => ({
    view: vi.fn(async (user: TestUser, resource?: Post) => {
      policyCallCount++
      return true
    }),
    create: vi.fn(async (user: TestUser) => {
      policyCallCount++
      return user.role === 'ADMIN'
    }),
    update: vi.fn(async (user: TestUser, resource?: Post) => {
      policyCallCount++
      if (!resource) return user.role === 'ADMIN'
      return user.role === 'ADMIN' || resource.authorId === user.id
    }),
  })

  it('should not cache when caching is disabled', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
    })

    await auth.checkPermission('view', 'Post')
    await auth.checkPermission('view', 'Post')
    await auth.checkPermission('view', 'Post')

    expect(policyCallCount).toBe(3) // Called every time
    expect(auth.cache).toBeNull()
  })

  it('should cache policy results when enabled', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true, ttl: 60000 },
    })

    const result1 = await auth.checkPermission('view', 'Post')
    const result2 = await auth.checkPermission('view', 'Post')
    const result3 = await auth.checkPermission('view', 'Post')

    expect(result1).toBe(true)
    expect(result2).toBe(true)
    expect(result3).toBe(true)
    expect(policyCallCount).toBe(1) // Only called once
    expect(auth.cache).not.toBeNull()
  })

  it('should use different cache keys for different resources', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true },
    })

    const post1: Post = { id: 'post-1', title: 'Post 1', authorId: 'user-1' }
    const post2: Post = { id: 'post-2', title: 'Post 2', authorId: 'user-2' }

    await auth.checkPermission('update', 'Post', { resource: post1 })
    await auth.checkPermission('update', 'Post', { resource: post1 })
    await auth.checkPermission('update', 'Post', { resource: post2 })
    await auth.checkPermission('update', 'Post', { resource: post2 })

    expect(policyCallCount).toBe(2) // One for each unique resource
  })

  it('should expire cache entries after TTL', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true, ttl: 1000 },
    })

    await auth.checkPermission('view', 'Post')
    expect(policyCallCount).toBe(1)

    // Advance time within TTL
    vi.advanceTimersByTime(500)
    await auth.checkPermission('view', 'Post')
    expect(policyCallCount).toBe(1) // Still cached

    // Advance time past TTL
    vi.advanceTimersByTime(600)
    await auth.checkPermission('view', 'Post')
    expect(policyCallCount).toBe(2) // Cache expired, called again
  })

  it('should cache results for canApi', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true },
    })

    await auth.canApi('view', 'Post')
    await auth.canApi('view', 'Post')
    await auth.canApi('view', 'Post')

    expect(policyCallCount).toBe(1)
  })

  it('should cache results for can', async () => {
    const PostPolicy = createTestPolicy()
    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true },
    })

    await auth.can('view', 'Post')
    await auth.can('view', 'Post')
    await auth.can('view', 'Post')

    expect(policyCallCount).toBe(1)
  })

  it('should include cached flag in audit metadata', async () => {
    const PostPolicy = createTestPolicy()
    const auditEntries: Array<{ cached?: boolean }> = []

    const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
      rolePermissions,
      policies: { Post: PostPolicy },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true },
      onAudit: (entry) => {
        auditEntries.push({ cached: entry.metadata?.cached as boolean })
      },
    })

    await auth.checkPermission('view', 'Post')
    await auth.checkPermission('view', 'Post')

    expect(auditEntries).toHaveLength(2)
    expect(auditEntries[0].cached).toBeUndefined() // First call, not from cache
    expect(auditEntries[1].cached).toBe(true) // Second call, from cache
  })

  describe('cache utilities', () => {
    it('should expose cache utilities when caching is enabled', () => {
      const auth = createAuth({
        rolePermissions,
        policies: { Post: createTestPolicy() },
        getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
        cache: { enabled: true },
      })

      expect(auth.cache).not.toBeNull()
      expect(auth.cache?.invalidateUser).toBeInstanceOf(Function)
      expect(auth.cache?.invalidateResourceType).toBeInstanceOf(Function)
      expect(auth.cache?.invalidateResource).toBeInstanceOf(Function)
      expect(auth.cache?.clear).toBeInstanceOf(Function)
      expect(auth.cache?.stats).toBeInstanceOf(Function)
      expect(auth.cache?.cleanup).toBeInstanceOf(Function)
    })

    it('should invalidate user cache entries', async () => {
      const PostPolicy = createTestPolicy()
      const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
        cache: { enabled: true },
      })

      await auth.checkPermission('view', 'Post')
      expect(policyCallCount).toBe(1)

      auth.cache?.invalidateUser('user-1')

      await auth.checkPermission('view', 'Post')
      expect(policyCallCount).toBe(2) // Cache invalidated, called again
    })

    it('should clear all cache entries', async () => {
      const PostPolicy = createTestPolicy()
      const auth = createAuth<TestUser, 'ADMIN' | 'USER', 'Post'>({
        rolePermissions,
        policies: { Post: PostPolicy },
        getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
        cache: { enabled: true },
      })

      await auth.checkPermission('view', 'Post')
      await auth.checkPermission('create', 'Post')

      expect(auth.cache?.stats().size).toBe(2)

      auth.cache?.clear()

      expect(auth.cache?.stats().size).toBe(0)
    })

    it('should report cache statistics', async () => {
      const auth = createAuth({
        rolePermissions,
        policies: { Post: createTestPolicy() },
        getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
        cache: { enabled: true, ttl: 30000, maxSize: 500 },
      })

      const stats = auth.cache?.stats()

      expect(stats?.ttl).toBe(30000)
      expect(stats?.maxSize).toBe(500)
      expect(stats?.size).toBe(0)
    })
  })

  it('should include cacheEnabled in config', () => {
    const authWithCache = createAuth({
      rolePermissions,
      policies: { Post: createTestPolicy() },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
      cache: { enabled: true },
    })

    const authWithoutCache = createAuth({
      rolePermissions,
      policies: { Post: createTestPolicy() },
      getUser: async () => ({ id: 'user-1', role: 'ADMIN' }),
    })

    expect(authWithCache.config.cacheEnabled).toBe(true)
    expect(authWithoutCache.config.cacheEnabled).toBe(false)
  })
})
