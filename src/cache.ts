/**
 * Cache configuration options
 */
export interface CacheConfig {
  /**
   * Enable or disable caching
   * @default false
   */
  enabled?: boolean

  /**
   * Time-to-live in milliseconds
   * Set to 0 for no expiration (not recommended for long-running processes)
   * @default 60000 (1 minute)
   */
  ttl?: number

  /**
   * Maximum number of entries in the cache
   * Uses LRU eviction when exceeded
   * @default 1000
   */
  maxSize?: number

  /**
   * Custom function to generate a cache key for a resource
   * By default, uses resource.id if available
   */
  getResourceKey?: (resource: unknown) => string | undefined
}

/**
 * Cache entry with value and expiration
 */
interface CacheEntry<T> {
  value: T
  expiresAt: number
  lastAccessed: number
}

/**
 * LRU Cache with TTL support for memoizing policy results
 */
export class PolicyCache {
  private cache = new Map<string, CacheEntry<boolean>>()
  private readonly ttl: number
  private readonly maxSize: number
  private readonly getResourceKey: (resource: unknown) => string | undefined

  constructor(config: CacheConfig = {}) {
    this.ttl = config.ttl ?? 60000 // 1 minute default
    this.maxSize = config.maxSize ?? 1000
    this.getResourceKey = config.getResourceKey ?? this.defaultGetResourceKey
  }

  /**
   * Default resource key generator
   * Extracts 'id' property if available
   */
  private defaultGetResourceKey(resource: unknown): string | undefined {
    if (resource === null || resource === undefined) {
      return undefined
    }
    if (typeof resource === 'object' && 'id' in resource) {
      const id = (resource as { id: unknown }).id
      if (typeof id === 'string' || typeof id === 'number') {
        return String(id)
      }
    }
    return undefined
  }

  /**
   * Generate a cache key for a policy check
   */
  generateKey(
    action: string,
    resourceType: string,
    userId: string,
    resource?: unknown
  ): string {
    const resourceKey = resource ? this.getResourceKey(resource) : undefined
    return `${action}:${resourceType}:${userId}:${resourceKey ?? 'no-resource'}`
  }

  /**
   * Get a cached value if it exists and hasn't expired
   */
  get(key: string): boolean | undefined {
    const entry = this.cache.get(key)

    if (!entry) {
      return undefined
    }

    // Check if expired
    if (this.ttl > 0 && Date.now() > entry.expiresAt) {
      this.cache.delete(key)
      return undefined
    }

    // Update last accessed time for LRU
    entry.lastAccessed = Date.now()
    return entry.value
  }

  /**
   * Set a cached value
   */
  set(key: string, value: boolean): void {
    // Evict if at max size
    if (this.cache.size >= this.maxSize) {
      this.evictLRU()
    }

    const now = Date.now()
    this.cache.set(key, {
      value,
      expiresAt: this.ttl > 0 ? now + this.ttl : Infinity,
      lastAccessed: now,
    })
  }

  /**
   * Evict the least recently used entry
   */
  private evictLRU(): void {
    let oldestKey: string | undefined
    let oldestTime = Infinity

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < oldestTime) {
        oldestTime = entry.lastAccessed
        oldestKey = key
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey)
    }
  }

  /**
   * Invalidate a specific cache entry
   */
  invalidate(key: string): boolean {
    return this.cache.delete(key)
  }

  /**
   * Invalidate all entries for a specific user
   */
  invalidateUser(userId: string): number {
    let count = 0
    for (const key of this.cache.keys()) {
      if (key.includes(`:${userId}:`)) {
        this.cache.delete(key)
        count++
      }
    }
    return count
  }

  /**
   * Invalidate all entries for a specific resource type
   */
  invalidateResourceType(resourceType: string): number {
    let count = 0
    for (const key of this.cache.keys()) {
      if (key.startsWith(`${resourceType}:`) || key.includes(`:${resourceType}:`)) {
        // Check if resourceType is in the correct position (second segment)
        const parts = key.split(':')
        if (parts[1] === resourceType) {
          this.cache.delete(key)
          count++
        }
      }
    }
    return count
  }

  /**
   * Invalidate all entries for a specific resource
   */
  invalidateResource(resourceType: string, resourceId: string): number {
    let count = 0
    const suffix = `:${resourceId}`
    for (const key of this.cache.keys()) {
      const parts = key.split(':')
      if (parts[1] === resourceType && key.endsWith(suffix)) {
        this.cache.delete(key)
        count++
      }
    }
    return count
  }

  /**
   * Clear all cached entries
   */
  clear(): void {
    this.cache.clear()
  }

  /**
   * Get cache statistics
   */
  stats(): { size: number; maxSize: number; ttl: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      ttl: this.ttl,
    }
  }

  /**
   * Clean up expired entries
   * Call this periodically in long-running processes
   */
  cleanup(): number {
    if (this.ttl <= 0) return 0

    const now = Date.now()
    let count = 0

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key)
        count++
      }
    }

    return count
  }
}

/**
 * Create a new policy cache instance
 */
export function createPolicyCache(config?: CacheConfig): PolicyCache {
  return new PolicyCache(config)
}
