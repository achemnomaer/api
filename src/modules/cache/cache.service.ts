import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import Redis from 'ioredis';

@Injectable()
export class CacheCustomService {
  private redis: Redis;

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {
    // Initialize direct Redis connection for advanced operations
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      db: parseInt(process.env.REDIS_DB || '0'),
    });
  }

  // Basic cache operations using NestJS cache manager
  async get<T>(key: string): Promise<T | undefined> {
    return this.cacheManager.get<T>(key);
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.cacheManager.set(key, value, ttl);
  }

  async del(key: string): Promise<void> {
    await this.cacheManager.del(key);
  }

  async reset(): Promise<void> {
    await this.cacheManager.reset();
  }

  // Advanced Redis operations
  async setWithExpiry(key: string, value: any, seconds: number): Promise<void> {
    await this.redis.setex(key, seconds, JSON.stringify(value));
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    return this.redis.incrby(key, amount);
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.redis.decrby(key, amount);
  }

  // Pattern-based operations
  async deleteByPattern(pattern: string): Promise<number> {
    const keys = await this.redis.keys(pattern);
    if (keys.length === 0) {
      return 0;
    }
    return this.redis.del(...keys);
  }

  async getKeys(pattern: string): Promise<string[]> {
    return this.redis.keys(pattern);
  }

  // Hash operations
  async hset(key: string, field: string, value: any): Promise<void> {
    await this.redis.hset(key, field, JSON.stringify(value));
  }

  async hget<T>(key: string, field: string): Promise<T | null> {
    const value = await this.redis.hget(key, field);
    return value ? JSON.parse(value) : null;
  }

  async hdel(key: string, field: string): Promise<void> {
    await this.redis.hdel(key, field);
  }

  async hgetall<T>(key: string): Promise<Record<string, T>> {
    const hash = await this.redis.hgetall(key);
    const result: Record<string, T> = {};

    for (const [field, value] of Object.entries(hash)) {
      result[field] = JSON.parse(value);
    }

    return result;
  }

  // Set operations
  async sadd(key: string, ...members: string[]): Promise<number> {
    return this.redis.sadd(key, ...members);
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    return this.redis.srem(key, ...members);
  }

  async smembers(key: string): Promise<string[]> {
    return this.redis.smembers(key);
  }

  async sismember(key: string, member: string): Promise<boolean> {
    const result = await this.redis.sismember(key, member);
    return result === 1;
  }

  // List operations
  async lpush(key: string, ...values: string[]): Promise<number> {
    return this.redis.lpush(key, ...values);
  }

  async rpush(key: string, ...values: string[]): Promise<number> {
    return this.redis.rpush(key, ...values);
  }

  async lpop(key: string): Promise<string | null> {
    return this.redis.lpop(key);
  }

  async rpop(key: string): Promise<string | null> {
    return this.redis.rpop(key);
  }

  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    return this.redis.lrange(key, start, stop);
  }

  // TTL operations
  async ttl(key: string): Promise<number> {
    return this.redis.ttl(key);
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    const result = await this.redis.expire(key, seconds);
    return result === 1;
  }

  async persist(key: string): Promise<boolean> {
    const result = await this.redis.persist(key);
    return result === 1;
  }

  // Utility methods for common patterns
  async cacheUserData(userId: string, userData: any, ttl: number = 3600): Promise<void> {
    await this.set(`user:${userId}`, userData, ttl);
  }

  async getUserData<T>(userId: string): Promise<T | undefined> {
    return this.get<T>(`user:${userId}`);
  }

  async invalidateUserCache(userId: string): Promise<void> {
    await this.deleteByPattern(`user:${userId}*`);
  }

  async cacheSessionData(sessionId: string, sessionData: any, ttl: number = 1800): Promise<void> {
    await this.set(`session:${sessionId}`, sessionData, ttl);
  }

  async getSessionData<T>(sessionId: string): Promise<T | undefined> {
    return this.get<T>(`session:${sessionId}`);
  }

  async invalidateSessionCache(sessionId: string): Promise<void> {
    await this.del(`session:${sessionId}`);
  }

  // Rate limiting helper
  async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    // Use Redis transaction to ensure atomicity
    const multi = this.redis.multi();
    multi.zremrangebyscore(key, '-inf', windowStart);
    multi.zcard(key);
    multi.zadd(key, now, `${now}-${Math.random()}`);
    multi.expire(key, windowSeconds);

    const results = await multi.exec();
    const currentCount = (results?.[1]?.[1] as number) || 0;

    const allowed = currentCount < limit;
    const remaining = Math.max(0, limit - currentCount - 1);
    const resetTime = now + windowSeconds * 1000;

    return { allowed, remaining, resetTime };
  }

  // Cache statistics
  async getStats(): Promise<{
    keyCount: number;
    memory: any;
    hitRate?: number;
  }> {
    const info = await this.redis.info('memory');
    const keyCount = await this.redis.dbsize();

    const memoryInfo: any = {};
    info.split('\n').forEach((line) => {
      const [key, value] = line.split(':');
      if (key && value) {
        memoryInfo[key.trim()] = value.trim();
      }
    });

    return {
      keyCount,
      memory: memoryInfo,
    };
  }

  // Health check
  async ping(): Promise<string> {
    return this.redis.ping();
  }

  // Cleanup method
  async onModuleDestroy(): Promise<void> {
    await this.redis.quit();
  }
}
