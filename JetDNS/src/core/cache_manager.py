"""
High-Performance Cache Manager
Multi-tier caching with Redis backend and in-memory L1 cache
"""

import asyncio
import logging
import time
import json
import hashlib
import pickle
from typing import Dict, Optional, Union, List, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import weakref

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class CacheLevel(Enum):
    L1_MEMORY = 1
    L2_REDIS = 2
    L3_DISK = 3


@dataclass
class CacheEntry:
    key: str
    value: Any
    ttl: int
    created_at: float
    hit_count: int = 0
    last_accessed: float = 0
    size_bytes: int = 0


class CacheStats:
    """Cache statistics tracking"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.l1_hits = 0
        self.l1_misses = 0
        self.l2_hits = 0 
        self.l2_misses = 0
        self.l3_hits = 0
        self.l3_misses = 0
        self.evictions = 0
        self.total_requests = 0
        self.total_size = 0
        self.start_time = time.time()

    @property
    def l1_hit_rate(self) -> float:
        total = self.l1_hits + self.l1_misses
        return (self.l1_hits / total * 100) if total > 0 else 0

    @property
    def l2_hit_rate(self) -> float:
        total = self.l2_hits + self.l2_misses
        return (self.l2_hits / total * 100) if total > 0 else 0

    @property
    def overall_hit_rate(self) -> float:
        total_hits = self.l1_hits + self.l2_hits + self.l3_hits
        return (total_hits / self.total_requests * 100) if self.total_requests > 0 else 0


class AdvancedCacheManager:
    """Multi-tier high-performance cache manager"""

    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # L1 Cache (In-Memory)
        self.l1_cache: Dict[str, CacheEntry] = {}
        self.l1_max_size = config.get('l1_max_size', 10000)  # Max entries
        self.l1_max_memory = config.get('l1_max_memory_mb', 100) * 1024 * 1024  # Bytes

        # L2 Cache (Redis)
        self.redis_client = None
        self.redis_enabled = config.get('enabled', False) and REDIS_AVAILABLE
        self.redis_host = config.get('host', 'localhost')
        self.redis_port = config.get('port', 6379)
        self.redis_db = config.get('db', 0)
        self.redis_password = config.get('password')

        # L3 Cache (Disk) - for persistent caching
        self.disk_cache_enabled = config.get('disk_cache_enabled', False)
        self.disk_cache_path = config.get('disk_cache_path', 'data/cache')

        # Cache settings
        self.default_ttl = config.get('default_ttl', 300)  # 5 minutes
        self.max_key_length = config.get('max_key_length', 250)
        self.compression_enabled = config.get('compression', True)

        # Statistics
        self.stats = CacheStats()

        # Background tasks
        self.cleanup_task = None
        self.stats_task = None

        # LRU tracking
        self.access_order = []

    async def initialize(self):
        """Initialize cache manager"""
        try:
            # Initialize Redis connection
            if self.redis_enabled:
                await self._initialize_redis()

            # Initialize disk cache
            if self.disk_cache_enabled:
                await self._initialize_disk_cache()

            # Start background tasks
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.stats_task = asyncio.create_task(self._stats_loop())

            self.logger.info(f"🧠 Cache Manager initialized (L1: Memory, L2: Redis={self.redis_enabled})")

        except Exception as e:
            self.logger.error(f"Failed to initialize cache manager: {e}")
            raise

    async def get(self, key: str) -> Optional[bytes]:
        """Get value from cache (multi-tier lookup)"""
        self.stats.total_requests += 1

        try:
            # Normalize key
            cache_key = self._normalize_key(key)

            # L1 Cache lookup (Memory)
            l1_result = await self._get_from_l1(cache_key)
            if l1_result is not None:
                self.stats.l1_hits += 1
                return l1_result

            self.stats.l1_misses += 1

            # L2 Cache lookup (Redis)
            if self.redis_enabled:
                l2_result = await self._get_from_l2(cache_key)
                if l2_result is not None:
                    self.stats.l2_hits += 1
                    # Promote to L1 cache
                    await self._set_to_l1(cache_key, l2_result, self.default_ttl)
                    return l2_result

                self.stats.l2_misses += 1

            # L3 Cache lookup (Disk) - if enabled
            if self.disk_cache_enabled:
                l3_result = await self._get_from_l3(cache_key)
                if l3_result is not None:
                    self.stats.l3_hits += 1
                    # Promote to higher tiers
                    await self._set_to_l1(cache_key, l3_result, self.default_ttl)
                    if self.redis_enabled:
                        await self._set_to_l2(cache_key, l3_result, self.default_ttl)
                    return l3_result

                self.stats.l3_misses += 1

            return None

        except Exception as e:
            self.logger.error(f"Error getting cache key {key}: {e}")
            return None

    async def set(self, key: str, value: bytes, ttl: Optional[int] = None) -> bool:
        """Set value in cache (multi-tier storage)"""
        try:
            if ttl is None:
                ttl = self.default_ttl

            cache_key = self._normalize_key(key)

            # Set in all available cache tiers
            success = True

            # L1 Cache (Memory)
            l1_success = await self._set_to_l1(cache_key, value, ttl)
            success = success and l1_success

            # L2 Cache (Redis)
            if self.redis_enabled:
                l2_success = await self._set_to_l2(cache_key, value, ttl)
                success = success and l2_success

            # L3 Cache (Disk)
            if self.disk_cache_enabled:
                l3_success = await self._set_to_l3(cache_key, value, ttl)
                success = success and l3_success

            return success

        except Exception as e:
            self.logger.error(f"Error setting cache key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from all cache tiers"""
        try:
            cache_key = self._normalize_key(key)
            success = True

            # Delete from L1
            if cache_key in self.l1_cache:
                entry = self.l1_cache[cache_key]
                self.stats.total_size -= entry.size_bytes
                del self.l1_cache[cache_key]

            # Delete from L2 (Redis)
            if self.redis_enabled and self.redis_client:
                await self.redis_client.delete(cache_key)

            # Delete from L3 (Disk)
            if self.disk_cache_enabled:
                await self._delete_from_l3(cache_key)

            return success

        except Exception as e:
            self.logger.error(f"Error deleting cache key {key}: {e}")
            return False

    async def clear(self) -> bool:
        """Clear all cache tiers"""
        try:
            # Clear L1
            self.l1_cache.clear()
            self.access_order.clear()
            self.stats.total_size = 0

            # Clear L2 (Redis)
            if self.redis_enabled and self.redis_client:
                await self.redis_client.flushdb()

            # Clear L3 (Disk)
            if self.disk_cache_enabled:
                await self._clear_l3()

            self.logger.info("🧹 All cache tiers cleared")
            return True

        except Exception as e:
            self.logger.error(f"Error clearing cache: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in any cache tier"""
        cache_key = self._normalize_key(key)

        # Check L1
        if cache_key in self.l1_cache:
            entry = self.l1_cache[cache_key]
            if not self._is_expired(entry):
                return True

        # Check L2 (Redis)
        if self.redis_enabled and self.redis_client:
            exists = await self.redis_client.exists(cache_key)
            if exists:
                return True

        # Check L3 (Disk)
        if self.disk_cache_enabled:
            return await self._exists_in_l3(cache_key)

        return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        memory_usage = sum(entry.size_bytes for entry in self.l1_cache.values())

        stats = {
            'l1_cache': {
                'entries': len(self.l1_cache),
                'max_entries': self.l1_max_size,
                'memory_usage_bytes': memory_usage,
                'max_memory_bytes': self.l1_max_memory,
                'memory_usage_percent': (memory_usage / self.l1_max_memory) * 100,
                'hit_rate': self.stats.l1_hit_rate,
                'hits': self.stats.l1_hits,
                'misses': self.stats.l1_misses
            },
            'l2_cache': {
                'enabled': self.redis_enabled,
                'hit_rate': self.stats.l2_hit_rate,
                'hits': self.stats.l2_hits,
                'misses': self.stats.l2_misses
            },
            'overall': {
                'total_requests': self.stats.total_requests,
                'overall_hit_rate': self.stats.overall_hit_rate,
                'evictions': self.stats.evictions,
                'uptime_seconds': time.time() - self.stats.start_time
            }
        }

        # Add Redis-specific stats if available
        if self.redis_enabled and self.redis_client:
            try:
                redis_info = await self.redis_client.info('memory')
                stats['l2_cache']['memory_usage'] = redis_info.get('used_memory_human', 'N/A')
                stats['l2_cache']['connections'] = redis_info.get('connected_clients', 0)
            except:
                pass

        return stats

    # L1 Cache Operations (Memory)
    async def _get_from_l1(self, key: str) -> Optional[bytes]:
        """Get from L1 memory cache"""
        if key not in self.l1_cache:
            return None

        entry = self.l1_cache[key]

        # Check if expired
        if self._is_expired(entry):
            # Remove expired entry
            self.stats.total_size -= entry.size_bytes
            del self.l1_cache[key]
            if key in self.access_order:
                self.access_order.remove(key)
            return None

        # Update access tracking
        entry.hit_count += 1
        entry.last_accessed = time.time()

        # Update LRU order
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

        return entry.value

    async def _set_to_l1(self, key: str, value: bytes, ttl: int) -> bool:
        """Set to L1 memory cache"""
        try:
            value_size = len(value)

            # Check if we need to make space
            while (len(self.l1_cache) >= self.l1_max_size or 
                   self.stats.total_size + value_size > self.l1_max_memory):
                if not await self._evict_l1_entry():
                    break  # No more entries to evict

            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                ttl=ttl,
                created_at=time.time(),
                hit_count=0,
                last_accessed=time.time(),
                size_bytes=value_size
            )

            # Remove old entry if exists
            if key in self.l1_cache:
                old_entry = self.l1_cache[key]
                self.stats.total_size -= old_entry.size_bytes

            # Add new entry
            self.l1_cache[key] = entry
            self.stats.total_size += value_size

            # Update LRU order
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)

            return True

        except Exception as e:
            self.logger.error(f"Error setting L1 cache entry: {e}")
            return False

    async def _evict_l1_entry(self) -> bool:
        """Evict least recently used entry from L1 cache"""
        if not self.access_order:
            return False

        # Get LRU key
        lru_key = self.access_order[0]

        if lru_key in self.l1_cache:
            entry = self.l1_cache[lru_key]
            self.stats.total_size -= entry.size_bytes
            del self.l1_cache[lru_key]
            self.stats.evictions += 1

        self.access_order.remove(lru_key)
        return True

    # L2 Cache Operations (Redis)
    async def _initialize_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                decode_responses=False,  # Keep binary data
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=30
            )

            # Test connection
            await self.redis_client.ping()
            self.logger.info(f"✅ Redis connected ({self.redis_host}:{self.redis_port})")

        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self.redis_enabled = False
            self.redis_client = None
            raise

    async def _get_from_l2(self, key: str) -> Optional[bytes]:
        """Get from L2 Redis cache"""
        if not self.redis_client:
            return None

        try:
            value = await self.redis_client.get(key)
            return value
        except Exception as e:
            self.logger.error(f"Error getting from Redis: {e}")
            return None

    async def _set_to_l2(self, key: str, value: bytes, ttl: int) -> bool:
        """Set to L2 Redis cache"""
        if not self.redis_client:
            return False

        try:
            await self.redis_client.setex(key, ttl, value)
            return True
        except Exception as e:
            self.logger.error(f"Error setting to Redis: {e}")
            return False

    # L3 Cache Operations (Disk)
    async def _initialize_disk_cache(self):
        """Initialize disk cache"""
        try:
            import os
            os.makedirs(self.disk_cache_path, exist_ok=True)
            self.logger.info(f"💽 Disk cache initialized: {self.disk_cache_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize disk cache: {e}")
            self.disk_cache_enabled = False

    async def _get_from_l3(self, key: str) -> Optional[bytes]:
        """Get from L3 disk cache"""
        if not self.disk_cache_enabled:
            return None

        try:
            file_path = self._get_disk_path(key)

            # Check if file exists and is not expired
            import os
            if not os.path.exists(file_path):
                return None

            # Check expiration based on file modification time
            stat = os.stat(file_path)
            if time.time() - stat.st_mtime > self.default_ttl:
                os.remove(file_path)
                return None

            # Read file
            with open(file_path, 'rb') as f:
                return f.read()

        except Exception as e:
            self.logger.debug(f"Error reading from disk cache: {e}")
            return None

    async def _set_to_l3(self, key: str, value: bytes, ttl: int) -> bool:
        """Set to L3 disk cache"""
        if not self.disk_cache_enabled:
            return False

        try:
            file_path = self._get_disk_path(key)

            # Create directory if needed
            import os
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Write file
            with open(file_path, 'wb') as f:
                f.write(value)

            return True

        except Exception as e:
            self.logger.error(f"Error writing to disk cache: {e}")
            return False

    async def _delete_from_l3(self, key: str) -> bool:
        """Delete from L3 disk cache"""
        try:
            file_path = self._get_disk_path(key)
            import os
            if os.path.exists(file_path):
                os.remove(file_path)
            return True
        except Exception as e:
            self.logger.debug(f"Error deleting from disk cache: {e}")
            return False

    async def _exists_in_l3(self, key: str) -> bool:
        """Check if key exists in L3 disk cache"""
        try:
            file_path = self._get_disk_path(key)
            import os
            if not os.path.exists(file_path):
                return False

            # Check if expired
            stat = os.stat(file_path)
            if time.time() - stat.st_mtime > self.default_ttl:
                os.remove(file_path)
                return False

            return True
        except:
            return False

    async def _clear_l3(self):
        """Clear L3 disk cache"""
        try:
            import os
            import shutil
            if os.path.exists(self.disk_cache_path):
                shutil.rmtree(self.disk_cache_path)
                os.makedirs(self.disk_cache_path, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Error clearing disk cache: {e}")

    def _get_disk_path(self, key: str) -> str:
        """Get disk file path for cache key"""
        # Create subdirectories based on key hash to avoid too many files in one directory
        key_hash = hashlib.md5(key.encode()).hexdigest()
        subdir1 = key_hash[:2]
        subdir2 = key_hash[2:4]
        filename = key_hash[4:]

        return f"{self.disk_cache_path}/{subdir1}/{subdir2}/{filename}.cache"

    # Utility methods
    def _normalize_key(self, key: str) -> str:
        """Normalize cache key"""
        if len(key) > self.max_key_length:
            # Hash long keys
            return f"hash:{hashlib.md5(key.encode()).hexdigest()}"
        return key

    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired"""
        return time.time() - entry.created_at > entry.ttl

    # Background tasks
    async def _cleanup_loop(self):
        """Background cleanup task"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Clean expired L1 entries
                current_time = time.time()
                expired_keys = []

                for key, entry in self.l1_cache.items():
                    if self._is_expired(entry):
                        expired_keys.append(key)

                for key in expired_keys:
                    entry = self.l1_cache[key]
                    self.stats.total_size -= entry.size_bytes
                    del self.l1_cache[key]
                    if key in self.access_order:
                        self.access_order.remove(key)

                if expired_keys:
                    self.logger.debug(f"🧹 Cleaned {len(expired_keys)} expired L1 entries")

                # Clean disk cache
                if self.disk_cache_enabled:
                    await self._cleanup_disk_cache()

            except Exception as e:
                self.logger.error(f"Cache cleanup error: {e}")

            await asyncio.sleep(300)  # Wait 5 minutes between cleanups

    async def _cleanup_disk_cache(self):
        """Clean up expired disk cache entries"""
        try:
            import os
            import time as time_module

            current_time = time_module.time()
            cleaned_count = 0

            for root, dirs, files in os.walk(self.disk_cache_path):
                for file in files:
                    if file.endswith('.cache'):
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            if current_time - stat.st_mtime > self.default_ttl:
                                os.remove(file_path)
                                cleaned_count += 1
                        except:
                            pass  # Ignore errors for individual files

            if cleaned_count > 0:
                self.logger.debug(f"🧹 Cleaned {cleaned_count} expired disk cache entries")

        except Exception as e:
            self.logger.debug(f"Disk cache cleanup error: {e}")

    async def _stats_loop(self):
        """Background statistics logging"""
        while True:
            try:
                await asyncio.sleep(300)  # Log every 5 minutes

                stats = await self.get_stats()
                self.logger.info(
                    f"📊 Cache Stats - L1: {stats['l1_cache']['hit_rate']:.1f}% hit rate "
                    f"({stats['l1_cache']['entries']} entries), "
                    f"Overall: {stats['overall']['overall_hit_rate']:.1f}% hit rate"
                )

            except Exception as e:
                self.logger.error(f"Stats logging error: {e}")

    async def close(self):
        """Close cache manager and cleanup resources"""
        try:
            # Cancel background tasks
            if self.cleanup_task:
                self.cleanup_task.cancel()
            if self.stats_task:
                self.stats_task.cancel()

            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()

            self.logger.info("🔒 Cache Manager closed")

        except Exception as e:
            self.logger.error(f"Error closing cache manager: {e}")

    # Advanced cache operations
    async def warm_cache(self, entries: List[Tuple[str, bytes, int]]):
        """Pre-warm cache with entries"""
        try:
            for key, value, ttl in entries:
                await self.set(key, value, ttl)

            self.logger.info(f"🔥 Cache warmed with {len(entries)} entries")

        except Exception as e:
            self.logger.error(f"Cache warming error: {e}")

    async def get_popular_keys(self, limit: int = 100) -> List[Tuple[str, int]]:
        """Get most popular cache keys by hit count"""
        try:
            popular = []
            for key, entry in self.l1_cache.items():
                if not self._is_expired(entry):
                    popular.append((key, entry.hit_count))

            popular.sort(key=lambda x: x[1], reverse=True)
            return popular[:limit]

        except Exception as e:
            self.logger.error(f"Error getting popular keys: {e}")
            return []

    async def compress_value(self, value: bytes) -> bytes:
        """Compress value if compression is enabled"""
        if not self.compression_enabled:
            return value

        try:
            import gzip
            return gzip.compress(value)
        except Exception as e:
            self.logger.debug(f"Compression error: {e}")
            return value

    async def decompress_value(self, value: bytes) -> bytes:
        """Decompress value if needed"""
        if not self.compression_enabled:
            return value

        try:
            import gzip
            return gzip.decompress(value)
        except Exception as e:
            self.logger.debug(f"Decompression error: {e}")
            return value
