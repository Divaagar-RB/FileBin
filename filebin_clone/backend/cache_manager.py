from cachetools import LRUCache, TTLCache, cached
from functools import wraps
import hashlib
import json
from typing import Any, Optional, Dict, List
from datetime import datetime

class FileSystemCacheManager:
    """Centralized cache management for file upload system"""
    
    def __init__(self):
        # Bin metadata cache - stores bin info
        self.bin_cache = LRUCache(maxsize=2000)
        
        # File listings cache - stores file lists for bins
        self.file_list_cache = LRUCache(maxsize=1000) 
        
        # User bins cache - stores user's bin lists
        self.user_bins_cache = LRUCache(maxsize=500)
        
        # JWT/Auth cache with TTL
        self.auth_cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour
        
        # File existence cache for quick lookups
        self.file_exists_cache = TTLCache(maxsize=5000, ttl=300)  # 5 minutes
    
    def generate_cache_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate consistent cache key"""
        key_data = {
            'prefix': prefix,
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return f"{prefix}_{hashlib.md5(key_string.encode()).hexdigest()[:12]}"
    
    def invalidate_bin_cache(self, bin_id: str):
        """Invalidate all cache entries related to a bin"""
        # For cachetools.cached: key is the function argument tuple (bin_id,)
        self.bin_cache.pop(bin_id, None)
        self.file_list_cache.pop((bin_id,), None)

        # Also clear file existence cache
        keys_to_remove = [key for key in self.file_exists_cache.keys() 
                        if bin_id in str(key)]
        for key in keys_to_remove:
            self.file_exists_cache.pop(key, None)

        print(f"🗑️ Invalidated cache for bin {bin_id}")

    
    def invalidate_user_cache(self, user_id: str):
        self.user_bins_cache.pop((user_id,), None)
        print(f"🗑️ Invalidated user cache for {user_id}")

# Global cache instance
cache_manager = FileSystemCacheManager()