"""
AI Shield Intelligence - Collection State Manager
Manages collection state and locking using Redis
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)


class CollectionStateManager:
    """
    Manages collection state and distributed locking using Redis.
    
    This class provides async methods for:
    - Tracking last collection run timestamp
    - Tracking last collection status
    - Distributed locking to prevent concurrent collections
    - Overdue detection based on elapsed time
    """
    
    # Redis key constants
    KEY_LAST_RUN = "collection:last_run"
    KEY_LAST_STATUS = "collection:last_status"
    KEY_LOCK = "collection:lock"
    
    # Lock TTL in seconds (2 hours)
    LOCK_TTL_SECONDS = 2 * 60 * 60
    
    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize the CollectionStateManager.
        
        Args:
            redis_url: Redis connection URL. If None, uses settings.redis_url
        """
        self.redis_url = redis_url or settings.redis_url
        self._redis_client: Optional[aioredis.Redis] = None
    
    async def _get_redis_client(self) -> aioredis.Redis:
        """
        Get or create Redis client with connection pooling.
        
        Returns:
            Redis client instance
        """
        if self._redis_client is None:
            self._redis_client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                encoding="utf-8"
            )
        return self._redis_client
    
    async def close(self):
        """Close Redis connection and cleanup resources."""
        if self._redis_client is not None:
            await self._redis_client.close()
            self._redis_client = None
    
    async def get_last_run(self) -> Optional[datetime]:
        """
        Retrieve the timestamp of the last collection run.
        
        Returns:
            datetime object of last run, or None if never run
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            timestamp_str = await redis_client.get(self.KEY_LAST_RUN)
            
            if timestamp_str is None:
                logger.debug("No last run timestamp found in Redis")
                return None
            
            # Parse ISO 8601 timestamp
            last_run = datetime.fromisoformat(timestamp_str)
            logger.debug(f"Retrieved last run timestamp: {last_run}")
            return last_run
            
        except Exception as e:
            logger.error(f"Failed to get last run timestamp from Redis: {e}")
            raise
    
    async def set_last_run(self, timestamp: datetime) -> None:
        """
        Update the last collection run timestamp.
        
        Args:
            timestamp: datetime object to store
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            # Store as ISO 8601 string
            timestamp_str = timestamp.isoformat()
            await redis_client.set(self.KEY_LAST_RUN, timestamp_str)
            logger.info(f"Updated last run timestamp to: {timestamp_str}")
            
        except Exception as e:
            logger.error(f"Failed to set last run timestamp in Redis: {e}")
            raise
    
    async def get_last_status(self) -> str:
        """
        Retrieve the last collection status.
        
        Returns:
            Status string: "success", "failed", "running", or "unknown" if not set
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            status = await redis_client.get(self.KEY_LAST_STATUS)
            
            if status is None:
                logger.debug("No last status found in Redis")
                return "unknown"
            
            logger.debug(f"Retrieved last status: {status}")
            return status
            
        except Exception as e:
            logger.error(f"Failed to get last status from Redis: {e}")
            raise
    
    async def set_last_status(self, status: str) -> None:
        """
        Update the last collection status.
        
        Args:
            status: Status string ("success", "failed", "running")
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            await redis_client.set(self.KEY_LAST_STATUS, status)
            logger.info(f"Updated last status to: {status}")
            
        except Exception as e:
            logger.error(f"Failed to set last status in Redis: {e}")
            raise
    
    async def acquire_lock(self) -> bool:
        """
        Attempt to acquire the collection lock with 2-hour TTL.
        
        Uses Redis SET NX EX to atomically set the lock only if it doesn't exist,
        with automatic expiration after 2 hours.
        
        Returns:
            True if lock was acquired, False if lock is already held
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            lock_value = f"locked:{datetime.utcnow().isoformat()}"
            
            # SET NX EX: Set if Not eXists with EXpiration
            result = await redis_client.set(
                self.KEY_LOCK,
                lock_value,
                nx=True,  # Only set if key doesn't exist
                ex=self.LOCK_TTL_SECONDS  # Expiration in seconds
            )
            
            if result:
                logger.info(f"Collection lock acquired with {self.LOCK_TTL_SECONDS}s TTL")
                return True
            else:
                logger.warning("Collection lock is already held")
                return False
                
        except Exception as e:
            logger.error(f"Failed to acquire collection lock: {e}")
            raise
    
    async def release_lock(self) -> None:
        """
        Release the collection lock.
        
        Uses Redis DEL to remove the lock key.
        
        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            result = await redis_client.delete(self.KEY_LOCK)
            
            if result > 0:
                logger.info("Collection lock released")
            else:
                logger.warning("Collection lock was not held (may have expired)")
                
        except Exception as e:
            logger.error(f"Failed to release collection lock: {e}")
            raise
    
    async def is_overdue(self, threshold_hours: int = 12) -> bool:
        """
        Check if the collection is overdue based on elapsed time.
        
        Args:
            threshold_hours: Number of hours after which collection is considered overdue
            
        Returns:
            True if elapsed time > threshold_hours, False otherwise
            
        Raises:
            Exception: If Redis operation fails
        """
        try:
            last_run = await self.get_last_run()
            
            if last_run is None:
                logger.info("No previous collection found, considering overdue")
                return True
            
            elapsed = datetime.utcnow() - last_run
            elapsed_hours = elapsed.total_seconds() / 3600
            
            is_overdue = elapsed_hours > threshold_hours
            
            if is_overdue:
                logger.warning(
                    f"Collection is overdue: {elapsed_hours:.1f} hours elapsed "
                    f"(threshold: {threshold_hours} hours)"
                )
            else:
                logger.debug(
                    f"Collection is not overdue: {elapsed_hours:.1f} hours elapsed "
                    f"(threshold: {threshold_hours} hours)"
                )
            
            return is_overdue
            
        except Exception as e:
            logger.error(f"Failed to check if collection is overdue: {e}")
            raise


# Global instance for easy access
_collection_state_manager: Optional[CollectionStateManager] = None


def get_collection_state_manager() -> CollectionStateManager:
    """
    Get or create the global CollectionStateManager instance.
    
    Returns:
        CollectionStateManager instance
    """
    global _collection_state_manager
    if _collection_state_manager is None:
        _collection_state_manager = CollectionStateManager()
    return _collection_state_manager


async def close_collection_state_manager():
    """Close the global CollectionStateManager instance."""
    global _collection_state_manager
    if _collection_state_manager is not None:
        await _collection_state_manager.close()
        _collection_state_manager = None
