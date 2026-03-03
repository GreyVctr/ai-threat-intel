"""
Unit tests for CollectionStateManager
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from services.collection_state import CollectionStateManager


@pytest.fixture
async def state_manager():
    """Create a CollectionStateManager instance for testing."""
    manager = CollectionStateManager()
    yield manager
    await manager.close()


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    mock = AsyncMock()
    return mock


class TestCollectionStateManager:
    """Test suite for CollectionStateManager."""
    
    @pytest.mark.asyncio
    async def test_get_last_run_returns_none_when_not_set(self, state_manager, mock_redis):
        """Test that get_last_run returns None when no timestamp is stored."""
        mock_redis.get.return_value = None
        state_manager._redis_client = mock_redis
        
        result = await state_manager.get_last_run()
        
        assert result is None
        mock_redis.get.assert_called_once_with(CollectionStateManager.KEY_LAST_RUN)
    
    @pytest.mark.asyncio
    async def test_get_last_run_returns_datetime(self, state_manager, mock_redis):
        """Test that get_last_run returns a datetime object."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        mock_redis.get.return_value = timestamp.isoformat()
        state_manager._redis_client = mock_redis
        
        result = await state_manager.get_last_run()
        
        assert result == timestamp
        mock_redis.get.assert_called_once_with(CollectionStateManager.KEY_LAST_RUN)
    
    @pytest.mark.asyncio
    async def test_set_last_run_stores_timestamp(self, state_manager, mock_redis):
        """Test that set_last_run stores timestamp as ISO string."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        state_manager._redis_client = mock_redis
        
        await state_manager.set_last_run(timestamp)
        
        mock_redis.set.assert_called_once_with(
            CollectionStateManager.KEY_LAST_RUN,
            timestamp.isoformat()
        )
    
    @pytest.mark.asyncio
    async def test_get_last_status_returns_unknown_when_not_set(self, state_manager, mock_redis):
        """Test that get_last_status returns 'unknown' when not set."""
        mock_redis.get.return_value = None
        state_manager._redis_client = mock_redis
        
        result = await state_manager.get_last_status()
        
        assert result == "unknown"
        mock_redis.get.assert_called_once_with(CollectionStateManager.KEY_LAST_STATUS)
    
    @pytest.mark.asyncio
    async def test_get_last_status_returns_status(self, state_manager, mock_redis):
        """Test that get_last_status returns the stored status."""
        mock_redis.get.return_value = "success"
        state_manager._redis_client = mock_redis
        
        result = await state_manager.get_last_status()
        
        assert result == "success"
        mock_redis.get.assert_called_once_with(CollectionStateManager.KEY_LAST_STATUS)
    
    @pytest.mark.asyncio
    async def test_set_last_status_stores_status(self, state_manager, mock_redis):
        """Test that set_last_status stores the status."""
        state_manager._redis_client = mock_redis
        
        await state_manager.set_last_status("running")
        
        mock_redis.set.assert_called_once_with(
            CollectionStateManager.KEY_LAST_STATUS,
            "running"
        )
    
    @pytest.mark.asyncio
    async def test_acquire_lock_succeeds_when_not_held(self, state_manager, mock_redis):
        """Test that acquire_lock returns True when lock is not held."""
        mock_redis.set.return_value = True
        state_manager._redis_client = mock_redis
        
        result = await state_manager.acquire_lock()
        
        assert result is True
        # Verify SET NX EX was called
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == CollectionStateManager.KEY_LOCK
        assert call_args[1]["nx"] is True
        assert call_args[1]["ex"] == CollectionStateManager.LOCK_TTL_SECONDS
    
    @pytest.mark.asyncio
    async def test_acquire_lock_fails_when_already_held(self, state_manager, mock_redis):
        """Test that acquire_lock returns False when lock is already held."""
        mock_redis.set.return_value = None  # Redis returns None when NX fails
        state_manager._redis_client = mock_redis
        
        result = await state_manager.acquire_lock()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_release_lock_deletes_key(self, state_manager, mock_redis):
        """Test that release_lock deletes the lock key."""
        mock_redis.delete.return_value = 1
        state_manager._redis_client = mock_redis
        
        await state_manager.release_lock()
        
        mock_redis.delete.assert_called_once_with(CollectionStateManager.KEY_LOCK)
    
    @pytest.mark.asyncio
    async def test_is_overdue_returns_true_when_no_last_run(self, state_manager, mock_redis):
        """Test that is_overdue returns True when no previous run exists."""
        mock_redis.get.return_value = None
        state_manager._redis_client = mock_redis
        
        result = await state_manager.is_overdue()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_overdue_returns_true_when_elapsed_exceeds_threshold(self, state_manager, mock_redis):
        """Test that is_overdue returns True when elapsed time > threshold."""
        # Set last run to 13 hours ago
        last_run = datetime.utcnow() - timedelta(hours=13)
        mock_redis.get.return_value = last_run.isoformat()
        state_manager._redis_client = mock_redis
        
        result = await state_manager.is_overdue(threshold_hours=12)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_overdue_returns_false_when_elapsed_within_threshold(self, state_manager, mock_redis):
        """Test that is_overdue returns False when elapsed time <= threshold."""
        # Set last run to 6 hours ago
        last_run = datetime.utcnow() - timedelta(hours=6)
        mock_redis.get.return_value = last_run.isoformat()
        state_manager._redis_client = mock_redis
        
        result = await state_manager.is_overdue(threshold_hours=12)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_is_overdue_uses_custom_threshold(self, state_manager, mock_redis):
        """Test that is_overdue respects custom threshold."""
        # Set last run to 7 hours ago
        last_run = datetime.utcnow() - timedelta(hours=7)
        mock_redis.get.return_value = last_run.isoformat()
        state_manager._redis_client = mock_redis
        
        # Should be overdue with 6-hour threshold
        result = await state_manager.is_overdue(threshold_hours=6)
        assert result is True
        
        # Should not be overdue with 8-hour threshold
        result = await state_manager.is_overdue(threshold_hours=8)
        assert result is False
