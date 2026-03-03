"""
Tests for startup catch-up functionality
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from main import check_and_trigger_catchup


class TestStartupCatchup:
    """Test suite for check_and_trigger_catchup function"""
    
    @pytest.mark.asyncio
    async def test_triggers_catchup_when_overdue(self):
        """Test that catch-up is triggered when collection is overdue"""
        # Mock the state manager
        mock_state_manager = AsyncMock()
        mock_state_manager.is_overdue.return_value = True
        mock_state_manager.get_last_run.return_value = datetime.utcnow() - timedelta(hours=24)
        mock_state_manager.set_last_run = AsyncMock()
        
        # Mock the task
        mock_task = MagicMock()
        mock_task.id = "test-task-id"
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('tasks.scheduled_source_fetch') as mock_scheduled_fetch:
                mock_scheduled_fetch.delay.return_value = mock_task
                
                # Call the function
                await check_and_trigger_catchup()
                
                # Verify state manager was called
                mock_state_manager.is_overdue.assert_called_once_with(threshold_hours=12)
                mock_state_manager.get_last_run.assert_called_once()
                
                # Verify task was queued
                mock_scheduled_fetch.delay.assert_called_once()
                
                # Verify last_run was updated
                mock_state_manager.set_last_run.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_no_catchup_when_not_overdue(self):
        """Test that catch-up is not triggered when collection is not overdue"""
        # Mock the state manager
        mock_state_manager = AsyncMock()
        mock_state_manager.is_overdue.return_value = False
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('tasks.scheduled_source_fetch') as mock_scheduled_fetch:
                
                # Call the function
                await check_and_trigger_catchup()
                
                # Verify state manager was called
                mock_state_manager.is_overdue.assert_called_once_with(threshold_hours=12)
                
                # Verify task was NOT queued
                mock_scheduled_fetch.delay.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_handles_redis_error_gracefully(self):
        """Test that Redis errors are handled gracefully without failing startup"""
        # Mock the state manager to raise an exception
        mock_state_manager = AsyncMock()
        mock_state_manager.is_overdue.side_effect = Exception("Redis connection failed")
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            # Should not raise an exception
            await check_and_trigger_catchup()
            
            # Verify the function completed without raising
            mock_state_manager.is_overdue.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_handles_task_queue_error(self):
        """Test that task queueing errors are logged but don't prevent timestamp update"""
        # Mock the state manager
        mock_state_manager = AsyncMock()
        mock_state_manager.is_overdue.return_value = True
        mock_state_manager.get_last_run.return_value = datetime.utcnow() - timedelta(hours=24)
        mock_state_manager.set_last_run = AsyncMock()
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('tasks.scheduled_source_fetch') as mock_scheduled_fetch:
                # Make task queueing fail
                mock_scheduled_fetch.delay.side_effect = Exception("Celery broker unavailable")
                
                # Should not raise an exception
                await check_and_trigger_catchup()
                
                # Verify state manager was called
                mock_state_manager.is_overdue.assert_called_once()
                
                # Verify task queueing was attempted
                mock_scheduled_fetch.delay.assert_called_once()
                
                # Verify last_run was NOT updated (because task queueing failed)
                mock_state_manager.set_last_run.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_triggers_catchup_when_no_previous_run(self):
        """Test that catch-up is triggered when there's no previous collection"""
        # Mock the state manager
        mock_state_manager = AsyncMock()
        mock_state_manager.is_overdue.return_value = True
        mock_state_manager.get_last_run.return_value = None  # No previous run
        mock_state_manager.set_last_run = AsyncMock()
        
        # Mock the task
        mock_task = MagicMock()
        mock_task.id = "test-task-id"
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('tasks.scheduled_source_fetch') as mock_scheduled_fetch:
                mock_scheduled_fetch.delay.return_value = mock_task
                
                # Call the function
                await check_and_trigger_catchup()
                
                # Verify state manager was called
                mock_state_manager.is_overdue.assert_called_once_with(threshold_hours=12)
                
                # Verify task was queued
                mock_scheduled_fetch.delay.assert_called_once()
                
                # Verify last_run was updated
                mock_state_manager.set_last_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_lifespan_calls_check_and_trigger_catchup(self):
        """Test that the lifespan function calls check_and_trigger_catchup during startup"""
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        
        # Mock check_and_trigger_catchup
        with patch('main.check_and_trigger_catchup', new_callable=AsyncMock) as mock_catchup:
            # Mock source manager to avoid actual file watching
            with patch('services.source_manager.get_source_manager') as mock_source_manager:
                mock_manager = MagicMock()
                mock_manager.start_watching = MagicMock()
                mock_manager.stop_watching = MagicMock()
                mock_source_manager.return_value = mock_manager
                
                # Import app after mocking to ensure mocks are in place
                from main import app
                
                # Create test client which triggers lifespan
                with TestClient(app):
                    # Verify check_and_trigger_catchup was called during startup
                    mock_catchup.assert_called_once()
