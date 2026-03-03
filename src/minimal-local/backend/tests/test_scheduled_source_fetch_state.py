"""
Unit tests for scheduled_source_fetch task state management
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime


class TestScheduledSourceFetchState:
    """Test scheduled_source_fetch task state management"""
    
    def test_updates_state_at_task_start(self):
        """Test that task updates collection state at start"""
        from tasks import scheduled_source_fetch
        
        # Mock the state manager
        mock_state_manager = Mock()
        mock_state_manager.set_last_run = AsyncMock()
        mock_state_manager.set_last_status = AsyncMock()
        mock_state_manager.release_lock = AsyncMock()
        
        # Mock source manager
        mock_source_manager = Mock()
        mock_source_manager.get_enabled_sources.return_value = []
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('services.source_manager.get_source_manager', return_value=mock_source_manager):
                # Call the task
                result = scheduled_source_fetch()
                
                # Verify state was updated at start
                assert mock_state_manager.set_last_run.call_count == 1
                assert mock_state_manager.set_last_status.call_count == 2  # "running" at start, "success" at end
                
                # Verify first status update was "running"
                first_status_call = mock_state_manager.set_last_status.call_args_list[0]
                assert first_status_call[0][0] == "running"
                
                # Verify result
                assert result['status'] == 'success'
    
    def test_updates_status_to_success_on_completion(self):
        """Test that task updates status to success on completion"""
        from tasks import scheduled_source_fetch
        
        # Mock the state manager
        mock_state_manager = Mock()
        mock_state_manager.set_last_run = AsyncMock()
        mock_state_manager.set_last_status = AsyncMock()
        mock_state_manager.release_lock = AsyncMock()
        
        # Mock source manager
        mock_source_manager = Mock()
        mock_source_manager.get_enabled_sources.return_value = []
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('services.source_manager.get_source_manager', return_value=mock_source_manager):
                # Call the task
                result = scheduled_source_fetch()
                
                # Verify status was updated to "success"
                second_status_call = mock_state_manager.set_last_status.call_args_list[1]
                assert second_status_call[0][0] == "success"
                
                # Verify lock was released
                assert mock_state_manager.release_lock.call_count == 1
    
    def test_updates_status_to_failed_on_error(self):
        """Test that task updates status to failed on error"""
        from tasks import scheduled_source_fetch
        
        # Mock the state manager
        mock_state_manager = Mock()
        mock_state_manager.set_last_run = AsyncMock()
        mock_state_manager.set_last_status = AsyncMock()
        mock_state_manager.release_lock = AsyncMock()
        
        # Mock source manager to raise an error
        mock_source_manager = Mock()
        mock_source_manager.get_enabled_sources.side_effect = Exception("Test error")
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('services.source_manager.get_source_manager', return_value=mock_source_manager):
                # Call the task
                result = scheduled_source_fetch()
                
                # Verify status was updated to "failed"
                # First call is "running", second call is "failed"
                assert mock_state_manager.set_last_status.call_count == 2
                second_status_call = mock_state_manager.set_last_status.call_args_list[1]
                assert second_status_call[0][0] == "failed"
                
                # Verify lock was released
                assert mock_state_manager.release_lock.call_count == 1
                
                # Verify result
                assert result['status'] == 'error'
    
    def test_releases_lock_in_finally_block(self):
        """Test that lock is released even if status update fails"""
        from tasks import scheduled_source_fetch
        
        # Mock the state manager
        mock_state_manager = Mock()
        mock_state_manager.set_last_run = AsyncMock()
        mock_state_manager.set_last_status = AsyncMock()
        mock_state_manager.release_lock = AsyncMock()
        
        # Mock source manager to raise an error
        mock_source_manager = Mock()
        mock_source_manager.get_enabled_sources.side_effect = Exception("Test error")
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('services.source_manager.get_source_manager', return_value=mock_source_manager):
                # Call the task
                result = scheduled_source_fetch()
                
                # Verify lock was released even though there was an error
                assert mock_state_manager.release_lock.call_count == 1
    
    def test_handles_lock_release_error_gracefully(self):
        """Test that task handles lock release errors gracefully"""
        from tasks import scheduled_source_fetch
        
        # Mock the state manager
        mock_state_manager = Mock()
        mock_state_manager.set_last_run = AsyncMock()
        mock_state_manager.set_last_status = AsyncMock()
        mock_state_manager.release_lock = AsyncMock(side_effect=Exception("Lock release error"))
        
        # Mock source manager to raise an error
        mock_source_manager = Mock()
        mock_source_manager.get_enabled_sources.side_effect = Exception("Test error")
        
        with patch('services.collection_state.get_collection_state_manager', return_value=mock_state_manager):
            with patch('services.source_manager.get_source_manager', return_value=mock_source_manager):
                # Call the task - should not raise exception
                result = scheduled_source_fetch()
                
                # Verify result is still returned despite lock release error
                assert result['status'] == 'error'
