#!/usr/bin/env python3
"""
Test script for Celery tasks

This script tests the Celery task queue functionality:
1. Tests task submission and execution
2. Tests source fetching task
3. Tests scheduled source fetching task
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tasks import celery_app, fetch_source, scheduled_source_fetch, get_task_status


def test_celery_connection():
    """Test connection to Celery broker"""
    print("\n=== Testing Celery Connection ===")
    
    try:
        # Inspect active workers
        inspect = celery_app.control.inspect()
        active_workers = inspect.active()
        
        if active_workers:
            print(f"✓ Connected to Celery broker")
            print(f"✓ Active workers: {list(active_workers.keys())}")
            return True
        else:
            print("✗ No active workers found")
            print("  Make sure Celery worker is running:")
            print("  celery -A tasks worker --loglevel=info --concurrency=2")
            return False
            
    except Exception as e:
        print(f"✗ Failed to connect to Celery broker: {e}")
        print("  Make sure Redis is running and accessible")
        return False


def test_fetch_source_task():
    """Test the fetch_source task"""
    print("\n=== Testing fetch_source Task ===")
    
    try:
        # Submit task
        print("Submitting fetch_source task for 'arXiv-CS-CR'...")
        result = fetch_source.delay('arXiv-CS-CR')
        
        print(f"✓ Task submitted with ID: {result.id}")
        print(f"  Task status: {result.status}")
        
        # Wait for task to complete (with timeout)
        print("Waiting for task to complete (timeout: 30s)...")
        try:
            task_result = result.get(timeout=30)
            print(f"✓ Task completed successfully")
            print(f"  Result: {task_result}")
            return True
        except Exception as e:
            print(f"✗ Task failed or timed out: {e}")
            print(f"  Task status: {result.status}")
            if result.failed():
                print(f"  Traceback: {result.traceback}")
            return False
            
    except Exception as e:
        print(f"✗ Failed to submit task: {e}")
        return False


def test_scheduled_source_fetch_task():
    """Test the scheduled_source_fetch task"""
    print("\n=== Testing scheduled_source_fetch Task ===")
    
    try:
        # Submit task
        print("Submitting scheduled_source_fetch task...")
        result = scheduled_source_fetch.delay()
        
        print(f"✓ Task submitted with ID: {result.id}")
        print(f"  Task status: {result.status}")
        
        # Wait for task to complete (with timeout)
        print("Waiting for task to complete (timeout: 30s)...")
        try:
            task_result = result.get(timeout=30)
            print(f"✓ Task completed successfully")
            print(f"  Result: {task_result}")
            return True
        except Exception as e:
            print(f"✗ Task failed or timed out: {e}")
            print(f"  Task status: {result.status}")
            if result.failed():
                print(f"  Traceback: {result.traceback}")
            return False
            
    except Exception as e:
        print(f"✗ Failed to submit task: {e}")
        return False


def test_task_status():
    """Test the get_task_status utility function"""
    print("\n=== Testing get_task_status Function ===")
    
    try:
        # Submit a task
        result = fetch_source.delay('test-source')
        task_id = result.id
        
        print(f"Submitted task with ID: {task_id}")
        
        # Get task status
        status = get_task_status(task_id)
        
        print(f"✓ Task status retrieved:")
        print(f"  Task ID: {status['task_id']}")
        print(f"  Status: {status['status']}")
        print(f"  Result: {status['result']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to get task status: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Celery Tasks Test Suite")
    print("=" * 60)
    
    results = []
    
    # Test 1: Celery connection
    results.append(("Celery Connection", test_celery_connection()))
    
    # Only run other tests if connection is successful
    if results[0][1]:
        # Test 2: fetch_source task
        results.append(("fetch_source Task", test_fetch_source_task()))
        
        # Test 3: scheduled_source_fetch task
        results.append(("scheduled_source_fetch Task", test_scheduled_source_fetch_task()))
        
        # Test 4: get_task_status function
        results.append(("get_task_status Function", test_task_status()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
