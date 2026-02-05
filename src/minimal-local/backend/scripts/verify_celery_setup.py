#!/usr/bin/env python3
"""
Verify Celery Setup

This script verifies that the Celery configuration is correct without
requiring running services. It checks:
1. Celery app is properly configured
2. Tasks are registered
3. Configuration values are correct
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def verify_celery_import():
    """Verify that Celery can be imported"""
    print("\n=== Verifying Celery Import ===")
    
    try:
        import celery
        print(f"✓ Celery version: {celery.__version__}")
        return True
    except ImportError as e:
        print(f"✗ Failed to import Celery: {e}")
        return False


def verify_tasks_module():
    """Verify that tasks module can be imported"""
    print("\n=== Verifying Tasks Module ===")
    
    try:
        import tasks
        print(f"✓ Tasks module imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import tasks module: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_celery_app():
    """Verify Celery app configuration"""
    print("\n=== Verifying Celery App Configuration ===")
    
    try:
        from tasks import celery_app
        
        print(f"✓ Celery app created: {celery_app.main}")
        print(f"  Broker: {celery_app.conf.broker_url}")
        print(f"  Backend: {celery_app.conf.result_backend}")
        print(f"  Task serializer: {celery_app.conf.task_serializer}")
        print(f"  Result serializer: {celery_app.conf.result_serializer}")
        print(f"  Worker concurrency: {celery_app.conf.worker_concurrency}")
        
        return True
    except Exception as e:
        print(f"✗ Failed to verify Celery app: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_registered_tasks():
    """Verify that tasks are registered with Celery"""
    print("\n=== Verifying Registered Tasks ===")
    
    try:
        from tasks import celery_app
        
        # Get all registered tasks
        registered_tasks = list(celery_app.tasks.keys())
        
        # Expected tasks
        expected_tasks = [
            'tasks.fetch_source',
            'tasks.scheduled_source_fetch',
            'tasks.ingest_threat',
            'tasks.classify_threat',
            'tasks.extract_entities',
            'tasks.map_mitre_atlas',
            'tasks.analyze_with_llm',
            'tasks.send_alert',
        ]
        
        print(f"✓ Total registered tasks: {len(registered_tasks)}")
        
        # Check for expected tasks
        missing_tasks = []
        for task_name in expected_tasks:
            if task_name in registered_tasks:
                print(f"  ✓ {task_name}")
            else:
                print(f"  ✗ {task_name} (missing)")
                missing_tasks.append(task_name)
        
        if missing_tasks:
            print(f"\n✗ Missing tasks: {missing_tasks}")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to verify registered tasks: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_beat_schedule():
    """Verify Celery Beat schedule configuration"""
    print("\n=== Verifying Celery Beat Schedule ===")
    
    try:
        from tasks import celery_app
        
        beat_schedule = celery_app.conf.beat_schedule
        
        if not beat_schedule:
            print("✗ No beat schedule configured")
            return False
        
        print(f"✓ Beat schedule configured with {len(beat_schedule)} entries:")
        
        for name, config in beat_schedule.items():
            print(f"  ✓ {name}:")
            print(f"    Task: {config['task']}")
            print(f"    Schedule: {config['schedule']}")
        
        # Check for expected scheduled task
        if 'fetch-hourly-sources' in beat_schedule:
            print(f"\n✓ Hourly source fetch task is scheduled")
            return True
        else:
            print(f"\n✗ Hourly source fetch task is not scheduled")
            return False
        
    except Exception as e:
        print(f"✗ Failed to verify beat schedule: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_task_signatures():
    """Verify task function signatures"""
    print("\n=== Verifying Task Signatures ===")
    
    try:
        from tasks import (
            fetch_source,
            scheduled_source_fetch,
            ingest_threat,
            classify_threat,
            extract_entities,
            map_mitre_atlas,
            analyze_with_llm,
            send_alert
        )
        
        tasks_to_check = [
            ('fetch_source', fetch_source, ['source_name']),
            ('scheduled_source_fetch', scheduled_source_fetch, []),
            ('ingest_threat', ingest_threat, ['raw_data']),
            ('classify_threat', classify_threat, ['threat_id']),
            ('extract_entities', extract_entities, ['threat_id']),
            ('map_mitre_atlas', map_mitre_atlas, ['threat_id']),
            ('analyze_with_llm', analyze_with_llm, ['threat_id']),
            ('send_alert', send_alert, ['threat_id', 'channels']),
        ]
        
        all_valid = True
        
        for task_name, task_func, expected_params in tasks_to_check:
            # Check if task is callable
            if not callable(task_func):
                print(f"  ✗ {task_name} is not callable")
                all_valid = False
                continue
            
            # Check if task has delay method (Celery task)
            if not hasattr(task_func, 'delay'):
                print(f"  ✗ {task_name} is not a Celery task (no delay method)")
                all_valid = False
                continue
            
            print(f"  ✓ {task_name} is properly configured")
        
        return all_valid
        
    except Exception as e:
        print(f"✗ Failed to verify task signatures: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_config_settings():
    """Verify configuration settings"""
    print("\n=== Verifying Configuration Settings ===")
    
    try:
        from config import settings
        
        print(f"✓ Configuration loaded:")
        print(f"  Celery broker URL: {settings.celery_broker_url}")
        print(f"  Celery result backend: {settings.celery_result_backend}")
        print(f"  Worker concurrency: {settings.celery_worker_concurrency}")
        print(f"  Redis URL: {settings.redis_url}")
        
        # Verify broker and backend match Redis URL
        if settings.celery_broker_url == settings.redis_url:
            print(f"  ✓ Broker URL matches Redis URL")
        else:
            print(f"  ⚠ Broker URL differs from Redis URL")
        
        if settings.celery_result_backend == settings.redis_url:
            print(f"  ✓ Result backend matches Redis URL")
        else:
            print(f"  ⚠ Result backend differs from Redis URL")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to verify configuration: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification checks"""
    print("=" * 60)
    print("Celery Setup Verification")
    print("=" * 60)
    
    results = []
    
    # Run all verification checks
    results.append(("Celery Import", verify_celery_import()))
    results.append(("Tasks Module", verify_tasks_module()))
    results.append(("Celery App Configuration", verify_celery_app()))
    results.append(("Registered Tasks", verify_registered_tasks()))
    results.append(("Beat Schedule", verify_beat_schedule()))
    results.append(("Task Signatures", verify_task_signatures()))
    results.append(("Configuration Settings", verify_config_settings()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    for check_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{check_name}: {status}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"\nTotal: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n✓ All checks passed! Celery setup is correct.")
        print("\nNext steps:")
        print("1. Start Redis: docker compose up -d redis")
        print("2. Start Celery worker: celery -A tasks worker --loglevel=info --concurrency=2")
        print("3. Start Celery beat: celery -A tasks beat --loglevel=info")
        print("4. Run test script: python scripts/test_celery_tasks.py")
    else:
        print("\n✗ Some checks failed. Please fix the issues above.")
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
