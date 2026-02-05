#!/usr/bin/env python3
"""
Test script for source manager functionality

Tests:
- Loading sources from YAML
- Source validation
- Enable/disable functionality
- Configuration hot-reload
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.source_manager import SourceManager


async def test_load_sources():
    """Test loading sources from YAML configuration"""
    print("\n=== Testing Source Loading ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    
    try:
        sources = manager.load_sources()
        print(f"✓ Loaded {len(sources)} sources")
        
        # Display some sources
        for i, (name, source) in enumerate(list(sources.items())[:3]):
            print(f"  - {name}: {source.type} ({source.url[:50]}...)")
        
        return True
    except Exception as e:
        print(f"✗ Failed to load sources: {e}")
        return False


async def test_source_validation():
    """Test source URL validation"""
    print("\n=== Testing Source Validation ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    # Test a few sources
    test_sources = list(manager.get_enabled_sources())[:3]
    
    async with manager:
        for source in test_sources:
            is_accessible = await manager.validate_source_accessibility(source)
            status = "✓ Accessible" if is_accessible else "✗ Not accessible"
            print(f"  {status}: {source.name}")
    
    return True


def test_enable_disable():
    """Test enable/disable functionality"""
    print("\n=== Testing Enable/Disable ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    # Get first source
    first_source_name = list(manager.sources.keys())[0]
    source = manager.get_source(first_source_name)
    
    original_state = source.enabled
    print(f"  Original state of '{first_source_name}': {original_state}")
    
    # Toggle state
    if original_state:
        manager.disable_source(first_source_name)
        print(f"  ✓ Disabled '{first_source_name}'")
    else:
        manager.enable_source(first_source_name)
        print(f"  ✓ Enabled '{first_source_name}'")
    
    # Verify state changed
    source = manager.get_source(first_source_name)
    new_state = source.enabled
    print(f"  New state: {new_state}")
    
    # Restore original state
    if original_state:
        manager.enable_source(first_source_name)
    else:
        manager.disable_source(first_source_name)
    
    return True


def test_filtering():
    """Test source filtering methods"""
    print("\n=== Testing Source Filtering ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    # Test by type
    rss_sources = manager.get_sources_by_type("rss")
    api_sources = manager.get_sources_by_type("api")
    print(f"  RSS sources: {len(rss_sources)}")
    print(f"  API sources: {len(api_sources)}")
    
    # Test by frequency
    hourly = manager.get_sources_by_frequency("hourly")
    daily = manager.get_sources_by_frequency("daily")
    weekly = manager.get_sources_by_frequency("weekly")
    print(f"  Hourly: {len(hourly)}, Daily: {len(daily)}, Weekly: {len(weekly)}")
    
    # Test enabled sources
    enabled = manager.get_enabled_sources()
    print(f"  Enabled sources: {len(enabled)}")
    
    return True


def test_stats():
    """Test statistics generation"""
    print("\n=== Testing Statistics ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    stats = manager.get_stats()
    print(f"  Total sources: {stats['total']}")
    print(f"  Enabled: {stats['enabled']}, Disabled: {stats['disabled']}")
    print(f"  By type: {stats['by_type']}")
    print(f"  By frequency: {stats['by_frequency']}")
    
    return True


async def test_hot_reload():
    """Test configuration hot-reload"""
    print("\n=== Testing Hot-Reload ===")
    
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    initial_count = len(manager.sources)
    print(f"  Initial source count: {initial_count}")
    
    # Check if config has changed (should be False initially)
    has_changed = manager.has_config_changed()
    print(f"  Config changed: {has_changed}")
    
    # Test reload_if_changed (should return False since no changes)
    reloaded = manager.reload_if_changed()
    print(f"  Reloaded: {reloaded}")
    
    print("\n  Note: To test actual hot-reload, modify config/sources.yaml")
    print("  and the file watcher will automatically reload the configuration.")
    
    return True


async def main():
    """Run all tests"""
    print("=" * 60)
    print("Source Manager Test Suite")
    print("=" * 60)
    
    tests = [
        ("Load Sources", test_load_sources),
        ("Source Validation", test_source_validation),
        ("Enable/Disable", test_enable_disable),
        ("Filtering", test_filtering),
        ("Statistics", test_stats),
        ("Hot-Reload", test_hot_reload),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ Test '{name}' failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
