#!/usr/bin/env python3
"""
Test script for sources API endpoints

Tests the REST API endpoints for source management.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_list_sources():
    """Test GET /api/v1/sources"""
    print("\n=== Testing List Sources ===")
    
    response = client.get("/api/v1/sources")
    assert response.status_code == 200
    
    data = response.json()
    assert "sources" in data
    assert "stats" in data
    
    print(f"✓ Found {len(data['sources'])} sources")
    print(f"  Stats: {data['stats']}")
    
    return True


def test_list_sources_filtered():
    """Test GET /api/v1/sources with filters"""
    print("\n=== Testing Filtered List ===")
    
    # Test enabled only
    response = client.get("/api/v1/sources?enabled_only=true")
    assert response.status_code == 200
    data = response.json()
    print(f"✓ Enabled sources: {len(data['sources'])}")
    
    # Test by type
    response = client.get("/api/v1/sources?source_type=rss")
    assert response.status_code == 200
    data = response.json()
    print(f"✓ RSS sources: {len(data['sources'])}")
    
    # Test by frequency
    response = client.get("/api/v1/sources?frequency=daily")
    assert response.status_code == 200
    data = response.json()
    print(f"✓ Daily sources: {len(data['sources'])}")
    
    return True


def test_get_source():
    """Test GET /api/v1/sources/{name}"""
    print("\n=== Testing Get Source ===")
    
    # Get a valid source
    response = client.get("/api/v1/sources/arXiv Computer Security")
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == "arXiv Computer Security"
    assert "type" in data
    assert "url" in data
    
    print(f"✓ Retrieved source: {data['name']}")
    print(f"  Type: {data['type']}, URL: {data['url'][:50]}...")
    
    # Test non-existent source
    response = client.get("/api/v1/sources/NonExistent")
    assert response.status_code == 404
    print("✓ 404 for non-existent source")
    
    return True


def test_enable_disable():
    """Test POST /api/v1/sources/{name}/enable and disable"""
    print("\n=== Testing Enable/Disable ===")
    
    source_name = "arXiv Computer Security"
    
    # Disable
    response = client.post(f"/api/v1/sources/{source_name}/disable")
    assert response.status_code == 200
    print(f"✓ Disabled: {source_name}")
    
    # Verify disabled
    response = client.get(f"/api/v1/sources/{source_name}")
    assert response.status_code == 200
    assert response.json()["enabled"] == False
    print("✓ Verified disabled state")
    
    # Enable
    response = client.post(f"/api/v1/sources/{source_name}/enable")
    assert response.status_code == 200
    print(f"✓ Enabled: {source_name}")
    
    # Verify enabled
    response = client.get(f"/api/v1/sources/{source_name}")
    assert response.status_code == 200
    assert response.json()["enabled"] == True
    print("✓ Verified enabled state")
    
    # Test non-existent source
    response = client.post("/api/v1/sources/NonExistent/enable")
    assert response.status_code == 404
    print("✓ 404 for non-existent source")
    
    return True


def test_reload():
    """Test POST /api/v1/sources/reload"""
    print("\n=== Testing Reload ===")
    
    response = client.post("/api/v1/sources/reload")
    assert response.status_code == 200
    
    data = response.json()
    assert "message" in data
    print(f"✓ {data['message']}")
    
    return True


def test_stats():
    """Test GET /api/v1/sources/stats"""
    print("\n=== Testing Stats ===")
    
    response = client.get("/api/v1/sources/stats")
    assert response.status_code == 200
    
    data = response.json()
    assert "total" in data
    assert "enabled" in data
    assert "by_type" in data
    assert "by_frequency" in data
    
    print(f"✓ Total: {data['total']}, Enabled: {data['enabled']}")
    print(f"  By type: {data['by_type']}")
    print(f"  By frequency: {data['by_frequency']}")
    
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("Sources API Test Suite")
    print("=" * 60)
    
    tests = [
        ("List Sources", test_list_sources),
        ("Filtered List", test_list_sources_filtered),
        ("Get Source", test_get_source),
        ("Enable/Disable", test_enable_disable),
        ("Reload", test_reload),
        ("Stats", test_stats),
    ]
    
    results = []
    for name, test_func in tests:
        try:
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
    success = main()
    sys.exit(0 if success else 1)
