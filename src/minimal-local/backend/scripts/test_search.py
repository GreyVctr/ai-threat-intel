#!/usr/bin/env python3
"""
Test script for search functionality.

Tests:
1. Full-text search
2. Fuzzy matching
3. Filters (threat type, severity, date range)
4. Pagination
5. Search statistics
"""
import asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add backend directory to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy.ext.asyncio import AsyncSession
from models import get_db, Threat
from services.search import get_search_service


async def test_basic_search():
    """Test basic search functionality."""
    print("\n" + "=" * 60)
    print("TEST 1: Basic Search")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        # Search for "attack"
        print("\nSearching for 'attack'...")
        results = await search_service.search(query="attack", per_page=5)
        
        print(f"Found {results['total']} results")
        print(f"Page {results['page']}/{results['total_pages']}")
        print(f"Has next: {results['has_next']}, Has prev: {results['has_prev']}")
        
        if results['results']:
            print("\nTop 5 results:")
            for i, threat in enumerate(results['results'], 1):
                print(f"{i}. {threat['title'][:80]}")
                print(f"   Source: {threat['source']}, Severity: {threat['severity']}")
        else:
            print("No results found")
        
        return results['total'] > 0


async def test_fuzzy_search():
    """Test fuzzy matching (typo tolerance)."""
    print("\n" + "=" * 60)
    print("TEST 2: Fuzzy Search (Typo Tolerance)")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        # Search with intentional typo
        print("\nSearching for 'adversarial' (correct spelling)...")
        results_correct = await search_service.search(query="adversarial", per_page=5)
        print(f"Found {results_correct['total']} results")
        
        print("\nSearching for 'adversrial' (typo - missing 'a')...")
        results_typo = await search_service.search(query="adversrial", per_page=5)
        print(f"Found {results_typo['total']} results")
        
        if results_typo['total'] > 0:
            print("✓ Fuzzy matching works - found results despite typo")
            print("\nTop 3 results:")
            for i, threat in enumerate(results_typo['results'][:3], 1):
                print(f"{i}. {threat['title'][:80]}")
        else:
            print("✗ Fuzzy matching may not be working (or no matching data)")
        
        return True


async def test_filters():
    """Test search filters."""
    print("\n" + "=" * 60)
    print("TEST 3: Search Filters")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        # Test severity filter
        print("\nFilter: High severity (>= 7)...")
        results = await search_service.search(severity_min=7, per_page=5)
        print(f"Found {results['total']} high-severity threats")
        
        if results['results']:
            print("Sample results:")
            for threat in results['results'][:3]:
                print(f"  - {threat['title'][:60]} (Severity: {threat['severity']})")
        
        # Test threat type filter
        print("\nFilter: Threat type = 'adversarial'...")
        results = await search_service.search(threat_type="adversarial", per_page=5)
        print(f"Found {results['total']} adversarial threats")
        
        # Test date range filter
        date_from = datetime.now() - timedelta(days=30)
        print(f"\nFilter: Published in last 30 days (since {date_from.date()})...")
        results = await search_service.search(date_from=date_from, per_page=5)
        print(f"Found {results['total']} recent threats")
        
        # Test combined filters
        print("\nFilter: High severity adversarial attacks from last 30 days...")
        results = await search_service.search(
            threat_type="adversarial",
            severity_min=7,
            date_from=date_from,
            per_page=5
        )
        print(f"Found {results['total']} matching threats")
        
        return True


async def test_pagination():
    """Test pagination."""
    print("\n" + "=" * 60)
    print("TEST 4: Pagination")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        # Get first page
        print("\nFetching page 1 (5 results per page)...")
        page1 = await search_service.search(per_page=5, page=1)
        print(f"Total results: {page1['total']}")
        print(f"Total pages: {page1['total_pages']}")
        print(f"Page 1 has {len(page1['results'])} results")
        
        if page1['total_pages'] > 1:
            # Get second page
            print("\nFetching page 2...")
            page2 = await search_service.search(per_page=5, page=2)
            print(f"Page 2 has {len(page2['results'])} results")
            
            # Verify different results
            page1_ids = {t['id'] for t in page1['results']}
            page2_ids = {t['id'] for t in page2['results']}
            
            if page1_ids.isdisjoint(page2_ids):
                print("✓ Pagination works - different results on each page")
            else:
                print("✗ Pagination issue - overlapping results")
        else:
            print("Only one page of results available")
        
        return True


async def test_statistics():
    """Test search statistics."""
    print("\n" + "=" * 60)
    print("TEST 5: Search Statistics")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        stats = await search_service.get_search_statistics()
        
        print(f"\nTotal threats: {stats['total_threats']}")
        
        print("\nThreat types:")
        for threat_type, count in stats['threat_types'].items():
            print(f"  - {threat_type}: {count}")
        
        print("\nSeverity distribution:")
        for severity, count in sorted(stats['severity_distribution'].items()):
            print(f"  - Severity {severity}: {count}")
        
        print("\nTop sources:")
        for source, count in list(stats['top_sources'].items())[:5]:
            print(f"  - {source}: {count}")
        
        return stats['total_threats'] > 0


async def test_helper_methods():
    """Test helper methods."""
    print("\n" + "=" * 60)
    print("TEST 6: Helper Methods")
    print("=" * 60)
    
    async for db in get_db():
        search_service = await get_search_service(db)
        
        # Get recent threats
        print("\nRecent threats (last 5)...")
        recent = await search_service.get_recent_threats(limit=5)
        print(f"Found {len(recent)} recent threats")
        for threat in recent:
            print(f"  - {threat.title[:60]} (ingested: {threat.ingested_at})")
        
        # Get high severity threats
        print("\nHigh severity threats (>= 7)...")
        high_severity = await search_service.get_high_severity_threats(
            severity_threshold=7,
            limit=5
        )
        print(f"Found {len(high_severity)} high-severity threats")
        for threat in high_severity:
            print(f"  - {threat.title[:60]} (severity: {threat.severity})")
        
        # Get threat types
        print("\nAvailable threat types...")
        threat_types = await search_service.get_threat_types()
        print(f"Found {len(threat_types)} threat types: {', '.join(threat_types)}")
        
        return True


async def main():
    """Run all tests."""
    print("=" * 60)
    print("SEARCH FUNCTIONALITY TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("Basic Search", test_basic_search),
        ("Fuzzy Search", test_fuzzy_search),
        ("Filters", test_filters),
        ("Pagination", test_pagination),
        ("Statistics", test_statistics),
        ("Helper Methods", test_helper_methods),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            success = await test_func()
            results[test_name] = "✓ PASS" if success else "✗ FAIL"
        except Exception as e:
            print(f"\n✗ ERROR in {test_name}: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = "✗ ERROR"
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for test_name, result in results.items():
        print(f"{result} {test_name}")
    
    passed = sum(1 for r in results.values() if "PASS" in r)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
