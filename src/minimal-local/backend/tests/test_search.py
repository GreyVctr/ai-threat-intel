"""
Unit tests for search functionality.

Tests the search service and API endpoints.
"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy import select
from models import Threat
from services.search import SearchService


@pytest.mark.asyncio
async def test_search_basic(db_session):
    """Test basic search functionality."""
    # Create test threats
    threat1 = Threat(
        title="Adversarial Attack on Neural Networks",
        description="A new adversarial attack technique",
        content="This is a test threat about adversarial attacks",
        source="Test",
        content_hash="test_hash_1",
        published_at=datetime.now(),
    )
    threat2 = Threat(
        title="Model Extraction Vulnerability",
        description="Extracting model weights through API",
        content="This is a test threat about model extraction",
        source="Test",
        content_hash="test_hash_2",
        published_at=datetime.now(),
    )
    
    db_session.add(threat1)
    db_session.add(threat2)
    await db_session.commit()
    
    # Test search
    search_service = SearchService(db_session)
    results = await search_service.search(query="adversarial", per_page=10)
    
    assert results['total'] >= 1
    assert any('adversarial' in t['title'].lower() for t in results['results'])


@pytest.mark.asyncio
async def test_search_pagination(db_session):
    """Test search pagination."""
    search_service = SearchService(db_session)
    
    # Get first page
    page1 = await search_service.search(per_page=2, page=1)
    
    # Get second page if available
    if page1['total_pages'] > 1:
        page2 = await search_service.search(per_page=2, page=2)
        
        # Verify different results
        page1_ids = {t['id'] for t in page1['results']}
        page2_ids = {t['id'] for t in page2['results']}
        
        assert page1_ids.isdisjoint(page2_ids), "Pages should have different results"


@pytest.mark.asyncio
async def test_search_filters(db_session):
    """Test search filters."""
    # Create test threat with severity
    threat = Threat(
        title="High Severity Attack",
        description="Critical vulnerability",
        content="This is a high severity threat",
        source="Test",
        content_hash="test_hash_severity",
        severity=9,
        threat_type="adversarial",
        published_at=datetime.now(),
    )
    
    db_session.add(threat)
    await db_session.commit()
    
    search_service = SearchService(db_session)
    
    # Test severity filter
    results = await search_service.search(severity_min=8)
    assert results['total'] >= 1
    assert all(t['severity'] is None or t['severity'] >= 8 for t in results['results'])
    
    # Test threat type filter
    results = await search_service.search(threat_type="adversarial")
    assert results['total'] >= 1
    assert all(t['threat_type'] is None or t['threat_type'] == "adversarial" 
               for t in results['results'])


@pytest.mark.asyncio
async def test_search_date_range(db_session):
    """Test date range filtering."""
    # Create threats with different dates
    old_threat = Threat(
        title="Old Threat",
        description="Old vulnerability",
        content="This is an old threat",
        source="Test",
        content_hash="test_hash_old",
        published_at=datetime.now() - timedelta(days=60),
    )
    recent_threat = Threat(
        title="Recent Threat",
        description="Recent vulnerability",
        content="This is a recent threat",
        source="Test",
        content_hash="test_hash_recent",
        published_at=datetime.now() - timedelta(days=5),
    )
    
    db_session.add(old_threat)
    db_session.add(recent_threat)
    await db_session.commit()
    
    search_service = SearchService(db_session)
    
    # Test date_from filter
    date_from = datetime.now() - timedelta(days=30)
    results = await search_service.search(date_from=date_from)
    
    # Should only include recent threat
    assert any(t['title'] == "Recent Threat" for t in results['results'])


@pytest.mark.asyncio
async def test_get_recent_threats(db_session):
    """Test getting recent threats."""
    search_service = SearchService(db_session)
    
    recent = await search_service.get_recent_threats(limit=5)
    
    assert len(recent) <= 5
    # Verify ordered by ingestion date (most recent first)
    if len(recent) > 1:
        for i in range(len(recent) - 1):
            assert recent[i].ingested_at >= recent[i + 1].ingested_at


@pytest.mark.asyncio
async def test_get_high_severity_threats(db_session):
    """Test getting high severity threats."""
    search_service = SearchService(db_session)
    
    high_severity = await search_service.get_high_severity_threats(
        severity_threshold=7,
        limit=5
    )
    
    assert len(high_severity) <= 5
    # Verify all have severity >= 7
    for threat in high_severity:
        assert threat.severity is not None
        assert threat.severity >= 7


@pytest.mark.asyncio
async def test_get_threat_by_id(db_session):
    """Test getting threat by ID."""
    # Create test threat
    threat = Threat(
        title="Test Threat",
        description="Test description",
        content="Test content",
        source="Test",
        content_hash="test_hash_by_id",
        published_at=datetime.now(),
    )
    
    db_session.add(threat)
    await db_session.commit()
    
    search_service = SearchService(db_session)
    
    # Get by ID
    retrieved = await search_service.get_threat_by_id(str(threat.id))
    
    assert retrieved is not None
    assert retrieved.id == threat.id
    assert retrieved.title == threat.title


@pytest.mark.asyncio
async def test_get_search_statistics(db_session):
    """Test getting search statistics."""
    search_service = SearchService(db_session)
    
    stats = await search_service.get_search_statistics()
    
    assert 'total_threats' in stats
    assert 'threat_types' in stats
    assert 'severity_distribution' in stats
    assert 'top_sources' in stats
    
    assert isinstance(stats['total_threats'], int)
    assert stats['total_threats'] >= 0


@pytest.mark.asyncio
async def test_search_by_content_hash(db_session):
    """Test searching by content hash (for deduplication)."""
    # Create test threat
    content_hash = "unique_test_hash_123"
    threat = Threat(
        title="Test Threat",
        description="Test description",
        content="Test content",
        source="Test",
        content_hash=content_hash,
        published_at=datetime.now(),
    )
    
    db_session.add(threat)
    await db_session.commit()
    
    search_service = SearchService(db_session)
    
    # Search by content hash
    found = await search_service.search_by_content_hash(content_hash)
    
    assert found is not None
    assert found.content_hash == content_hash
    assert found.title == threat.title


@pytest.mark.asyncio
async def test_search_relevance_ranking(db_session):
    """Test that search results are ranked by relevance."""
    # Create threats with different relevance to query
    high_relevance = Threat(
        title="Machine Learning Attack",
        description="Attack on machine learning models",
        content="This threat is about machine learning attacks",
        source="Test",
        content_hash="test_hash_high_rel",
        published_at=datetime.now(),
    )
    low_relevance = Threat(
        title="General Security Issue",
        description="A general security issue",
        content="This mentions machine learning briefly",
        source="Test",
        content_hash="test_hash_low_rel",
        published_at=datetime.now(),
    )
    
    db_session.add(high_relevance)
    db_session.add(low_relevance)
    await db_session.commit()
    
    search_service = SearchService(db_session)
    
    # Search for "machine learning"
    results = await search_service.search(query="machine learning", per_page=10)
    
    # High relevance threat should appear first
    if results['total'] >= 2:
        titles = [t['title'] for t in results['results']]
        high_rel_index = titles.index("Machine Learning Attack")
        low_rel_index = titles.index("General Security Issue")
        
        assert high_rel_index < low_rel_index, "Higher relevance should rank first"
