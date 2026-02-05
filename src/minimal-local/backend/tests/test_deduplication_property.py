"""
Property-Based Test: Threat Deduplication

**Property 3: Threat Deduplication**
**Validates: Requirements 6.14**

This test verifies that the deduplication system correctly identifies and prevents
duplicate threats based on content hash, regardless of:
- Minor formatting differences (whitespace, case)
- Metadata variations (different titles, sources, dates)
- Concurrent ingestion attempts

The property being tested:
  For any threat content C, ingesting C multiple times should result in exactly
  one threat record in the database, with all subsequent attempts returning the
  same threat ID.
"""

import pytest
import asyncio
from hypothesis import given, strategies as st, settings as hypothesis_settings, HealthCheck
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func

from config import settings as app_settings
from models.threat import Threat
from services.ingestion import IngestionService


# Strategy for generating threat content
threat_content_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'P', 'Z')),
    min_size=10,
    max_size=500
)

# Strategy for generating threat metadata variations
threat_metadata_strategy = st.fixed_dictionaries({
    'title': st.text(min_size=5, max_size=100),
    'description': st.text(min_size=10, max_size=200),
    'source': st.sampled_from(['arXiv', 'GitHub', 'Security Blog', 'CVE', 'Reddit']),
    'url': st.text(min_size=10, max_size=100),
    'authors': st.lists(st.text(min_size=3, max_size=50), min_size=0, max_size=3),
})


class TestDeduplicationProperty:
    """Property-based tests for threat deduplication"""
    
    @pytest.fixture
    async def db_session(self):
        """Create a test database session"""
        engine = create_async_engine(app_settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with async_session_maker() as session:
            yield session
        
        await engine.dispose()
    
    @pytest.fixture
    async def ingestion_service(self, db_session):
        """Create an ingestion service instance"""
        return IngestionService(db_session)
    
    @pytest.mark.asyncio
    @given(content=threat_content_strategy)
    @hypothesis_settings(
        max_examples=20,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    async def test_duplicate_content_same_hash(self, content):
        """
        Property: Same content always produces the same hash
        
        This verifies that the hash function is deterministic and that
        normalization (lowercase, strip whitespace) works correctly.
        """
        # Create ingestion service
        engine = create_async_engine(app_settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with async_session_maker() as session:
            service = IngestionService(session)
            
            # Calculate hash for original content
            hash1 = service.calculate_content_hash(content)
            
            # Calculate hash for content with different whitespace
            content_with_spaces = f"  {content}  \n\t"
            hash2 = service.calculate_content_hash(content_with_spaces)
            
            # Calculate hash for content with different case (using casefold for consistency)
            content_casefolded = content.casefold()
            hash3 = service.calculate_content_hash(content_casefolded)
            
            # All hashes should be identical
            assert hash1 == hash2, "Whitespace differences should not affect hash"
            assert hash1 == hash3, "Case differences should not affect hash (using casefold)"
        
        await engine.dispose()
    
    @pytest.mark.asyncio
    @given(
        content=threat_content_strategy,
        metadata1=threat_metadata_strategy,
        metadata2=threat_metadata_strategy
    )
    @hypothesis_settings(
        max_examples=10,
        deadline=10000,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    async def test_duplicate_content_different_metadata(self, content, metadata1, metadata2):
        """
        Property: Same content with different metadata should be detected as duplicate
        
        This verifies that deduplication is based on content hash, not metadata.
        Even if title, source, or other metadata differs, the same content should
        be recognized as a duplicate.
        """
        # Create ingestion service
        engine = create_async_engine(app_settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with async_session_maker() as session:
            service = IngestionService(session)
            
            # Create first threat data
            raw_data1 = {
                'content': content,
                'title': metadata1['title'],
                'description': metadata1['description'],
                'source': metadata1['source'],
                'url': metadata1['url'],
                'authors': metadata1['authors']
            }
            
            # Ingest first threat
            result1 = await service.ingest(raw_data1)
            
            # Create second threat data with same content but different metadata
            raw_data2 = {
                'content': content,
                'title': metadata2['title'],
                'description': metadata2['description'],
                'source': metadata2['source'],
                'url': metadata2['url'],
                'authors': metadata2['authors']
            }
            
            # Ingest second threat
            result2 = await service.ingest(raw_data2)
            
            # Verify results
            if result1['status'] == 'success':
                # First ingestion succeeded, second should be duplicate
                assert result2['status'] == 'duplicate', \
                    "Second ingestion with same content should be detected as duplicate"
                assert result1['threat_id'] == result2['threat_id'], \
                    "Duplicate should return same threat ID"
                assert result1['content_hash'] == result2['content_hash'], \
                    "Content hashes should match"
            elif result1['status'] == 'duplicate':
                # First ingestion was already a duplicate (from previous test run)
                # Second should also be duplicate with same ID
                assert result2['status'] == 'duplicate', \
                    "Both ingestions should be duplicates"
                assert result1['threat_id'] == result2['threat_id'], \
                    "Both should return same threat ID"
        
        await engine.dispose()
    
    @pytest.mark.asyncio
    async def test_concurrent_ingestion_no_duplicates(self):
        """
        Property: Concurrent ingestion of same content should result in exactly one record
        
        This tests the race condition handling - if multiple workers try to ingest
        the same content simultaneously, only one should succeed in creating a new
        record, and all should return the same threat ID.
        """
        # Create ingestion service
        engine = create_async_engine(app_settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        # Generate unique content for this test
        import uuid
        unique_content = f"Test concurrent ingestion {uuid.uuid4()}"
        
        raw_data = {
            'content': unique_content,
            'title': 'Concurrent Test Threat',
            'description': 'Testing concurrent ingestion',
            'source': 'Test',
            'url': 'http://test.example.com',
            'authors': ['Test Author']
        }
        
        # Create multiple concurrent ingestion tasks
        async def ingest_task():
            async with async_session_maker() as session:
                service = IngestionService(session)
                return await service.ingest(raw_data)
        
        # Run 5 concurrent ingestion attempts
        results = await asyncio.gather(*[ingest_task() for _ in range(5)])
        
        # Collect all threat IDs
        threat_ids = [r['threat_id'] for r in results if r['threat_id']]
        
        # All threat IDs should be the same
        assert len(set(threat_ids)) == 1, \
            f"All concurrent ingestions should return same threat ID, got: {set(threat_ids)}"
        
        # Verify only one record exists in database
        async with async_session_maker() as session:
            service = IngestionService(session)
            content_hash = service.calculate_content_hash(unique_content)
            
            result = await session.execute(
                select(func.count()).select_from(Threat).where(
                    Threat.content_hash == content_hash
                )
            )
            count = result.scalar()
            
            assert count == 1, \
                f"Expected exactly 1 threat record, found {count}"
        
        await engine.dispose()
    
    @pytest.mark.asyncio
    async def test_different_content_different_records(self):
        """
        Property: Different content should create different records
        
        This is the inverse property - ensures that genuinely different content
        is not incorrectly deduplicated.
        """
        # Create ingestion service
        engine = create_async_engine(app_settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        # Generate two unique pieces of content
        import uuid
        content1 = f"Unique threat content A {uuid.uuid4()}"
        content2 = f"Unique threat content B {uuid.uuid4()}"
        
        raw_data1 = {
            'content': content1,
            'title': 'Test Threat A',
            'description': 'First test threat',
            'source': 'Test',
            'url': 'http://test.example.com/a',
            'authors': ['Test Author']
        }
        
        raw_data2 = {
            'content': content2,
            'title': 'Test Threat B',
            'description': 'Second test threat',
            'source': 'Test',
            'url': 'http://test.example.com/b',
            'authors': ['Test Author']
        }
        
        async with async_session_maker() as session:
            service = IngestionService(session)
            
            # Ingest both threats
            result1 = await service.ingest(raw_data1)
            result2 = await service.ingest(raw_data2)
            
            # Both should succeed (or be duplicates from previous runs)
            assert result1['threat_id'] is not None, "First ingestion should return threat ID"
            assert result2['threat_id'] is not None, "Second ingestion should return threat ID"
            
            # Threat IDs should be different
            assert result1['threat_id'] != result2['threat_id'], \
                "Different content should create different threat records"
            
            # Content hashes should be different
            assert result1['content_hash'] != result2['content_hash'], \
                "Different content should have different hashes"
        
        await engine.dispose()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
