"""
Unit tests for GET /threats endpoint with metadata filtering.

Tests the metadata filtering functionality added in task 5.2 of the
enhanced-threat-metadata spec.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
"""
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Threat
from utils.query_builders import build_metadata_filter


class TestMetadataFiltering:
    """Test suite for metadata filtering functionality"""
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_attack_surface(self, db_session: AsyncSession):
        """Test filtering by attack_surface"""
        # Create test threats with different metadata
        threat1 = Threat(
            title="Runtime Attack",
            description="A runtime attack",
            source="test",
            content_hash="hash1",
            classification_metadata={
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm"]
            }
        )
        threat2 = Threat(
            title="Training Attack",
            description="A training attack",
            source="test",
            content_hash="hash2",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["vision"]
            }
        )
        threat3 = Threat(
            title="No Metadata",
            description="No metadata",
            source="test",
            content_hash="hash3",
            classification_metadata=None
        )
        
        db_session.add_all([threat1, threat2, threat3])
        await db_session.commit()
        
        # Test filtering by attack_surface
        filters = build_metadata_filter(Threat, attack_surface=["runtime"])
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        assert len(threats) == 1
        assert threats[0].title == "Runtime Attack"
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_testability(self, db_session: AsyncSession):
        """Test filtering by testability"""
        # Create test threats
        threat1 = Threat(
            title="Testable Threat",
            description="Can be tested",
            source="test",
            content_hash="hash4",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm"]
            }
        )
        threat2 = Threat(
            title="Non-testable Threat",
            description="Cannot be tested",
            source="test",
            content_hash="hash5",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["vision"]
            }
        )
        
        db_session.add_all([threat1, threat2])
        await db_session.commit()
        
        # Test filtering by testability
        filters = build_metadata_filter(Threat, testability="yes")
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        assert len(threats) == 1
        assert threats[0].title == "Testable Threat"
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_techniques(self, db_session: AsyncSession):
        """Test filtering by techniques"""
        # Create test threats
        threat1 = Threat(
            title="Jailbreak Attack",
            description="Uses jailbreak",
            source="test",
            content_hash="hash6",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak", "prompt_injection"],
                "target_systems": ["llm"]
            }
        )
        threat2 = Threat(
            title="Backdoor Attack",
            description="Uses backdoor",
            source="test",
            content_hash="hash7",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor", "poisoning"],
                "target_systems": ["vision"]
            }
        )
        
        db_session.add_all([threat1, threat2])
        await db_session.commit()
        
        # Test filtering by techniques
        filters = build_metadata_filter(Threat, techniques=["jailbreak"])
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        assert len(threats) == 1
        assert threats[0].title == "Jailbreak Attack"
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_target_systems(self, db_session: AsyncSession):
        """Test filtering by target_systems"""
        # Create test threats
        threat1 = Threat(
            title="LLM Attack",
            description="Targets LLM",
            source="test",
            content_hash="hash8",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm", "chat"]
            }
        )
        threat2 = Threat(
            title="Vision Attack",
            description="Targets vision",
            source="test",
            content_hash="hash9",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["vision"]
            }
        )
        
        db_session.add_all([threat1, threat2])
        await db_session.commit()
        
        # Test filtering by target_systems
        filters = build_metadata_filter(Threat, target_systems=["llm"])
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        assert len(threats) == 1
        assert threats[0].title == "LLM Attack"
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_combined(self, db_session: AsyncSession):
        """Test filtering with multiple criteria (AND logic)"""
        # Create test threats
        threat1 = Threat(
            title="Runtime LLM Jailbreak",
            description="Runtime jailbreak for LLM",
            source="test",
            content_hash="hash10",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm"]
            }
        )
        threat2 = Threat(
            title="Runtime Vision Attack",
            description="Runtime attack for vision",
            source="test",
            content_hash="hash11",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["adversarial"],
                "target_systems": ["vision"]
            }
        )
        threat3 = Threat(
            title="Training LLM Attack",
            description="Training attack for LLM",
            source="test",
            content_hash="hash12",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["llm"]
            }
        )
        
        db_session.add_all([threat1, threat2, threat3])
        await db_session.commit()
        
        # Test combined filtering (attack_surface=runtime AND target_systems=llm)
        filters = build_metadata_filter(
            Threat,
            attack_surface=["runtime"],
            target_systems=["llm"]
        )
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        # Should only return threat1 (runtime AND llm)
        assert len(threats) == 1
        assert threats[0].title == "Runtime LLM Jailbreak"
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_no_filters(self, db_session: AsyncSession):
        """Test that no filters returns empty list"""
        filters = build_metadata_filter(Threat)
        assert filters == []
    
    @pytest.mark.asyncio
    async def test_build_metadata_filter_multiple_values_or_logic(self, db_session: AsyncSession):
        """Test that multiple values for same field use OR logic"""
        # Create test threats
        threat1 = Threat(
            title="Runtime Attack",
            description="Runtime",
            source="test",
            content_hash="hash13",
            classification_metadata={
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm"]
            }
        )
        threat2 = Threat(
            title="Training Attack",
            description="Training",
            source="test",
            content_hash="hash14",
            classification_metadata={
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["vision"]
            }
        )
        threat3 = Threat(
            title="Inference Attack",
            description="Inference",
            source="test",
            content_hash="hash15",
            classification_metadata={
                "attack_surface": ["inference"],
                "testability": "conditional",
                "techniques": ["extraction"],
                "target_systems": ["multimodal"]
            }
        )
        
        db_session.add_all([threat1, threat2, threat3])
        await db_session.commit()
        
        # Test multiple attack surfaces (should use OR logic)
        filters = build_metadata_filter(Threat, attack_surface=["runtime", "training"])
        query = select(Threat).where(*filters) if filters else select(Threat)
        result = await db_session.execute(query)
        threats = result.scalars().all()
        
        # Should return both threat1 and threat2
        assert len(threats) == 2
        titles = {t.title for t in threats}
        assert "Runtime Attack" in titles
        assert "Training Attack" in titles
