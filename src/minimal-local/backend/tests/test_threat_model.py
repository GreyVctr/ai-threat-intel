"""
Unit tests for Threat model field validation.

Tests the new classification fields added for hybrid threat classification.
"""
import pytest
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat


class TestThreatModelClassificationFields:
    """Test the classification fields added to the Threat model."""
    
    @pytest.mark.asyncio
    async def test_create_threat_with_classification_fields(self, db_session: AsyncSession):
        """Test creating a threat with all classification fields populated."""
        threat = Threat(
            title="Test Adversarial Attack",
            description="A test adversarial attack threat",
            source="test_source",
            content_hash="test_hash_001",
            threat_type="adversarial",
            classification_method="hybrid",
            classification_confidence="medium",
            classification_score=3,
            classification_metadata={
                "keyword_matches": {
                    "adversarial": ["attack", "adversarial", "evasion"]
                },
                "keyword_result": "adversarial",
                "keyword_score": 3,
                "llm_suggestion": "adversarial",
                "method": "hybrid",
                "confidence": "medium"
            }
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify all fields are persisted correctly
        assert threat.classification_method == "hybrid"
        assert threat.classification_confidence == "medium"
        assert threat.classification_score == 3
        assert threat.classification_metadata is not None
        assert threat.classification_metadata["method"] == "hybrid"
        assert threat.classification_metadata["keyword_score"] == 3
    
    @pytest.mark.asyncio
    async def test_create_threat_without_classification_fields(self, db_session: AsyncSession):
        """Test creating a threat without classification fields (backwards compatibility)."""
        threat = Threat(
            title="Test Threat Without Classification",
            description="A test threat without classification metadata",
            source="test_source",
            content_hash="test_hash_002",
            threat_type="unknown"
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify classification fields are null
        assert threat.classification_method is None
        assert threat.classification_confidence is None
        assert threat.classification_score is None
        assert threat.classification_metadata is None
    
    @pytest.mark.asyncio
    async def test_update_existing_threat_with_classification(self, db_session: AsyncSession):
        """Test updating an existing threat with classification data."""
        # Create threat without classification
        threat = Threat(
            title="Test Threat to Update",
            description="A test threat that will be classified",
            source="test_source",
            content_hash="test_hash_003",
            threat_type="unknown"
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Update with classification data
        threat.classification_method = "keyword"
        threat.classification_confidence = "high"
        threat.classification_score = 7
        threat.classification_metadata = {
            "keyword_matches": {
                "poisoning": ["poison", "contaminate", "corrupt", "backdoor", "malicious", "inject", "tamper"]
            },
            "keyword_result": "poisoning",
            "keyword_score": 7,
            "method": "keyword",
            "confidence": "high"
        }
        threat.threat_type = "poisoning"
        
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify updates
        assert threat.classification_method == "keyword"
        assert threat.classification_confidence == "high"
        assert threat.classification_score == 7
        assert threat.threat_type == "poisoning"
        assert threat.classification_metadata["keyword_score"] == 7
    
    @pytest.mark.asyncio
    async def test_classification_method_values(self, db_session: AsyncSession):
        """Test all valid classification_method values."""
        methods = ["keyword", "llm", "hybrid", "keyword_fallback", "failed"]
        
        for i, method in enumerate(methods):
            threat = Threat(
                title=f"Test Threat {method}",
                description=f"Test threat with {method} classification",
                source="test_source",
                content_hash=f"test_hash_method_{i}",
                threat_type="adversarial",
                classification_method=method
            )
            
            db_session.add(threat)
            await db_session.commit()
            await db_session.refresh(threat)
            
            assert threat.classification_method == method
    
    @pytest.mark.asyncio
    async def test_classification_confidence_values(self, db_session: AsyncSession):
        """Test all valid classification_confidence values."""
        confidence_levels = ["high", "medium", "low", "none"]
        
        for i, confidence in enumerate(confidence_levels):
            threat = Threat(
                title=f"Test Threat {confidence}",
                description=f"Test threat with {confidence} confidence",
                source="test_source",
                content_hash=f"test_hash_conf_{i}",
                threat_type="adversarial",
                classification_confidence=confidence
            )
            
            db_session.add(threat)
            await db_session.commit()
            await db_session.refresh(threat)
            
            assert threat.classification_confidence == confidence
    
    @pytest.mark.asyncio
    async def test_classification_score_range(self, db_session: AsyncSession):
        """Test classification_score with various values."""
        scores = [0, 1, 3, 5, 10, 20]
        
        for score in scores:
            threat = Threat(
                title=f"Test Threat Score {score}",
                description=f"Test threat with score {score}",
                source="test_source",
                content_hash=f"test_hash_score_{score}",
                threat_type="adversarial",
                classification_score=score
            )
            
            db_session.add(threat)
            await db_session.commit()
            await db_session.refresh(threat)
            
            assert threat.classification_score == score
    
    @pytest.mark.asyncio
    async def test_classification_metadata_json_structure(self, db_session: AsyncSession):
        """Test classification_metadata with complex JSON structure."""
        metadata = {
            "keyword_matches": {
                "adversarial": ["attack", "adversarial"],
                "poisoning": ["poison"]
            },
            "keyword_result": "adversarial",
            "keyword_score": 2,
            "llm_suggestion": "adversarial",
            "llm_raw_response": "Based on the description, this is an adversarial attack.",
            "method": "hybrid",
            "confidence": "medium",
            "timestamp": "2024-01-15T10:30:00Z",
            "llm_error": None
        }
        
        threat = Threat(
            title="Test Complex Metadata",
            description="Test threat with complex metadata",
            source="test_source",
            content_hash="test_hash_complex",
            threat_type="adversarial",
            classification_metadata=metadata
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify JSON structure is preserved
        assert threat.classification_metadata["keyword_matches"]["adversarial"] == ["attack", "adversarial"]
        assert threat.classification_metadata["keyword_score"] == 2
        assert threat.classification_metadata["llm_suggestion"] == "adversarial"
        assert threat.classification_metadata["timestamp"] == "2024-01-15T10:30:00Z"
    
    @pytest.mark.asyncio
    async def test_to_dict_includes_classification_fields(self, db_session: AsyncSession):
        """Test that to_dict() includes all classification fields."""
        threat = Threat(
            title="Test to_dict",
            description="Test threat for to_dict method",
            source="test_source",
            content_hash="test_hash_dict",
            threat_type="adversarial",
            classification_method="hybrid",
            classification_confidence="medium",
            classification_score=3,
            classification_metadata={"test": "data"}
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        threat_dict = threat.to_dict()
        
        # Verify all classification fields are in the dictionary
        assert "classification_method" in threat_dict
        assert "classification_confidence" in threat_dict
        assert "classification_score" in threat_dict
        assert "classification_metadata" in threat_dict
        
        assert threat_dict["classification_method"] == "hybrid"
        assert threat_dict["classification_confidence"] == "medium"
        assert threat_dict["classification_score"] == 3
        assert threat_dict["classification_metadata"] == {"test": "data"}
    
    @pytest.mark.asyncio
    async def test_to_dict_with_null_classification_fields(self, db_session: AsyncSession):
        """Test that to_dict() handles null classification fields correctly."""
        threat = Threat(
            title="Test to_dict Null",
            description="Test threat with null classification fields",
            source="test_source",
            content_hash="test_hash_dict_null",
            threat_type="unknown"
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        threat_dict = threat.to_dict()
        
        # Verify classification fields are present but null
        assert "classification_method" in threat_dict
        assert "classification_confidence" in threat_dict
        assert "classification_score" in threat_dict
        assert "classification_metadata" in threat_dict
        
        assert threat_dict["classification_method"] is None
        assert threat_dict["classification_confidence"] is None
        assert threat_dict["classification_score"] is None
        assert threat_dict["classification_metadata"] is None
    
    @pytest.mark.asyncio
    async def test_llm_failure_fallback_scenario(self, db_session: AsyncSession):
        """Test classification fields for LLM failure with keyword fallback."""
        threat = Threat(
            title="Test LLM Failure",
            description="Test threat where LLM failed but keyword worked",
            source="test_source",
            content_hash="test_hash_fallback",
            threat_type="poisoning",
            classification_method="keyword_fallback",
            classification_confidence="medium",
            classification_score=3,
            classification_metadata={
                "keyword_matches": {
                    "poisoning": ["poison", "contaminate", "corrupt"]
                },
                "keyword_result": "poisoning",
                "keyword_score": 3,
                "llm_error": "Connection timeout after 30s",
                "fallback_used": True,
                "fallback_method": "keyword",
                "method": "keyword_fallback",
                "confidence": "medium"
            }
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify fallback scenario is properly stored
        assert threat.classification_method == "keyword_fallback"
        assert threat.classification_metadata["llm_error"] is not None
        assert threat.classification_metadata["fallback_used"] is True
        assert threat.threat_type == "poisoning"
    
    @pytest.mark.asyncio
    async def test_complete_failure_scenario(self, db_session: AsyncSession):
        """Test classification fields when all classification methods fail."""
        threat = Threat(
            title="Test Complete Failure",
            description="Test threat where all classification failed",
            source="test_source",
            content_hash="test_hash_failed",
            threat_type="unknown",
            classification_method="failed",
            classification_confidence="none",
            classification_score=0,
            classification_metadata={
                "keyword_score": 0,
                "llm_error": "Service unavailable",
                "method": "failed",
                "confidence": "none"
            }
        )
        
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Verify failure scenario is properly stored
        assert threat.classification_method == "failed"
        assert threat.classification_confidence == "none"
        assert threat.classification_score == 0
        assert threat.threat_type == "unknown"
