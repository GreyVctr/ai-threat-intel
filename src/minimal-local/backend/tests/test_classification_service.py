"""
Unit tests for ClassificationService.

Tests the hybrid threat classification workflow including keyword matching,
LLM classification, confidence-based decision tree, and database persistence.
"""
import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime

from services.classification_service import ClassificationService
from services.classification_types import (
    ClassificationResult,
    KeywordResult,
    LLMResult,
    ConfidenceLevel
)
from models.threat import Threat


class TestClassificationServiceInit:
    """Tests for ClassificationService initialization."""
    
    def test_init_with_defaults(self):
        """Test initialization with default configuration."""
        service = ClassificationService()
        
        assert service.keyword_matcher is not None
        assert service.llm_classifier is not None
        assert "adversarial" in service.valid_threat_types
        assert "unknown" in service.valid_threat_types
    
    def test_init_with_custom_keywords(self):
        """Test initialization with custom keyword configuration."""
        custom_config = {
            "test_type": ["test", "keyword"]
        }
        service = ClassificationService(keyword_config=custom_config)
        
        assert "test_type" in service.valid_threat_types
        assert "unknown" in service.valid_threat_types
    
    def test_init_with_custom_llm_classifier(self):
        """Test initialization with custom LLM classifier."""
        mock_llm = Mock()
        service = ClassificationService(llm_classifier=mock_llm)
        
        assert service.llm_classifier == mock_llm


class TestClassificationServiceKeywordPath:
    """Tests for high confidence keyword-only classification path."""
    
    @pytest.mark.asyncio
    async def test_high_confidence_keyword_classification(self, db_session):
        """Test classification with high confidence keyword match (≥5 matches)."""
        service = ClassificationService()
        
        # Create threat with description that matches many keywords
        threat = Threat(
            title="Test Threat",
            description="This is an adversarial attack using evasion techniques and perturbation methods with malicious adversary intent.",
            source="test",
            content_hash="test_hash_1"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify result
        assert result.threat_type == "adversarial"
        assert result.method == "keyword"
        assert result.confidence == "high"
        assert result.score >= 5
        assert "keyword_matches" in result.metadata
        assert result.metadata["method"] == "keyword"
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "adversarial"
        assert threat.classification_method == "keyword"
        assert threat.classification_confidence == "high"
        assert threat.classification_score >= 5
        assert threat.classification_metadata is not None
    
    @pytest.mark.asyncio
    async def test_high_confidence_no_llm_call(self, db_session):
        """Test that LLM is not called for high confidence matches."""
        # Create mock LLM classifier that should not be called
        mock_llm = AsyncMock()
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="adversarial attack evasion perturbation malicious adversary",
            source="test",
            content_hash="test_hash_2"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was not called
        mock_llm.classify.assert_not_called()
        assert result.method == "keyword"


class TestClassificationServiceHybridPath:
    """Tests for medium confidence hybrid validation path."""
    
    @pytest.mark.asyncio
    async def test_medium_confidence_hybrid_classification(self, db_session):
        """Test classification with medium confidence (2-4 matches) triggers LLM validation."""
        # Create mock LLM classifier
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="adversarial",
            raw_response="adversarial",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="This involves an attack using evasion techniques.",
            source="test",
            content_hash="test_hash_3"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify result uses LLM classification
        assert result.threat_type == "adversarial"
        assert result.method == "hybrid"
        assert result.confidence == "medium"
        assert "llm_suggestion" in result.metadata
        assert "keyword_result" in result.metadata
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.classification_method == "hybrid"
    
    @pytest.mark.asyncio
    async def test_hybrid_uses_llm_result(self, db_session):
        """Test that hybrid classification always uses LLM result."""
        # Mock LLM to return different result than keyword
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="poisoning",
            raw_response="poisoning",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="attack evasion adversarial",  # Keywords suggest adversarial
            source="test",
            content_hash="test_hash_4"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM result is used
        assert result.threat_type == "poisoning"
        assert result.method == "hybrid"
        assert result.metadata["llm_suggestion"] == "poisoning"
        assert result.metadata["keyword_result"] == "adversarial"
        assert result.metadata["agreement"] is False
    
    @pytest.mark.asyncio
    async def test_hybrid_llm_failure_fallback(self, db_session):
        """Test fallback to keyword result when LLM fails in hybrid path."""
        # Mock LLM to raise connection error
        mock_llm = AsyncMock()
        mock_llm.classify.side_effect = ConnectionError("Ollama unavailable")
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="attack evasion adversarial",
            source="test",
            content_hash="test_hash_5"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify fallback to keyword result
        assert result.threat_type == "adversarial"
        assert result.method == "keyword_fallback"
        assert "llm_error" in result.metadata
        assert result.metadata["fallback_used"] is True


class TestClassificationServiceLLMPath:
    """Tests for low/none confidence LLM-only classification path."""
    
    @pytest.mark.asyncio
    async def test_low_confidence_llm_classification(self, db_session):
        """Test classification with low confidence (0-1 matches) uses LLM."""
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="This threat involves sensitive data handling issues.",
            source="test",
            content_hash="test_hash_6"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify result
        assert result.threat_type == "privacy"
        assert result.method == "llm"
        assert result.confidence in ["low", "none"]
        assert "llm_suggestion" in result.metadata
    
    @pytest.mark.asyncio
    async def test_none_confidence_llm_classification(self, db_session):
        """Test classification with no keyword matches uses LLM."""
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="robustness",
            raw_response="robustness",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="Some generic description without specific keywords.",
            source="test",
            content_hash="test_hash_7"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify result
        assert result.threat_type == "robustness"
        assert result.method == "llm"
        assert result.confidence == "none"
    
    @pytest.mark.asyncio
    async def test_llm_failure_with_keyword_fallback(self, db_session):
        """Test fallback to keyword when LLM fails and keyword result exists."""
        mock_llm = AsyncMock()
        mock_llm.classify.side_effect = TimeoutError("Request timeout")
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="attack",  # Low confidence (1 match)
            source="test",
            content_hash="test_hash_8"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify fallback to keyword
        assert result.threat_type == "adversarial"
        assert result.method == "keyword_fallback"
        assert "llm_error" in result.metadata
    
    @pytest.mark.asyncio
    async def test_llm_failure_no_keyword_unknown(self, db_session):
        """Test classification fails to unknown when LLM fails and no keyword match."""
        mock_llm = AsyncMock()
        mock_llm.classify.side_effect = ConnectionError("Connection failed")
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="Generic description with no keywords.",
            source="test",
            content_hash="test_hash_9"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Verify failed classification
        assert result.threat_type == "unknown"
        assert result.method == "failed"
        assert result.confidence == "none"
        assert "llm_error" in result.metadata
        assert result.metadata["fallback_used"] is False


class TestClassificationServiceHelperMethods:
    """Tests for helper methods."""
    
    def test_classify_with_keywords(self):
        """Test _classify_with_keywords method."""
        service = ClassificationService()
        
        result = service._classify_with_keywords("adversarial attack evasion")
        
        assert isinstance(result, KeywordResult)
        assert result.threat_type == "adversarial"
        assert result.score >= 2
    
    def test_determine_confidence_level(self):
        """Test _determine_confidence_level method."""
        service = ClassificationService()
        
        assert service._determine_confidence_level(5) == ConfidenceLevel.HIGH
        assert service._determine_confidence_level(3) == ConfidenceLevel.MEDIUM
        assert service._determine_confidence_level(1) == ConfidenceLevel.LOW
        assert service._determine_confidence_level(0) == ConfidenceLevel.NONE
    
    def test_build_keyword_result(self):
        """Test _build_keyword_result method."""
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={"adversarial": ["attack", "evasion"]},
            confidence_level=ConfidenceLevel.HIGH
        )
        
        result = service._build_keyword_result(keyword_result)
        
        assert result.threat_type == "adversarial"
        assert result.method == "keyword"
        assert result.confidence == "high"
        assert result.score == 5
        assert "keyword_matches" in result.metadata
    
    def test_build_hybrid_result(self):
        """Test _build_hybrid_result method."""
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=3,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        
        llm_result = LLMResult(
            threat_type="poisoning",
            raw_response="poisoning",
            success=True,
            error=None
        )
        
        result = service._build_hybrid_result(keyword_result, llm_result)
        
        # Should use LLM result
        assert result.threat_type == "poisoning"
        assert result.method == "hybrid"
        assert result.confidence == "medium"
        assert result.metadata["keyword_result"] == "adversarial"
        assert result.metadata["llm_suggestion"] == "poisoning"
        assert result.metadata["agreement"] is False
    
    def test_build_llm_result(self):
        """Test _build_llm_result method."""
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        
        llm_result = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        
        result = service._build_llm_result(llm_result, keyword_result)
        
        assert result.threat_type == "privacy"
        assert result.method == "llm"
        assert result.confidence == "none"
        assert result.metadata["llm_suggestion"] == "privacy"
    
    def test_build_fallback_result(self):
        """Test _build_fallback_result method."""
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=2,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        
        result = service._build_fallback_result(keyword_result, "LLM timeout")
        
        assert result.threat_type == "adversarial"
        assert result.method == "keyword_fallback"
        assert result.metadata["llm_error"] == "LLM timeout"
        assert result.metadata["fallback_used"] is True
    
    def test_build_failed_result(self):
        """Test _build_failed_result method."""
        service = ClassificationService()
        
        result = service._build_failed_result("Connection error")
        
        assert result.threat_type == "unknown"
        assert result.method == "failed"
        assert result.confidence == "none"
        assert result.score == 0
        assert result.metadata["llm_error"] == "Connection error"
        assert result.metadata["fallback_used"] is False


class TestClassificationServiceEdgeCases:
    """Tests for edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_empty_description(self, db_session):
        """Test classification with empty description."""
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="unknown",
            raw_response="unknown",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description="",
            source="test",
            content_hash="test_hash_10"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Should use LLM due to no keyword matches
        assert result.score == 0
        assert result.confidence == "none"
    
    @pytest.mark.asyncio
    async def test_none_description(self, db_session):
        """Test classification with None description."""
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="unknown",
            raw_response="unknown",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Test Threat",
            description=None,
            source="test",
            content_hash="test_hash_11"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        result = await service.classify_threat(threat, db_session)
        
        # Should handle None gracefully
        assert result is not None
        assert result.score == 0
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self, db_session):
        """Test handling of database errors during persistence."""
        service = ClassificationService()
        
        threat = Threat(
            title="Test Threat",
            description="adversarial attack evasion perturbation malicious",
            source="test",
            content_hash="test_hash_12"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Mock db.commit to raise an error
        with patch.object(db_session, 'commit', side_effect=Exception("DB error")):
            with pytest.raises(Exception, match="DB error"):
                await service.classify_threat(threat, db_session)
