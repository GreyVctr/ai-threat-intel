"""
Integration tests for ClassificationService.

Tests the complete classification workflow with database persistence,
including all decision paths and error handling scenarios.
"""
import pytest
from unittest.mock import AsyncMock

from services.classification_service import ClassificationService
from services.classification_types import LLMResult
from models.threat import Threat


class TestClassificationServiceIntegration:
    """Integration tests for ClassificationService with database."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_high_confidence_keyword_path(self, db_session):
        """
        Test complete workflow for high confidence keyword classification.
        
        Validates:
        - Keyword matching is attempted first
        - High confidence (≥5 matches) uses keyword result only
        - No LLM call is made
        - Results are persisted to database correctly
        """
        service = ClassificationService()
        
        # Create threat with high keyword match count
        threat = Threat(
            title="Adversarial Attack Research",
            description=(
                "This research explores adversarial attacks using evasion techniques "
                "and perturbation methods. The adversary employs malicious strategies "
                "to compromise the model through adversarial examples."
            ),
            source="test_source",
            content_hash="integration_test_1"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify classification result
        assert result.threat_type == "adversarial"
        assert result.method == "keyword"
        assert result.confidence == "high"
        assert result.score >= 5
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "adversarial"
        assert threat.classification_method == "keyword"
        assert threat.classification_confidence == "high"
        assert threat.classification_score >= 5
        assert threat.classification_metadata is not None
        assert threat.classification_metadata["method"] == "keyword"
        assert "keyword_matches" in threat.classification_metadata
    
    @pytest.mark.asyncio
    async def test_end_to_end_medium_confidence_hybrid_path(self, db_session):
        """
        Test complete workflow for medium confidence hybrid validation.
        
        Validates:
        - Keyword matching is attempted first
        - Medium confidence (2-4 matches) triggers LLM validation
        - LLM result is used as final classification
        - Both keyword and LLM results are stored in metadata
        - Results are persisted to database correctly
        """
        # Mock LLM classifier
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="adversarial",
            raw_response="Based on the description, this is an adversarial threat.",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        # Create threat with medium keyword match count
        threat = Threat(
            title="Security Vulnerability",
            description="This involves an attack using evasion techniques to bypass security.",
            source="test_source",
            content_hash="integration_test_2"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify classification result
        assert result.threat_type == "adversarial"
        assert result.method == "hybrid"
        assert result.confidence == "medium"
        assert 2 <= result.score <= 4
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "adversarial"
        assert threat.classification_method == "hybrid"
        assert threat.classification_confidence == "medium"
        assert threat.classification_metadata is not None
        assert threat.classification_metadata["method"] == "hybrid"
        assert "keyword_result" in threat.classification_metadata
        assert "llm_suggestion" in threat.classification_metadata
    
    @pytest.mark.asyncio
    async def test_end_to_end_low_confidence_llm_path(self, db_session):
        """
        Test complete workflow for low confidence LLM classification.
        
        Validates:
        - Keyword matching is attempted first
        - Low confidence (0-1 matches) triggers LLM classification
        - LLM result is used as final classification
        - Results are persisted to database correctly
        """
        # Mock LLM classifier
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="privacy",
            raw_response="This appears to be a privacy-related threat.",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        # Create threat with low/no keyword matches
        threat = Threat(
            title="Data Handling Issue",
            description="This system has issues with how it handles sensitive information.",
            source="test_source",
            content_hash="integration_test_3"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify classification result
        assert result.threat_type == "privacy"
        assert result.method == "llm"
        assert result.confidence in ["low", "none"]
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "privacy"
        assert threat.classification_method == "llm"
        assert threat.classification_metadata is not None
        assert threat.classification_metadata["method"] == "llm"
        assert "llm_suggestion" in threat.classification_metadata
    
    @pytest.mark.asyncio
    async def test_end_to_end_llm_failure_with_keyword_fallback(self, db_session):
        """
        Test complete workflow when LLM fails but keyword result is available.
        
        Validates:
        - Keyword matching is attempted first
        - LLM is called for medium/low confidence
        - When LLM fails, system falls back to keyword result
        - Error is logged in metadata
        - Results are persisted to database correctly
        """
        # Mock LLM classifier to fail
        mock_llm = AsyncMock()
        mock_llm.classify.side_effect = ConnectionError("Ollama service unavailable")
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        # Create threat with medium keyword match count
        threat = Threat(
            title="Attack Vector",
            description="This describes an attack using evasion methods.",
            source="test_source",
            content_hash="integration_test_4"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify fallback to keyword result
        assert result.threat_type == "adversarial"
        assert result.method == "keyword_fallback"
        assert result.confidence == "medium"
        assert "llm_error" in result.metadata
        assert result.metadata["fallback_used"] is True
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "adversarial"
        assert threat.classification_method == "keyword_fallback"
        assert threat.classification_metadata is not None
        assert "llm_error" in threat.classification_metadata
    
    @pytest.mark.asyncio
    async def test_end_to_end_complete_failure_unknown(self, db_session):
        """
        Test complete workflow when all classification methods fail.
        
        Validates:
        - Keyword matching is attempted first
        - No keyword matches found
        - LLM classification fails
        - System defaults to "unknown"
        - Error is logged in metadata
        - Results are persisted to database correctly
        """
        # Mock LLM classifier to fail
        mock_llm = AsyncMock()
        mock_llm.classify.side_effect = TimeoutError("Request timeout")
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        # Create threat with no keyword matches
        threat = Threat(
            title="Generic Issue",
            description="This is a generic description without specific keywords.",
            source="test_source",
            content_hash="integration_test_5"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM was called
        mock_llm.classify.assert_called_once()
        
        # Verify failed classification
        assert result.threat_type == "unknown"
        assert result.method == "failed"
        assert result.confidence == "none"
        assert "llm_error" in result.metadata
        assert result.metadata["fallback_used"] is False
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "unknown"
        assert threat.classification_method == "failed"
        assert threat.classification_metadata is not None
        assert "llm_error" in threat.classification_metadata
    
    @pytest.mark.asyncio
    async def test_end_to_end_hybrid_disagreement(self, db_session):
        """
        Test hybrid path when LLM disagrees with keyword classification.
        
        Validates:
        - Keyword suggests one type
        - LLM suggests different type
        - LLM result is used as final classification
        - Both results are stored in metadata
        - Agreement flag is set to False
        """
        # Mock LLM to return different result than keyword
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="poisoning",
            raw_response="This is actually a poisoning attack.",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        # Create threat that keywords suggest is adversarial
        threat = Threat(
            title="Attack Analysis",
            description="This involves an attack using evasion techniques.",
            source="test_source",
            content_hash="integration_test_6"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Verify LLM result is used
        assert result.threat_type == "poisoning"
        assert result.method == "hybrid"
        assert result.metadata["keyword_result"] == "adversarial"
        assert result.metadata["llm_suggestion"] == "poisoning"
        assert result.metadata["agreement"] is False
        
        # Verify database persistence
        await db_session.refresh(threat)
        assert threat.threat_type == "poisoning"
        assert threat.classification_metadata["agreement"] is False
    
    @pytest.mark.asyncio
    async def test_end_to_end_multiple_threats_batch(self, db_session):
        """
        Test classification of multiple threats in sequence.
        
        Validates:
        - Multiple threats can be classified
        - Each threat gets correct classification
        - Database state is consistent
        """
        service = ClassificationService()
        
        # Create multiple threats
        threats = [
            Threat(
                title="Adversarial Attack",
                description="adversarial attack evasion perturbation malicious adversary",
                source="test",
                content_hash=f"batch_test_{i}"
            )
            for i in range(3)
        ]
        
        for threat in threats:
            db_session.add(threat)
        await db_session.commit()
        
        # Classify all threats
        results = []
        for threat in threats:
            await db_session.refresh(threat)
            result = await service.classify_threat(threat, db_session)
            results.append(result)
        
        # Verify all classifications
        for i, (threat, result) in enumerate(zip(threats, results)):
            await db_session.refresh(threat)
            assert threat.threat_type == "adversarial"
            assert threat.classification_method == "keyword"
            assert threat.classification_score >= 5
            assert result.threat_type == "adversarial"
    
    @pytest.mark.asyncio
    async def test_end_to_end_empty_description_handling(self, db_session):
        """
        Test handling of threats with empty descriptions.
        
        Validates:
        - Empty descriptions are handled gracefully
        - LLM is called due to no keyword matches
        - System doesn't crash
        """
        # Mock LLM classifier
        mock_llm = AsyncMock()
        mock_llm.classify.return_value = LLMResult(
            threat_type="unknown",
            raw_response="Cannot classify without description.",
            success=True,
            error=None
        )
        
        service = ClassificationService(llm_classifier=mock_llm)
        
        threat = Threat(
            title="Empty Description Test",
            description="",
            source="test",
            content_hash="empty_desc_test"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Should not crash
        result = await service.classify_threat(threat, db_session)
        
        assert result is not None
        assert result.score == 0
        assert result.confidence == "none"
    
    @pytest.mark.asyncio
    async def test_end_to_end_metadata_persistence_round_trip(self, db_session):
        """
        Test that classification metadata survives database round-trip.
        
        Validates Property 14: Classification metadata round-trip
        """
        service = ClassificationService()
        
        threat = Threat(
            title="Metadata Test",
            description="adversarial attack evasion perturbation malicious",
            source="test",
            content_hash="metadata_test"
        )
        db_session.add(threat)
        await db_session.commit()
        await db_session.refresh(threat)
        
        # Classify threat
        result = await service.classify_threat(threat, db_session)
        
        # Get original metadata
        original_metadata = result.metadata.copy()
        
        # Refresh from database
        await db_session.refresh(threat)
        persisted_metadata = threat.classification_metadata
        
        # Verify key fields are preserved
        assert persisted_metadata["method"] == original_metadata["method"]
        assert persisted_metadata["confidence"] == original_metadata["confidence"]
        assert persisted_metadata["keyword_score"] == original_metadata["keyword_score"]
        assert persisted_metadata["keyword_matches"] == original_metadata["keyword_matches"]
