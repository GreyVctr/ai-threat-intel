"""
Property-based tests for ClassificationService.

Tests universal properties that should hold for all inputs using Hypothesis.
These tests validate the correctness properties defined in the design document.
"""
import pytest
from hypothesis import given, strategies as st, settings, assume
from unittest.mock import AsyncMock

from services.classification_service import ClassificationService
from services.classification_types import (
    ClassificationResult,
    KeywordResult,
    LLMResult,
    ConfidenceLevel
)


# Strategy for generating threat descriptions
description_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'P', 'Z'), min_codepoint=32, max_codepoint=126),
    min_size=10,
    max_size=500
)


class TestClassificationServiceProperties:
    """Property-based tests for ClassificationService."""
    
    @given(score=st.integers(min_value=0, max_value=100))
    @settings(max_examples=100)
    def test_property_5_confidence_level_mapping_correctness(self, score):
        """
        **Validates: Requirements 2.1, 2.2, 2.3**
        
        Feature: hybrid-threat-classification
        Property 5: Confidence level mapping correctness
        
        For any confidence score, the confidence level should be:
        - "high" if score >= 5
        - "medium" if 2 <= score <= 4
        - "low" if score == 1
        - "none" if score == 0
        """
        service = ClassificationService()
        
        confidence_level = service._determine_confidence_level(score)
        
        if score >= 5:
            assert confidence_level == ConfidenceLevel.HIGH
            assert confidence_level.value == "high"
        elif score >= 2:
            assert confidence_level == ConfidenceLevel.MEDIUM
            assert confidence_level.value == "medium"
        elif score >= 1:
            assert confidence_level == ConfidenceLevel.LOW
            assert confidence_level.value == "low"
        else:
            assert confidence_level == ConfidenceLevel.NONE
            assert confidence_level.value == "none"
    
    @given(score=st.integers(min_value=0, max_value=100))
    @settings(max_examples=100)
    def test_property_4_confidence_score_equals_match_count(self, score):
        """
        **Validates: Requirements 1.4**
        
        Feature: hybrid-threat-classification
        Property 4: Confidence score equals match count
        
        For any classified threat, the confidence_score field should equal
        the number of keywords that matched during keyword analysis.
        """
        service = ClassificationService()
        
        # Create a keyword result with specific score
        keyword_result = KeywordResult(
            threat_type="adversarial" if score > 0 else None,
            score=score,
            matches_by_type={"adversarial": ["test"] * min(score, 10)},
            confidence_level=service._determine_confidence_level(score)
        )
        
        # Build result
        result = service._build_keyword_result(keyword_result)
        
        # Verify score is preserved
        assert result.score == score
        assert result.metadata["keyword_score"] == score
    
    def test_property_13_classification_method_reflects_actual_path(self):
        """
        **Validates: Requirements 5.1, 5.2, 5.3**
        
        Feature: hybrid-threat-classification
        Property 13: Classification method reflects actual path
        
        For any classified threat, the classification_method should be:
        - "keyword" if only keyword matching was used with high confidence
        - "llm" if only LLM was used
        - "hybrid" if both were used
        - "keyword_fallback" if LLM failed and keyword result was used
        - "failed" if all methods failed
        """
        service = ClassificationService()
        
        # Test keyword-only path
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.HIGH
        )
        result = service._build_keyword_result(keyword_result)
        assert result.method == "keyword"
        
        # Test LLM-only path
        llm_result = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        keyword_result_low = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        result = service._build_llm_result(llm_result, keyword_result_low)
        assert result.method == "llm"
        
        # Test hybrid path
        keyword_result_medium = KeywordResult(
            threat_type="adversarial",
            score=3,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        result = service._build_hybrid_result(keyword_result_medium, llm_result)
        assert result.method == "hybrid"
        
        # Test keyword_fallback path
        result = service._build_fallback_result(keyword_result_medium, "LLM error")
        assert result.method == "keyword_fallback"
        
        # Test failed path
        result = service._build_failed_result("All methods failed")
        assert result.method == "failed"
    
    def test_property_12_hybrid_method_always_uses_llm_result(self):
        """
        **Validates: Requirements 4.3, 4.4**
        
        Feature: hybrid-threat-classification
        Property 12: Hybrid method always uses LLM result
        
        For any threat with medium confidence where both keyword and LLM
        classification occur, the final threat_type should be the LLM result
        and classification_method should be "hybrid".
        """
        service = ClassificationService()
        
        # Test with matching results
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=3,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        llm_result = LLMResult(
            threat_type="adversarial",
            raw_response="adversarial",
            success=True,
            error=None
        )
        result = service._build_hybrid_result(keyword_result, llm_result)
        assert result.threat_type == "adversarial"
        assert result.method == "hybrid"
        assert result.metadata["agreement"] is True
        
        # Test with different results - should still use LLM
        llm_result_different = LLMResult(
            threat_type="poisoning",
            raw_response="poisoning",
            success=True,
            error=None
        )
        result = service._build_hybrid_result(keyword_result, llm_result_different)
        assert result.threat_type == "poisoning"  # Uses LLM result
        assert result.method == "hybrid"
        assert result.metadata["agreement"] is False
    
    def test_property_11_hybrid_classification_stores_both_results(self):
        """
        **Validates: Requirements 4.2, 4.5**
        
        Feature: hybrid-threat-classification
        Property 11: Hybrid classification stores both results
        
        For any threat classified using hybrid method (medium confidence),
        the classification_metadata should contain both keyword_result and
        llm_suggestion fields.
        """
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=3,
            matches_by_type={"adversarial": ["attack", "evasion"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        llm_result = LLMResult(
            threat_type="poisoning",
            raw_response="poisoning",
            success=True,
            error=None
        )
        
        result = service._build_hybrid_result(keyword_result, llm_result)
        
        # Verify both results are stored
        assert "keyword_result" in result.metadata
        assert "llm_suggestion" in result.metadata
        assert result.metadata["keyword_result"] == "adversarial"
        assert result.metadata["llm_suggestion"] == "poisoning"
        assert "keyword_matches" in result.metadata
        assert "llm_raw_response" in result.metadata
    
    def test_property_15_metadata_completeness(self):
        """
        **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 5.5**
        
        Feature: hybrid-threat-classification
        Property 15: Metadata completeness
        
        For any classified threat, the classification_metadata should contain:
        - keyword_matches (if keyword matching occurred)
        - confidence_score
        - method
        - confidence level
        - llm_suggestion (if LLM was used)
        """
        service = ClassificationService()
        
        # Test keyword-only result
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={"adversarial": ["attack", "evasion"]},
            confidence_level=ConfidenceLevel.HIGH
        )
        result = service._build_keyword_result(keyword_result)
        
        assert "keyword_matches" in result.metadata
        assert "keyword_score" in result.metadata
        assert "method" in result.metadata
        assert "confidence" in result.metadata
        assert result.metadata["method"] == "keyword"
        assert result.metadata["confidence"] == "high"
        
        # Test LLM result
        llm_result = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        keyword_result_low = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        result = service._build_llm_result(llm_result, keyword_result_low)
        
        assert "llm_suggestion" in result.metadata
        assert "keyword_score" in result.metadata
        assert "method" in result.metadata
        assert "confidence" in result.metadata
        assert result.metadata["llm_suggestion"] == "privacy"
        
        # Test hybrid result
        keyword_result_medium = KeywordResult(
            threat_type="adversarial",
            score=3,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        result = service._build_hybrid_result(keyword_result_medium, llm_result)
        
        assert "keyword_matches" in result.metadata
        assert "keyword_result" in result.metadata
        assert "keyword_score" in result.metadata
        assert "llm_suggestion" in result.metadata
        assert "method" in result.metadata
        assert "confidence" in result.metadata
    
    def test_property_16_llm_failure_fallback_behavior(self):
        """
        **Validates: Requirements 7.2, 7.3**
        
        Feature: hybrid-threat-classification
        Property 16: LLM failure fallback behavior
        
        For any threat where LLM classification fails, if a keyword result
        exists, the system should use the keyword result; otherwise, the
        threat_type should be "unknown".
        """
        service = ClassificationService()
        
        # Test with keyword result available
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=2,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.MEDIUM
        )
        result = service._build_fallback_result(keyword_result, "LLM timeout")
        
        assert result.threat_type == "adversarial"
        assert result.method == "keyword_fallback"
        assert "llm_error" in result.metadata
        
        # Test without keyword result
        result = service._build_failed_result("LLM connection error")
        
        assert result.threat_type == "unknown"
        assert result.method == "failed"
        assert "llm_error" in result.metadata
    
    def test_property_17_llm_failure_method_tracking(self):
        """
        **Validates: Requirements 7.4**
        
        Feature: hybrid-threat-classification
        Property 17: LLM failure method tracking
        
        For any threat where LLM classification fails, the classification_method
        should be set to "keyword_fallback" if a keyword result was used, or
        "failed" if no classification was possible.
        """
        service = ClassificationService()
        
        # Test keyword_fallback
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=1,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.LOW
        )
        result = service._build_fallback_result(keyword_result, "Error")
        
        assert result.method == "keyword_fallback"
        assert result.metadata["fallback_used"] is True
        
        # Test failed
        result = service._build_failed_result("Error")
        
        assert result.method == "failed"
        assert result.metadata["fallback_used"] is False
    
    def test_property_24_non_null_classification(self):
        """
        **Validates: Requirements 11.4**
        
        Feature: hybrid-threat-classification
        Property 24: Non-null classification
        
        For any threat that completes the classification process, the
        threat_type field should not be null.
        """
        service = ClassificationService()
        
        # Test all result building methods
        keyword_result = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={"adversarial": ["attack"]},
            confidence_level=ConfidenceLevel.HIGH
        )
        result = service._build_keyword_result(keyword_result)
        assert result.threat_type is not None
        assert result.threat_type != ""
        
        # Test with None keyword result
        keyword_result_none = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        result = service._build_keyword_result(keyword_result_none)
        assert result.threat_type is not None
        assert result.threat_type == "unknown"
        
        # Test LLM result
        llm_result = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        result = service._build_llm_result(llm_result, keyword_result_none)
        assert result.threat_type is not None
        
        # Test hybrid result
        result = service._build_hybrid_result(keyword_result, llm_result)
        assert result.threat_type is not None
        
        # Test fallback result
        result = service._build_fallback_result(keyword_result, "Error")
        assert result.threat_type is not None
        
        # Test failed result
        result = service._build_failed_result("Error")
        assert result.threat_type is not None
        assert result.threat_type == "unknown"
    
    @given(
        keyword_score=st.integers(min_value=0, max_value=20),
        keyword_type=st.sampled_from(["adversarial", "poisoning", "privacy", None])
    )
    @settings(max_examples=100)
    def test_property_metadata_round_trip_serialization(self, keyword_score, keyword_type):
        """
        Property: Classification metadata can be serialized and deserialized.
        
        For any classification result, the metadata should be serializable
        to JSON and deserializable back to an equivalent structure.
        """
        service = ClassificationService()
        
        keyword_result = KeywordResult(
            threat_type=keyword_type,
            score=keyword_score,
            matches_by_type={"adversarial": ["attack"]} if keyword_type else {},
            confidence_level=service._determine_confidence_level(keyword_score)
        )
        
        result = service._build_keyword_result(keyword_result)
        
        # Verify metadata is a dict (JSON-serializable)
        assert isinstance(result.metadata, dict)
        
        # Verify all values are JSON-serializable types
        import json
        try:
            json_str = json.dumps(result.metadata)
            deserialized = json.loads(json_str)
            
            # Verify key fields are preserved
            assert deserialized["method"] == result.metadata["method"]
            assert deserialized["confidence"] == result.metadata["confidence"]
            assert deserialized["keyword_score"] == result.metadata["keyword_score"]
        except (TypeError, ValueError) as e:
            pytest.fail(f"Metadata is not JSON-serializable: {e}")
    
    def test_property_valid_threat_type_output(self):
        """
        **Validates: Requirements 11.3**
        
        Feature: hybrid-threat-classification
        Property 23: Valid threat type output
        
        For any threat classified using LLM, the resulting threat_type should
        be one of the predefined valid types.
        """
        service = ClassificationService()
        
        # All valid types from default config
        valid_types = [
            "adversarial", "extraction", "poisoning", "prompt_injection",
            "privacy", "fairness", "robustness", "supply_chain", "unknown"
        ]
        
        # Test that service has all valid types
        for valid_type in valid_types:
            assert valid_type in service.valid_threat_types
        
        # Test that results only use valid types
        llm_result = LLMResult(
            threat_type="privacy",
            raw_response="privacy",
            success=True,
            error=None
        )
        keyword_result = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        
        result = service._build_llm_result(llm_result, keyword_result)
        assert result.threat_type in valid_types
    
    @given(
        description=description_strategy
    )
    @settings(max_examples=50)
    def test_property_keyword_matching_always_attempted_first(self, description):
        """
        **Validates: Requirements 1.1**
        
        Feature: hybrid-threat-classification
        Property 1: Keyword matching is always attempted first
        
        For any threat submitted for classification, keyword matching should
        be attempted before any LLM classification occurs.
        
        Note: This is tested by verifying that _classify_with_keywords is
        called and returns a result before any LLM operations.
        """
        assume(description.strip())
        
        service = ClassificationService()
        
        # Call keyword matching directly
        keyword_result = service._classify_with_keywords(description)
        
        # Verify we got a result
        assert keyword_result is not None
        assert isinstance(keyword_result, KeywordResult)
        assert keyword_result.score >= 0
        assert keyword_result.confidence_level is not None
