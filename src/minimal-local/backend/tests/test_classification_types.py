"""
Unit tests for classification data classes and types.

Tests dataclass serialization, deserialization, and validation for the
hybrid threat classification system.
"""
import pytest
from services.classification_types import (
    ConfidenceLevel,
    KeywordResult,
    LLMResult,
    ClassificationResult
)


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""
    
    def test_confidence_level_values(self):
        """Test that all confidence levels have correct string values."""
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.NONE.value == "none"
    
    def test_confidence_level_enum_members(self):
        """Test that all expected enum members exist."""
        levels = [level.value for level in ConfidenceLevel]
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels
        assert "none" in levels
        assert len(levels) == 4


class TestKeywordResult:
    """Tests for KeywordResult dataclass."""
    
    def test_keyword_result_creation(self):
        """Test creating a KeywordResult with all fields."""
        result = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={
                "adversarial": ["attack", "evasion", "adversarial"],
                "poisoning": ["poison"]
            },
            confidence_level=ConfidenceLevel.HIGH
        )
        
        assert result.threat_type == "adversarial"
        assert result.score == 5
        assert len(result.matches_by_type) == 2
        assert result.confidence_level == ConfidenceLevel.HIGH
    
    def test_keyword_result_with_none_threat_type(self):
        """Test KeywordResult with no matches (None threat_type)."""
        result = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        
        assert result.threat_type is None
        assert result.score == 0
        assert result.matches_by_type == {}
        assert result.confidence_level == ConfidenceLevel.NONE
    
    def test_keyword_result_to_dict(self):
        """Test serialization of KeywordResult to dictionary."""
        result = KeywordResult(
            threat_type="poisoning",
            score=3,
            matches_by_type={
                "poisoning": ["poison", "contaminate", "backdoor"]
            },
            confidence_level=ConfidenceLevel.MEDIUM
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["threat_type"] == "poisoning"
        assert result_dict["score"] == 3
        assert result_dict["matches_by_type"] == {
            "poisoning": ["poison", "contaminate", "backdoor"]
        }
        assert result_dict["confidence_level"] == "medium"
    
    def test_keyword_result_to_dict_with_none(self):
        """Test serialization with None threat_type."""
        result = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["threat_type"] is None
        assert result_dict["score"] == 0
        assert result_dict["confidence_level"] == "none"
    
    def test_keyword_result_empty_matches(self):
        """Test KeywordResult with empty matches_by_type."""
        result = KeywordResult(
            threat_type=None,
            score=0,
            matches_by_type={},
            confidence_level=ConfidenceLevel.NONE
        )
        
        assert result.matches_by_type == {}
        assert result.to_dict()["matches_by_type"] == {}


class TestLLMResult:
    """Tests for LLMResult dataclass."""
    
    def test_llm_result_success(self):
        """Test creating a successful LLMResult."""
        result = LLMResult(
            threat_type="adversarial",
            raw_response="Based on the description, this is an adversarial attack.",
            success=True,
            error=None
        )
        
        assert result.threat_type == "adversarial"
        assert "adversarial attack" in result.raw_response
        assert result.success is True
        assert result.error is None
    
    def test_llm_result_failure(self):
        """Test creating a failed LLMResult."""
        result = LLMResult(
            threat_type="unknown",
            raw_response="",
            success=False,
            error="Connection timeout after 30s"
        )
        
        assert result.threat_type == "unknown"
        assert result.raw_response == ""
        assert result.success is False
        assert result.error == "Connection timeout after 30s"
    
    def test_llm_result_to_dict_success(self):
        """Test serialization of successful LLMResult."""
        result = LLMResult(
            threat_type="extraction",
            raw_response="This appears to be a model extraction attack.",
            success=True
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["threat_type"] == "extraction"
        assert result_dict["raw_response"] == "This appears to be a model extraction attack."
        assert result_dict["success"] is True
        assert result_dict["error"] is None
    
    def test_llm_result_to_dict_failure(self):
        """Test serialization of failed LLMResult."""
        result = LLMResult(
            threat_type="unknown",
            raw_response="",
            success=False,
            error="LLM service unavailable"
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["threat_type"] == "unknown"
        assert result_dict["success"] is False
        assert result_dict["error"] == "LLM service unavailable"
    
    def test_llm_result_default_error(self):
        """Test that error defaults to None."""
        result = LLMResult(
            threat_type="privacy",
            raw_response="Privacy violation detected.",
            success=True
        )
        
        assert result.error is None


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""
    
    def test_classification_result_keyword_method(self):
        """Test ClassificationResult for keyword-only classification."""
        result = ClassificationResult(
            threat_type="adversarial",
            method="keyword",
            confidence="high",
            score=7,
            metadata={
                "keyword_matches": {
                    "adversarial": ["attack", "evasion", "adversarial"]
                },
                "keyword_result": "adversarial",
                "keyword_score": 7
            }
        )
        
        assert result.threat_type == "adversarial"
        assert result.method == "keyword"
        assert result.confidence == "high"
        assert result.score == 7
        assert "keyword_matches" in result.metadata
    
    def test_classification_result_llm_method(self):
        """Test ClassificationResult for LLM-only classification."""
        result = ClassificationResult(
            threat_type="poisoning",
            method="llm",
            confidence="low",
            score=1,
            metadata={
                "llm_suggestion": "poisoning",
                "llm_raw_response": "This is a data poisoning attack.",
                "keyword_score": 1
            }
        )
        
        assert result.threat_type == "poisoning"
        assert result.method == "llm"
        assert result.confidence == "low"
        assert result.score == 1
        assert "llm_suggestion" in result.metadata
    
    def test_classification_result_hybrid_method(self):
        """Test ClassificationResult for hybrid classification."""
        result = ClassificationResult(
            threat_type="extraction",
            method="hybrid",
            confidence="medium",
            score=3,
            metadata={
                "keyword_matches": {
                    "extraction": ["extract", "steal"]
                },
                "keyword_result": "extraction",
                "llm_suggestion": "extraction",
                "keyword_score": 3
            }
        )
        
        assert result.threat_type == "extraction"
        assert result.method == "hybrid"
        assert result.confidence == "medium"
        assert result.score == 3
        assert "keyword_result" in result.metadata
        assert "llm_suggestion" in result.metadata
    
    def test_classification_result_to_dict(self):
        """Test serialization of ClassificationResult."""
        result = ClassificationResult(
            threat_type="prompt_injection",
            method="keyword",
            confidence="high",
            score=6,
            metadata={
                "keyword_matches": {
                    "prompt_injection": ["injection", "jailbreak", "prompt"]
                }
            }
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["threat_type"] == "prompt_injection"
        assert result_dict["method"] == "keyword"
        assert result_dict["confidence"] == "high"
        assert result_dict["score"] == 6
        assert "keyword_matches" in result_dict["metadata"]
    
    def test_classification_result_empty_metadata(self):
        """Test ClassificationResult with empty metadata."""
        result = ClassificationResult(
            threat_type="unknown",
            method="failed",
            confidence="none",
            score=0
        )
        
        assert result.metadata == {}
        assert result.to_dict()["metadata"] == {}
    
    def test_classification_result_default_metadata(self):
        """Test that metadata defaults to empty dict."""
        result = ClassificationResult(
            threat_type="fairness",
            method="llm",
            confidence="low",
            score=0
        )
        
        assert result.metadata == {}
        assert isinstance(result.metadata, dict)
    
    def test_classification_result_keyword_fallback(self):
        """Test ClassificationResult for keyword_fallback method."""
        result = ClassificationResult(
            threat_type="robustness",
            method="keyword_fallback",
            confidence="medium",
            score=3,
            metadata={
                "keyword_result": "robustness",
                "llm_error": "Connection timeout",
                "fallback_used": True
            }
        )
        
        assert result.method == "keyword_fallback"
        assert result.metadata["llm_error"] == "Connection timeout"
        assert result.metadata["fallback_used"] is True
    
    def test_classification_result_failed_method(self):
        """Test ClassificationResult for failed classification."""
        result = ClassificationResult(
            threat_type="unknown",
            method="failed",
            confidence="none",
            score=0,
            metadata={
                "llm_error": "Service unavailable",
                "keyword_result": None
            }
        )
        
        assert result.threat_type == "unknown"
        assert result.method == "failed"
        assert result.confidence == "none"
        assert result.score == 0


class TestDataclassSerialization:
    """Integration tests for dataclass serialization round-trips."""
    
    def test_keyword_result_round_trip(self):
        """Test that KeywordResult can be serialized and maintains data integrity."""
        original = KeywordResult(
            threat_type="adversarial",
            score=5,
            matches_by_type={
                "adversarial": ["attack", "evasion"],
                "poisoning": ["poison"]
            },
            confidence_level=ConfidenceLevel.HIGH
        )
        
        # Serialize to dict
        serialized = original.to_dict()
        
        # Verify all data is preserved
        assert serialized["threat_type"] == original.threat_type
        assert serialized["score"] == original.score
        assert serialized["matches_by_type"] == original.matches_by_type
        assert serialized["confidence_level"] == original.confidence_level.value
    
    def test_llm_result_round_trip(self):
        """Test that LLMResult can be serialized and maintains data integrity."""
        original = LLMResult(
            threat_type="extraction",
            raw_response="Model extraction detected.",
            success=True,
            error=None
        )
        
        # Serialize to dict
        serialized = original.to_dict()
        
        # Verify all data is preserved
        assert serialized["threat_type"] == original.threat_type
        assert serialized["raw_response"] == original.raw_response
        assert serialized["success"] == original.success
        assert serialized["error"] == original.error
    
    def test_classification_result_round_trip(self):
        """Test that ClassificationResult can be serialized and maintains data integrity."""
        original = ClassificationResult(
            threat_type="poisoning",
            method="hybrid",
            confidence="medium",
            score=3,
            metadata={
                "keyword_matches": {"poisoning": ["poison", "backdoor"]},
                "llm_suggestion": "poisoning",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        )
        
        # Serialize to dict
        serialized = original.to_dict()
        
        # Verify all data is preserved
        assert serialized["threat_type"] == original.threat_type
        assert serialized["method"] == original.method
        assert serialized["confidence"] == original.confidence
        assert serialized["score"] == original.score
        assert serialized["metadata"] == original.metadata
    
    def test_nested_metadata_serialization(self):
        """Test that nested metadata structures are properly serialized."""
        result = ClassificationResult(
            threat_type="supply_chain",
            method="hybrid",
            confidence="medium",
            score=4,
            metadata={
                "keyword_matches": {
                    "supply_chain": ["supply", "dependency", "vendor"],
                    "robustness": ["stability"]
                },
                "keyword_result": "supply_chain",
                "llm_suggestion": "supply_chain",
                "llm_raw_response": "Supply chain vulnerability detected.",
                "confidence": "medium",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        )
        
        serialized = result.to_dict()
        
        # Verify nested structures are preserved
        assert isinstance(serialized["metadata"]["keyword_matches"], dict)
        assert len(serialized["metadata"]["keyword_matches"]["supply_chain"]) == 3
        assert serialized["metadata"]["llm_suggestion"] == "supply_chain"
