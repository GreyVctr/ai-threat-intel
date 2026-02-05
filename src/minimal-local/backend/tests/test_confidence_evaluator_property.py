"""
Property-based tests for ConfidenceEvaluator.

Tests universal properties of confidence level mapping that should hold
for all valid inputs.

Feature: hybrid-threat-classification
"""
import pytest
from hypothesis import given, strategies as st, settings
from services.confidence_evaluator import ConfidenceEvaluator
from services.classification_types import ConfidenceLevel


class TestConfidenceEvaluatorProperties:
    """Property-based tests for ConfidenceEvaluator."""
    
    @given(score=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=100)
    def test_property_5_confidence_level_mapping_correctness(self, score: int):
        """
        **Validates: Requirements 2.1, 2.2, 2.3**
        
        Property 5: Confidence level mapping correctness
        
        For any confidence score, the confidence level should be:
        - "high" if score >= 5
        - "medium" if 2 <= score <= 4
        - "low" if score == 1
        - "none" if score == 0
        
        This property ensures that the confidence level mapping is always
        correct regardless of the input score value.
        """
        result = ConfidenceEvaluator.evaluate(score)
        
        # Verify the mapping follows the specification
        if score >= 5:
            assert result == ConfidenceLevel.HIGH, \
                f"Score {score} should map to HIGH confidence"
        elif 2 <= score <= 4:
            assert result == ConfidenceLevel.MEDIUM, \
                f"Score {score} should map to MEDIUM confidence"
        elif score == 1:
            assert result == ConfidenceLevel.LOW, \
                f"Score {score} should map to LOW confidence"
        elif score == 0:
            assert result == ConfidenceLevel.NONE, \
                f"Score {score} should map to NONE confidence"
    
    @given(score=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=100)
    def test_evaluate_returns_valid_confidence_level(self, score: int):
        """
        Property: evaluate() always returns a valid ConfidenceLevel enum value.
        
        For any non-negative integer score, the evaluate method should return
        one of the four valid ConfidenceLevel enum values.
        """
        result = ConfidenceEvaluator.evaluate(score)
        
        # Result must be a ConfidenceLevel enum
        assert isinstance(result, ConfidenceLevel), \
            f"Result must be a ConfidenceLevel enum, got {type(result)}"
        
        # Result must be one of the four valid values
        valid_levels = {
            ConfidenceLevel.HIGH,
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.LOW,
            ConfidenceLevel.NONE
        }
        assert result in valid_levels, \
            f"Result {result} must be one of {valid_levels}"
    
    @given(score=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=100)
    def test_monotonic_confidence_ordering(self, score: int):
        """
        Property: Higher scores never result in lower confidence levels.
        
        For any score, increasing the score should never decrease the
        confidence level. The ordering is: NONE < LOW < MEDIUM < HIGH.
        """
        result = ConfidenceEvaluator.evaluate(score)
        
        # Define confidence level ordering
        level_order = {
            ConfidenceLevel.NONE: 0,
            ConfidenceLevel.LOW: 1,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.HIGH: 3
        }
        
        # Test that score + 1 gives equal or higher confidence
        if score < 10000:  # Avoid overflow
            next_result = ConfidenceEvaluator.evaluate(score + 1)
            assert level_order[next_result] >= level_order[result], \
                f"Score {score + 1} should have >= confidence than score {score}"
    
    @given(
        score1=st.integers(min_value=0, max_value=10000),
        score2=st.integers(min_value=0, max_value=10000)
    )
    @settings(max_examples=100)
    def test_deterministic_evaluation(self, score1: int, score2: int):
        """
        Property: evaluate() is deterministic.
        
        For any score, calling evaluate() multiple times with the same score
        should always return the same confidence level.
        """
        if score1 == score2:
            result1 = ConfidenceEvaluator.evaluate(score1)
            result2 = ConfidenceEvaluator.evaluate(score2)
            assert result1 == result2, \
                f"Same score {score1} should always return same confidence level"
    
    @given(score=st.integers(min_value=5, max_value=10000))
    @settings(max_examples=100)
    def test_high_confidence_threshold(self, score: int):
        """
        Property: All scores >= HIGH_THRESHOLD return HIGH confidence.
        
        For any score at or above the HIGH_THRESHOLD (5), the confidence
        level should be HIGH.
        """
        result = ConfidenceEvaluator.evaluate(score)
        assert result == ConfidenceLevel.HIGH, \
            f"Score {score} >= {ConfidenceEvaluator.HIGH_THRESHOLD} should be HIGH"
    
    @given(score=st.integers(min_value=2, max_value=4))
    @settings(max_examples=100)
    def test_medium_confidence_range(self, score: int):
        """
        Property: All scores in [MEDIUM_THRESHOLD, HIGH_THRESHOLD) return MEDIUM.
        
        For any score in the range [2, 5), the confidence level should be MEDIUM.
        """
        result = ConfidenceEvaluator.evaluate(score)
        assert result == ConfidenceLevel.MEDIUM, \
            f"Score {score} in [2, 5) should be MEDIUM"
    
    @given(score=st.integers(min_value=0, max_value=1))
    @settings(max_examples=100)
    def test_low_and_none_confidence_range(self, score: int):
        """
        Property: Scores 0 and 1 return NONE or LOW respectively.
        
        For score 0, confidence should be NONE.
        For score 1, confidence should be LOW.
        """
        result = ConfidenceEvaluator.evaluate(score)
        
        if score == 0:
            assert result == ConfidenceLevel.NONE, \
                "Score 0 should be NONE"
        elif score == 1:
            assert result == ConfidenceLevel.LOW, \
                "Score 1 should be LOW"
    
    @given(score=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=100)
    def test_confidence_level_has_string_value(self, score: int):
        """
        Property: ConfidenceLevel enum values have string representations.
        
        For any score, the returned ConfidenceLevel should have a valid
        string value that matches one of: "high", "medium", "low", "none".
        """
        result = ConfidenceEvaluator.evaluate(score)
        
        valid_string_values = {"high", "medium", "low", "none"}
        assert result.value in valid_string_values, \
            f"ConfidenceLevel value {result.value} must be in {valid_string_values}"
