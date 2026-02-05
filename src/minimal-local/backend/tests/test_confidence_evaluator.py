"""
Unit tests for ConfidenceEvaluator.

Tests the confidence level evaluation logic, including boundary conditions
and threshold mappings.
"""
import pytest
from services.confidence_evaluator import ConfidenceEvaluator
from services.classification_types import ConfidenceLevel


class TestConfidenceEvaluator:
    """Test suite for ConfidenceEvaluator class."""
    
    def test_high_confidence_at_threshold(self):
        """Test that score of 5 (HIGH_THRESHOLD) returns HIGH confidence."""
        result = ConfidenceEvaluator.evaluate(5)
        assert result == ConfidenceLevel.HIGH
    
    def test_high_confidence_above_threshold(self):
        """Test that scores above HIGH_THRESHOLD return HIGH confidence."""
        assert ConfidenceEvaluator.evaluate(6) == ConfidenceLevel.HIGH
        assert ConfidenceEvaluator.evaluate(10) == ConfidenceLevel.HIGH
        assert ConfidenceEvaluator.evaluate(100) == ConfidenceLevel.HIGH
    
    def test_medium_confidence_at_lower_threshold(self):
        """Test that score of 2 (MEDIUM_THRESHOLD) returns MEDIUM confidence."""
        result = ConfidenceEvaluator.evaluate(2)
        assert result == ConfidenceLevel.MEDIUM
    
    def test_medium_confidence_in_range(self):
        """Test that scores in medium range (2-4) return MEDIUM confidence."""
        assert ConfidenceEvaluator.evaluate(2) == ConfidenceLevel.MEDIUM
        assert ConfidenceEvaluator.evaluate(3) == ConfidenceLevel.MEDIUM
        assert ConfidenceEvaluator.evaluate(4) == ConfidenceLevel.MEDIUM
    
    def test_medium_confidence_at_upper_boundary(self):
        """Test that score of 4 (one below HIGH_THRESHOLD) returns MEDIUM."""
        result = ConfidenceEvaluator.evaluate(4)
        assert result == ConfidenceLevel.MEDIUM
    
    def test_low_confidence_single_match(self):
        """Test that score of 1 returns LOW confidence."""
        result = ConfidenceEvaluator.evaluate(1)
        assert result == ConfidenceLevel.LOW
    
    def test_none_confidence_zero_matches(self):
        """Test that score of 0 returns NONE confidence."""
        result = ConfidenceEvaluator.evaluate(0)
        assert result == ConfidenceLevel.NONE
    
    def test_boundary_between_medium_and_high(self):
        """Test the boundary between MEDIUM and HIGH confidence levels."""
        # Score of 4 should be MEDIUM
        assert ConfidenceEvaluator.evaluate(4) == ConfidenceLevel.MEDIUM
        # Score of 5 should be HIGH
        assert ConfidenceEvaluator.evaluate(5) == ConfidenceLevel.HIGH
    
    def test_boundary_between_low_and_medium(self):
        """Test the boundary between LOW and MEDIUM confidence levels."""
        # Score of 1 should be LOW
        assert ConfidenceEvaluator.evaluate(1) == ConfidenceLevel.LOW
        # Score of 2 should be MEDIUM
        assert ConfidenceEvaluator.evaluate(2) == ConfidenceLevel.MEDIUM
    
    def test_boundary_between_none_and_low(self):
        """Test the boundary between NONE and LOW confidence levels."""
        # Score of 0 should be NONE
        assert ConfidenceEvaluator.evaluate(0) == ConfidenceLevel.NONE
        # Score of 1 should be LOW
        assert ConfidenceEvaluator.evaluate(1) == ConfidenceLevel.LOW
    
    def test_threshold_constants(self):
        """Test that threshold constants have expected values."""
        assert ConfidenceEvaluator.HIGH_THRESHOLD == 5
        assert ConfidenceEvaluator.MEDIUM_THRESHOLD == 2
    
    def test_all_confidence_levels_reachable(self):
        """Test that all confidence levels can be reached with valid scores."""
        # Verify each confidence level is reachable
        assert ConfidenceEvaluator.evaluate(0) == ConfidenceLevel.NONE
        assert ConfidenceEvaluator.evaluate(1) == ConfidenceLevel.LOW
        assert ConfidenceEvaluator.evaluate(2) == ConfidenceLevel.MEDIUM
        assert ConfidenceEvaluator.evaluate(5) == ConfidenceLevel.HIGH
    
    def test_large_scores(self):
        """Test that very large scores still return HIGH confidence."""
        assert ConfidenceEvaluator.evaluate(1000) == ConfidenceLevel.HIGH
        assert ConfidenceEvaluator.evaluate(999999) == ConfidenceLevel.HIGH
    
    def test_evaluate_is_static(self):
        """Test that evaluate can be called without instantiating the class."""
        # Should be callable as a static method
        result = ConfidenceEvaluator.evaluate(3)
        assert result == ConfidenceLevel.MEDIUM
        
        # Should not require instance
        assert callable(ConfidenceEvaluator.evaluate)
