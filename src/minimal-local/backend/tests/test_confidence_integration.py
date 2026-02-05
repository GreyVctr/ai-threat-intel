"""
Integration tests for ConfidenceEvaluator with KeywordMatcher.

Tests that the confidence evaluator correctly integrates with the keyword
matcher to provide end-to-end confidence level determination.
"""
import pytest
from services.keyword_matcher import KeywordMatcher
from services.confidence_evaluator import ConfidenceEvaluator
from services.classification_types import ConfidenceLevel


class TestConfidenceIntegration:
    """Integration tests for ConfidenceEvaluator with KeywordMatcher."""
    
    @pytest.fixture
    def keyword_config(self):
        """Sample keyword configuration for testing."""
        return {
            "adversarial": ["attack", "evasion", "adversarial", "perturbation", "manipulation"],
            "poisoning": ["poison", "contaminate", "corrupt", "backdoor"],
            "extraction": ["extract", "steal", "exfiltrate", "leak"],
        }
    
    def test_high_confidence_integration(self, keyword_config):
        """Test that high keyword matches result in HIGH confidence."""
        matcher = KeywordMatcher(keyword_config)
        
        # Description with many adversarial keywords
        description = "This is an adversarial attack using evasion techniques and perturbation manipulation"
        
        result = matcher.match(description)
        
        # Should have high score (5+ matches)
        assert result.score >= 5
        assert result.confidence_level == ConfidenceLevel.HIGH
        
        # Verify ConfidenceEvaluator agrees
        confidence = ConfidenceEvaluator.evaluate(result.score)
        assert confidence == ConfidenceLevel.HIGH
    
    def test_medium_confidence_integration(self, keyword_config):
        """Test that medium keyword matches result in MEDIUM confidence."""
        matcher = KeywordMatcher(keyword_config)
        
        # Description with 2-4 keywords
        description = "This threat involves poison and backdoor techniques"
        
        result = matcher.match(description)
        
        # Should have medium score (2-4 matches)
        assert 2 <= result.score <= 4
        assert result.confidence_level == ConfidenceLevel.MEDIUM
        
        # Verify ConfidenceEvaluator agrees
        confidence = ConfidenceEvaluator.evaluate(result.score)
        assert confidence == ConfidenceLevel.MEDIUM
    
    def test_low_confidence_integration(self, keyword_config):
        """Test that single keyword match results in LOW confidence."""
        matcher = KeywordMatcher(keyword_config)
        
        # Description with only 1 keyword
        description = "This threat involves an attack on the system"
        
        result = matcher.match(description)
        
        # Should have low score (1 match)
        assert result.score == 1
        assert result.confidence_level == ConfidenceLevel.LOW
        
        # Verify ConfidenceEvaluator agrees
        confidence = ConfidenceEvaluator.evaluate(result.score)
        assert confidence == ConfidenceLevel.LOW
    
    def test_no_confidence_integration(self, keyword_config):
        """Test that no keyword matches result in NONE confidence."""
        matcher = KeywordMatcher(keyword_config)
        
        # Description with no matching keywords
        description = "This is a completely unrelated description about weather"
        
        result = matcher.match(description)
        
        # Should have no matches
        assert result.score == 0
        assert result.confidence_level == ConfidenceLevel.NONE
        
        # Verify ConfidenceEvaluator agrees
        confidence = ConfidenceEvaluator.evaluate(result.score)
        assert confidence == ConfidenceLevel.NONE
    
    def test_keyword_result_includes_correct_confidence(self, keyword_config):
        """Test that KeywordResult includes the correct confidence level."""
        matcher = KeywordMatcher(keyword_config)
        
        # Test various descriptions
        test_cases = [
            ("attack evasion adversarial perturbation manipulation", ConfidenceLevel.HIGH),
            ("poison backdoor corrupt", ConfidenceLevel.MEDIUM),
            ("extract", ConfidenceLevel.LOW),
            ("nothing relevant", ConfidenceLevel.NONE),
        ]
        
        for description, expected_confidence in test_cases:
            result = matcher.match(description)
            assert result.confidence_level == expected_confidence, \
                f"Description '{description}' should have {expected_confidence} confidence"
            
            # Verify ConfidenceEvaluator produces same result
            evaluator_confidence = ConfidenceEvaluator.evaluate(result.score)
            assert evaluator_confidence == expected_confidence
