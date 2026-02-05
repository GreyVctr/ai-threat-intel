"""
Confidence level evaluator for threat classification.

This module provides functionality to evaluate confidence levels based on
keyword match counts, mapping numeric scores to categorical confidence levels
(high, medium, low, none) that determine the classification strategy.
"""
from services.classification_types import ConfidenceLevel
from services.classification_config import ClassificationConfig


class ConfidenceEvaluator:
    """
    Evaluates confidence levels from keyword match counts.
    
    The ConfidenceEvaluator uses configurable thresholds to map keyword match
    scores to confidence levels, which determine whether to use keyword-only
    classification, hybrid validation, or LLM-only classification.
    
    Thresholds (configurable via environment variables):
        HIGH_THRESHOLD: Score >= threshold indicates high confidence (keyword only)
        MEDIUM_THRESHOLD: Score >= threshold indicates medium confidence (hybrid validation)
        Score < MEDIUM_THRESHOLD and > 0: Low confidence (LLM classification)
        Score of 0: No confidence (LLM classification)
    """
    
    @staticmethod
    def evaluate(score: int) -> ConfidenceLevel:
        """
        Determine confidence level from score.
        
        Maps a keyword match count to a confidence level using configurable
        thresholds from ClassificationConfig. The confidence level determines
        the classification strategy:
        
        - HIGH (score >= HIGH_THRESHOLD): Use keyword result directly (fast path)
        - MEDIUM (MEDIUM_THRESHOLD <= score < HIGH_THRESHOLD): Validate keyword result with LLM (hybrid)
        - LOW (0 < score < MEDIUM_THRESHOLD): Use LLM classification (fallback)
        - NONE (score == 0): Use LLM classification (fallback)
        
        Args:
            score: Number of keyword matches (must be non-negative)
            
        Returns:
            ConfidenceLevel enum value corresponding to the score
            
        Examples:
            >>> ConfidenceEvaluator.evaluate(7)
            ConfidenceLevel.HIGH
            >>> ConfidenceEvaluator.evaluate(3)
            ConfidenceLevel.MEDIUM
            >>> ConfidenceEvaluator.evaluate(1)
            ConfidenceLevel.LOW
            >>> ConfidenceEvaluator.evaluate(0)
            ConfidenceLevel.NONE
        """
        if score >= ClassificationConfig.HIGH_CONFIDENCE_THRESHOLD:
            return ConfidenceLevel.HIGH
        elif score >= ClassificationConfig.MEDIUM_CONFIDENCE_THRESHOLD:
            return ConfidenceLevel.MEDIUM
        elif score > 0:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.NONE
