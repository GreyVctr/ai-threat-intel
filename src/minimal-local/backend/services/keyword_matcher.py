"""
Keyword-based threat classification matcher.

This module implements keyword matching for threat descriptions, counting
matches against predefined keyword lists for each threat type and determining
the most likely threat classification based on match counts.
"""
import re
import string
from typing import Dict, List, Tuple, Optional

from services.classification_types import KeywordResult, ConfidenceLevel


class KeywordMatcher:
    """
    Matches threat descriptions against keyword lists for classification.
    
    The KeywordMatcher performs case-insensitive keyword matching with text
    normalization (lowercase, punctuation removal) to identify threat types
    based on keyword frequency in the description.
    
    Attributes:
        keywords: Dictionary mapping threat_type to list of keywords
    """
    
    def __init__(self, keyword_config: Dict[str, List[str]]):
        """
        Initialize with keyword configuration.
        
        Args:
            keyword_config: Dict mapping threat_type to keyword list.
                          Example: {"adversarial": ["attack", "evasion"], ...}
        """
        self.keywords = keyword_config
    
    def match(self, description: str) -> KeywordResult:
        """
        Match description against all keyword lists.
        
        Performs keyword matching across all threat types, counts matches,
        and returns the threat type with the highest match count along with
        detailed match information.
        
        Args:
            description: Threat description text to analyze
            
        Returns:
            KeywordResult with:
                - threat_type: Type with highest match count (or None if no matches)
                - score: Number of matches for the selected type
                - matches_by_type: Dict of all matches per type
                - confidence_level: Confidence level based on score
        """
        # Handle edge case: empty description
        if not description or not description.strip():
            return KeywordResult(
                threat_type=None,
                score=0,
                matches_by_type={},
                confidence_level=ConfidenceLevel.NONE
            )
        
        # Normalize the description for matching
        normalized_desc = self._normalize_text(description)
        
        # Count matches for each threat type
        matches_by_type: Dict[str, List[str]] = {}
        scores: Dict[str, int] = {}
        
        for threat_type, keyword_list in self.keywords.items():
            count, matched_keywords = self._count_matches(normalized_desc, keyword_list)
            if count > 0:
                matches_by_type[threat_type] = matched_keywords
                scores[threat_type] = count
        
        # Determine the threat type with highest score
        if not scores:
            # No matches found
            return KeywordResult(
                threat_type=None,
                score=0,
                matches_by_type={},
                confidence_level=ConfidenceLevel.NONE
            )
        
        # Get threat type with maximum score
        best_threat_type = max(scores.items(), key=lambda x: x[1])
        threat_type = best_threat_type[0]
        score = best_threat_type[1]
        
        # Determine confidence level based on score
        confidence_level = self._get_confidence_level(score)
        
        return KeywordResult(
            threat_type=threat_type,
            score=score,
            matches_by_type=matches_by_type,
            confidence_level=confidence_level
        )
    
    def _count_matches(
        self,
        description: str,
        keywords: List[str]
    ) -> Tuple[int, List[str]]:
        """
        Count and return matching keywords.
        
        Counts how many keywords from the provided list appear in the
        description. Each keyword is counted at most once, even if it
        appears multiple times in the description.
        
        Args:
            description: Normalized threat description text
            keywords: List of keywords to search for
            
        Returns:
            Tuple of (match_count, list_of_matched_keywords)
        """
        matched_keywords = []
        
        for keyword in keywords:
            # Normalize keyword for matching
            normalized_keyword = self._normalize_text(keyword)
            
            # Check if keyword appears in description as a substring
            # This allows matching within compound words (e.g., "poison" in "poisoning")
            if normalized_keyword in description:
                matched_keywords.append(keyword)
        
        return len(matched_keywords), matched_keywords
    
    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for matching (lowercase, strip punctuation).
        
        Converts text to lowercase and removes punctuation to enable
        consistent matching regardless of formatting.
        
        Args:
            text: Text to normalize
            
        Returns:
            Normalized text string
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation but keep spaces
        # Create translation table that maps punctuation to spaces
        translator = str.maketrans(string.punctuation, ' ' * len(string.punctuation))
        text = text.translate(translator)
        
        # Collapse multiple spaces into single space
        text = ' '.join(text.split())
        
        return text
    
    def _get_confidence_level(self, score: int) -> ConfidenceLevel:
        """
        Determine confidence level from match score.
        
        Maps the keyword match count to a confidence level:
        - HIGH: 5 or more matches
        - MEDIUM: 2-4 matches
        - LOW: 1 match
        - NONE: 0 matches
        
        Args:
            score: Number of keyword matches
            
        Returns:
            ConfidenceLevel enum value
        """
        if score >= 5:
            return ConfidenceLevel.HIGH
        elif score >= 2:
            return ConfidenceLevel.MEDIUM
        elif score >= 1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.NONE
