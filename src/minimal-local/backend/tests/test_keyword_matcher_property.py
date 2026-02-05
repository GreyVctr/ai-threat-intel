"""
Property-based tests for KeywordMatcher.

Tests universal properties that should hold for all inputs using Hypothesis.
"""
import pytest
from hypothesis import given, strategies as st, settings, assume
from services.keyword_matcher import KeywordMatcher
from services.classification_types import ConfidenceLevel


# Strategy for generating valid keywords (alphanumeric with some special chars)
keyword_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), min_codepoint=32, max_codepoint=126),
    min_size=2,
    max_size=20
).filter(lambda x: x.strip() and not x.isspace())

# Strategy for generating threat descriptions
description_strategy = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'P', 'Z'), min_codepoint=32, max_codepoint=126),
    min_size=10,
    max_size=500
)

# Strategy for generating keyword lists
keyword_list_strategy = st.lists(
    keyword_strategy,
    min_size=1,
    max_size=20,
    unique=True
)


class TestKeywordMatcherProperties:
    """Property-based tests for KeywordMatcher."""
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_2_keyword_match_count_accuracy(self, description, keywords):
        """
        **Validates: Requirements 1.2**
        
        Feature: hybrid-threat-classification
        Property 2: Keyword match count accuracy
        
        For any threat description and keyword list, the count of matching
        keywords should equal the number of keywords from the list that
        appear in the description.
        
        This property ensures that the keyword matcher accurately counts
        how many keywords from the provided list appear in the description,
        with each keyword counted at most once.
        """
        # Skip if description is empty or whitespace only
        assume(description.strip())
        
        # Create matcher with single threat type
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        # Get the match result
        result = matcher.match(description)
        
        # Manually count matches using the same normalization logic
        normalized_desc = matcher._normalize_text(description)
        expected_count = 0
        expected_matches = []
        
        for keyword in keywords:
            normalized_keyword = matcher._normalize_text(keyword)
            if normalized_keyword and normalized_keyword in normalized_desc:
                expected_count += 1
                expected_matches.append(keyword)
        
        # Verify the count matches our manual count
        assert result.score == expected_count, (
            f"Expected {expected_count} matches but got {result.score}. "
            f"Description: {description[:100]}... "
            f"Keywords: {keywords[:5]}... "
            f"Expected matches: {expected_matches} "
            f"Actual matches: {result.matches_by_type.get('test_type', [])}"
        )
        
        # Verify the matched keywords list has the correct length
        if result.threat_type:
            assert len(result.matches_by_type["test_type"]) == expected_count
        else:
            assert expected_count == 0
    
    @given(
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_empty_description_returns_zero_matches(self, keywords):
        """
        Property: Empty descriptions always return zero matches.
        
        For any keyword list, an empty or whitespace-only description
        should always result in zero matches.
        """
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        # Test with various empty/whitespace descriptions
        empty_descriptions = ["", "   ", "\n\t", "  \n  \t  "]
        
        for desc in empty_descriptions:
            result = matcher.match(desc)
            assert result.score == 0
            assert result.threat_type is None
            assert result.confidence_level == ConfidenceLevel.NONE
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_confidence_level_matches_score(self, description, keywords):
        """
        Property: Confidence level correctly maps to score.
        
        For any description and keyword list, the confidence level should
        be correctly determined from the match score:
        - HIGH: score >= 5
        - MEDIUM: 2 <= score <= 4
        - LOW: score == 1
        - NONE: score == 0
        """
        assume(description.strip())
        
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        result = matcher.match(description)
        
        # Verify confidence level matches score
        if result.score >= 5:
            assert result.confidence_level == ConfidenceLevel.HIGH
        elif result.score >= 2:
            assert result.confidence_level == ConfidenceLevel.MEDIUM
        elif result.score >= 1:
            assert result.confidence_level == ConfidenceLevel.LOW
        else:
            assert result.confidence_level == ConfidenceLevel.NONE
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_match_count_non_negative(self, description, keywords):
        """
        Property: Match count is always non-negative.
        
        For any description and keyword list, the match count should
        never be negative.
        """
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        result = matcher.match(description)
        
        assert result.score >= 0
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_match_count_bounded_by_keyword_list_size(self, description, keywords):
        """
        Property: Match count never exceeds keyword list size.
        
        For any description and keyword list, the number of matches cannot
        exceed the number of keywords in the list (since each keyword is
        counted at most once).
        """
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        result = matcher.match(description)
        
        assert result.score <= len(keywords)
    
    @given(
        description=description_strategy,
        threat_types=st.dictionaries(
            keys=st.text(min_size=1, max_size=20),
            values=keyword_list_strategy,
            min_size=1,
            max_size=5
        )
    )
    @settings(max_examples=100)
    def test_property_highest_score_wins(self, description, threat_types):
        """
        Property: Threat type with highest match count is selected.
        
        For any description and multiple threat types with keyword lists,
        the selected threat type should be the one with the highest match count.
        """
        assume(description.strip())
        assume(len(threat_types) > 0)
        
        matcher = KeywordMatcher(threat_types)
        result = matcher.match(description)
        
        # If there are matches, verify the selected type has the highest score
        if result.threat_type:
            selected_score = result.score
            
            # Check that no other type has a higher score
            for threat_type, keywords in threat_types.items():
                normalized_desc = matcher._normalize_text(description)
                count = 0
                for keyword in keywords:
                    normalized_keyword = matcher._normalize_text(keyword)
                    if normalized_keyword and normalized_keyword in normalized_desc:
                        count += 1
                
                # The selected type should have the highest (or tied for highest) score
                assert selected_score >= count, (
                    f"Selected type '{result.threat_type}' has score {selected_score}, "
                    f"but type '{threat_type}' has score {count}"
                )
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_case_insensitive_matching(self, description, keywords):
        """
        Property: Matching is case-insensitive.
        
        For any description and keyword list, the match count should be
        the same regardless of the case of the description or keywords.
        """
        assume(description.strip())
        
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        # Get results for original, uppercase, and lowercase descriptions
        result_original = matcher.match(description)
        result_upper = matcher.match(description.upper())
        result_lower = matcher.match(description.lower())
        
        # All should have the same score
        assert result_original.score == result_upper.score == result_lower.score
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_matches_by_type_consistency(self, description, keywords):
        """
        Property: matches_by_type is consistent with score.
        
        For any description and keyword list, the length of the matched
        keywords list should equal the score.
        """
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        result = matcher.match(description)
        
        if result.threat_type:
            # The number of matched keywords should equal the score
            assert len(result.matches_by_type["test_type"]) == result.score
        else:
            # If no threat type, matches_by_type should be empty
            assert len(result.matches_by_type) == 0
    
    @given(
        description=description_strategy,
        keywords=keyword_list_strategy
    )
    @settings(max_examples=100)
    def test_property_no_duplicate_matches(self, description, keywords):
        """
        Property: Each keyword is matched at most once.
        
        For any description and keyword list, each keyword should appear
        at most once in the matched keywords list, even if it appears
        multiple times in the description.
        """
        config = {"test_type": keywords}
        matcher = KeywordMatcher(config)
        
        result = matcher.match(description)
        
        if result.threat_type:
            matched = result.matches_by_type["test_type"]
            # Check for duplicates
            assert len(matched) == len(set(matched)), (
                f"Found duplicate matches: {matched}"
            )
