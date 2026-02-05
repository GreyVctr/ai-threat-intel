"""
Unit tests for KeywordMatcher.

Tests keyword matching functionality including text normalization,
match counting, edge cases, and confidence level determination.
"""
import pytest
from services.keyword_matcher import KeywordMatcher
from services.classification_types import ConfidenceLevel


class TestKeywordMatcherInit:
    """Tests for KeywordMatcher initialization."""
    
    def test_init_with_keywords(self):
        """Test initialization with keyword configuration."""
        config = {
            "adversarial": ["attack", "evasion"],
            "poisoning": ["poison", "contaminate"]
        }
        matcher = KeywordMatcher(config)
        
        assert matcher.keywords == config
        assert "adversarial" in matcher.keywords
        assert "poisoning" in matcher.keywords
    
    def test_init_with_empty_config(self):
        """Test initialization with empty configuration."""
        matcher = KeywordMatcher({})
        
        assert matcher.keywords == {}


class TestKeywordMatcherMatch:
    """Tests for the match() method."""
    
    def test_match_single_type_high_confidence(self):
        """Test matching with high confidence (5+ matches)."""
        config = {
            "adversarial": ["attack", "evasion", "adversarial", "perturbation", "malicious"]
        }
        matcher = KeywordMatcher(config)
        
        description = "This is an adversarial attack using evasion techniques and perturbation methods with malicious intent."
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score == 5
        assert result.confidence_level == ConfidenceLevel.HIGH
        assert "adversarial" in result.matches_by_type
        assert len(result.matches_by_type["adversarial"]) == 5
    
    def test_match_single_type_medium_confidence(self):
        """Test matching with medium confidence (2-4 matches)."""
        config = {
            "poisoning": ["poison", "contaminate", "corrupt", "backdoor"]
        }
        matcher = KeywordMatcher(config)
        
        description = "Data poisoning attack that can corrupt the model."
        result = matcher.match(description)
        
        assert result.threat_type == "poisoning"
        assert result.score == 2  # "poison" (in poisoning) and "corrupt"
        assert result.confidence_level == ConfidenceLevel.MEDIUM
        assert "poison" in result.matches_by_type["poisoning"]
        assert "corrupt" in result.matches_by_type["poisoning"]
    
    def test_match_single_type_low_confidence(self):
        """Test matching with low confidence (1 match)."""
        config = {
            "extraction": ["extract", "steal", "exfiltrate"]
        }
        matcher = KeywordMatcher(config)
        
        description = "Attempting to extract model information."
        result = matcher.match(description)
        
        assert result.threat_type == "extraction"
        assert result.score == 1
        assert result.confidence_level == ConfidenceLevel.LOW
        assert len(result.matches_by_type["extraction"]) == 1
    
    def test_match_no_matches(self):
        """Test matching with no keyword matches."""
        config = {
            "adversarial": ["attack", "evasion"],
            "poisoning": ["poison", "contaminate"]
        }
        matcher = KeywordMatcher(config)
        
        description = "This is a completely unrelated description."
        result = matcher.match(description)
        
        assert result.threat_type is None
        assert result.score == 0
        assert result.confidence_level == ConfidenceLevel.NONE
        assert result.matches_by_type == {}
    
    def test_match_multiple_types_highest_wins(self):
        """Test that threat type with highest match count wins."""
        config = {
            "adversarial": ["attack", "evasion", "adversarial"],
            "poisoning": ["poison", "contaminate", "corrupt", "backdoor", "malicious"]
        }
        matcher = KeywordMatcher(config)
        
        description = "Poisoning attack with backdoor and malicious corrupt data contaminate."
        result = matcher.match(description)
        
        # Poisoning should win with 5 matches
        assert result.threat_type == "poisoning"
        assert result.score == 5
        assert "poisoning" in result.matches_by_type
        assert "adversarial" in result.matches_by_type
        assert len(result.matches_by_type["poisoning"]) == 5
        assert len(result.matches_by_type["adversarial"]) == 1  # Only "attack"
    
    def test_match_empty_description(self):
        """Test matching with empty description."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        result = matcher.match("")
        
        assert result.threat_type is None
        assert result.score == 0
        assert result.confidence_level == ConfidenceLevel.NONE
        assert result.matches_by_type == {}
    
    def test_match_whitespace_only_description(self):
        """Test matching with whitespace-only description."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        result = matcher.match("   \n\t  ")
        
        assert result.threat_type is None
        assert result.score == 0
        assert result.confidence_level == ConfidenceLevel.NONE


class TestTextNormalization:
    """Tests for text normalization functionality."""
    
    def test_match_case_insensitive(self):
        """Test that matching is case-insensitive."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        # Test various case combinations
        descriptions = [
            "This is an ATTACK using EVASION.",
            "This is an Attack using Evasion.",
            "This is an attack using evasion."
        ]
        
        for desc in descriptions:
            result = matcher.match(desc)
            assert result.threat_type == "adversarial"
            assert result.score == 2
    
    def test_match_with_punctuation(self):
        """Test matching works with punctuation in description."""
        config = {
            "prompt_injection": ["injection", "jailbreak"]
        }
        matcher = KeywordMatcher(config)
        
        description = "Prompt-injection! Using jailbreak, techniques."
        result = matcher.match(description)
        
        assert result.threat_type == "prompt_injection"
        assert result.score == 2
    
    def test_match_with_special_characters(self):
        """Test matching with special characters."""
        config = {
            "adversarial": ["attack"]
        }
        matcher = KeywordMatcher(config)
        
        description = "This is an @attack# with $pecial characters!"
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score == 1
    
    def test_match_unicode_characters(self):
        """Test matching with unicode characters."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "This is an attack using évasion techniques with unicode: 你好"
        result = matcher.match(description)
        
        # Should match "attack" but not "évasion" (different from "evasion")
        assert result.threat_type == "adversarial"
        assert result.score == 1
        assert "attack" in result.matches_by_type["adversarial"]
    
    def test_match_word_boundaries(self):
        """Test that matching works with word variations."""
        config = {
            "adversarial": ["attack"]
        }
        matcher = KeywordMatcher(config)
        
        # "attack" should match in "attack", "attacking", "attacks" (substring matching)
        description = "This is an attack, not attacking or attacks."
        result = matcher.match(description)
        
        # Should match "attack" once (even though it appears in multiple forms)
        assert result.threat_type == "adversarial"
        assert result.score == 1


class TestCountMatches:
    """Tests for the _count_matches() helper method."""
    
    def test_count_matches_basic(self):
        """Test basic keyword counting."""
        config = {"test": ["keyword1", "keyword2"]}
        matcher = KeywordMatcher(config)
        
        description = "this has keyword1 and keyword2"
        count, matched = matcher._count_matches(description, ["keyword1", "keyword2"])
        
        assert count == 2
        assert "keyword1" in matched
        assert "keyword2" in matched
    
    def test_count_matches_no_duplicates(self):
        """Test that each keyword is counted only once."""
        config = {"test": ["attack"]}
        matcher = KeywordMatcher(config)
        
        description = "attack attack attack"
        count, matched = matcher._count_matches(description, ["attack"])
        
        # Should count "attack" only once even though it appears 3 times
        assert count == 1
        assert matched == ["attack"]
    
    def test_count_matches_empty_keywords(self):
        """Test counting with empty keyword list."""
        config = {"test": []}
        matcher = KeywordMatcher(config)
        
        description = "some description"
        count, matched = matcher._count_matches(description, [])
        
        assert count == 0
        assert matched == []
    
    def test_count_matches_partial_match(self):
        """Test that substring matches work correctly."""
        config = {"test": ["act"]}
        matcher = KeywordMatcher(config)
        
        # "act" should match in "attack", "action", and standalone "act"
        description = "attack and action but not act"
        count, matched = matcher._count_matches(description, ["act"])
        
        assert count == 1  # Matches once (substring matching)
        assert matched == ["act"]


class TestConfidenceLevelMapping:
    """Tests for confidence level determination."""
    
    def test_confidence_high(self):
        """Test high confidence level (5+ matches)."""
        config = {
            "adversarial": ["a", "b", "c", "d", "e", "f"]
        }
        matcher = KeywordMatcher(config)
        
        description = "a b c d e f"
        result = matcher.match(description)
        
        assert result.confidence_level == ConfidenceLevel.HIGH
        assert result.score >= 5
    
    def test_confidence_medium(self):
        """Test medium confidence level (2-4 matches)."""
        config = {
            "adversarial": ["attack", "evasion", "adversarial"]
        }
        matcher = KeywordMatcher(config)
        
        # Test with 2, 3, and 4 matches
        descriptions = [
            "attack and evasion",  # 2 matches
            "attack evasion adversarial",  # 3 matches
        ]
        
        for desc in descriptions:
            result = matcher.match(desc)
            assert result.confidence_level == ConfidenceLevel.MEDIUM
            assert 2 <= result.score <= 4
    
    def test_confidence_low(self):
        """Test low confidence level (1 match)."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "only attack here"
        result = matcher.match(description)
        
        assert result.confidence_level == ConfidenceLevel.LOW
        assert result.score == 1
    
    def test_confidence_none(self):
        """Test none confidence level (0 matches)."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "no matching keywords"
        result = matcher.match(description)
        
        assert result.confidence_level == ConfidenceLevel.NONE
        assert result.score == 0
    
    def test_confidence_boundary_5_matches(self):
        """Test boundary condition: exactly 5 matches."""
        config = {
            "adversarial": ["a", "b", "c", "d", "e"]
        }
        matcher = KeywordMatcher(config)
        
        description = "a b c d e"
        result = matcher.match(description)
        
        assert result.score == 5
        assert result.confidence_level == ConfidenceLevel.HIGH
    
    def test_confidence_boundary_2_matches(self):
        """Test boundary condition: exactly 2 matches."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "attack and evasion"
        result = matcher.match(description)
        
        assert result.score == 2
        assert result.confidence_level == ConfidenceLevel.MEDIUM


class TestEdgeCases:
    """Tests for edge cases and error conditions."""
    
    def test_empty_keyword_list_for_type(self):
        """Test with empty keyword list for a threat type."""
        config = {
            "adversarial": [],
            "poisoning": ["poison"]
        }
        matcher = KeywordMatcher(config)
        
        description = "poison attack"
        result = matcher.match(description)
        
        assert result.threat_type == "poisoning"
        assert result.score == 1
    
    def test_very_long_description(self):
        """Test with very long description."""
        config = {
            "adversarial": ["attack"]
        }
        matcher = KeywordMatcher(config)
        
        # Create a very long description
        description = "This is a test. " * 1000 + "attack"
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score == 1
    
    def test_description_with_only_punctuation(self):
        """Test description with only punctuation."""
        config = {
            "adversarial": ["attack"]
        }
        matcher = KeywordMatcher(config)
        
        description = "!@#$%^&*()"
        result = matcher.match(description)
        
        assert result.threat_type is None
        assert result.score == 0
    
    def test_keyword_with_special_regex_characters(self):
        """Test keywords containing special regex characters."""
        config = {
            "test": ["c++", "c#"]
        }
        matcher = KeywordMatcher(config)
        
        # These should be matched as substrings
        description = "programming in c++ and c#"
        result = matcher.match(description)
        
        # Should match both keywords
        assert result.threat_type == "test"
        assert result.score == 2
    
    def test_multiple_spaces_in_description(self):
        """Test description with multiple consecutive spaces."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "attack    with    multiple    spaces    evasion"
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score == 2
    
    def test_newlines_and_tabs_in_description(self):
        """Test description with newlines and tabs."""
        config = {
            "adversarial": ["attack", "evasion"]
        }
        matcher = KeywordMatcher(config)
        
        description = "attack\nwith\nnewlines\tand\ttabs\tevasion"
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score == 2


class TestRealWorldScenarios:
    """Tests with realistic threat descriptions."""
    
    def test_adversarial_attack_description(self):
        """Test with realistic adversarial attack description."""
        config = {
            "adversarial": ["attack", "evasion", "adversarial", "perturbation", "malicious"],
            "poisoning": ["poison", "contaminate"]
        }
        matcher = KeywordMatcher(config)
        
        description = """
        This adversarial attack uses evasion techniques to fool the model.
        The attacker applies small perturbations to the input data.
        """
        result = matcher.match(description)
        
        assert result.threat_type == "adversarial"
        assert result.score >= 3
        assert result.confidence_level in [ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH]
    
    def test_poisoning_attack_description(self):
        """Test with realistic poisoning attack description."""
        config = {
            "adversarial": ["attack"],
            "poisoning": ["poison", "contaminate", "corrupt", "backdoor", "malicious"]
        }
        matcher = KeywordMatcher(config)
        
        description = """
        Data poisoning attack that injects backdoor triggers into the training set.
        The contaminated data corrupts the model's behavior.
        """
        result = matcher.match(description)
        
        assert result.threat_type == "poisoning"
        assert result.score == 4  # poison, contaminate, corrupt, backdoor
        assert result.confidence_level == ConfidenceLevel.MEDIUM
    
    def test_mixed_threat_description(self):
        """Test with description mentioning multiple threat types."""
        config = {
            "adversarial": ["adversarial", "evasion"],
            "poisoning": ["poisoning", "backdoor"],
            "extraction": ["extraction", "steal"]
        }
        matcher = KeywordMatcher(config)
        
        description = """
        This attack combines adversarial evasion with data poisoning.
        It also attempts model extraction to steal the model.
        """
        result = matcher.match(description)
        
        # Should have matches for all three types
        assert len(result.matches_by_type) == 3
        # Each type should have 2 matches, so any could win (implementation dependent)
        assert result.score == 2
        assert result.threat_type in ["adversarial", "poisoning", "extraction"]
