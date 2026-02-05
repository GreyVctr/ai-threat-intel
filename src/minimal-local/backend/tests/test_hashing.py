"""
Tests for content hashing and deduplication normalization.
"""
import pytest
from utils.hashing import calculate_content_hash, normalize_arxiv_content


class TestArxivNormalization:
    """Test arXiv content normalization for deduplication."""
    
    def test_normalize_arxiv_announce_type_replace_cross(self):
        """Test that 'replace-cross' is normalized to 'replace'."""
        content = "arXiv:2511.06161v2 Announce Type: replace-cross Abstract: Transfer learning..."
        normalized = normalize_arxiv_content(content)
        
        assert "replace-cross" not in normalized
        assert "announce type: " in normalized.lower()
    
    def test_normalize_arxiv_announce_type_replace(self):
        """Test that 'replace' is normalized consistently."""
        content = "arXiv:2511.06161v2 Announce Type: replace Abstract: Transfer learning..."
        normalized = normalize_arxiv_content(content)
        
        assert "announce type: " in normalized.lower()
    
    def test_arxiv_cross_post_same_hash(self):
        """Test that arXiv cross-posts produce the same hash."""
        # Content from arXiv Artificial Intelligence (replace-cross)
        content_ai = "arXiv:2511.06161v2 Announce Type: replace-cross Abstract: Transfer learning on tabular data is challenging..."
        
        # Content from arXiv Machine Learning (replace)
        content_ml = "arXiv:2511.06161v2 Announce Type: replace Abstract: Transfer learning on tabular data is challenging..."
        
        hash_ai = calculate_content_hash(content_ai)
        hash_ml = calculate_content_hash(content_ml)
        
        # Both should produce the same hash
        assert hash_ai == hash_ml, "arXiv cross-posts should have the same hash"
    
    def test_normalize_arxiv_version_numbers(self):
        """Test that arXiv version numbers are normalized."""
        content_v1 = "arXiv:2511.06161v1 Abstract: Test content"
        content_v2 = "arXiv:2511.06161v2 Abstract: Test content"
        
        normalized_v1 = normalize_arxiv_content(content_v1)
        normalized_v2 = normalize_arxiv_content(content_v2)
        
        # Version numbers should be removed
        assert "v1" not in normalized_v1
        assert "v2" not in normalized_v2
        assert "arxiv:2511.06161" in normalized_v1.lower()
        assert "arxiv:2511.06161" in normalized_v2.lower()
    
    def test_non_arxiv_content_unchanged(self):
        """Test that non-arXiv content is not modified."""
        content = "This is a regular threat from a blog post"
        normalized = normalize_arxiv_content(content)
        
        assert normalized == content
    
    def test_empty_content(self):
        """Test that empty content is handled gracefully."""
        assert normalize_arxiv_content("") == ""
        assert normalize_arxiv_content(None) == None


class TestContentHashing:
    """Test content hash calculation."""
    
    def test_same_content_same_hash(self):
        """Test that identical content produces the same hash."""
        content = "This is a test threat"
        hash1 = calculate_content_hash(content)
        hash2 = calculate_content_hash(content)
        
        assert hash1 == hash2
    
    def test_different_content_different_hash(self):
        """Test that different content produces different hashes."""
        content1 = "This is threat A"
        content2 = "This is threat B"
        
        hash1 = calculate_content_hash(content1)
        hash2 = calculate_content_hash(content2)
        
        assert hash1 != hash2
    
    def test_case_insensitive(self):
        """Test that hashing is case-insensitive."""
        content1 = "This Is A Test"
        content2 = "this is a test"
        
        hash1 = calculate_content_hash(content1)
        hash2 = calculate_content_hash(content2)
        
        assert hash1 == hash2
    
    def test_whitespace_normalized(self):
        """Test that leading/trailing whitespace is normalized."""
        content1 = "  This is a test  "
        content2 = "This is a test"
        
        hash1 = calculate_content_hash(content1)
        hash2 = calculate_content_hash(content2)
        
        assert hash1 == hash2
    
    def test_empty_content(self):
        """Test that empty content produces a hash."""
        hash1 = calculate_content_hash("")
        hash2 = calculate_content_hash(None)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters
    
    def test_unicode_content(self):
        """Test that Unicode content is handled correctly."""
        content = "Threat with émojis 🔒 and spëcial çharacters"
        hash_result = calculate_content_hash(content)
        
        assert len(hash_result) == 64
        assert hash_result.isalnum()  # Should be hexadecimal
    
    def test_real_world_arxiv_duplicate(self):
        """Test real-world arXiv duplicate scenario."""
        # Actual content from the LATTLE paper
        content_ai = """arXiv:2511.06161v2 Announce Type: replace-cross Abstract: Transfer learning on tabular data is challenging due to disparate feature spaces across domains, in contrast to the homogeneous structures of image and text. Large language models (LLMs) offer a knowledge base to improve the limited effectiveness of cross-domain transfer learning for tabular data."""
        
        content_ml = """arXiv:2511.06161v2 Announce Type: replace Abstract: Transfer learning on tabular data is challenging due to disparate feature spaces across domains, in contrast to the homogeneous structures of image and text. Large language models (LLMs) offer a knowledge base to improve the limited effectiveness of cross-domain transfer learning for tabular data."""
        
        hash_ai = calculate_content_hash(content_ai)
        hash_ml = calculate_content_hash(content_ml)
        
        # These should now produce the same hash
        assert hash_ai == hash_ml, "Real-world arXiv cross-posts should deduplicate"
