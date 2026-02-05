"""
Utility functions for content hashing and deduplication.

Provides consistent hashing across ingestion and manual threat creation.
"""
import hashlib
import re


def normalize_arxiv_content(content: str) -> str:
    """
    Normalize arXiv-specific metadata to prevent near-duplicates.
    
    arXiv cross-posts papers to multiple categories (e.g., AI and ML),
    and the RSS feeds have slight differences in the "Announce Type" field:
    - "replace-cross" for cross-listed updates
    - "replace" for primary category updates
    
    This function removes these variations to ensure the same paper
    from different arXiv categories hashes identically.
    
    Args:
        content: Raw content from arXiv RSS feed
        
    Returns:
        Normalized content with arXiv metadata variations removed
    """
    if not content or 'arxiv:' not in content.lower():
        return content
    
    # Remove "Announce Type: replace-cross" or "Announce Type: replace"
    # This is the main source of near-duplicates from arXiv cross-posts
    content = re.sub(r'announce type:\s*replace(-cross)?\s+', 'announce type: ', content, flags=re.IGNORECASE)
    
    # Normalize arXiv version numbers (v1, v2, etc.) - optional, but helps with updates
    # Keep the arXiv ID but normalize version format
    content = re.sub(r'arxiv:(\d+\.\d+)v\d+', r'arxiv:\1', content, flags=re.IGNORECASE)
    
    return content


def calculate_content_hash(content: str) -> str:
    """
    Calculate SHA-256 hash of content for deduplication.
    
    This function normalizes content before hashing to ensure consistent
    deduplication regardless of minor formatting differences.
    
    Normalization steps:
    1. Strip leading/trailing whitespace
    2. Normalize arXiv-specific metadata (Announce Type, version numbers)
    3. Convert to lowercase using casefold() for Unicode-aware normalization
    4. Calculate SHA-256 hash
    
    Args:
        content: Text content to hash
        
    Returns:
        Hexadecimal SHA-256 hash string
        
    Note:
        - Uses casefold() for Unicode-aware case normalization
        - Removes arXiv metadata variations to prevent cross-post duplicates
        - Empty content returns hash of empty string
    """
    if not content:
        content = ""
    
    # Step 1: Strip whitespace
    normalized_content = content.strip()
    
    # Step 2: Normalize arXiv-specific metadata
    normalized_content = normalize_arxiv_content(normalized_content)
    
    # Step 3: Convert to lowercase (Unicode-aware)
    # Use casefold() instead of lower() for better Unicode handling
    # This ensures minor formatting differences don't create duplicates
    normalized_content = normalized_content.casefold()
    
    # Step 4: Calculate SHA-256 hash
    hash_obj = hashlib.sha256(normalized_content.encode('utf-8'))
    content_hash = hash_obj.hexdigest()
    
    return content_hash
