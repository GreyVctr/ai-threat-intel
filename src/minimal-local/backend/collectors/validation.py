"""
Data validation and sanitization for collectors.

This module provides utilities to validate and clean data collected from
external sources to prevent corrupted or malicious data from entering the system.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def is_valid_text(text: str, min_ascii_ratio: float = 0.7) -> bool:
    """
    Check if text is valid (not corrupted binary data).
    
    Args:
        text: Text to validate
        min_ascii_ratio: Minimum ratio of ASCII/common Unicode characters (0.0-1.0)
        
    Returns:
        True if text appears valid, False if likely corrupted
    """
    if not text or len(text) < 3:
        return False
    
    # Count printable ASCII and common Unicode characters
    valid_chars = 0
    total_chars = len(text)
    
    for char in text:
        code = ord(char)
        # ASCII printable (32-126) or common Unicode ranges
        if (32 <= code <= 126 or  # ASCII printable
            0x00A0 <= code <= 0x00FF or  # Latin-1 Supplement
            0x0100 <= code <= 0x017F or  # Latin Extended-A
            0x0180 <= code <= 0x024F or  # Latin Extended-B
            0x2000 <= code <= 0x206F or  # General Punctuation
            0x3000 <= code <= 0x303F or  # CJK Symbols
            0x4E00 <= code <= 0x9FFF or  # CJK Unified Ideographs
            code in (0x0A, 0x0D, 0x09)):  # Newline, carriage return, tab
            valid_chars += 1
    
    ratio = valid_chars / total_chars
    return ratio >= min_ascii_ratio


def has_meaningful_content(text: str, min_words: int = 3) -> bool:
    """
    Check if text has meaningful content (not just symbols/numbers).
    
    Args:
        text: Text to check
        min_words: Minimum number of words required
        
    Returns:
        True if text has meaningful content
    """
    if not text:
        return False
    
    # Extract words (sequences of letters)
    words = re.findall(r'[a-zA-Z]{2,}', text)
    return len(words) >= min_words


def sanitize_text(text: Optional[str], max_length: int = 100000) -> Optional[str]:
    """
    Sanitize text by removing control characters and limiting length.
    
    Args:
        text: Text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text or None if invalid
    """
    if not text:
        return None
    
    # Remove control characters except newline, tab, carriage return
    sanitized = ''.join(
        char for char in text
        if ord(char) >= 32 or char in ('\n', '\t', '\r')
    )
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
        logger.warning(f"Text truncated to {max_length} characters")
    
    return sanitized if sanitized else None


def validate_url(url: Optional[str]) -> bool:
    """
    Validate that a URL is well-formed.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid
    """
    if not url:
        return False
    
    # Basic URL pattern
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    return bool(url_pattern.match(url))


def validate_collector_result(title: str, content: str, url: str) -> tuple[bool, Optional[str]]:
    """
    Validate a collector result before ingestion.
    
    Args:
        title: Title text
        content: Content text
        url: Source URL
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate title
    if not title or len(title) < 3:
        return False, "Title too short"
    
    if not is_valid_text(title, min_ascii_ratio=0.6):
        return False, "Title contains corrupted data (invalid characters)"
    
    if not has_meaningful_content(title, min_words=1):
        return False, "Title has no meaningful content"
    
    # Validate content
    if not content or len(content) < 10:
        return False, "Content too short"
    
    if not is_valid_text(content, min_ascii_ratio=0.6):
        return False, "Content contains corrupted data (invalid characters)"
    
    if not has_meaningful_content(content, min_words=3):
        return False, "Content has no meaningful content"
    
    # Validate URL
    if not validate_url(url):
        return False, "Invalid URL format"
    
    return True, None


def clean_html_entities(text: str) -> str:
    """
    Clean HTML entities and normalize whitespace.
    
    Args:
        text: Text with potential HTML entities
        
    Returns:
        Cleaned text
    """
    import html
    
    # Decode HTML entities
    text = html.unescape(text)
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text
