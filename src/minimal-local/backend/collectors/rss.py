"""
RSS feed collector for threat intelligence data.

This module implements a collector that fetches data from RSS feeds
using the feedparser library.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List

import feedparser

from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)


class RSSCollector(Collector):
    """
    Collector for RSS feeds.
    
    Fetches threat intelligence data from RSS feeds and extracts:
    - Title
    - Description/summary
    - Link (URL)
    - Published date
    - Authors
    """
    
    async def fetch(self) -> List[CollectorResult]:
        """
        Fetch data from an RSS feed.
        
        Returns:
            List of CollectorResult objects, one for each feed entry.
            
        Raises:
            Exception: If the feed cannot be fetched or parsed.
        """
        logger.info(f"Fetching RSS feed from {self.url}")
        
        try:
            # Parse the RSS feed
            feed = feedparser.parse(self.url)
            
            # Check for errors
            if feed.bozo:
                logger.warning(f"RSS feed parsing warning for {self.url}: {feed.bozo_exception}")
            
            if not feed.entries:
                logger.warning(f"No entries found in RSS feed {self.url}")
                return []
            
            results = []
            for entry in feed.entries:
                try:
                    result = self._parse_entry(entry)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error parsing RSS entry from {self.url}: {e}")
                    continue
            
            logger.info(f"Successfully fetched {len(results)} items from RSS feed {self.url}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to fetch RSS feed from {self.url}: {e}")
            raise
    
    def _parse_entry(self, entry: Any) -> CollectorResult:
        """
        Parse a single RSS feed entry into a CollectorResult.
        
        Args:
            entry: feedparser entry object
            
        Returns:
            CollectorResult object
        """
        # Import validation
        from .validation import sanitize_text, clean_html_entities
        
        # Extract title
        title = entry.get("title", "Untitled")
        title = sanitize_text(clean_html_entities(title)) if title else "Untitled"
        
        # Extract description/summary
        description = entry.get("summary", entry.get("description", ""))
        description = sanitize_text(clean_html_entities(description)) if description else ""
        
        # Extract content (prefer content over summary)
        content = ""
        if hasattr(entry, "content") and entry.content:
            # Some feeds have multiple content entries
            content = " ".join([c.get("value", "") for c in entry.content])
        elif entry.get("summary"):
            content = entry.get("summary")
        elif entry.get("description"):
            content = entry.get("description")
        
        content = sanitize_text(clean_html_entities(content)) if content else ""
        
        # Extract URL
        url = entry.get("link", "")
        
        # Extract authors
        authors = []
        if hasattr(entry, "authors") and entry.authors:
            authors = [author.get("name", "") for author in entry.authors if author.get("name")]
        elif entry.get("author"):
            authors = [entry.get("author")]
        
        # Extract published date
        published_at = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            try:
                published_at = datetime(*entry.published_parsed[:6])
            except Exception as e:
                logger.warning(f"Failed to parse published date: {e}")
        elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
            try:
                published_at = datetime(*entry.updated_parsed[:6])
            except Exception as e:
                logger.warning(f"Failed to parse updated date: {e}")
        
        # Extract additional metadata
        metadata = {
            "feed_title": entry.get("feed", {}).get("title", ""),
            "tags": [tag.get("term", "") for tag in entry.get("tags", [])],
            "id": entry.get("id", ""),
        }
        
        return CollectorResult(
            title=title,
            description=description,
            content=content,
            url=url,
            authors=authors,
            published_at=published_at,
            metadata=metadata,
        )
