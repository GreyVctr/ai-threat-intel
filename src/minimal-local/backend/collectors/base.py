"""
Base collector interface for threat intelligence data collection.

This module defines the abstract base class for all collectors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class CollectorResult:
    """
    Result from a collector fetch operation.
    
    Attributes:
        title: Title of the collected item
        description: Description or summary
        content: Full content text
        url: Source URL
        authors: List of author names
        published_at: Publication timestamp
        metadata: Additional source-specific metadata
    """
    title: str
    description: Optional[str]
    content: str
    url: str
    authors: Optional[List[str]] = None
    published_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class Collector(ABC):
    """
    Abstract base class for data collectors.
    
    All collectors must implement the fetch() method to retrieve data
    from their respective sources.
    """
    
    def __init__(self, source_config: Dict[str, Any]):
        """
        Initialize the collector with source configuration.
        
        Args:
            source_config: Configuration dictionary containing:
                - url: Source URL
                - name: Source name
                - type: Source type (rss, api, web_scrape)
                - config: Additional source-specific configuration
        """
        self.source_config = source_config
        self.url = source_config.get("url")
        self.name = source_config.get("name", "Unknown")
        self.source_type = source_config.get("type", "unknown")
        self.config = source_config.get("config", {})
    
    @abstractmethod
    async def fetch(self) -> List[CollectorResult]:
        """
        Fetch data from the source.
        
        Returns:
            List of CollectorResult objects containing the fetched data.
            
        Raises:
            Exception: If the fetch operation fails.
        """
        pass
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', url='{self.url}')"
