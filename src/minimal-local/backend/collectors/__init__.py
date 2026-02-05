"""
Data collectors for fetching threat intelligence from external sources.

This package provides collectors for various data sources:
- RSS feeds
- APIs (arXiv, GitHub)
- Web scraping
"""

from .base import Collector, CollectorResult
from .rss import RSSCollector
from .api import ArxivAPICollector, GitHubAPICollector
from .scraper import WebScraperCollector

__all__ = [
    "Collector",
    "CollectorResult",
    "RSSCollector",
    "ArxivAPICollector",
    "GitHubAPICollector",
    "WebScraperCollector",
]
