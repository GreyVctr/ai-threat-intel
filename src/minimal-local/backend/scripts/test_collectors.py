#!/usr/bin/env python3
"""
Test script for data collectors.

This script tests all collector implementations:
- Base collector interface
- RSS feed collector
- API collectors (arXiv, GitHub)
- Web scraper collector
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.base import Collector, CollectorResult
from collectors.rss import RSSCollector
from collectors.api import ArxivAPICollector, GitHubAPICollector
from collectors.scraper import WebScraperCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_rss_collector():
    """Test RSS feed collector."""
    logger.info("=" * 60)
    logger.info("Testing RSS Collector")
    logger.info("=" * 60)
    
    # Test with arXiv RSS feed
    config = {
        "name": "arXiv CS.CR RSS",
        "type": "rss",
        "url": "http://export.arxiv.org/rss/cs.CR",
        "config": {}
    }
    
    collector = RSSCollector(config)
    logger.info(f"Created collector: {collector}")
    
    try:
        results = await collector.fetch()
        logger.info(f"✓ Successfully fetched {len(results)} items")
        
        if results:
            # Display first result
            result = results[0]
            logger.info(f"\nFirst result:")
            logger.info(f"  Title: {result.title[:80]}...")
            logger.info(f"  URL: {result.url}")
            logger.info(f"  Authors: {result.authors}")
            logger.info(f"  Published: {result.published_at}")
            logger.info(f"  Description: {result.description[:100] if result.description else 'N/A'}...")
        
        return True
    except Exception as e:
        logger.error(f"✗ RSS collector test failed: {e}")
        return False


async def test_arxiv_api_collector():
    """Test arXiv API collector."""
    logger.info("\n" + "=" * 60)
    logger.info("Testing arXiv API Collector")
    logger.info("=" * 60)
    
    config = {
        "name": "arXiv CS.CR API",
        "type": "api",
        "url": "https://export.arxiv.org/api/query",
        "config": {
            "category": "cs.CR",
            "max_results": 5
        }
    }
    
    collector = ArxivAPICollector(config)
    logger.info(f"Created collector: {collector}")
    
    try:
        results = await collector.fetch()
        logger.info(f"✓ Successfully fetched {len(results)} papers")
        
        if results:
            # Display first result
            result = results[0]
            logger.info(f"\nFirst result:")
            logger.info(f"  Title: {result.title[:80]}...")
            logger.info(f"  URL: {result.url}")
            logger.info(f"  Authors: {', '.join(result.authors[:3]) if result.authors else 'N/A'}...")
            logger.info(f"  Published: {result.published_at}")
            logger.info(f"  Categories: {result.metadata.get('categories', [])}")
        
        return True
    except Exception as e:
        logger.error(f"✗ arXiv API collector test failed: {e}")
        return False


async def test_github_api_collector():
    """Test GitHub API collector."""
    logger.info("\n" + "=" * 60)
    logger.info("Testing GitHub API Collector")
    logger.info("=" * 60)
    
    # Test advisories endpoint
    config = {
        "name": "GitHub Security Advisories",
        "type": "api",
        "url": "https://api.github.com/advisories",
        "config": {
            "endpoint": "advisories",
            "max_results": 5
        }
    }
    
    collector = GitHubAPICollector(config)
    logger.info(f"Created collector: {collector}")
    
    try:
        results = await collector.fetch()
        logger.info(f"✓ Successfully fetched {len(results)} advisories")
        
        if results:
            # Display first result
            result = results[0]
            logger.info(f"\nFirst result:")
            logger.info(f"  Title: {result.title[:80]}...")
            logger.info(f"  URL: {result.url}")
            logger.info(f"  Published: {result.published_at}")
            logger.info(f"  Severity: {result.metadata.get('severity', 'N/A')}")
            logger.info(f"  CVE IDs: {result.metadata.get('cve_ids', [])}")
        
        return True
    except Exception as e:
        logger.error(f"✗ GitHub API collector test failed: {e}")
        return False


async def test_web_scraper_collector():
    """Test web scraper collector."""
    logger.info("\n" + "=" * 60)
    logger.info("Testing Web Scraper Collector")
    logger.info("=" * 60)
    
    # Test with a simple, reliable page
    config = {
        "name": "Example Web Page",
        "type": "web_scrape",
        "url": "https://example.com",
        "config": {
            "rate_limit_delay": 1.0,
            "selectors": {
                "title": "h1",
                "content": "div"
            }
        }
    }
    
    collector = WebScraperCollector(config)
    logger.info(f"Created collector: {collector}")
    
    try:
        results = await collector.fetch()
        logger.info(f"✓ Successfully scraped {len(results)} items")
        
        if results:
            # Display first result
            result = results[0]
            logger.info(f"\nFirst result:")
            logger.info(f"  Title: {result.title}")
            logger.info(f"  URL: {result.url}")
            logger.info(f"  Content length: {len(result.content)} characters")
        
        return True
    except Exception as e:
        logger.error(f"✗ Web scraper collector test failed: {e}")
        return False


async def main():
    """Run all collector tests."""
    logger.info("Starting collector tests...\n")
    
    results = {
        "RSS Collector": await test_rss_collector(),
        "arXiv API Collector": await test_arxiv_api_collector(),
        "GitHub API Collector": await test_github_api_collector(),
        "Web Scraper Collector": await test_web_scraper_collector(),
    }
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        logger.info(f"{test_name}: {status}")
    
    total = len(results)
    passed = sum(results.values())
    logger.info(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("✓ All tests passed!")
        return 0
    else:
        logger.error(f"✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
