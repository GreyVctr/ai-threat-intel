"""
Web scraper collector for threat intelligence data.

This module implements a collector that scrapes web pages using BeautifulSoup
with rate limiting to avoid overwhelming target servers.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Simple rate limiter to control request frequency.
    
    Ensures a minimum delay between requests to avoid overwhelming servers.
    """
    
    def __init__(self, min_delay: float = 1.0):
        """
        Initialize rate limiter.
        
        Args:
            min_delay: Minimum delay in seconds between requests (default: 1.0)
        """
        self.min_delay = min_delay
        self.last_request_time: Optional[float] = None
    
    async def wait(self):
        """Wait if necessary to respect rate limit."""
        if self.last_request_time is not None:
            elapsed = asyncio.get_event_loop().time() - self.last_request_time
            if elapsed < self.min_delay:
                await asyncio.sleep(self.min_delay - elapsed)
        
        self.last_request_time = asyncio.get_event_loop().time()


class WebScraperCollector(Collector):
    """
    Collector for web scraping.
    
    Scrapes web pages using BeautifulSoup with configurable selectors
    and rate limiting to be respectful to target servers.
    """
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        
        # Rate limiting configuration
        self.rate_limit_delay = self.config.get("rate_limit_delay", 1.0)
        self.rate_limiter = RateLimiter(min_delay=self.rate_limit_delay)
        
        # Scraping configuration
        self.selectors = self.config.get("selectors", {})
        self.title_selector = self.selectors.get("title", "h1")
        self.content_selector = self.selectors.get("content", "article")
        self.description_selector = self.selectors.get("description", "meta[name='description']")
        self.author_selector = self.selectors.get("author", "meta[name='author']")
        self.date_selector = self.selectors.get("date", "time")
        
        # Follow links configuration
        self.follow_links = self.config.get("follow_links", False)
        self.link_selector = self.config.get("link_selector", "a")
        self.max_pages = self.config.get("max_pages", 1)
        
        # User agent
        self.user_agent = self.config.get(
            "user_agent",
            "AI-Shield-Intelligence/0.1.0 (Threat Intelligence Collector)"
        )
    
    async def fetch(self) -> List[CollectorResult]:
        """
        Fetch data by scraping web pages.
        
        Returns:
            List of CollectorResult objects.
            
        Raises:
            Exception: If the scraping fails.
        """
        logger.info(f"Scraping web page: {self.url}")
        
        try:
            results = []
            
            if self.follow_links:
                # Scrape multiple pages by following links
                results = await self._scrape_multiple_pages()
            else:
                # Scrape single page
                result = await self._scrape_page(self.url)
                if result:
                    results.append(result)
            
            logger.info(f"Successfully scraped {len(results)} items from {self.url}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to scrape {self.url}: {e}")
            raise
    
    async def _scrape_multiple_pages(self) -> List[CollectorResult]:
        """
        Scrape multiple pages by following links.
        
        Returns:
            List of CollectorResult objects.
        """
        results = []
        visited_urls = set()
        urls_to_visit = [self.url]
        
        while urls_to_visit and len(results) < self.max_pages:
            url = urls_to_visit.pop(0)
            
            if url in visited_urls:
                continue
            
            visited_urls.add(url)
            
            try:
                # Rate limit
                await self.rate_limiter.wait()
                
                # Scrape page
                result = await self._scrape_page(url)
                if result:
                    results.append(result)
                
                # Extract links if we haven't reached max pages
                if len(results) < self.max_pages:
                    links = await self._extract_links(url)
                    for link in links:
                        if link not in visited_urls:
                            urls_to_visit.append(link)
                
            except Exception as e:
                logger.error(f"Error scraping {url}: {e}")
                continue
        
        return results
    
    async def _scrape_page(self, url: str) -> Optional[CollectorResult]:
        """
        Scrape a single web page.
        
        Args:
            url: URL to scrape
            
        Returns:
            CollectorResult object or None if scraping fails
        """
        # Rate limit
        await self.rate_limiter.wait()
        
        # Fetch page
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, "lxml")
        
        # Extract data
        title = self._extract_title(soup)
        description = self._extract_description(soup)
        content = self._extract_content(soup)
        authors = self._extract_authors(soup)
        published_at = self._extract_date(soup)
        
        # Skip if no meaningful content
        if not title and not content:
            logger.warning(f"No meaningful content found at {url}")
            return None
        
        metadata = {
            "scraped_url": url,
            "source_type": "web_scrape",
        }
        
        return CollectorResult(
            title=title or "Untitled",
            description=description,
            content=content or description or "",
            url=url,
            authors=authors,
            published_at=published_at,
            metadata=metadata,
        )
    
    def _extract_title(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract title from page."""
        # Try configured selector
        elem = soup.select_one(self.title_selector)
        if elem:
            return elem.get_text(strip=True)
        
        # Fallback to <title> tag
        title_tag = soup.find("title")
        if title_tag:
            return title_tag.get_text(strip=True)
        
        return None
    
    def _extract_description(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract description from page."""
        # Try meta description
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            return meta.get("content").strip()
        
        # Try Open Graph description
        og_desc = soup.find("meta", attrs={"property": "og:description"})
        if og_desc and og_desc.get("content"):
            return og_desc.get("content").strip()
        
        return None
    
    def _extract_content(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract main content from page."""
        # Try configured selector
        elem = soup.select_one(self.content_selector)
        if elem:
            # Remove script and style tags
            for tag in elem.find_all(["script", "style"]):
                tag.decompose()
            return elem.get_text(separator="\n", strip=True)
        
        # Fallback to body
        body = soup.find("body")
        if body:
            # Remove script and style tags
            for tag in body.find_all(["script", "style", "nav", "footer", "header"]):
                tag.decompose()
            return body.get_text(separator="\n", strip=True)
        
        return None
    
    def _extract_authors(self, soup: BeautifulSoup) -> Optional[List[str]]:
        """Extract authors from page."""
        authors = []
        
        # Try meta author
        meta = soup.find("meta", attrs={"name": "author"})
        if meta and meta.get("content"):
            authors.append(meta.get("content").strip())
        
        # Try configured selector
        if self.author_selector:
            elems = soup.select(self.author_selector)
            for elem in elems:
                author = elem.get_text(strip=True)
                if author and author not in authors:
                    authors.append(author)
        
        return authors if authors else None
    
    def _extract_date(self, soup: BeautifulSoup) -> Optional[datetime]:
        """Extract publication date from page."""
        # Try configured selector
        if self.date_selector:
            elem = soup.select_one(self.date_selector)
            if elem:
                # Try datetime attribute
                date_str = elem.get("datetime")
                if date_str:
                    try:
                        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception as e:
                        logger.warning(f"Failed to parse datetime attribute: {e}")
                
                # Try text content
                date_str = elem.get_text(strip=True)
                if date_str:
                    try:
                        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception:
                        pass
        
        # Try meta published_time
        meta = soup.find("meta", attrs={"property": "article:published_time"})
        if meta and meta.get("content"):
            try:
                return datetime.fromisoformat(
                    meta.get("content").replace("Z", "+00:00")
                )
            except Exception as e:
                logger.warning(f"Failed to parse published_time: {e}")
        
        return None
    
    async def _extract_links(self, base_url: str) -> List[str]:
        """
        Extract links from a page.
        
        Args:
            base_url: Base URL for resolving relative links
            
        Returns:
            List of absolute URLs
        """
        # Fetch page
        headers = {
            "User-Agent": self.user_agent,
        }
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(base_url, headers=headers)
            response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, "lxml")
        
        # Extract links
        links = []
        base_domain = urlparse(base_url).netloc
        
        for link in soup.select(self.link_selector):
            href = link.get("href")
            if not href:
                continue
            
            # Resolve relative URLs
            absolute_url = urljoin(base_url, href)
            
            # Only include links from the same domain
            if urlparse(absolute_url).netloc == base_domain:
                links.append(absolute_url)
        
        return links
