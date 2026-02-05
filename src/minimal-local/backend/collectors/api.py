"""
API collectors for threat intelligence data.

This module implements collectors for various public APIs:
- arXiv API for academic papers
- GitHub API for repositories and security advisories
"""

import logging
from datetime import datetime
from typing import Any, Dict, List
from xml.etree import ElementTree as ET

import httpx

from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)


class ArxivAPICollector(Collector):
    """
    Collector for arXiv API.
    
    Fetches academic papers from arXiv categories related to AI/ML security:
    - cs.CR (Cryptography and Security)
    - cs.LG (Machine Learning)
    - cs.AI (Artificial Intelligence)
    - stat.ML (Machine Learning Statistics)
    """
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        self.base_url = "https://export.arxiv.org/api/query"
        self.max_results = self.config.get("max_results", 10)
        self.category = self.config.get("category", "cs.CR")
    
    async def fetch(self) -> List[CollectorResult]:
        """
        Fetch papers from arXiv API.
        
        Returns:
            List of CollectorResult objects, one for each paper.
            
        Raises:
            Exception: If the API request fails.
        """
        logger.info(f"Fetching papers from arXiv category {self.category}")
        
        try:
            # Build query parameters
            params = {
                "search_query": f"cat:{self.category}",
                "start": 0,
                "max_results": self.max_results,
                "sortBy": "submittedDate",
                "sortOrder": "descending",
            }
            
            # Make API request
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            
            # Define namespace
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            
            # Extract entries
            entries = root.findall("atom:entry", ns)
            
            if not entries:
                logger.warning(f"No papers found in arXiv category {self.category}")
                return []
            
            results = []
            for entry in entries:
                try:
                    result = self._parse_arxiv_entry(entry, ns)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error parsing arXiv entry: {e}")
                    continue
            
            logger.info(f"Successfully fetched {len(results)} papers from arXiv")
            return results
            
        except Exception as e:
            logger.error(f"Failed to fetch from arXiv API: {e}")
            raise
    
    def _parse_arxiv_entry(self, entry: ET.Element, ns: Dict[str, str]) -> CollectorResult:
        """
        Parse an arXiv entry into a CollectorResult.
        
        Args:
            entry: XML element for the entry
            ns: XML namespace dictionary
            
        Returns:
            CollectorResult object
        """
        # Extract title
        title_elem = entry.find("atom:title", ns)
        title = title_elem.text.strip() if title_elem is not None else "Untitled"
        
        # Extract summary
        summary_elem = entry.find("atom:summary", ns)
        summary = summary_elem.text.strip() if summary_elem is not None else ""
        
        # Extract URL
        id_elem = entry.find("atom:id", ns)
        url = id_elem.text.strip() if id_elem is not None else ""
        
        # Extract authors
        authors = []
        for author in entry.findall("atom:author", ns):
            name_elem = author.find("atom:name", ns)
            if name_elem is not None:
                authors.append(name_elem.text.strip())
        
        # Extract published date
        published_elem = entry.find("atom:published", ns)
        published_at = None
        if published_elem is not None:
            try:
                # Parse ISO 8601 format: 2024-01-15T12:00:00Z
                published_at = datetime.fromisoformat(
                    published_elem.text.strip().replace("Z", "+00:00")
                )
            except Exception as e:
                logger.warning(f"Failed to parse published date: {e}")
        
        # Extract categories
        categories = []
        for category in entry.findall("atom:category", ns):
            term = category.get("term")
            if term:
                categories.append(term)
        
        # Extract arXiv ID
        arxiv_id = url.split("/")[-1] if url else ""
        
        metadata = {
            "arxiv_id": arxiv_id,
            "categories": categories,
            "source_type": "arxiv",
        }
        
        return CollectorResult(
            title=title,
            description=summary,
            content=summary,  # For arXiv, content is the abstract
            url=url,
            authors=authors,
            published_at=published_at,
            metadata=metadata,
        )


class GitHubAPICollector(Collector):
    """
    Collector for GitHub API.
    
    Fetches security advisories and trending repositories related to AI/ML security.
    Uses the public GitHub API (no authentication required for public data).
    """
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        self.base_url = "https://api.github.com"
        self.endpoint = self.config.get("endpoint", "advisories")
        self.query = self.config.get("query", "machine learning")
        self.max_results = self.config.get("max_results", 10)
    
    async def fetch(self) -> List[CollectorResult]:
        """
        Fetch data from GitHub API.
        
        Returns:
            List of CollectorResult objects.
            
        Raises:
            Exception: If the API request fails.
        """
        logger.info(f"Fetching data from GitHub API endpoint: {self.endpoint}")
        
        try:
            if self.endpoint == "advisories":
                return await self._fetch_advisories()
            elif self.endpoint == "search_repos":
                return await self._fetch_repositories()
            else:
                logger.error(f"Unknown GitHub endpoint: {self.endpoint}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to fetch from GitHub API: {e}")
            raise
    
    async def _fetch_advisories(self) -> List[CollectorResult]:
        """Fetch security advisories from GitHub."""
        url = f"{self.base_url}/advisories"
        
        params = {
            "per_page": self.max_results,
            "sort": "published",
            "direction": "desc",
        }
        
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        
        results = []
        for advisory in data:
            try:
                result = self._parse_advisory(advisory)
                results.append(result)
            except Exception as e:
                logger.error(f"Error parsing GitHub advisory: {e}")
                continue
        
        logger.info(f"Successfully fetched {len(results)} advisories from GitHub")
        return results
    
    async def _fetch_repositories(self) -> List[CollectorResult]:
        """Fetch repositories from GitHub search."""
        url = f"{self.base_url}/search/repositories"
        
        params = {
            "q": self.query,
            "sort": "updated",
            "order": "desc",
            "per_page": self.max_results,
        }
        
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        
        results = []
        for repo in data.get("items", []):
            try:
                result = self._parse_repository(repo)
                results.append(result)
            except Exception as e:
                logger.error(f"Error parsing GitHub repository: {e}")
                continue
        
        logger.info(f"Successfully fetched {len(results)} repositories from GitHub")
        return results
    
    def _parse_advisory(self, advisory: Dict[str, Any]) -> CollectorResult:
        """Parse a GitHub advisory into a CollectorResult."""
        title = advisory.get("summary", "Untitled Advisory")
        description = advisory.get("description", "")
        url = advisory.get("html_url", "")
        
        # Extract published date
        published_at = None
        published_str = advisory.get("published_at")
        if published_str:
            try:
                published_at = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except Exception as e:
                logger.warning(f"Failed to parse published date: {e}")
        
        # Extract CVE IDs
        cve_ids = []
        for cve in advisory.get("cve_ids", []):
            cve_ids.append(cve)
        
        # Extract affected packages
        vulnerabilities = advisory.get("vulnerabilities", [])
        affected_packages = []
        for vuln in vulnerabilities:
            package = vuln.get("package", {})
            if package.get("name"):
                affected_packages.append(package.get("name"))
        
        metadata = {
            "ghsa_id": advisory.get("ghsa_id", ""),
            "cve_ids": cve_ids,
            "severity": advisory.get("severity", ""),
            "affected_packages": affected_packages,
            "source_type": "github_advisory",
        }
        
        return CollectorResult(
            title=title,
            description=description,
            content=description,
            url=url,
            authors=None,
            published_at=published_at,
            metadata=metadata,
        )
    
    def _parse_repository(self, repo: Dict[str, Any]) -> CollectorResult:
        """Parse a GitHub repository into a CollectorResult."""
        title = repo.get("full_name", "Untitled Repository")
        description = repo.get("description", "")
        url = repo.get("html_url", "")
        
        # Extract owner as author
        owner = repo.get("owner", {})
        authors = [owner.get("login")] if owner.get("login") else None
        
        # Extract updated date
        published_at = None
        updated_str = repo.get("updated_at")
        if updated_str:
            try:
                published_at = datetime.fromisoformat(
                    updated_str.replace("Z", "+00:00")
                )
            except Exception as e:
                logger.warning(f"Failed to parse updated date: {e}")
        
        metadata = {
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
            "topics": repo.get("topics", []),
            "source_type": "github_repository",
        }
        
        return CollectorResult(
            title=title,
            description=description,
            content=description,
            url=url,
            authors=authors,
            published_at=published_at,
            metadata=metadata,
        )
