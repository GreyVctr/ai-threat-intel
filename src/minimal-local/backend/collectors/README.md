# Data Collection Layer

This directory contains the data collection layer for the AI Shield Intelligence system. The collectors fetch threat intelligence data from various public sources.

## Architecture

All collectors implement the `Collector` abstract base class defined in `base.py`, which provides a consistent interface for data collection.

### Base Collector Interface (`base.py`)

The base collector defines:
- **CollectorResult**: A dataclass containing the structured result of a collection operation
  - `title`: Title of the collected item
  - `description`: Description or summary
  - `content`: Full content text
  - `url`: Source URL
  - `authors`: List of author names (optional)
  - `published_at`: Publication timestamp (optional)
  - `metadata`: Additional source-specific metadata (optional)

- **Collector**: Abstract base class that all collectors must inherit from
  - `__init__(source_config)`: Initialize with source configuration
  - `fetch()`: Abstract method that must be implemented by subclasses

## Implemented Collectors

### 1. RSS Feed Collector (`rss.py`)

**Purpose**: Fetches threat intelligence data from RSS feeds.

**Features**:
- Uses `feedparser` library for robust RSS/Atom parsing
- Extracts title, description, content, link, authors, and published date
- Handles multiple content formats (summary, description, content)
- Extracts feed metadata and tags

**Example Configuration**:
```yaml
name: "arXiv CS.CR RSS"
type: "rss"
url: "http://export.arxiv.org/rss/cs.CR"
enabled: true
```

**Validates**: Requirements 6.5

### 2. arXiv API Collector (`api.py` - ArxivAPICollector)

**Purpose**: Fetches academic papers from arXiv categories related to AI/ML security.

**Features**:
- Queries arXiv API for papers in specific categories (cs.CR, cs.LG, cs.AI, stat.ML)
- Parses XML responses
- Extracts paper metadata including arXiv ID, authors, abstract, and categories
- Supports configurable result limits and sorting

**Example Configuration**:
```yaml
name: "arXiv CS.CR API"
type: "api"
url: "https://export.arxiv.org/api/query"
enabled: true
config:
  category: "cs.CR"
  max_results: 10
```

**Validates**: Requirements 6.2, 6.7

### 3. GitHub API Collector (`api.py` - GitHubAPICollector)

**Purpose**: Fetches security advisories and repositories from GitHub's public API.

**Features**:
- Supports two endpoints:
  - `advisories`: Fetches security advisories with CVE IDs and severity
  - `search_repos`: Searches for repositories matching a query
- No authentication required for public data
- Extracts GHSA IDs, CVE IDs, affected packages, and severity levels

**Example Configuration**:
```yaml
name: "GitHub Security Advisories"
type: "api"
url: "https://api.github.com/advisories"
enabled: true
config:
  endpoint: "advisories"
  max_results: 10
```

**Validates**: Requirements 6.3, 6.7

### 4. Web Scraper Collector (`scraper.py`)

**Purpose**: Scrapes web pages using BeautifulSoup with configurable selectors.

**Features**:
- Uses BeautifulSoup with lxml parser for HTML parsing
- Configurable CSS selectors for title, content, description, author, and date
- Built-in rate limiting to respect target servers
- Supports following links to scrape multiple pages
- Extracts metadata from meta tags and Open Graph tags
- Removes script, style, nav, footer, and header tags from content

**Example Configuration**:
```yaml
name: "Security Blog"
type: "web_scrape"
url: "https://example.com/blog"
enabled: true
config:
  rate_limit_delay: 1.0
  selectors:
    title: "h1.post-title"
    content: "article.post-content"
    author: ".author-name"
    date: "time.published"
  follow_links: false
  max_pages: 1
```

**Validates**: Requirements 6.8

## Rate Limiting

The web scraper includes a `RateLimiter` class that ensures a minimum delay between requests:
- Default: 1 second between requests
- Configurable via `rate_limit_delay` in source configuration
- Prevents overwhelming target servers

## Error Handling

All collectors implement robust error handling:
- Log errors and continue processing other items
- Raise exceptions for critical failures (network errors, invalid responses)
- Gracefully handle missing or malformed data
- Provide detailed error messages for debugging

## Testing

Run the test script to verify all collectors:

```bash
python backend/scripts/test_collectors.py
```

This will test:
- RSS feed parsing with arXiv RSS
- arXiv API with cs.CR category
- GitHub API with security advisories
- Web scraping with example.com

All tests should pass, demonstrating that each collector can successfully fetch and parse data from its respective source.

## Usage Example

```python
from collectors.rss import RSSCollector
from collectors.api import ArxivAPICollector, GitHubAPICollector
from collectors.scraper import WebScraperCollector

# Create a collector
config = {
    "name": "arXiv CS.CR",
    "type": "rss",
    "url": "http://export.arxiv.org/rss/cs.CR",
    "config": {}
}
collector = RSSCollector(config)

# Fetch data
results = await collector.fetch()

# Process results
for result in results:
    print(f"Title: {result.title}")
    print(f"URL: {result.url}")
    print(f"Published: {result.published_at}")
    print(f"Authors: {result.authors}")
    print(f"Content: {result.content[:100]}...")
    print()
```

## Integration with Ingestion Pipeline

These collectors are used by the ingestion pipeline (implemented in task 9) to fetch threat intelligence data from configured sources. The `CollectorResult` objects are converted to threat records and stored in the database.

## Future Enhancements

Potential improvements for future iterations:
- Add more API collectors (CVE/NVD, Reddit, Hacker News)
- Implement caching to avoid re-fetching unchanged data
- Add support for authenticated API access (optional)
- Implement incremental fetching (only fetch new items since last run)
- Add content deduplication at the collector level
