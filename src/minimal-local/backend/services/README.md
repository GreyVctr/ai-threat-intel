# Services Layer

This directory contains the business logic and service layer for the AI Shield Intelligence system.

## Source Manager

The `source_manager.py` module provides intelligence source configuration management with the following features:

### Features

1. **YAML Configuration Loading**
   - Load intelligence sources from `config/sources.yaml`
   - Support for multiple source types: RSS, API, web scraping
   - Configurable collection frequency: hourly, daily, weekly
   - Enable/disable individual sources

2. **Source Validation**
   - URL format validation
   - Public accessibility checking
   - Authentication/paywall detection
   - Batch validation of all sources

3. **Hot-Reload**
   - Automatic file watching for configuration changes
   - Reload without service restart
   - Callback system for reload notifications
   - Background task management

4. **Source Management**
   - Enable/disable sources programmatically
   - Filter sources by type, frequency, or enabled status
   - Get statistics about configured sources
   - Query individual sources by name

### Usage Examples

#### Basic Usage

```python
from services.source_manager import SourceManager

# Initialize and load sources
manager = SourceManager(config_path="config/sources.yaml")
manager.load_sources()

# Get all enabled sources
enabled_sources = manager.get_enabled_sources()

# Get sources by type
rss_sources = manager.get_sources_by_type("rss")
api_sources = manager.get_sources_by_type("api")

# Get sources by frequency
hourly_sources = manager.get_sources_by_frequency("hourly")

# Get statistics
stats = manager.get_stats()
print(f"Total sources: {stats['total']}")
print(f"Enabled: {stats['enabled']}")
```

#### Source Validation

```python
import asyncio
from services.source_manager import SourceManager

async def validate_sources():
    manager = SourceManager()
    manager.load_sources()
    
    # Validate all enabled sources
    async with manager:
        results = await manager.validate_all_sources()
        
        for name, is_accessible in results.items():
            if is_accessible:
                print(f"✓ {name} is accessible")
            elif is_accessible is None:
                print(f"⊘ {name} is disabled")
            else:
                print(f"✗ {name} is not accessible")

asyncio.run(validate_sources())
```

#### Enable/Disable Sources

```python
manager = SourceManager()
manager.load_sources()

# Disable a source
manager.disable_source("arXiv Computer Security")

# Enable a source
manager.enable_source("arXiv Computer Security")

# Check if source is enabled
source = manager.get_source("arXiv Computer Security")
print(f"Enabled: {source.enabled}")
```

#### Hot-Reload with File Watcher

```python
import asyncio
from services.source_manager import SourceManager

async def on_config_reload():
    """Callback when configuration is reloaded"""
    print("Configuration reloaded!")

async def main():
    manager = SourceManager()
    manager.load_sources()
    
    # Register callback
    manager.register_reload_callback(on_config_reload)
    
    # Start watching for changes
    manager.start_watching()
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        manager.stop_watching()

asyncio.run(main())
```

#### Manual Reload Check

```python
manager = SourceManager()
manager.load_sources()

# Check if config file has changed
if manager.has_config_changed():
    print("Configuration file has been modified")
    manager.load_sources()  # Reload manually

# Or use convenience method
if manager.reload_if_changed():
    print("Configuration was reloaded")
```

### Configuration File Format

The `config/sources.yaml` file should follow this structure:

```yaml
sources:
  - name: "Source Name"
    type: "rss"  # or "api" or "web_scrape"
    url: "https://example.com/feed"
    enabled: true
    frequency: "daily"  # or "hourly" or "weekly"
    description: "Optional description"
    tags:
      - tag1
      - tag2
    config:
      # Source-specific configuration
      rate_limit: 60
      max_items: 100
```

### Source Types

- **RSS**: RSS/Atom feed sources
- **API**: RESTful API endpoints
- **web_scrape**: Web pages requiring HTML parsing

### Collection Frequencies

- **hourly**: Collect every hour
- **daily**: Collect once per day
- **weekly**: Collect once per week

### Public Accessibility Requirements

All sources must be publicly accessible:
- ✓ No authentication required
- ✓ No paywall
- ✓ No login required
- ✓ Freely available content

Sources requiring authentication will be skipped with a warning.

### Testing

Run the test suite:

```bash
python backend/scripts/test_source_manager.py
```

Test hot-reload functionality:

```bash
python backend/scripts/demo_hot_reload.py
```

### API Integration

The source manager is designed to integrate with the FastAPI backend:

```python
from fastapi import FastAPI, Depends
from services.source_manager import get_source_manager, SourceManager

app = FastAPI()

@app.get("/api/v1/sources")
async def list_sources(manager: SourceManager = Depends(get_source_manager)):
    """List all configured sources"""
    return {
        "sources": [
            {
                "name": source.name,
                "type": source.type,
                "url": source.url,
                "enabled": source.enabled,
                "frequency": source.frequency,
                "description": source.description,
                "tags": source.tags
            }
            for source in manager.sources.values()
        ],
        "stats": manager.get_stats()
    }

@app.post("/api/v1/sources/{name}/enable")
async def enable_source(name: str, manager: SourceManager = Depends(get_source_manager)):
    """Enable a source"""
    if manager.enable_source(name):
        return {"message": f"Source '{name}' enabled"}
    return {"error": f"Source '{name}' not found"}, 404

@app.post("/api/v1/sources/{name}/disable")
async def disable_source(name: str, manager: SourceManager = Depends(get_source_manager)):
    """Disable a source"""
    if manager.disable_source(name):
        return {"message": f"Source '{name}' disabled"}
    return {"error": f"Source '{name}' not found"}, 404
```

### Error Handling

The source manager handles various error conditions:

- **FileNotFoundError**: Configuration file doesn't exist
- **yaml.YAMLError**: Invalid YAML syntax
- **ValidationError**: Invalid source configuration
- **httpx.TimeoutException**: Source validation timeout
- **httpx.RequestError**: Network errors during validation

All errors are logged with appropriate context.

### Logging

The source manager uses Python's standard logging:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Source manager will log:
# - Source loading events
# - Validation results
# - Enable/disable operations
# - Configuration reloads
# - Errors and warnings
```

### Thread Safety

The source manager is designed for async/await usage and is not thread-safe. Use within an asyncio event loop.

### Performance Considerations

- **File Watching**: Uses efficient file system events (not polling)
- **Validation**: Async HTTP requests with configurable timeout
- **Batch Operations**: Validate multiple sources concurrently
- **Memory**: Minimal memory footprint, configuration cached in memory

### Future Enhancements

Potential future improvements:

1. Database persistence of source state
2. Source health monitoring and metrics
3. Automatic retry for failed validations
4. Source discovery and recommendation
5. Integration with Celery for scheduled fetching
