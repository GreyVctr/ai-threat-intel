"""
Source Manager Service

Manages intelligence source configuration including:
- Loading sources from YAML configuration
- Validating source URLs and accessibility
- Enable/disable functionality
- Hot-reload of configuration changes
"""

import asyncio
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import BaseModel, Field, HttpUrl, ValidationError
from watchfiles import awatch

logger = logging.getLogger(__name__)


class SourceConfig(BaseModel):
    """Configuration model for an intelligence source"""
    
    name: str = Field(..., description="Human-readable source name")
    type: str = Field(..., description="Source type: rss, api, or web_scrape")
    url: str = Field(..., description="Source URL")
    enabled: bool = Field(default=True, description="Whether source is enabled")
    frequency: str = Field(default="daily", description="Collection frequency")
    description: Optional[str] = Field(None, description="Source description")
    tags: List[str] = Field(default_factory=list, description="Source tags")
    config: Dict = Field(default_factory=dict, description="Source-specific config")
    
    def validate_type(self) -> bool:
        """Validate that source type is one of the allowed values"""
        return self.type in ["rss", "api", "web_scrape"]
    
    def validate_frequency(self) -> bool:
        """Validate that frequency is one of the allowed values"""
        return self.frequency in ["hourly", "daily", "weekly"]


class SourceManager:
    """Manages intelligence source configuration and validation"""
    
    def __init__(self, config_path: str = "../config/sources.yaml"):
        """
        Initialize the source manager
        
        Args:
            config_path: Path to the sources YAML configuration file
        """
        self.config_path = Path(config_path)
        self.sources: Dict[str, SourceConfig] = {}
        self._last_modified: Optional[float] = None
        self._http_client: Optional[httpx.AsyncClient] = None
        self._watch_task: Optional[asyncio.Task] = None
        self._reload_callbacks: List[Callable] = []
        
    async def __aenter__(self):
        """Async context manager entry"""
        self._http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._http_client:
            await self._http_client.aclose()
    
    def load_sources(self) -> Dict[str, SourceConfig]:
        """
        Load sources from YAML configuration file
        
        Returns:
            Dictionary of source name to SourceConfig
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
            ValidationError: If source configuration is invalid
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Source configuration file not found: {self.config_path}")
        
        logger.info(f"Loading sources from {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML configuration: {e}")
            raise
        
        if not config_data or 'sources' not in config_data:
            logger.warning("No sources found in configuration file")
            # Clear existing sources when config is empty
            self.sources = {}
            return {}
        
        sources = {}
        for source_data in config_data['sources']:
            try:
                source = SourceConfig(**source_data)
                
                # Validate source type and frequency
                if not source.validate_type():
                    logger.error(f"Invalid source type '{source.type}' for source '{source.name}'")
                    continue
                
                if not source.validate_frequency():
                    logger.error(f"Invalid frequency '{source.frequency}' for source '{source.name}'")
                    continue
                
                # Validate URL format
                if not self._validate_url_format(source.url):
                    logger.error(f"Invalid URL format for source '{source.name}': {source.url}")
                    continue
                
                sources[source.name] = source
                logger.info(f"Loaded source: {source.name} ({source.type}, enabled={source.enabled})")
                
            except ValidationError as e:
                logger.error(f"Invalid source configuration: {e}")
                continue
        
        self.sources = sources
        self._last_modified = self.config_path.stat().st_mtime
        
        logger.info(f"Successfully loaded {len(sources)} sources")
        return sources
    
    def _validate_url_format(self, url: str) -> bool:
        """
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL format is valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False
    
    async def validate_source_accessibility(self, source: SourceConfig) -> bool:
        """
        Validate that a source is publicly accessible
        
        Args:
            source: Source configuration to validate
            
        Returns:
            True if source is accessible, False otherwise
        """
        if not self._http_client:
            logger.error("HTTP client not initialized. Use async context manager.")
            return False
        
        try:
            logger.info(f"Validating accessibility for source: {source.name}")
            
            # Make HEAD request to check accessibility
            response = await self._http_client.head(source.url)
            
            # Check if response indicates authentication required
            if response.status_code in [401, 403]:
                logger.warning(f"Source '{source.name}' requires authentication (status {response.status_code})")
                return False
            
            # Check if response indicates paywall or other access restriction
            if response.status_code == 402:
                logger.warning(f"Source '{source.name}' is behind a paywall")
                return False
            
            # Accept any 2xx or 3xx status as accessible
            if 200 <= response.status_code < 400:
                logger.info(f"Source '{source.name}' is accessible (status {response.status_code})")
                return True
            
            logger.warning(f"Source '{source.name}' returned status {response.status_code}")
            return False
            
        except httpx.TimeoutException:
            logger.error(f"Timeout validating source '{source.name}'")
            return False
        except httpx.RequestError as e:
            logger.error(f"Error validating source '{source.name}': {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error validating source '{source.name}': {e}")
            return False
    
    async def validate_all_sources(self) -> Dict[str, bool]:
        """
        Validate accessibility of all enabled sources
        
        Returns:
            Dictionary mapping source name to accessibility status
        """
        results = {}
        
        for name, source in self.sources.items():
            if not source.enabled:
                logger.info(f"Skipping disabled source: {name}")
                results[name] = None  # None indicates skipped
                continue
            
            results[name] = await self.validate_source_accessibility(source)
        
        return results
    
    def get_source(self, name: str) -> Optional[SourceConfig]:
        """
        Get a source by name
        
        Args:
            name: Source name
            
        Returns:
            SourceConfig if found, None otherwise
        """
        return self.sources.get(name)
    
    def get_enabled_sources(self) -> List[SourceConfig]:
        """
        Get all enabled sources
        
        Returns:
            List of enabled SourceConfig objects
        """
        return [source for source in self.sources.values() if source.enabled]
    
    def get_sources_by_type(self, source_type: str) -> List[SourceConfig]:
        """
        Get all sources of a specific type
        
        Args:
            source_type: Source type (rss, api, web_scrape)
            
        Returns:
            List of SourceConfig objects matching the type
        """
        return [source for source in self.sources.values() if source.type == source_type]
    
    def get_sources_by_frequency(self, frequency: str) -> List[SourceConfig]:
        """
        Get all sources with a specific collection frequency
        
        Args:
            frequency: Collection frequency (hourly, daily, weekly)
            
        Returns:
            List of SourceConfig objects matching the frequency
        """
        return [source for source in self.sources.values() if source.frequency == frequency]
    
    def enable_source(self, name: str) -> bool:
        """
        Enable a source
        
        Args:
            name: Source name
            
        Returns:
            True if source was enabled, False if not found
        """
        source = self.sources.get(name)
        if source:
            source.enabled = True
            logger.info(f"Enabled source: {name}")
            return True
        logger.warning(f"Source not found: {name}")
        return False
    
    def disable_source(self, name: str) -> bool:
        """
        Disable a source
        
        Args:
            name: Source name
            
        Returns:
            True if source was disabled, False if not found
        """
        source = self.sources.get(name)
        if source:
            source.enabled = False
            logger.info(f"Disabled source: {name}")
            return True
        logger.warning(f"Source not found: {name}")
        return False
    
    def has_config_changed(self) -> bool:
        """
        Check if the configuration file has been modified
        
        Returns:
            True if file has been modified since last load, False otherwise
        """
        if not self.config_path.exists():
            return False
        
        current_mtime = self.config_path.stat().st_mtime
        return current_mtime != self._last_modified
    
    def reload_if_changed(self) -> bool:
        """
        Reload configuration if file has changed
        
        Returns:
            True if configuration was reloaded, False otherwise
        """
        if self.has_config_changed():
            logger.info("Configuration file changed, reloading sources")
            try:
                self.load_sources()
                return True
            except Exception as e:
                logger.error(f"Failed to reload sources: {e}")
                return False
        return False
    
    def get_stats(self) -> Dict:
        """
        Get statistics about configured sources
        
        Returns:
            Dictionary with source statistics
        """
        total = len(self.sources)
        enabled = len(self.get_enabled_sources())
        disabled = total - enabled
        
        by_type = {}
        for source_type in ["rss", "api", "web_scrape"]:
            by_type[source_type] = len(self.get_sources_by_type(source_type))
        
        by_frequency = {}
        for frequency in ["hourly", "daily", "weekly"]:
            by_frequency[frequency] = len(self.get_sources_by_frequency(frequency))
        
        return {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "by_type": by_type,
            "by_frequency": by_frequency,
            "config_path": str(self.config_path),
            "last_modified": self._last_modified
        }
    
    def register_reload_callback(self, callback: Callable) -> None:
        """
        Register a callback to be called when configuration is reloaded
        
        Args:
            callback: Callable to be invoked on reload
        """
        self._reload_callbacks.append(callback)
        logger.info(f"Registered reload callback: {callback.__name__}")
    
    async def _notify_reload_callbacks(self) -> None:
        """Notify all registered callbacks that configuration was reloaded"""
        for callback in self._reload_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                logger.error(f"Error in reload callback {callback.__name__}: {e}")
    
    async def _watch_config_file(self) -> None:
        """
        Watch the configuration file for changes and reload automatically
        
        This method runs in a background task and monitors the config file
        for modifications. When changes are detected, it reloads the configuration
        and notifies registered callbacks.
        """
        logger.info(f"Starting file watcher for {self.config_path}")
        
        try:
            async for changes in awatch(self.config_path):
                logger.info(f"Configuration file changed: {changes}")
                
                try:
                    # Reload sources from file
                    self.load_sources()
                    logger.info("Configuration reloaded successfully")
                    
                    # Notify callbacks
                    await self._notify_reload_callbacks()
                    
                except Exception as e:
                    logger.error(f"Failed to reload configuration: {e}")
                    # Continue watching even if reload fails
        
        except asyncio.CancelledError:
            logger.info("File watcher stopped")
            raise
        except Exception as e:
            logger.error(f"File watcher error: {e}")
    
    def start_watching(self) -> None:
        """
        Start watching the configuration file for changes
        
        This starts a background task that monitors the config file and
        automatically reloads when changes are detected.
        """
        if self._watch_task is not None and not self._watch_task.done():
            logger.warning("File watcher already running")
            return
        
        self._watch_task = asyncio.create_task(self._watch_config_file())
        logger.info("File watcher started")
    
    def stop_watching(self) -> None:
        """
        Stop watching the configuration file
        
        Cancels the background file watcher task.
        """
        if self._watch_task is not None and not self._watch_task.done():
            self._watch_task.cancel()
            logger.info("File watcher stopped")
        else:
            logger.warning("File watcher not running")
    
    def is_watching(self) -> bool:
        """
        Check if file watcher is currently running
        
        Returns:
            True if watcher is active, False otherwise
        """
        return self._watch_task is not None and not self._watch_task.done()


# Global source manager instance
_source_manager: Optional[SourceManager] = None


def get_source_manager() -> SourceManager:
    """
    Get the global source manager instance
    
    Returns:
        SourceManager instance
    """
    global _source_manager
    if _source_manager is None:
        _source_manager = SourceManager()
        try:
            _source_manager.load_sources()
        except Exception as e:
            logger.error(f"Failed to load sources on initialization: {e}")
    return _source_manager
