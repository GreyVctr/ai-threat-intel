"""
Source model for intelligence source configuration.
"""
from sqlalchemy import Column, String, Text, Boolean, TIMESTAMP, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from . import Base


class Source(Base):
    """
    Represents an intelligence source configuration.
    
    Sources can be RSS feeds, APIs, or web scrapers that collect
    AI/ML security threat intelligence from public sources.
    """
    __tablename__ = "sources"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Source identification
    name = Column(String(255), unique=True, nullable=False, index=True)
    source_type = Column(String(50), nullable=False, index=True)  # rss, api, web_scrape
    url = Column(Text, nullable=False)
    
    # Configuration
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    fetch_frequency = Column(String(20))  # hourly, daily, weekly
    config = Column(JSON)  # Source-specific configuration (API keys, parameters, etc.)
    
    # Status tracking
    last_fetch = Column(TIMESTAMP(timezone=True))
    last_status = Column(String(20))  # success, http_error, timeout, error
    last_error = Column(Text)  # Error message from last fetch attempt
    
    # Metadata
    description = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)
    
    def __repr__(self):
        return f"<Source(name='{self.name}', type='{self.source_type}', enabled={self.enabled})>"
    
    def to_dict(self):
        """Convert source to dictionary for API responses."""
        return {
            "id": str(self.id),
            "name": self.name,
            "source_type": self.source_type,
            "url": self.url,
            "enabled": self.enabled,
            "fetch_frequency": self.fetch_frequency,
            "config": self.config,
            "last_fetch": self.last_fetch.isoformat() if self.last_fetch else None,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
