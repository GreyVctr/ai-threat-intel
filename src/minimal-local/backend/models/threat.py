"""
Threat model for storing AI/ML security threat intelligence.
"""
from sqlalchemy import Column, String, Text, Integer, TIMESTAMP, ARRAY, JSON, CheckConstraint, Index
from sqlalchemy.dialects.postgresql import UUID, TSVECTOR
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from . import Base


class Threat(Base):
    """
    Represents an AI/ML security threat from various intelligence sources.
    
    Stores threat metadata, content, and references to enrichment data.
    Supports full-text search and fuzzy matching via PostgreSQL extensions.
    """
    __tablename__ = "threats"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Core threat information
    title = Column(Text, nullable=False, index=True)
    description = Column(Text)
    content = Column(Text)
    
    # Source information
    source = Column(String(255), nullable=False, index=True)
    source_url = Column(Text)
    authors = Column(ARRAY(Text))
    
    # Timestamps
    published_at = Column(TIMESTAMP(timezone=True))
    ingested_at = Column(TIMESTAMP(timezone=True), default=func.now(), nullable=False)
    
    # Deduplication
    content_hash = Column(String(64), unique=True, nullable=False, index=True)
    
    # Classification and scoring
    threat_type = Column(String(50), index=True)  # adversarial, extraction, poisoning, etc.
    severity = Column(Integer, CheckConstraint('severity >= 1 AND severity <= 10'))
    exploitability_score = Column(String(10))  # Stored as string to avoid precision issues
    
    # Storage reference
    raw_data_key = Column(String(255))  # MinIO object key
    
    # Search vector (populated by trigger or application)
    search_vector = Column(TSVECTOR)
    
    # Additional metadata (renamed to avoid SQLAlchemy reserved name)
    extra_metadata = Column("metadata", JSON)
    
    # Enrichment status tracking
    enrichment_status = Column(String(20), default="pending")  # pending, partial, complete
    enrichment_errors = Column(ARRAY(Text))
    
    # LLM analysis status
    llm_analysis_status = Column(String(20), default="pending")  # pending, complete, failed
    
    # Classification metadata (hybrid threat classification)
    classification_method = Column(String(20), nullable=True)  # keyword, llm, hybrid, keyword_fallback, failed
    classification_confidence = Column(String(10), nullable=True)  # high, medium, low, none
    classification_score = Column(Integer, nullable=True)  # Number of keyword matches
    classification_metadata = Column(JSON, nullable=True)  # Detailed classification data
    
    # Relationships
    entities = relationship("Entity", back_populates="threat", cascade="all, delete-orphan")
    mitre_mappings = relationship("MitreMapping", back_populates="threat", cascade="all, delete-orphan")
    llm_analysis = relationship("LLMAnalysis", back_populates="threat", cascade="all, delete-orphan", uselist=False)
    
    # Indexes are defined in init_db.py script
    
    def __repr__(self):
        return f"<Threat(id={self.id}, title='{self.title[:50]}...', source='{self.source}')>"
    
    def to_dict(self):
        """Convert threat to dictionary for API responses."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "content": self.content,
            "source": self.source,
            "source_url": self.source_url,
            "authors": self.authors,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "content_hash": self.content_hash,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "exploitability_score": self.exploitability_score,
            "raw_data_key": self.raw_data_key,
            "metadata": self.extra_metadata,
            "enrichment_status": self.enrichment_status,
            "llm_analysis_status": self.llm_analysis_status,
            "classification_method": self.classification_method,
            "classification_confidence": self.classification_confidence,
            "classification_score": self.classification_score,
            "classification_metadata": self.classification_metadata,
        }
