"""
Entity model for storing extracted entities from threat data.
"""
from sqlalchemy import Column, String, Text, TIMESTAMP, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from . import Base


class Entity(Base):
    """
    Represents an extracted entity from threat intelligence data.
    
    Entities include CVE IDs, framework names, attack techniques, and affected systems.
    Extracted using Named Entity Recognition (NER) during enrichment.
    """
    __tablename__ = "entities"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to threat
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Entity information
    entity_type = Column(String(50), nullable=False, index=True)  # cve, framework, technique, system
    entity_value = Column(Text, nullable=False)
    confidence = Column(String(10))  # Stored as string to avoid precision issues (e.g., "0.95")
    
    # Timestamp
    extracted_at = Column(TIMESTAMP(timezone=True), default=func.now(), nullable=False)
    
    # Relationship
    threat = relationship("Threat", back_populates="entities")
    
    # Composite index for efficient queries
    __table_args__ = (
        Index('idx_entity_type_value', 'entity_type', 'entity_value'),
    )
    
    def __repr__(self):
        return f"<Entity(type='{self.entity_type}', value='{self.entity_value}', confidence={self.confidence})>"
    
    def to_dict(self):
        """Convert entity to dictionary for API responses."""
        return {
            "id": str(self.id),
            "threat_id": str(self.threat_id),
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "confidence": self.confidence,
            "extracted_at": self.extracted_at.isoformat() if self.extracted_at else None,
        }
