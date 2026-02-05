"""
MITRE ATLAS mapping model for threat intelligence.
"""
from sqlalchemy import Column, String, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from . import Base


class MitreMapping(Base):
    """
    Represents a mapping between a threat and MITRE ATLAS tactics/techniques.
    
    MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is a framework
    for understanding adversarial tactics and techniques against AI/ML systems.
    """
    __tablename__ = "mitre_mappings"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to threat
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # MITRE ATLAS information
    tactic = Column(String(100))  # e.g., "ML Model Access", "Reconnaissance"
    technique = Column(String(100))  # e.g., "Model Extraction", "Discover ML Artifacts"
    technique_id = Column(String(20), index=True)  # e.g., "AML.T0002"
    confidence = Column(String(10))  # Stored as string to avoid precision issues (e.g., "0.85")
    
    # Relationship
    threat = relationship("Threat", back_populates="mitre_mappings")
    
    # Composite index for efficient queries
    __table_args__ = (
        Index('idx_mitre_tactic_technique', 'tactic', 'technique'),
    )
    
    def __repr__(self):
        return f"<MitreMapping(technique_id='{self.technique_id}', technique='{self.technique}', confidence={self.confidence})>"
    
    def to_dict(self):
        """Convert MITRE mapping to dictionary for API responses."""
        return {
            "id": str(self.id),
            "threat_id": str(self.threat_id),
            "tactic": self.tactic,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "confidence": self.confidence,
        }
