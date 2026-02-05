"""
LLM analysis model for storing AI-generated threat analysis.
"""
from sqlalchemy import Column, String, Text, TIMESTAMP, ForeignKey, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from . import Base


class LLMAnalysis(Base):
    """
    Represents LLM-generated analysis of a threat.
    
    Uses local Ollama LLM to analyze threat data and generate:
    - Summary of the threat
    - Key findings
    - Attack vectors
    - Recommended mitigations
    """
    __tablename__ = "llm_analysis"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to threat (one-to-one relationship)
    threat_id = Column(
        UUID(as_uuid=True),
        ForeignKey("threats.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True
    )
    
    # Analysis results
    summary = Column(Text)  # High-level summary of the threat
    key_findings = Column(ARRAY(Text))  # List of key findings
    attack_vectors = Column(ARRAY(Text))  # List of identified attack vectors
    mitigations = Column(ARRAY(Text))  # List of recommended mitigations
    
    # Model information
    model_name = Column(String(50))  # e.g., "phi3:mini"
    
    # Timestamp
    analyzed_at = Column(TIMESTAMP(timezone=True), default=func.now(), nullable=False)
    
    # Relationship
    threat = relationship("Threat", back_populates="llm_analysis")
    
    def __repr__(self):
        return f"<LLMAnalysis(threat_id={self.threat_id}, model='{self.model_name}', analyzed_at={self.analyzed_at})>"
    
    def to_dict(self):
        """Convert LLM analysis to dictionary for API responses."""
        return {
            "id": str(self.id),
            "threat_id": str(self.threat_id),
            "summary": self.summary,
            "key_findings": self.key_findings,
            "attack_vectors": self.attack_vectors,
            "mitigations": self.mitigations,
            "model_name": self.model_name,
            "analyzed_at": self.analyzed_at.isoformat() if self.analyzed_at else None,
        }
