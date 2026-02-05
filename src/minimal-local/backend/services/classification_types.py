"""
Data classes and types for hybrid threat classification system.

This module defines the core data structures used throughout the classification
workflow, including confidence levels, keyword matching results, LLM classification
results, and final classification results.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Literal
from pydantic import BaseModel, Field


class ConfidenceLevel(Enum):
    """
    Confidence level enumeration for classification results.
    
    Confidence levels are determined by the number of keyword matches:
    - HIGH: 5 or more keyword matches
    - MEDIUM: 2-4 keyword matches
    - LOW: 1 keyword match
    - NONE: 0 keyword matches or no classification possible
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class KeywordResult:
    """
    Result from keyword-based threat classification.
    
    Attributes:
        threat_type: The threat type with the highest keyword match count,
                    or None if no matches found
        score: Total number of keyword matches for the selected threat type
        matches_by_type: Dictionary mapping each threat type to the list of
                        keywords that matched in the description
        confidence_level: Confidence level derived from the score
    """
    threat_type: Optional[str]
    score: int
    matches_by_type: Dict[str, List[str]]
    confidence_level: ConfidenceLevel
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "threat_type": self.threat_type,
            "score": self.score,
            "matches_by_type": self.matches_by_type,
            "confidence_level": self.confidence_level.value
        }


@dataclass
class LLMResult:
    """
    Result from LLM-based threat classification.
    
    Attributes:
        threat_type: The threat type returned by the LLM
        raw_response: The complete raw response text from the LLM
        success: Whether the LLM classification succeeded
        error: Error message if classification failed, None otherwise
    """
    threat_type: str
    raw_response: str
    success: bool
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "threat_type": self.threat_type,
            "raw_response": self.raw_response,
            "success": self.success,
            "error": self.error
        }


@dataclass
class ClassificationResult:
    """
    Final classification result combining keyword and/or LLM classification.
    
    This is the complete result that gets persisted to the database,
    including the final threat type, classification method used, confidence
    level, score, and detailed metadata about the classification process.
    
    Attributes:
        threat_type: The final classified threat type
        method: Classification method used (keyword, llm, hybrid, 
                keyword_fallback, failed)
        confidence: Confidence level (high, medium, low, none)
        score: Number of keyword matches (0 if no keyword matching performed)
        metadata: Detailed classification metadata including keyword matches,
                 LLM suggestions, timestamps, and any errors
    """
    threat_type: str
    method: str
    confidence: str
    score: int
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "threat_type": self.threat_type,
            "method": self.method,
            "confidence": self.confidence,
            "score": self.score,
            "metadata": self.metadata
        }


# Enumerated types for metadata fields
AttackSurface = Literal["runtime", "training", "inference", "fine-tuning", "deployment"]
Testability = Literal["yes", "no", "conditional"]
TargetSystem = Literal["llm", "vision", "multimodal", "rag", "agentic", "chat"]


class ThreatMetadata(BaseModel):
    """
    Structured metadata for threat classification.
    
    This model defines the rich metadata that can be extracted from threat
    descriptions, including attack surface, testability, techniques, and
    target systems. All fields are optional to handle cases where the LLM
    cannot determine certain metadata.
    
    Attributes:
        attack_surface: Phases where the threat can be exploited
        testability: Whether the threat can be tested at runtime
        techniques: Specific attack techniques mentioned (e.g., jailbreak, FGSM, backdoor)
        target_systems: Types of AI systems the threat applies to
        confidence: LLM confidence in metadata extraction (0.0-1.0)
        reasoning: LLM reasoning for metadata extraction
    """
    
    attack_surface: List[AttackSurface] = Field(
        default_factory=list,
        description="Phases where the threat can be exploited"
    )
    
    testability: Optional[Testability] = Field(
        default=None,
        description="Whether the threat can be tested at runtime"
    )
    
    techniques: List[str] = Field(
        default_factory=list,
        description="Specific attack techniques mentioned (e.g., jailbreak, FGSM, backdoor)"
    )
    
    target_systems: List[TargetSystem] = Field(
        default_factory=list,
        description="Types of AI systems the threat applies to"
    )
    
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="LLM confidence in metadata extraction"
    )
    
    reasoning: Optional[str] = Field(
        default=None,
        description="LLM reasoning for metadata extraction"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak", "prompt_injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.92,
                "reasoning": "Threat describes runtime prompt manipulation targeting LLM chat systems"
            }
        }


def validate_metadata(metadata: dict) -> ThreatMetadata:
    """
    Validate and parse metadata dictionary into ThreatMetadata model.
    
    Args:
        metadata: Dictionary containing metadata fields
        
    Returns:
        ThreatMetadata: Validated metadata object
        
    Raises:
        ValidationError: If metadata doesn't conform to schema
    """
    return ThreatMetadata.model_validate(metadata)


def metadata_to_dict(metadata: ThreatMetadata) -> dict:
    """
    Convert ThreatMetadata to dictionary for JSON storage.
    
    Args:
        metadata: ThreatMetadata object
        
    Returns:
        Dictionary representation excluding None values
    """
    return metadata.model_dump(exclude_none=True)
