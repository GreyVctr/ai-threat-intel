"""
Classification service for hybrid threat classification.

This module orchestrates the hybrid threat classification workflow, combining
keyword-based matching with LLM-based classification to improve accuracy and
reduce "unknown" threat classifications.

Enhanced to extract structured metadata (attack_surface, testability, techniques, 
target_systems) alongside category classification.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat
from services.classification_types import (
    ClassificationResult,
    KeywordResult,
    LLMResult,
    ConfidenceLevel,
    ThreatMetadata
)
from services.keyword_matcher import KeywordMatcher
from services.confidence_evaluator import ConfidenceEvaluator
from services.llm_classifier import LLMClassifier, classify_threat_with_metadata
from services.classification_config import ClassificationConfig

logger = logging.getLogger(__name__)


class ClassificationService:
    """
    Orchestrates hybrid threat classification.
    
    The ClassificationService combines keyword matching and LLM classification
    using a confidence-based decision tree:
    - High confidence (≥5 matches): Use keyword result directly
    - Medium confidence (2-4 matches): Validate keyword result with LLM
    - Low confidence (0-1 matches): Use LLM classification
    
    Configuration is loaded from ClassificationConfig, which provides:
    - Confidence thresholds (HIGH_CONFIDENCE_THRESHOLD, MEDIUM_CONFIDENCE_THRESHOLD)
    - LLM settings (OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT)
    - Keyword lists (KEYWORDS dictionary)
    
    Attributes:
        keyword_matcher: KeywordMatcher instance for keyword-based classification
        llm_classifier: LLMClassifier instance for LLM-based classification
        valid_threat_types: List of valid threat type strings
    """
    
    def __init__(
        self,
        keyword_config: Optional[Dict[str, List[str]]] = None,
        llm_classifier: Optional[LLMClassifier] = None
    ):
        """
        Initialize classification service with dependencies.
        
        Args:
            keyword_config: Optional keyword configuration dict. If None, uses ClassificationConfig.KEYWORDS
            llm_classifier: Optional LLMClassifier instance. If None, creates a new one
        """
        # Use configuration from ClassificationConfig if not provided
        keywords = keyword_config or ClassificationConfig.KEYWORDS
        
        # Initialize keyword matcher
        self.keyword_matcher = KeywordMatcher(keywords)
        
        # Initialize LLM classifier
        self.llm_classifier = llm_classifier or LLMClassifier()
        
        # Valid threat types (from keyword config + unknown)
        self.valid_threat_types = list(keywords.keys()) + ["unknown"]
        
        logger.info(
            f"Initialized ClassificationService with {len(self.valid_threat_types)} "
            f"threat types: {', '.join(self.valid_threat_types)}"
        )
    
    async def classify_threat(
        self,
        threat: Threat,
        db: AsyncSession
    ) -> ClassificationResult:
        """
        Classify a threat using hybrid approach.
        
        Implements the classification decision tree:
        1. Attempt keyword matching first
        2. Determine confidence level from keyword score
        3. Based on confidence:
           - HIGH: Use keyword result (fast path)
           - MEDIUM: Validate with LLM (hybrid path)
           - LOW/NONE: Use LLM classification (fallback path)
        4. Handle LLM failures gracefully with fallback
        5. Persist results to database
        
        Args:
            threat: Threat object to classify
            db: Database session for persistence
            
        Returns:
            ClassificationResult with threat_type and metadata
        """
        logger.info(f"Classifying threat {threat.id}")
        
        # Step 1: Keyword matching (always attempted first)
        keyword_result = self._classify_with_keywords(threat.description or "")
        
        # Step 2: Determine confidence level
        confidence_level = self._determine_confidence_level(keyword_result.score)
        
        logger.info(
            f"Keyword matching: type={keyword_result.threat_type}, "
            f"score={keyword_result.score}, confidence={confidence_level.value}"
        )
        
        # Step 3: Decision tree based on confidence
        if confidence_level == ConfidenceLevel.HIGH:
            # High confidence path: use keyword result directly
            logger.info("High confidence - using keyword result")
            result = self._build_keyword_result(keyword_result)
            
        elif confidence_level == ConfidenceLevel.MEDIUM:
            # Medium confidence path: validate with LLM (hybrid)
            logger.info("Medium confidence - validating with LLM")
            try:
                llm_result, metadata = await self._classify_with_llm(
                    threat.description or "",
                    context=f"Keyword analysis suggests: {keyword_result.threat_type}"
                )
                result = self._build_hybrid_result(keyword_result, llm_result, metadata)
            except (ConnectionError, TimeoutError) as e:
                logger.error(f"LLM validation failed: {e}")
                result = self._build_fallback_result(keyword_result, str(e))
                
        else:  # LOW or NONE
            # Low/none confidence path: use LLM classification
            logger.info(f"{confidence_level.value} confidence - using LLM classification")
            try:
                llm_result, metadata = await self._classify_with_llm(threat.description or "")
                result = self._build_llm_result(llm_result, keyword_result, metadata)
            except (ConnectionError, TimeoutError) as e:
                logger.error(f"LLM classification failed: {e}")
                if keyword_result.threat_type:
                    result = self._build_fallback_result(keyword_result, str(e))
                else:
                    result = self._build_failed_result(str(e))
        
        # Step 4: Persist to database
        await self._persist_classification(threat, result, db)
        
        logger.info(
            f"Classification complete: type={result.threat_type}, "
            f"method={result.method}"
        )
        
        return result
    
    def _classify_with_keywords(self, description: str) -> KeywordResult:
        """
        Run keyword matching and return results.
        
        Args:
            description: Threat description text
            
        Returns:
            KeywordResult with matches and confidence
        """
        return self.keyword_matcher.match(description)
    
    async def _classify_with_llm(
        self,
        description: str,
        context: Optional[str] = None
    ) -> tuple[LLMResult, Optional[ThreatMetadata]]:
        """
        Run LLM classification with metadata extraction.
        
        Args:
            description: Threat description text
            context: Optional context from keyword matching
            
        Returns:
            Tuple of (LLMResult, ThreatMetadata or None)
            
        Raises:
            ConnectionError: When Ollama service is unavailable
            TimeoutError: When request exceeds timeout
        """
        try:
            # Use enhanced metadata extraction
            category, metadata = await classify_threat_with_metadata(
                description,
                self.llm_classifier
            )
            
            # Create LLMResult for backward compatibility
            llm_result = LLMResult(
                threat_type=category,
                raw_response=f"Category: {category}, Metadata extracted",
                success=True,
                error=None
            )
            
            return llm_result, metadata
            
        except Exception as e:
            logger.error(f"Metadata extraction failed: {e}, falling back to basic classification")
            # Fall back to basic classification without metadata
            llm_result = await self.llm_classifier.classify(
                description,
                self.valid_threat_types,
                context
            )
            return llm_result, None
    
    def _determine_confidence_level(self, score: int) -> ConfidenceLevel:
        """
        Map confidence score to level.
        
        Args:
            score: Number of keyword matches
            
        Returns:
            ConfidenceLevel enum value
        """
        return ConfidenceEvaluator.evaluate(score)
    
    def _build_keyword_result(self, keyword_result: KeywordResult) -> ClassificationResult:
        """
        Build result for high-confidence keyword classification.
        
        Args:
            keyword_result: Result from keyword matching
            
        Returns:
            ClassificationResult with method="keyword"
        """
        metadata = {
            "keyword_matches": keyword_result.matches_by_type,
            "keyword_result": keyword_result.threat_type,
            "keyword_score": keyword_result.score,
            "method": "keyword",
            "confidence": keyword_result.confidence_level.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return ClassificationResult(
            threat_type=keyword_result.threat_type or "unknown",
            method="keyword",
            confidence=keyword_result.confidence_level.value,
            score=keyword_result.score,
            metadata=metadata
        )
    
    def _build_hybrid_result(
        self,
        keyword_result: KeywordResult,
        llm_result: LLMResult,
        metadata: Optional[ThreatMetadata] = None
    ) -> ClassificationResult:
        """
        Build result for hybrid classification (keyword + LLM validation).
        
        Always uses the LLM result as the final classification when both
        keyword and LLM classification are performed.
        
        Args:
            keyword_result: Result from keyword matching
            llm_result: Result from LLM classification
            metadata: Extracted threat metadata (optional)
            
        Returns:
            ClassificationResult with method="hybrid"
        """
        base_metadata = {
            "keyword_matches": keyword_result.matches_by_type,
            "keyword_result": keyword_result.threat_type,
            "keyword_score": keyword_result.score,
            "llm_suggestion": llm_result.threat_type,
            "llm_raw_response": llm_result.raw_response,
            "method": "hybrid",
            "confidence": keyword_result.confidence_level.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agreement": keyword_result.threat_type == llm_result.threat_type
        }
        
        # Add structured metadata if available
        if metadata:
            base_metadata["threat_metadata"] = {
                "attack_surface": metadata.attack_surface,
                "testability": metadata.testability,
                "techniques": metadata.techniques,
                "target_systems": metadata.target_systems,
                "confidence": metadata.confidence,
                "reasoning": metadata.reasoning
            }
        
        # Always use LLM result for hybrid classification
        return ClassificationResult(
            threat_type=llm_result.threat_type,
            method="hybrid",
            confidence=keyword_result.confidence_level.value,
            score=keyword_result.score,
            metadata=base_metadata
        )
    
    def _build_llm_result(
        self,
        llm_result: LLMResult,
        keyword_result: KeywordResult,
        metadata: Optional[ThreatMetadata] = None
    ) -> ClassificationResult:
        """
        Build result for LLM-only classification.
        
        Args:
            llm_result: Result from LLM classification
            keyword_result: Result from keyword matching (for metadata)
            metadata: Extracted threat metadata (optional)
            
        Returns:
            ClassificationResult with method="llm"
        """
        base_metadata = {
            "keyword_matches": keyword_result.matches_by_type,
            "keyword_score": keyword_result.score,
            "llm_suggestion": llm_result.threat_type,
            "llm_raw_response": llm_result.raw_response,
            "method": "llm",
            "confidence": keyword_result.confidence_level.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Add structured metadata if available
        if metadata:
            base_metadata["threat_metadata"] = {
                "attack_surface": metadata.attack_surface,
                "testability": metadata.testability,
                "techniques": metadata.techniques,
                "target_systems": metadata.target_systems,
                "confidence": metadata.confidence,
                "reasoning": metadata.reasoning
            }
        
        return ClassificationResult(
            threat_type=llm_result.threat_type,
            method="llm",
            confidence=keyword_result.confidence_level.value,
            score=keyword_result.score,
            metadata=base_metadata
        )
    
    def _build_fallback_result(
        self,
        keyword_result: KeywordResult,
        error: str
    ) -> ClassificationResult:
        """
        Build result when LLM fails but keyword result is available.
        
        Args:
            keyword_result: Result from keyword matching
            error: Error message from LLM failure
            
        Returns:
            ClassificationResult with method="keyword_fallback"
        """
        metadata = {
            "keyword_matches": keyword_result.matches_by_type,
            "keyword_result": keyword_result.threat_type,
            "keyword_score": keyword_result.score,
            "method": "keyword_fallback",
            "confidence": keyword_result.confidence_level.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "llm_error": error,
            "fallback_used": True
        }
        
        return ClassificationResult(
            threat_type=keyword_result.threat_type or "unknown",
            method="keyword_fallback",
            confidence=keyword_result.confidence_level.value,
            score=keyword_result.score,
            metadata=metadata
        )
    
    def _build_failed_result(self, error: str) -> ClassificationResult:
        """
        Build result when all classification methods fail.
        
        Args:
            error: Error message from LLM failure
            
        Returns:
            ClassificationResult with method="failed" and threat_type="unknown"
        """
        metadata = {
            "method": "failed",
            "confidence": "none",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "llm_error": error,
            "fallback_used": False
        }
        
        return ClassificationResult(
            threat_type="unknown",
            method="failed",
            confidence="none",
            score=0,
            metadata=metadata
        )
    
    async def _persist_classification(
        self,
        threat: Threat,
        result: ClassificationResult,
        db: AsyncSession
    ) -> None:
        """
        Persist classification result to database.
        
        Updates the threat record with classification fields and commits
        the transaction. Handles database errors with retry logic.
        
        Args:
            threat: Threat object to update
            result: ClassificationResult to persist
            db: Database session
            
        Raises:
            Exception: If database update fails after retries
        """
        try:
            # Update threat fields
            threat.threat_type = result.threat_type
            threat.classification_method = result.method
            threat.classification_confidence = result.confidence
            threat.classification_score = result.score
            threat.classification_metadata = result.metadata
            
            # Commit to database
            await db.commit()
            await db.refresh(threat)
            
            logger.info(f"Persisted classification for threat {threat.id}")
            
        except Exception as e:
            logger.error(f"Failed to persist classification: {e}")
            await db.rollback()
            raise
