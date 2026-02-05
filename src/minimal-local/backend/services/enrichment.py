"""
Enrichment service for AI/ML threat intelligence.

Provides NLP-based classification, entity extraction, MITRE ATLAS mapping,
and severity scoring for threat data.
"""
import re
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from models.threat import Threat
from models.entity import Entity
from models.mitre import MitreMapping
from services.classification_service import ClassificationService

logger = logging.getLogger(__name__)


# Threat type classification keywords
THREAT_TYPE_KEYWORDS = {
    "adversarial": [
        "adversarial", "perturbation", "evasion", "fgsm", "pgd", "carlini",
        "wagner", "deepfool", "foolbox", "adversarial example", "adversarial attack",
        "adversarial robustness", "adversarial training", "adversarial noise"
    ],
    "extraction": [
        "model extraction", "model stealing", "model theft", "knowledge distillation",
        "membership inference", "model inversion", "extract model", "steal model",
        "query attack", "api attack", "black-box extraction"
    ],
    "poisoning": [
        "data poisoning", "backdoor", "trojan", "trigger", "poison", "contamination",
        "training data attack", "label flipping", "backdoor attack", "trojan attack",
        "clean-label attack", "federated learning attack"
    ],
    "prompt_injection": [
        "prompt injection", "jailbreak", "prompt manipulation", "llm attack",
        "prompt engineering attack", "instruction injection", "system prompt",
        "prompt leaking", "indirect prompt injection"
    ],
    "privacy": [
        "privacy", "differential privacy", "membership inference", "model inversion",
        "data leakage", "information leakage", "privacy attack", "reconstruction attack",
        "attribute inference", "property inference"
    ],
    "fairness": [
        "fairness", "bias", "discrimination", "disparate impact", "demographic parity",
        "equalized odds", "fairness attack", "bias amplification", "algorithmic bias"
    ],
    "robustness": [
        "robustness", "certified defense", "provable defense", "randomized smoothing",
        "adversarial training", "defensive distillation", "input transformation"
    ],
    "supply_chain": [
        "supply chain", "model zoo", "pretrained model", "transfer learning attack",
        "model repository", "hugging face", "pytorch hub", "tensorflow hub",
        "malicious model", "compromised model"
    ],
}


# CVE pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


# Framework patterns
FRAMEWORK_PATTERNS = {
    "tensorflow": re.compile(r'\btensorflow\b', re.IGNORECASE),
    "pytorch": re.compile(r'\bpytorch\b|\btorch\b', re.IGNORECASE),
    "keras": re.compile(r'\bkeras\b', re.IGNORECASE),
    "scikit-learn": re.compile(r'\bscikit-learn\b|\bsklearn\b', re.IGNORECASE),
    "jax": re.compile(r'\bjax\b', re.IGNORECASE),
    "mxnet": re.compile(r'\bmxnet\b', re.IGNORECASE),
    "caffe": re.compile(r'\bcaffe\b', re.IGNORECASE),
    "onnx": re.compile(r'\bonnx\b', re.IGNORECASE),
    "huggingface": re.compile(r'\bhugging\s*face\b|\btransformers\b', re.IGNORECASE),
    "langchain": re.compile(r'\blangchain\b', re.IGNORECASE),
    "llama": re.compile(r'\bllama\b', re.IGNORECASE),
    "openai": re.compile(r'\bopenai\b|\bgpt-\d+\b', re.IGNORECASE),
}


# MITRE ATLAS taxonomy (simplified version)
MITRE_ATLAS_MAPPINGS = {
    "adversarial": [
        {
            "tactic": "ML Attack Staging",
            "technique": "Craft Adversarial Data",
            "technique_id": "AML.T0043",
        },
        {
            "tactic": "ML Model Access",
            "technique": "Evade ML Model",
            "technique_id": "AML.T0015",
        },
    ],
    "extraction": [
        {
            "tactic": "ML Model Access",
            "technique": "ML Model Inference API Access",
            "technique_id": "AML.T0040",
        },
        {
            "tactic": "Exfiltration",
            "technique": "Exfiltrate ML Model",
            "technique_id": "AML.T0024",
        },
    ],
    "poisoning": [
        {
            "tactic": "ML Attack Staging",
            "technique": "Poison Training Data",
            "technique_id": "AML.T0020",
        },
        {
            "tactic": "Persistence",
            "technique": "Backdoor ML Model",
            "technique_id": "AML.T0018",
        },
    ],
    "prompt_injection": [
        {
            "tactic": "Initial Access",
            "technique": "LLM Prompt Injection",
            "technique_id": "AML.T0051",
        },
        {
            "tactic": "ML Model Access",
            "technique": "Evade ML Model",
            "technique_id": "AML.T0015",
        },
    ],
    "privacy": [
        {
            "tactic": "Collection",
            "technique": "Infer Training Data Membership",
            "technique_id": "AML.T0033",
        },
        {
            "tactic": "Collection",
            "technique": "Invert ML Model",
            "technique_id": "AML.T0034",
        },
    ],
    "supply_chain": [
        {
            "tactic": "Initial Access",
            "technique": "Supply Chain Compromise",
            "technique_id": "AML.T0010",
        },
        {
            "tactic": "ML Model Access",
            "technique": "Obtain Capabilities",
            "technique_id": "AML.T0002",
        },
    ],
}


class EnrichmentService:
    """
    Service for enriching threat intelligence data.
    
    Provides:
    - Threat type classification using hybrid keyword + LLM approach
    - Entity extraction (CVEs, frameworks, techniques)
    - MITRE ATLAS mapping
    - Severity scoring
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize enrichment service.
        
        Args:
            db_session: Database session for storing enrichment data
        """
        self.db = db_session
        # Initialize the hybrid classification service
        self.classification_service = ClassificationService(
            keyword_config=THREAT_TYPE_KEYWORDS
        )
    
    async def classify_threat_type(self, content: str) -> Optional[str]:
        """
        Classify threat type using keyword matching.
        
        DEPRECATED: This method is preserved for backward compatibility and fallback.
        New code should use ClassificationService directly via enrich_threat().
        
        Args:
            content: Threat content (title + description + content)
        
        Returns:
            Threat type string or None if no match
        """
        if not content:
            return None
        
        content_lower = content.lower()
        
        # Count keyword matches for each threat type
        scores = {}
        for threat_type, keywords in THREAT_TYPE_KEYWORDS.items():
            score = sum(1 for keyword in keywords if keyword in content_lower)
            if score > 0:
                scores[threat_type] = score
        
        # Return threat type with highest score
        if scores:
            best_type = max(scores.items(), key=lambda x: x[1])
            logger.info(f"Classified threat type: {best_type[0]} (score: {best_type[1]})")
            return best_type[0]
        
        logger.warning("No threat type classification found")
        return None
    
    async def extract_cves(self, content: str) -> List[str]:
        """
        Extract CVE IDs from content.
        
        Args:
            content: Threat content
        
        Returns:
            List of CVE IDs
        """
        if not content:
            return []
        
        cves = CVE_PATTERN.findall(content)
        # Normalize to uppercase
        cves = [cve.upper() for cve in cves]
        # Remove duplicates while preserving order
        seen = set()
        unique_cves = []
        for cve in cves:
            if cve not in seen:
                seen.add(cve)
                unique_cves.append(cve)
        
        if unique_cves:
            logger.info(f"Extracted CVEs: {unique_cves}")
        
        return unique_cves
    
    async def extract_frameworks(self, content: str) -> List[str]:
        """
        Extract AI/ML framework names from content.
        
        Args:
            content: Threat content
        
        Returns:
            List of framework names
        """
        if not content:
            return []
        
        frameworks = []
        for framework_name, pattern in FRAMEWORK_PATTERNS.items():
            if pattern.search(content):
                frameworks.append(framework_name)
        
        if frameworks:
            logger.info(f"Extracted frameworks: {frameworks}")
        
        return frameworks
    
    async def extract_entities(self, threat_id: str, content: str) -> List[Entity]:
        """
        Extract all entities from threat content.
        
        Args:
            threat_id: Threat UUID
            content: Threat content
        
        Returns:
            List of Entity objects
        """
        entities = []
        
        # Extract CVEs
        cves = await self.extract_cves(content)
        for cve in cves:
            entity = Entity(
                threat_id=threat_id,
                entity_type="cve",
                entity_value=cve,
                confidence="1.0",  # High confidence for regex matches
            )
            entities.append(entity)
        
        # Extract frameworks
        frameworks = await self.extract_frameworks(content)
        for framework in frameworks:
            entity = Entity(
                threat_id=threat_id,
                entity_type="framework",
                entity_value=framework,
                confidence="0.9",  # High confidence for regex matches
            )
            entities.append(entity)
        
        logger.info(f"Extracted {len(entities)} entities for threat {threat_id}")
        return entities
    
    async def map_to_mitre_atlas(self, threat_id: str, threat_type: Optional[str]) -> List[MitreMapping]:
        """
        Map threat to MITRE ATLAS tactics and techniques.
        
        Args:
            threat_id: Threat UUID
            threat_type: Classified threat type
        
        Returns:
            List of MitreMapping objects
        """
        if not threat_type or threat_type not in MITRE_ATLAS_MAPPINGS:
            logger.warning(f"No MITRE ATLAS mapping for threat type: {threat_type}")
            return []
        
        mappings = []
        for mapping_data in MITRE_ATLAS_MAPPINGS[threat_type]:
            mapping = MitreMapping(
                threat_id=threat_id,
                tactic=mapping_data["tactic"],
                technique=mapping_data["technique"],
                technique_id=mapping_data["technique_id"],
                confidence="0.8",  # Moderate confidence for keyword-based mapping
            )
            mappings.append(mapping)
        
        logger.info(f"Created {len(mappings)} MITRE ATLAS mappings for threat {threat_id}")
        return mappings
    
    async def calculate_severity(self, threat_type: Optional[str], has_cve: bool, has_poc: bool) -> int:
        """
        Calculate severity score (1-10) based on threat characteristics.
        
        Args:
            threat_type: Classified threat type
            has_cve: Whether threat has associated CVE
            has_poc: Whether proof-of-concept is available (detected by keywords)
        
        Returns:
            Severity score (1-10)
        """
        # Base severity by threat type
        base_severity = {
            "adversarial": 7,
            "extraction": 8,
            "poisoning": 9,
            "prompt_injection": 6,
            "privacy": 7,
            "fairness": 5,
            "robustness": 4,
            "supply_chain": 9,
        }
        
        severity = base_severity.get(threat_type, 5)
        
        # Increase severity if CVE exists
        if has_cve:
            severity = min(10, severity + 1)
        
        # Increase severity if PoC is available
        if has_poc:
            severity = min(10, severity + 1)
        
        logger.info(f"Calculated severity: {severity} (type={threat_type}, cve={has_cve}, poc={has_poc})")
        return severity
    
    async def detect_poc_availability(self, content: str) -> bool:
        """
        Detect if proof-of-concept code is available.
        
        Args:
            content: Threat content
        
        Returns:
            True if PoC indicators found
        """
        if not content:
            return False
        
        poc_keywords = [
            "proof of concept", "poc", "proof-of-concept",
            "github.com", "code available", "implementation",
            "exploit code", "attack code", "demo code"
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in poc_keywords)
    
    async def enrich_threat(self, threat_id: str) -> Dict[str, any]:
        """
        Perform complete enrichment on a threat.
        
        Args:
            threat_id: Threat UUID
        
        Returns:
            Dictionary with enrichment results and any errors
        """
        logger.info(f"Starting enrichment for threat {threat_id}")
        
        # Fetch threat from database
        result = await self.db.execute(
            select(Threat).where(Threat.id == threat_id)
        )
        threat = result.scalar_one_or_none()
        
        if not threat:
            logger.error(f"Threat {threat_id} not found")
            return {"success": False, "error": "Threat not found"}
        
        # Combine content for analysis
        content = " ".join(filter(None, [
            threat.title or "",
            threat.description or "",
            threat.content or ""
        ]))
        
        errors = []
        
        # 1. Classify threat type using hybrid classification service
        try:
            classification_result = await self.classification_service.classify_threat(
                threat, self.db
            )
            # The classification service already updates the threat object and persists to DB
            logger.info(
                f"Hybrid classification complete: type={classification_result.threat_type}, "
                f"method={classification_result.method}, confidence={classification_result.confidence}"
            )
        except Exception as e:
            logger.error(f"Hybrid classification failed: {e}")
            errors.append(f"Hybrid classification failed: {str(e)}")
            
            # Fallback to old keyword-only classification
            try:
                logger.warning("Falling back to legacy keyword classification")
                threat_type = await self.classify_threat_type(content)
                threat.threat_type = threat_type
                # Mark as fallback in metadata
                threat.classification_method = "legacy_fallback"
                threat.classification_confidence = "unknown"
                threat.classification_metadata = {
                    "method": "legacy_fallback",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as fallback_error:
                logger.error(f"Fallback classification also failed: {fallback_error}")
                errors.append(f"Fallback classification failed: {str(fallback_error)}")
        
        # 2. Extract entities
        try:
            entities = await self.extract_entities(str(threat.id), content)
            
            # Clear existing entities for idempotency (only after successful extraction)
            delete_entities = delete(Entity).where(Entity.threat_id == threat.id)
            await self.db.execute(delete_entities)
            
            # Add new entities to database
            for entity in entities:
                self.db.add(entity)
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            errors.append(f"Entity extraction failed: {str(e)}")
            # Don't delete existing entities if extraction failed
        
        # 3. Map to MITRE ATLAS
        try:
            mappings = await self.map_to_mitre_atlas(str(threat.id), threat.threat_type)
            
            # Clear existing MITRE mappings for idempotency (only after successful mapping)
            delete_mappings = delete(MitreMapping).where(MitreMapping.threat_id == threat.id)
            await self.db.execute(delete_mappings)
            
            # Add new mappings to database
            for mapping in mappings:
                self.db.add(mapping)
        except Exception as e:
            logger.error(f"MITRE mapping failed: {e}")
            errors.append(f"MITRE mapping failed: {str(e)}")
            # Don't delete existing mappings if mapping failed
        
        # 4. Calculate severity
        try:
            has_cve = len(await self.extract_cves(content)) > 0
            has_poc = await self.detect_poc_availability(content)
            severity = await self.calculate_severity(threat.threat_type, has_cve, has_poc)
            threat.severity = severity
            
            # Calculate exploitability score (simplified)
            if has_poc and has_cve:
                threat.exploitability_score = "0.9"
            elif has_poc or has_cve:
                threat.exploitability_score = "0.7"
            else:
                threat.exploitability_score = "0.5"
        except Exception as e:
            logger.error(f"Severity scoring failed: {e}")
            errors.append(f"Severity scoring failed: {str(e)}")
        
        # Update enrichment status
        if errors:
            threat.enrichment_status = "partial"
            threat.enrichment_errors = errors
        else:
            threat.enrichment_status = "complete"
            threat.enrichment_errors = None
        
        # Commit changes
        try:
            await self.db.commit()
            logger.info(f"Enrichment completed for threat {threat_id} (status: {threat.enrichment_status})")
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to commit enrichment: {e}")
            return {"success": False, "error": f"Database commit failed: {str(e)}"}
        
        return {
            "success": True,
            "threat_id": str(threat_id),
            "threat_type": threat.threat_type,
            "classification_method": threat.classification_method,
            "classification_confidence": threat.classification_confidence,
            "severity": threat.severity,
            "entities_count": len(entities) if 'entities' in locals() else 0,
            "mappings_count": len(mappings) if 'mappings' in locals() else 0,
            "errors": errors if errors else None,
        }
