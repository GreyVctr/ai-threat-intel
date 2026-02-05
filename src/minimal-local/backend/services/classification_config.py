"""
Configuration for the hybrid threat classification system.

This module provides configuration settings for the classification service,
including confidence thresholds, LLM settings, and keyword lists.
"""
import os
from typing import Dict, List


class ClassificationConfig:
    """
    Configuration for classification service.
    
    This class centralizes all configuration settings for the hybrid threat
    classification system. Settings can be overridden via environment variables.
    
    Attributes:
        HIGH_CONFIDENCE_THRESHOLD: Minimum keyword matches for high confidence (≥5)
        MEDIUM_CONFIDENCE_THRESHOLD: Minimum keyword matches for medium confidence (≥2)
        OLLAMA_URL: Ollama API URL (from OLLAMA_URL env var)
        OLLAMA_MODEL: Ollama model name (from OLLAMA_MODEL env var)
        OLLAMA_TIMEOUT: Request timeout in seconds (from OLLAMA_TIMEOUT env var)
        KEYWORDS: Keyword lists for each threat type
    """
    
    # Confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD: int = int(os.getenv("CLASSIFICATION_HIGH_THRESHOLD", "5"))
    MEDIUM_CONFIDENCE_THRESHOLD: int = int(os.getenv("CLASSIFICATION_MEDIUM_THRESHOLD", "2"))
    
    # LLM settings - reuse existing Ollama configuration from .env.minimal
    # Note: Uses OLLAMA_URL (not OLLAMA_BASE_URL) to match existing environment variable
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "30"))
    
    # Keyword lists for threat classification
    # These can be extended or customized based on domain knowledge
    KEYWORDS: Dict[str, List[str]] = {
        "adversarial": [
            "adversarial", "perturbation", "evasion", "attack", "adversary",
            "fgsm", "pgd", "carlini", "wagner", "deepfool", "foolbox",
            "adversarial example", "adversarial attack", "adversarial robustness",
            "adversarial training", "adversarial noise", "adversarial perturbation"
        ],
        "extraction": [
            "extract", "steal", "exfiltrate", "leak", "extraction",
            "model extraction", "model stealing", "model theft",
            "knowledge distillation", "membership inference", "model inversion",
            "extract model", "steal model", "query attack", "api attack",
            "black-box extraction"
        ],
        "poisoning": [
            "poison", "contaminate", "corrupt", "backdoor", "poisoning",
            "data poisoning", "trojan", "trigger", "contamination",
            "training data attack", "label flipping", "backdoor attack",
            "trojan attack", "clean-label attack", "federated learning attack"
        ],
        "prompt_injection": [
            "injection", "jailbreak", "prompt", "manipulate",
            "prompt injection", "prompt manipulation", "llm attack",
            "prompt engineering attack", "instruction injection",
            "system prompt", "prompt leaking", "indirect prompt injection"
        ],
        "privacy": [
            "privacy", "pii", "personal", "gdpr", "confidential",
            "differential privacy", "membership inference", "model inversion",
            "data leakage", "information leakage", "privacy attack",
            "reconstruction attack", "attribute inference", "property inference"
        ],
        "fairness": [
            "fairness", "bias", "discrimination", "equity", "unfair",
            "disparate impact", "demographic parity", "equalized odds",
            "fairness attack", "bias amplification", "algorithmic bias"
        ],
        "robustness": [
            "robustness", "robust", "stability", "reliability", "resilience",
            "certified defense", "provable defense", "randomized smoothing",
            "adversarial training", "defensive distillation",
            "input transformation"
        ],
        "supply_chain": [
            "supply", "dependency", "third-party", "vendor", "chain",
            "supply chain", "model zoo", "pretrained model",
            "transfer learning attack", "model repository", "hugging face",
            "pytorch hub", "tensorflow hub", "malicious model",
            "compromised model"
        ]
    }
    
    @classmethod
    def validate(cls) -> List[str]:
        """
        Validate configuration settings.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate thresholds
        if cls.HIGH_CONFIDENCE_THRESHOLD < cls.MEDIUM_CONFIDENCE_THRESHOLD:
            errors.append(
                f"HIGH_CONFIDENCE_THRESHOLD ({cls.HIGH_CONFIDENCE_THRESHOLD}) must be "
                f">= MEDIUM_CONFIDENCE_THRESHOLD ({cls.MEDIUM_CONFIDENCE_THRESHOLD})"
            )
        
        if cls.MEDIUM_CONFIDENCE_THRESHOLD < 0:
            errors.append(
                f"MEDIUM_CONFIDENCE_THRESHOLD ({cls.MEDIUM_CONFIDENCE_THRESHOLD}) "
                f"must be >= 0"
            )
        
        # Validate LLM settings
        if not cls.OLLAMA_URL:
            errors.append("OLLAMA_URL is required")
        
        if not cls.OLLAMA_MODEL:
            errors.append("OLLAMA_MODEL is required")
        
        if cls.OLLAMA_TIMEOUT <= 0:
            errors.append(
                f"OLLAMA_TIMEOUT ({cls.OLLAMA_TIMEOUT}) must be > 0"
            )
        
        # Validate keyword lists
        if not cls.KEYWORDS:
            errors.append("KEYWORDS dictionary is empty")
        
        for threat_type, keywords in cls.KEYWORDS.items():
            if not keywords:
                errors.append(f"Keyword list for '{threat_type}' is empty")
            if not isinstance(keywords, list):
                errors.append(f"Keyword list for '{threat_type}' must be a list")
        
        return errors
    
    @classmethod
    def get_summary(cls) -> Dict[str, any]:
        """
        Get a summary of current configuration.
        
        Returns:
            Dictionary with configuration summary
        """
        return {
            "thresholds": {
                "high": cls.HIGH_CONFIDENCE_THRESHOLD,
                "medium": cls.MEDIUM_CONFIDENCE_THRESHOLD
            },
            "llm": {
                "url": cls.OLLAMA_URL,
                "model": cls.OLLAMA_MODEL,
                "timeout": cls.OLLAMA_TIMEOUT
            },
            "threat_types": list(cls.KEYWORDS.keys()),
            "total_keywords": sum(len(kw) for kw in cls.KEYWORDS.values())
        }


# Validate configuration on import
_validation_errors = ClassificationConfig.validate()
if _validation_errors:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(
        f"Classification configuration validation warnings:\n" +
        "\n".join(f"  - {error}" for error in _validation_errors)
    )
