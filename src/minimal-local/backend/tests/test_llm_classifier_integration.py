"""
Integration tests for LLM classifier with real Ollama service.

These tests require a running Ollama service and should be run separately
from unit tests. They verify end-to-end functionality with the actual LLM.

Run with: pytest tests/test_llm_classifier_integration.py -v
Skip with: pytest -m "not integration"
"""
import pytest
import httpx
from config import settings
from services.llm_classifier import LLMClassifier


# Valid threat types for testing
VALID_TYPES = [
    "adversarial",
    "extraction",
    "poisoning",
    "prompt_injection",
    "privacy",
    "fairness",
    "robustness",
    "supply_chain",
    "unknown"
]


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture
async def ollama_available():
    """Check if Ollama service is available."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.ollama_url}/api/tags")
            return response.status_code == 200
    except Exception:
        return False


@pytest.fixture
async def llm_classifier():
    """Create LLM classifier instance for integration testing."""
    classifier = LLMClassifier()
    yield classifier
    await classifier.close()


async def check_ollama():
    """Helper to check Ollama availability."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.ollama_url}/api/tags")
            return response.status_code == 200
    except Exception:
        return False


class TestLLMClassifierIntegration:
    """Integration tests with real Ollama service."""
    
    @pytest.mark.asyncio
    async def test_ollama_service_available(self):
        """Test that Ollama service is available."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        assert available is True
    
    @pytest.mark.asyncio
    async def test_classify_adversarial_threat(self):
        """Test classification of adversarial threat."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            An attacker crafts adversarial examples by adding imperceptible 
            perturbations to input images, causing the ML model to misclassify 
            them with high confidence. This evasion attack exploits the model's 
            vulnerability to small input changes.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            assert result.raw_response
            assert result.error is None
            
            # Adversarial is the most likely classification
            assert result.threat_type == "adversarial"
    
    @pytest.mark.asyncio
    async def test_classify_poisoning_threat(self):
        """Test classification of poisoning threat."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            An attacker injects malicious data into the training dataset, 
            causing the model to learn backdoor behaviors. When specific 
            trigger patterns are present in inputs, the poisoned model 
            produces attacker-controlled outputs.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Poisoning is the most likely classification
            assert result.threat_type == "poisoning"
    
    @pytest.mark.asyncio
    async def test_classify_extraction_threat(self):
        """Test classification of extraction threat."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            An attacker queries the ML model repeatedly with carefully crafted 
            inputs to extract information about the training data or model 
            parameters. This model stealing attack allows the adversary to 
            replicate the model's functionality.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Extraction is the most likely classification
            assert result.threat_type == "extraction"
    
    @pytest.mark.asyncio
    async def test_classify_prompt_injection(self):
        """Test classification of prompt injection threat."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            An attacker crafts malicious prompts that override the LLM's 
            system instructions, causing it to ignore safety guidelines and 
            produce harmful outputs. This jailbreak technique exploits the 
            model's instruction-following behavior.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Prompt injection is the most likely classification
            assert result.threat_type == "prompt_injection"
    
    @pytest.mark.asyncio
    async def test_classify_privacy_threat(self):
        """Test classification of privacy threat."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            The ML model inadvertently memorizes and leaks sensitive personal 
            information from its training data. Attackers can extract PII, 
            medical records, or other confidential data through carefully 
            designed queries, violating GDPR and privacy regulations.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Privacy is the most likely classification
            assert result.threat_type == "privacy"
    
    @pytest.mark.asyncio
    async def test_classify_with_keyword_context(self):
        """Test classification with keyword context."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "Model shows different accuracy for different demographic groups"
            context = "keyword analysis suggests: fairness (2 matches)"
            
            result = await llm_classifier.classify(description, VALID_TYPES, context)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Should classify as fairness
            assert result.threat_type == "fairness"
    
    @pytest.mark.asyncio
    async def test_classify_ambiguous_threat(self):
        """Test classification of ambiguous threat description."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "The ML system has security vulnerabilities"
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Should return some valid classification, even if generic
            assert result.threat_type is not None
    
    @pytest.mark.asyncio
    async def test_classify_short_description(self):
        """Test classification with minimal description."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "Backdoor attack"
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
    
    @pytest.mark.asyncio
    async def test_classify_technical_description(self):
        """Test classification with technical jargon."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = """
            Gradient-based optimization attack using FGSM to generate 
            adversarial perturbations in the L-infinity norm ball, 
            maximizing the loss function to cause misclassification.
            """
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result.success is True
            assert result.threat_type in VALID_TYPES
            # Should recognize as adversarial despite technical language
            assert result.threat_type == "adversarial"
    
    @pytest.mark.asyncio
    async def test_multiple_classifications(self):
        """Test multiple sequential classifications."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            descriptions = [
                "Adversarial attack using perturbations",
                "Data poisoning in training set",
                "Model extraction through queries"
            ]
            
            expected_types = ["adversarial", "poisoning", "extraction"]
            
            for description, expected in zip(descriptions, expected_types):
                result = await llm_classifier.classify(description, VALID_TYPES)
                assert result.success is True
                assert result.threat_type == expected
    
    @pytest.mark.asyncio
    async def test_response_format(self):
        """Test that response format is consistent."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "Test threat description"
            
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            # Verify result structure
            assert hasattr(result, 'threat_type')
            assert hasattr(result, 'raw_response')
            assert hasattr(result, 'success')
            assert hasattr(result, 'error')
            
            # Verify types
            assert isinstance(result.threat_type, str)
            assert isinstance(result.raw_response, str)
            assert isinstance(result.success, bool)
            assert result.error is None or isinstance(result.error, str)


class TestLLMClassifierErrorHandling:
    """Integration tests for error handling."""
    
    @pytest.mark.asyncio
    async def test_invalid_model_name(self):
        """Test handling of invalid model name."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier(model="nonexistent-model-xyz") as classifier:
            description = "Test threat"
            result = await classifier.classify(description, VALID_TYPES)
            
            # Should handle gracefully
            assert result.success is False
            assert result.threat_type == "unknown"
            assert result.error is not None
    
    @pytest.mark.asyncio
    async def test_invalid_ollama_url(self):
        """Test handling of invalid Ollama URL."""
        async with LLMClassifier(
            ollama_url="http://nonexistent-host:11434",
            timeout=5
        ) as classifier:
            description = "Test threat"
            
            with pytest.raises(ConnectionError):
                await classifier.classify(description, VALID_TYPES)
    
    @pytest.mark.asyncio
    async def test_empty_valid_types(self):
        """Test classification with empty valid types list."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "Test threat"
            
            # Should still work but return unknown
            result = await llm_classifier.classify(description, [])
            
            # The LLM will respond, but parsing will fail
            assert result.threat_type == "unknown"


class TestLLMClassifierPerformance:
    """Integration tests for performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_classification_completes_within_timeout(self):
        """Test that classification completes within timeout."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        async with LLMClassifier() as llm_classifier:
            description = "Test threat description"
            
            # Should complete without timeout error
            result = await llm_classifier.classify(description, VALID_TYPES)
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_concurrent_classifications(self):
        """Test multiple concurrent classifications."""
        available = await check_ollama()
        if not available:
            pytest.skip("Ollama service not available")
        
        import asyncio
        
        async with LLMClassifier() as classifier:
            descriptions = [
                "Adversarial attack",
                "Data poisoning",
                "Model extraction"
            ] * 3  # 9 concurrent requests
            
            # Run classifications concurrently
            tasks = [
                classifier.classify(desc, VALID_TYPES)
                for desc in descriptions
            ]
            
            results = await asyncio.gather(*tasks)
            
            # All should succeed
            assert len(results) == 9
            assert all(r.success for r in results)
            assert all(r.threat_type in VALID_TYPES for r in results)
