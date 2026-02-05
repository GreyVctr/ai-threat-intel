"""
Unit tests for LLM classifier with mocked Ollama responses.

Tests the LLMClassifier class with various mocked responses to verify
prompt construction, response parsing, and error handling without requiring
a real Ollama service.
"""
import pytest
from unittest.mock import AsyncMock, Mock, patch
import httpx

from services.llm_classifier import LLMClassifier
from services.classification_types import LLMResult


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


@pytest.fixture
def llm_classifier():
    """Create LLM classifier instance for testing."""
    return LLMClassifier(
        ollama_url="http://test-ollama:11434",
        model="test-model",
        timeout=30
    )


@pytest.fixture
def mock_httpx_client():
    """Create mock httpx client."""
    with patch('services.llm_classifier.httpx.AsyncClient') as mock_client:
        yield mock_client


class TestLLMClassifierInit:
    """Test LLMClassifier initialization."""
    
    def test_init_with_defaults(self):
        """Test initialization with default settings."""
        classifier = LLMClassifier()
        assert classifier.ollama_url
        assert classifier.model
        assert classifier.timeout > 0
        assert classifier.client is not None
    
    def test_init_with_custom_values(self):
        """Test initialization with custom values."""
        classifier = LLMClassifier(
            ollama_url="http://custom:11434",
            model="custom-model",
            timeout=60
        )
        assert classifier.ollama_url == "http://custom:11434"
        assert classifier.model == "custom-model"
        assert classifier.timeout == 60
    
    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from URL."""
        classifier = LLMClassifier(ollama_url="http://test:11434/")
        assert classifier.ollama_url == "http://test:11434"


class TestBuildPrompt:
    """Test prompt construction."""
    
    def test_build_prompt_without_context(self, llm_classifier):
        """Test prompt building without keyword context."""
        description = "Test threat description"
        prompt = llm_classifier._build_prompt(description, VALID_TYPES, None)
        
        assert "threat classification expert" in prompt.lower()
        assert description in prompt
        assert all(t in prompt for t in VALID_TYPES)
        assert "Category:" in prompt
    
    def test_build_prompt_with_context(self, llm_classifier):
        """Test prompt building with keyword context."""
        description = "Test threat description"
        context = "keyword analysis suggests: adversarial"
        prompt = llm_classifier._build_prompt(description, VALID_TYPES, context)
        
        assert description in prompt
        assert context in prompt
        assert "Keyword Analysis Context:" in prompt
    
    def test_build_prompt_includes_all_valid_types(self, llm_classifier):
        """Test that prompt includes all valid threat types."""
        description = "Test threat"
        prompt = llm_classifier._build_prompt(description, VALID_TYPES, None)
        
        for threat_type in VALID_TYPES:
            assert threat_type in prompt


class TestParseResponse:
    """Test response parsing."""
    
    def test_parse_exact_match(self, llm_classifier):
        """Test parsing exact threat type match."""
        result = llm_classifier._parse_response("adversarial", VALID_TYPES)
        assert result == "adversarial"
    
    def test_parse_case_insensitive(self, llm_classifier):
        """Test parsing with different case."""
        result = llm_classifier._parse_response("ADVERSARIAL", VALID_TYPES)
        assert result == "adversarial"
    
    def test_parse_with_prefix(self, llm_classifier):
        """Test parsing with common prefixes."""
        test_cases = [
            "Category: adversarial",
            "Classification: poisoning",
            "Answer: extraction",
            "Result: privacy"
        ]
        
        expected = ["adversarial", "poisoning", "extraction", "privacy"]
        
        for response, expected_type in zip(test_cases, expected):
            result = llm_classifier._parse_response(response, VALID_TYPES)
            assert result == expected_type
    
    def test_parse_with_extra_text(self, llm_classifier):
        """Test parsing when threat type is embedded in text."""
        response = "Based on the description, this is clearly an adversarial attack."
        result = llm_classifier._parse_response(response, VALID_TYPES)
        assert result == "adversarial"
    
    def test_parse_first_word(self, llm_classifier):
        """Test parsing extracts first word if it's valid."""
        response = "poisoning attack on the model"
        result = llm_classifier._parse_response(response, VALID_TYPES)
        assert result == "poisoning"
    
    def test_parse_invalid_response(self, llm_classifier):
        """Test parsing returns unknown for invalid response."""
        result = llm_classifier._parse_response("invalid_type", VALID_TYPES)
        assert result == "unknown"
    
    def test_parse_empty_response(self, llm_classifier):
        """Test parsing empty response."""
        result = llm_classifier._parse_response("", VALID_TYPES)
        assert result == "unknown"
    
    def test_parse_whitespace_response(self, llm_classifier):
        """Test parsing whitespace-only response."""
        result = llm_classifier._parse_response("   \n\t  ", VALID_TYPES)
        assert result == "unknown"


class TestClassifySuccess:
    """Test successful classification scenarios."""
    
    @pytest.mark.asyncio
    async def test_classify_success(self, llm_classifier):
        """Test successful classification."""
        description = "Adversarial attack using evasion techniques"
        
        # Mock the HTTP client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "adversarial",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert isinstance(result, LLMResult)
        assert result.success is True
        assert result.threat_type == "adversarial"
        assert result.raw_response == "adversarial"
        assert result.error is None
    
    @pytest.mark.asyncio
    async def test_classify_with_context(self, llm_classifier):
        """Test classification with keyword context."""
        description = "Test threat"
        context = "keyword analysis suggests: poisoning"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "poisoning",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES, context)
        
        assert result.success is True
        assert result.threat_type == "poisoning"
    
    @pytest.mark.asyncio
    async def test_classify_parses_complex_response(self, llm_classifier):
        """Test classification with complex LLM response."""
        description = "Test threat"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "Category: extraction\n\nThis appears to be a model extraction attack.",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is True
        assert result.threat_type == "extraction"


class TestClassifyErrors:
    """Test error handling in classification."""
    
    @pytest.mark.asyncio
    async def test_classify_model_not_found(self, llm_classifier):
        """Test handling of model not found error."""
        description = "Test threat"
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Model not found"
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is False
        assert result.threat_type == "unknown"
        assert "not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_classify_http_error(self, llm_classifier):
        """Test handling of HTTP error status."""
        description = "Test threat"
        
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is False
        assert result.threat_type == "unknown"
        assert "500" in result.error
    
    @pytest.mark.asyncio
    async def test_classify_invalid_response_structure(self, llm_classifier):
        """Test handling of invalid response structure."""
        description = "Test threat"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "invalid": "structure"
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is False
        assert result.threat_type == "unknown"
        assert "missing 'response' field" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_classify_invalid_threat_type(self, llm_classifier):
        """Test handling of invalid threat type in response."""
        description = "Test threat"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "invalid_threat_type",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is False
        assert result.threat_type == "unknown"
        assert "invalid" in result.error.lower() and "unparseable" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_classify_connection_error(self, llm_classifier):
        """Test handling of connection error."""
        description = "Test threat"
        
        llm_classifier.client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        
        with pytest.raises(ConnectionError) as exc_info:
            await llm_classifier.classify(description, VALID_TYPES)
        
        assert "Failed to connect" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_classify_timeout_error(self, llm_classifier):
        """Test handling of timeout error."""
        description = "Test threat"
        
        llm_classifier.client.post = AsyncMock(
            side_effect=httpx.TimeoutException("Request timeout")
        )
        
        with pytest.raises(TimeoutError) as exc_info:
            await llm_classifier.classify(description, VALID_TYPES)
        
        assert "timed out" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_classify_http_exception(self, llm_classifier):
        """Test handling of general HTTP exception."""
        description = "Test threat"
        
        llm_classifier.client.post = AsyncMock(
            side_effect=httpx.HTTPError("HTTP error")
        )
        
        with pytest.raises(ConnectionError) as exc_info:
            await llm_classifier.classify(description, VALID_TYPES)
        
        assert "HTTP error" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_classify_unexpected_exception(self, llm_classifier):
        """Test handling of unexpected exception."""
        description = "Test threat"
        
        llm_classifier.client.post = AsyncMock(
            side_effect=ValueError("Unexpected error")
        )
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is False
        assert result.threat_type == "unknown"
        assert "Unexpected error" in result.error


class TestContextManager:
    """Test async context manager functionality."""
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test using classifier as async context manager."""
        async with LLMClassifier(
            ollama_url="http://test:11434",
            model="test-model",
            timeout=30
        ) as classifier:
            assert classifier is not None
            assert classifier.client is not None
    
    @pytest.mark.asyncio
    async def test_close(self, llm_classifier):
        """Test explicit close method."""
        # Mock the aclose method
        llm_classifier.client.aclose = AsyncMock()
        
        await llm_classifier.close()
        
        llm_classifier.client.aclose.assert_called_once()


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_classify_empty_description(self, llm_classifier):
        """Test classification with empty description."""
        description = ""
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "unknown",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        # Should still attempt classification
        assert isinstance(result, LLMResult)
    
    @pytest.mark.asyncio
    async def test_classify_very_long_description(self, llm_classifier):
        """Test classification with very long description."""
        description = "threat " * 1000  # Very long description
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "adversarial",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is True
    
    @pytest.mark.asyncio
    async def test_classify_unicode_description(self, llm_classifier):
        """Test classification with unicode characters."""
        description = "Threat with unicode: 攻击 атака 공격"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "adversarial",
            "done": True
        }
        
        llm_classifier.client.post = AsyncMock(return_value=mock_response)
        
        result = await llm_classifier.classify(description, VALID_TYPES)
        
        assert result.success is True
    
    def test_parse_response_with_underscores(self, llm_classifier):
        """Test parsing threat types with underscores."""
        result = llm_classifier._parse_response("prompt_injection", VALID_TYPES)
        assert result == "prompt_injection"
        
        result = llm_classifier._parse_response("supply_chain", VALID_TYPES)
        assert result == "supply_chain"
