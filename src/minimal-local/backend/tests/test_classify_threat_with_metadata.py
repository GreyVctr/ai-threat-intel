"""
Unit tests for classify_threat_with_metadata function.

Tests the enhanced LLM classifier that extracts both category and metadata
from threat descriptions.
"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock

from services.llm_classifier import classify_threat_with_metadata
from services.classification_types import ThreatMetadata


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_success():
    """Test successful classification with metadata extraction."""
    # Mock LLM client
    mock_client = AsyncMock()
    
    # Mock LLM response with valid JSON
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak", "prompt_injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.92,
                "reasoning": "Threat describes runtime prompt manipulation targeting LLM chat systems"
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    # Test the function
    description = "An attacker can manipulate prompts to bypass safety filters in a chatbot."
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify results
    assert category == "prompt_injection"
    assert isinstance(metadata, ThreatMetadata)
    assert metadata.attack_surface == ["runtime", "inference"]
    assert metadata.testability == "yes"
    assert metadata.techniques == ["jailbreak", "prompt_injection"]
    assert metadata.target_systems == ["llm", "chat"]
    assert metadata.confidence == 0.92
    assert "runtime prompt manipulation" in metadata.reasoning


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_partial():
    """Test classification with partial metadata (some fields missing)."""
    mock_client = AsyncMock()
    
    # Mock response with partial metadata
    mock_response = {
        'response': json.dumps({
            "category": "adversarial",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["fgsm"],
                "target_systems": ["vision"]
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "FGSM attack on image classifier during training."
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    assert category == "adversarial"
    assert metadata.attack_surface == ["training"]
    assert metadata.testability == "no"
    assert metadata.techniques == ["fgsm"]
    assert metadata.target_systems == ["vision"]
    assert metadata.confidence is None  # Not provided
    assert metadata.reasoning is None  # Not provided


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_empty_metadata():
    """Test classification with empty metadata."""
    mock_client = AsyncMock()
    
    # Mock response with empty metadata
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {}
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some unclear threat description."
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    assert category == "unknown"
    assert isinstance(metadata, ThreatMetadata)
    assert metadata.attack_surface == []
    assert metadata.testability is None
    assert metadata.techniques == []
    assert metadata.target_systems == []


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_json_with_extra_text():
    """Test parsing JSON when LLM includes extra text in response."""
    mock_client = AsyncMock()
    
    # Mock response with extra text around JSON
    mock_response = {
        'response': '''Here is my analysis:
        
        {
            "category": "privacy",
            "metadata": {
                "attack_surface": ["runtime"],
                "testability": "conditional",
                "techniques": ["membership_inference"],
                "target_systems": ["llm"]
            }
        }
        
        This is a privacy threat.'''
    }
    mock_client.generate.return_value = mock_response
    
    description = "Membership inference attack on language model."
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    assert category == "privacy"
    assert metadata.attack_surface == ["runtime"]
    assert metadata.testability == "conditional"
    assert metadata.techniques == ["membership_inference"]


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_invalid_json():
    """Test error handling when LLM returns invalid JSON."""
    mock_client = AsyncMock()
    
    # Mock response with invalid JSON
    mock_response = {
        'response': 'This is not valid JSON at all'
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some threat description."
    
    with pytest.raises(ValueError, match="does not contain valid JSON"):
        await classify_threat_with_metadata(description, mock_client)


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_malformed_json():
    """Test error handling when JSON is malformed."""
    mock_client = AsyncMock()
    
    # Mock response with malformed JSON
    mock_response = {
        'response': '{"category": "adversarial", "metadata": {invalid}}'
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some threat description."
    
    with pytest.raises(ValueError, match="Invalid JSON"):
        await classify_threat_with_metadata(description, mock_client)


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_empty_response():
    """Test error handling when LLM returns empty response."""
    mock_client = AsyncMock()
    
    # Mock empty response
    mock_response = {
        'response': ''
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some threat description."
    
    with pytest.raises(ValueError, match="empty response"):
        await classify_threat_with_metadata(description, mock_client)


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_connection_error():
    """Test error handling when LLM service is unavailable."""
    mock_client = AsyncMock()
    
    # Mock connection error
    mock_client.generate.side_effect = ConnectionError("Failed to connect to Ollama")
    
    description = "Some threat description."
    
    with pytest.raises(ConnectionError):
        await classify_threat_with_metadata(description, mock_client)


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_timeout():
    """Test error handling when LLM request times out."""
    mock_client = AsyncMock()
    
    # Mock timeout error
    mock_client.generate.side_effect = TimeoutError("Request timed out")
    
    description = "Some threat description."
    
    with pytest.raises(TimeoutError):
        await classify_threat_with_metadata(description, mock_client)


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_invalid_enum_values():
    """Test handling of invalid enum values in metadata."""
    mock_client = AsyncMock()
    
    # Mock response with invalid enum values
    mock_response = {
        'response': json.dumps({
            "category": "adversarial",
            "metadata": {
                "attack_surface": ["invalid_surface"],  # Invalid value
                "testability": "maybe",  # Invalid value
                "techniques": ["fgsm"],
                "target_systems": ["invalid_system"]  # Invalid value
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some threat description."
    
    # Should handle validation error gracefully and return empty metadata
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    assert category == "adversarial"
    # Metadata validation failed, so we get empty metadata
    assert isinstance(metadata, ThreatMetadata)
    assert metadata.attack_surface == []
    assert metadata.testability is None


@pytest.mark.asyncio
async def test_classify_threat_with_metadata_missing_category():
    """Test handling when category is missing from response."""
    mock_client = AsyncMock()
    
    # Mock response without category
    mock_response = {
        'response': json.dumps({
            "metadata": {
                "attack_surface": ["runtime"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm"]
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Some threat description."
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should default to "unknown" when category is missing
    assert category == "unknown"
    assert isinstance(metadata, ThreatMetadata)
