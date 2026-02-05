"""
Unit tests for GenAI context validation.

Tests that threats with GenAI context indicators (model-related, interaction-related,
architecture-related, system-related) are properly classified as GenAI threats,
not "unknown" with high confidence.

Feature: llm-classification-improvements
"""
import pytest
import json
from unittest.mock import AsyncMock
from hypothesis import given, settings

from services.llm_classifier import classify_threat_with_metadata
from services.classification_types import ThreatMetadata
from tests.generators import genai_threat_descriptions, ambiguous_threat_descriptions


# ============================================================================
# Task 5.1: Unit tests for model-related context
# ============================================================================

@pytest.mark.asyncio
async def test_llm_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "LLM" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with LLM context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (LLM indicator). Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack targeting LLM systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security vulnerability in LLM system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "LLM context should not result in 'unknown' with confidence >= 0.5"
    else:
        # Should be classified as a GenAI threat category
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"], \
            f"Expected GenAI threat category, got {category}"
        assert len(metadata.target_systems) > 0, \
            "GenAI threat should have at least one target system"


@pytest.mark.asyncio
async def test_gpt_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "GPT" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with GPT context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (GPT model). Attack vector: jailbreak. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack targeting GPT model"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "GPT context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_transformer_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "transformer" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with transformer context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (transformer architecture). Attack vector: model extraction. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction attack on transformer architecture"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Transformer context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_language_model_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "language model" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with language model context
    mock_response = {
        'response': json.dumps({
            "category": "privacy",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["membership inference"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (language model). Attack vector: membership inference. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Membership inference attack on language model"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Language model context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_bert_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "BERT" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with BERT context
    mock_response = {
        'response': json.dumps({
            "category": "adversarial",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["adversarial examples"],
                "target_systems": ["llm"],
                "confidence": 0.87,
                "reasoning": "GenAI context present (BERT model). Attack vector: adversarial examples. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial attack targeting BERT model"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "BERT context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_neural_network_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "neural network" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with neural network context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model inversion"],
                "target_systems": ["llm", "vision"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (neural network). Attack vector: model inversion. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model inversion attack on neural network"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Neural network context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_ai_model_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "AI model" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with AI model context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (AI model). Attack vector: data poisoning. Not a web vulnerability. Training-time attack, not runtime testable."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning attack on AI model training"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "AI model context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_machine_learning_model_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "machine learning model" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with machine learning model context
    mock_response = {
        'response': json.dumps({
            "category": "robustness",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["adversarial perturbation"],
                "target_systems": ["llm", "vision"],
                "confidence": 0.88,
                "reasoning": "GenAI context present (machine learning model). Attack vector: adversarial perturbation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial perturbation attack on machine learning model"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Machine learning model context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_deep_learning_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "deep learning" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with deep learning context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["llm", "vision"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (deep learning model). Attack vector: backdoor attack. Not a web vulnerability. Training-time attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Backdoor attack on deep learning model training"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Deep learning context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_multiple_model_indicators_not_unknown_high_confidence():
    """
    Test that descriptions with multiple model-related indicators are properly classified.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with multiple model indicators
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm"],
                "confidence": 0.96,
                "reasoning": "GenAI context present (LLM, GPT, transformer indicators). Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack on GPT-based LLM using transformer architecture"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Multiple model indicators should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # With multiple strong indicators, confidence should be high
        assert metadata.confidence >= 0.8, \
            "Multiple model indicators should result in high confidence"


@pytest.mark.asyncio
async def test_model_context_with_attack_vector():
    """
    Test that model-related context combined with attack vectors is properly classified.
    
    Validates: Requirements 3.1, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with model context and attack vector
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (transformer model). Attack vector: model extraction. Not a web vulnerability. Runtime testable through query-based extraction."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction attack targeting transformer model through repeated queries"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as extraction, not unknown
    assert category == "extraction", \
        "Model extraction with model context should be classified as extraction"
    assert metadata.confidence >= 0.5, \
        "Should have confidence >= 0.5 with clear model context and attack vector"
    assert len(metadata.target_systems) > 0
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("model extraction" in t for t in techniques_lower)


@pytest.mark.asyncio
async def test_model_context_reasoning_mentions_genai():
    """
    Test that reasoning field mentions GenAI context when model indicators are present.
    
    Validates: Requirements 3.1, 3.5, 6.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with detailed reasoning
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.93,
                "reasoning": "GenAI context present: LLM and language model indicators found. Attack vector: jailbreak identified. Not a traditional web vulnerability. Runtime testable attack targeting LLM chat systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack on LLM language model chat system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify reasoning mentions GenAI context
    reasoning_lower = metadata.reasoning.lower()
    assert "genai" in reasoning_lower or "ai" in reasoning_lower or "model" in reasoning_lower, \
        "Reasoning should mention GenAI context when model indicators are present"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"


# ============================================================================
# Task 5.2: Unit tests for interaction-related context
# ============================================================================

@pytest.mark.asyncio
async def test_prompt_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "prompt" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with prompt context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (prompt interaction indicator). Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security vulnerability in prompt handling system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Prompt context should not result in 'unknown' with confidence >= 0.5"
    else:
        # Should be classified as a GenAI threat category
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"], \
            f"Expected GenAI threat category, got {category}"
        assert len(metadata.target_systems) > 0, \
            "GenAI threat should have at least one target system"


@pytest.mark.asyncio
async def test_chat_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "chat" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with chat context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["chat"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (chat interaction). Attack vector: jailbreak. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack targeting chat interface"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Chat context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_conversation_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "conversation" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with conversation context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context manipulation"],
                "target_systems": ["chat", "llm"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (conversation interaction). Attack vector: context manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Context manipulation in conversation history"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Conversation context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_completion_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "completion" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with completion context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.88,
                "reasoning": "GenAI context present (completion interaction). Attack vector: model extraction through completions. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction through completion API abuse"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Completion context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_generation_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "generation" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with generation context
    mock_response = {
        'response': json.dumps({
            "category": "adversarial",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["adversarial generation"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (generation interaction). Attack vector: adversarial generation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial attack on text generation system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Generation context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_inference_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "inference" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with inference context
    mock_response = {
        'response': json.dumps({
            "category": "privacy",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["membership inference"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (inference interaction). Attack vector: membership inference. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Membership inference attack during model inference"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Inference context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_query_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "query" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with query context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.87,
                "reasoning": "GenAI context present (query interaction). Attack vector: model extraction through queries. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction through repeated query attacks"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Query context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_response_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "response" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with response context
    mock_response = {
        'response': json.dumps({
            "category": "privacy",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["data leakage"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.86,
                "reasoning": "GenAI context present (response interaction). Attack vector: data leakage through responses. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data leakage in model response generation"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Response context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_multiple_interaction_indicators_not_unknown_high_confidence():
    """
    Test that descriptions with multiple interaction-related indicators are properly classified.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with multiple interaction indicators
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.96,
                "reasoning": "GenAI context present (prompt, chat, conversation indicators). Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack in chat conversation interface"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Multiple interaction indicators should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # With multiple strong indicators, confidence should be high
        assert metadata.confidence >= 0.8, \
            "Multiple interaction indicators should result in high confidence"


@pytest.mark.asyncio
async def test_interaction_context_with_attack_vector():
    """
    Test that interaction-related context combined with attack vectors is properly classified.
    
    Validates: Requirements 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with interaction context and attack vector
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection", "jailbreak"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (prompt and chat interaction). Attack vectors: prompt injection and jailbreak. Not a web vulnerability. Runtime testable through prompt manipulation."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack using malicious prompts in chat system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as prompt_injection, not unknown
    assert category == "prompt_injection", \
        "Prompt injection with interaction context should be classified as prompt_injection"
    assert metadata.confidence >= 0.5, \
        "Should have confidence >= 0.5 with clear interaction context and attack vector"
    assert len(metadata.target_systems) > 0
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("prompt injection" in t or "jailbreak" in t for t in techniques_lower)


@pytest.mark.asyncio
async def test_interaction_context_reasoning_mentions_genai():
    """
    Test that reasoning field mentions GenAI context when interaction indicators are present.
    
    Validates: Requirements 3.2, 3.5, 6.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with detailed reasoning
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.93,
                "reasoning": "GenAI context present: prompt and conversation interaction indicators found. Attack vector: prompt injection identified. Not a traditional web vulnerability. Runtime testable attack targeting chat systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack in conversation system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify reasoning mentions GenAI context
    reasoning_lower = metadata.reasoning.lower()
    assert "genai" in reasoning_lower or "ai" in reasoning_lower or "interaction" in reasoning_lower or "prompt" in reasoning_lower or "conversation" in reasoning_lower, \
        "Reasoning should mention GenAI context when interaction indicators are present"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"


@pytest.mark.asyncio
async def test_interaction_and_model_context_combined():
    """
    Test that combined interaction and model context indicators result in strong GenAI classification.
    
    Validates: Requirements 3.1, 3.2, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with both interaction and model context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.97,
                "reasoning": "GenAI context present: LLM model indicator and prompt interaction indicator. Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack targeting LLM chat system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as GenAI threat with high confidence
    assert category != "unknown" or metadata.confidence < 0.5, \
        "Combined model and interaction context should not result in 'unknown' with confidence >= 0.5"
    if category != "unknown":
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # Combined indicators should result in very high confidence
        assert metadata.confidence >= 0.85, \
            "Combined model and interaction indicators should result in very high confidence"


# ============================================================================
# Task 5.3: Unit tests for architecture-related context
# ============================================================================

@pytest.mark.asyncio
async def test_rag_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "RAG" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with RAG context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning", "RAG poisoning"],
                "target_systems": ["rag"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (RAG architecture indicator). Attack vector: RAG poisoning. Not a web vulnerability. Runtime testable attack targeting RAG systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Context poisoning attack on RAG system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "RAG context should not result in 'unknown' with confidence >= 0.5"
    else:
        # Should be classified as a GenAI threat category
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"], \
            f"Expected GenAI threat category, got {category}"
        assert len(metadata.target_systems) > 0, \
            "GenAI threat should have at least one target system"


@pytest.mark.asyncio
async def test_embedding_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "embedding" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with embedding context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["embedding manipulation"],
                "target_systems": ["rag", "llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (embedding architecture indicator). Attack vector: embedding manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Embedding manipulation attack on vector database"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Embedding context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_fine_tuning_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "fine-tuning" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with fine-tuning context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["fine-tuning", "training"],
                "testability": "conditional",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (fine-tuning architecture indicator). Attack vector: data poisoning during fine-tuning. Not a web vulnerability. Testable with fine-tuning setup."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning attack during model fine-tuning"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Fine-tuning context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_vector_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "vector" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with vector context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["vector database manipulation"],
                "target_systems": ["rag"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (vector architecture indicator). Attack vector: vector database manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Vector database manipulation in retrieval system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Vector context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_retrieval_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "retrieval" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with retrieval context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["retrieval manipulation"],
                "target_systems": ["rag"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (retrieval architecture indicator). Attack vector: retrieval manipulation. Not a web vulnerability. Runtime testable attack targeting RAG systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Retrieval manipulation attack on RAG system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Retrieval context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_rlhf_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "RLHF" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with RLHF context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training", "fine-tuning"],
                "testability": "no",
                "techniques": ["reward hacking"],
                "target_systems": ["llm"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (RLHF architecture indicator). Attack vector: reward hacking. Not a web vulnerability. Training-time attack, not runtime testable."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Reward hacking attack during RLHF training"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "RLHF context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_alignment_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "alignment" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with alignment context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training", "fine-tuning"],
                "testability": "no",
                "techniques": ["alignment manipulation"],
                "target_systems": ["llm"],
                "confidence": 0.88,
                "reasoning": "GenAI context present (alignment architecture indicator). Attack vector: alignment manipulation. Not a web vulnerability. Training-time attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Alignment manipulation attack on model training"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Alignment context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_training_data_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "training data" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with training data context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (training data architecture indicator). Attack vector: data poisoning. Not a web vulnerability. Training-time attack, not runtime testable."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning attack on training data"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Training data context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_model_weights_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "model weights" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with model weights context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (model weights architecture indicator). Attack vector: model extraction. Not a web vulnerability. Runtime testable through query-based extraction."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model weights extraction through API queries"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Model weights context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_multiple_architecture_indicators_not_unknown_high_confidence():
    """
    Test that descriptions with multiple architecture-related indicators are properly classified.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with multiple architecture indicators
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["RAG poisoning", "embedding manipulation"],
                "target_systems": ["rag"],
                "confidence": 0.96,
                "reasoning": "GenAI context present (RAG, embedding, vector indicators). Attack vectors: RAG poisoning and embedding manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "RAG poisoning attack using malicious embeddings in vector database"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Multiple architecture indicators should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # With multiple strong indicators, confidence should be high
        assert metadata.confidence >= 0.8, \
            "Multiple architecture indicators should result in high confidence"


@pytest.mark.asyncio
async def test_architecture_context_with_attack_vector():
    """
    Test that architecture-related context combined with attack vectors is properly classified.
    
    Validates: Requirements 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with architecture context and attack vector
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning", "document injection"],
                "target_systems": ["rag"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (RAG and retrieval architecture). Attack vectors: context poisoning and document injection. Not a web vulnerability. Runtime testable through document manipulation."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Document injection attack targeting RAG retrieval system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as poisoning, not unknown
    assert category == "poisoning", \
        "RAG poisoning with architecture context should be classified as poisoning"
    assert metadata.confidence >= 0.5, \
        "Should have confidence >= 0.5 with clear architecture context and attack vector"
    assert len(metadata.target_systems) > 0
    assert "rag" in metadata.target_systems, \
        "RAG attack should include 'rag' in target_systems"
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("context poisoning" in t or "document injection" in t for t in techniques_lower)


@pytest.mark.asyncio
async def test_architecture_context_reasoning_mentions_genai():
    """
    Test that reasoning field mentions GenAI context when architecture indicators are present.
    
    Validates: Requirements 3.3, 3.5, 6.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with detailed reasoning
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["RAG poisoning"],
                "target_systems": ["rag"],
                "confidence": 0.94,
                "reasoning": "GenAI context present: RAG and embedding architecture indicators found. Attack vector: RAG poisoning identified. Not a traditional web vulnerability. Runtime testable attack targeting RAG systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "RAG poisoning attack using malicious embeddings"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify reasoning mentions GenAI context
    reasoning_lower = metadata.reasoning.lower()
    assert "genai" in reasoning_lower or "ai" in reasoning_lower or "rag" in reasoning_lower or "embedding" in reasoning_lower or "architecture" in reasoning_lower, \
        "Reasoning should mention GenAI context when architecture indicators are present"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"


@pytest.mark.asyncio
async def test_architecture_and_model_context_combined():
    """
    Test that combined architecture and model context indicators result in strong GenAI classification.
    
    Validates: Requirements 3.1, 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with both architecture and model context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["fine-tuning", "training"],
                "testability": "conditional",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.96,
                "reasoning": "GenAI context present: LLM model indicator and fine-tuning architecture indicator. Attack vector: data poisoning. Not a web vulnerability. Testable with fine-tuning setup."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning attack during LLM fine-tuning"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as GenAI threat with high confidence
    assert category != "unknown" or metadata.confidence < 0.5, \
        "Combined model and architecture context should not result in 'unknown' with confidence >= 0.5"
    if category != "unknown":
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # Combined indicators should result in very high confidence
        assert metadata.confidence >= 0.85, \
            "Combined model and architecture indicators should result in very high confidence"


@pytest.mark.asyncio
async def test_architecture_interaction_model_context_combined():
    """
    Test that combined architecture, interaction, and model context indicators result in very strong GenAI classification.
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with architecture, interaction, and model context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["RAG poisoning", "prompt injection"],
                "target_systems": ["rag", "llm"],
                "confidence": 0.98,
                "reasoning": "GenAI context present: LLM model, prompt interaction, and RAG architecture indicators. Attack vectors: RAG poisoning and prompt injection. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection combined with RAG poisoning attack on LLM system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as GenAI threat with very high confidence
    assert category != "unknown" or metadata.confidence < 0.5, \
        "Combined model, interaction, and architecture context should not result in 'unknown' with confidence >= 0.5"
    if category != "unknown":
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # Multiple combined indicators should result in very high confidence
        assert metadata.confidence >= 0.9, \
            "Combined model, interaction, and architecture indicators should result in very high confidence"


# ============================================================================
# Task 5.4: Unit tests for system-related context
# ============================================================================

@pytest.mark.asyncio
async def test_agent_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "agent" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with agent context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["agent manipulation", "action hijacking"],
                "target_systems": ["agentic"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (agent system indicator). Attack vector: agent manipulation. Not a web vulnerability. Runtime testable attack targeting agentic systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Agent manipulation attack on AI agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Agent context should not result in 'unknown' with confidence >= 0.5"
    else:
        # Should be classified as a GenAI threat category
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"], \
            f"Expected GenAI threat category, got {category}"
        assert len(metadata.target_systems) > 0, \
            "GenAI threat should have at least one target system"


@pytest.mark.asyncio
async def test_tool_calling_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "tool calling" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with tool calling context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (tool calling system indicator). Attack vector: tool calling exploitation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation in AI agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Tool calling context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_function_calling_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "function calling" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with function calling context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["function calling abuse"],
                "target_systems": ["agentic", "llm"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (function calling system indicator). Attack vector: function calling abuse. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Function calling abuse in LLM agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Function calling context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_autonomous_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "autonomous" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with autonomous context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["autonomous behavior exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (autonomous system indicator). Attack vector: autonomous behavior exploitation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Autonomous behavior exploitation in AI system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Autonomous context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_multi_agent_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "multi-agent" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with multi-agent context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["multi-agent manipulation"],
                "target_systems": ["agentic"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (multi-agent system indicator). Attack vector: multi-agent manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Multi-agent manipulation attack on collaborative AI system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Multi-agent context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_ai_system_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "AI system" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with AI system context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["system manipulation"],
                "target_systems": ["llm", "agentic"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (AI system indicator). Attack vector: system manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security vulnerability in AI system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "AI system context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_chatbot_indicator_not_unknown_high_confidence():
    """
    Test that descriptions with "chatbot" are not classified as unknown with confidence >= 0.5.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with chatbot context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["chat"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (chatbot system indicator). Attack vector: prompt injection. Not a web vulnerability. Runtime testable attack targeting chatbot systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack on chatbot"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Chatbot context should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0


@pytest.mark.asyncio
async def test_multiple_system_indicators_not_unknown_high_confidence():
    """
    Test that descriptions with multiple system-related indicators are properly classified.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with multiple system indicators
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation", "agent manipulation"],
                "target_systems": ["agentic"],
                "confidence": 0.96,
                "reasoning": "GenAI context present (agent, tool calling, autonomous indicators). Attack vectors: tool calling exploitation and agent manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation in autonomous agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify NOT classified as unknown with high confidence
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            "Multiple system indicators should not result in 'unknown' with confidence >= 0.5"
    else:
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # With multiple strong indicators, confidence should be high
        assert metadata.confidence >= 0.8, \
            "Multiple system indicators should result in high confidence"


@pytest.mark.asyncio
async def test_system_context_with_attack_vector():
    """
    Test that system-related context combined with attack vectors is properly classified.
    
    Validates: Requirements 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with system context and attack vector
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["function calling abuse", "prompt injection"],
                "target_systems": ["agentic", "llm"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (agent and function calling system indicators). Attack vectors: function calling abuse and prompt injection. Not a web vulnerability. Runtime testable through agent manipulation."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection leading to function calling abuse in AI agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as prompt_injection, not unknown
    assert category == "prompt_injection", \
        "Agent attack with system context should be classified as prompt_injection"
    assert metadata.confidence >= 0.5, \
        "Should have confidence >= 0.5 with clear system context and attack vector"
    assert len(metadata.target_systems) > 0
    assert "agentic" in metadata.target_systems or "llm" in metadata.target_systems, \
        "Agent attack should include 'agentic' or 'llm' in target_systems"
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("function calling" in t or "prompt injection" in t for t in techniques_lower)


@pytest.mark.asyncio
async def test_system_context_reasoning_mentions_genai():
    """
    Test that reasoning field mentions GenAI context when system indicators are present.
    
    Validates: Requirements 3.4, 3.5, 6.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with detailed reasoning
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.94,
                "reasoning": "GenAI context present: agent and tool calling system indicators found. Attack vector: tool calling exploitation identified. Not a traditional web vulnerability. Runtime testable attack targeting agentic systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation in agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify reasoning mentions GenAI context
    reasoning_lower = metadata.reasoning.lower()
    assert "genai" in reasoning_lower or "ai" in reasoning_lower or "agent" in reasoning_lower or "tool calling" in reasoning_lower or "system" in reasoning_lower, \
        "Reasoning should mention GenAI context when system indicators are present"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"


@pytest.mark.asyncio
async def test_system_and_model_context_combined():
    """
    Test that combined system and model context indicators result in strong GenAI classification.
    
    Validates: Requirements 3.1, 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with both system and model context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection", "agent manipulation"],
                "target_systems": ["llm", "agentic"],
                "confidence": 0.97,
                "reasoning": "GenAI context present: LLM model indicator and agent system indicator. Attack vectors: prompt injection and agent manipulation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack on LLM-based agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as GenAI threat with high confidence
    assert category != "unknown" or metadata.confidence < 0.5, \
        "Combined model and system context should not result in 'unknown' with confidence >= 0.5"
    if category != "unknown":
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # Combined indicators should result in very high confidence
        assert metadata.confidence >= 0.85, \
            "Combined model and system indicators should result in very high confidence"


@pytest.mark.asyncio
async def test_system_interaction_model_context_combined():
    """
    Test that combined system, interaction, and model context indicators result in very strong GenAI classification.
    
    Validates: Requirements 3.1, 3.2, 3.4, 3.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat with system, interaction, and model context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection", "tool calling exploitation"],
                "target_systems": ["llm", "agentic", "chat"],
                "confidence": 0.98,
                "reasoning": "GenAI context present: LLM model, chat interaction, and agent system indicators. Attack vectors: prompt injection and tool calling exploitation. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection in LLM chatbot leading to tool calling exploitation in agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Should be classified as GenAI threat with very high confidence
    assert category != "unknown" or metadata.confidence < 0.5, \
        "Combined model, interaction, and system context should not result in 'unknown' with confidence >= 0.5"
    if category != "unknown":
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"]
        assert len(metadata.target_systems) > 0
        # Multiple combined indicators should result in very high confidence
        assert metadata.confidence >= 0.9, \
            "Combined model, interaction, and system indicators should result in very high confidence"


# ============================================================================
# Task 5.5: Unit tests for missing context
# ============================================================================

@pytest.mark.asyncio
async def test_generic_vulnerability_without_genai_context():
    """
    Test that generic vulnerability descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for generic vulnerability without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.3,
                "reasoning": "No GenAI context indicators found. Generic vulnerability description without specific AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security vulnerability detected in system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Generic vulnerability without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_generic_attack_without_genai_context():
    """
    Test that generic attack descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for generic attack without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.25,
                "reasoning": "No GenAI context indicators found. Generic attack description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Attack detected on system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Generic attack without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_security_issue_without_genai_context():
    """
    Test that security issue descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for security issue without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.2,
                "reasoning": "No GenAI context indicators found. Generic security issue without specific AI/ML references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security issue found in application"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Security issue without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_data_breach_without_genai_context():
    """
    Test that data breach descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for data breach without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.35,
                "reasoning": "No GenAI context indicators found. Data breach description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data breach in database system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Data breach without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_unauthorized_access_without_genai_context():
    """
    Test that unauthorized access descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for unauthorized access without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.28,
                "reasoning": "No GenAI context indicators found. Unauthorized access description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Unauthorized access to system resources"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Unauthorized access without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_malware_without_genai_context():
    """
    Test that malware descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for malware without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.32,
                "reasoning": "No GenAI context indicators found. Malware description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Malware infection detected in system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Malware without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_denial_of_service_without_genai_context():
    """
    Test that denial of service descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for DoS without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.27,
                "reasoning": "No GenAI context indicators found. Denial of service description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Denial of service attack on server"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Denial of service without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_privilege_escalation_without_genai_context():
    """
    Test that privilege escalation descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for privilege escalation without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.29,
                "reasoning": "No GenAI context indicators found. Privilege escalation description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Privilege escalation vulnerability in application"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Privilege escalation without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_code_execution_without_genai_context():
    """
    Test that code execution descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for code execution without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.31,
                "reasoning": "No GenAI context indicators found. Code execution description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Remote code execution vulnerability"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Code execution without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_information_disclosure_without_genai_context():
    """
    Test that information disclosure descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for information disclosure without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.26,
                "reasoning": "No GenAI context indicators found. Information disclosure description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Information disclosure through error messages"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Information disclosure without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_very_short_description_without_genai_context():
    """
    Test that very short descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6, 8.1
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for very short description
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.15,
                "reasoning": "Very short description with insufficient information. No GenAI context indicators found. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Bug found"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Very short description without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_ambiguous_threat_without_genai_context():
    """
    Test that ambiguous threat descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for ambiguous threat
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.22,
                "reasoning": "Ambiguous threat description without specific details. No GenAI context indicators found. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Potential security risk identified"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Ambiguous threat without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_network_attack_without_genai_context():
    """
    Test that network attack descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for network attack without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.33,
                "reasoning": "No GenAI context indicators found. Network attack description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Network intrusion detected"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Network attack without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_configuration_issue_without_genai_context():
    """
    Test that configuration issue descriptions without GenAI context are classified as unknown OR confidence < 0.5.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for configuration issue without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.24,
                "reasoning": "No GenAI context indicators found. Configuration issue description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Misconfiguration in system settings"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classified as unknown OR confidence < 0.5
    assert category == "unknown" or metadata.confidence < 0.5, \
        "Configuration issue without GenAI context should be 'unknown' OR confidence < 0.5"


@pytest.mark.asyncio
async def test_missing_context_reasoning_explains_absence():
    """
    Test that reasoning field explains the absence of GenAI context indicators.
    
    Validates: Requirements 3.6, 6.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with detailed reasoning about missing context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.25,
                "reasoning": "No GenAI context indicators found. Description lacks model-related, interaction-related, architecture-related, or system-related AI/ML terms. Cannot classify as GenAI threat without GenAI context."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "System vulnerability detected"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify reasoning explains absence of GenAI context
    reasoning_lower = metadata.reasoning.lower()
    assert "no genai" in reasoning_lower or "no ai" in reasoning_lower or "lack" in reasoning_lower or "without" in reasoning_lower, \
        "Reasoning should explain the absence of GenAI context indicators"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"


@pytest.mark.asyncio
async def test_missing_context_empty_target_systems():
    """
    Test that threats without GenAI context have empty target_systems.
    
    Validates: Requirements 3.6, 5.2
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.28,
                "reasoning": "No GenAI context indicators found. Generic threat description without AI/ML system references. Cannot classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Security threat detected"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify empty target_systems when no GenAI context
    if category == "unknown":
        assert len(metadata.target_systems) == 0, \
            "Threats without GenAI context should have empty target_systems"


@pytest.mark.asyncio
async def test_missing_context_low_confidence():
    """
    Test that threats without GenAI context have low confidence scores.
    
    Validates: Requirements 3.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for threat without GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.19,
                "reasoning": "No GenAI context indicators found. Insufficient information to classify as GenAI threat. Low confidence due to lack of AI/ML system references."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Threat identified"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify low confidence when no GenAI context
    if category == "unknown":
        # Confidence should be low for unknown threats without context
        assert metadata.confidence < 0.5, \
            "Unknown threats without GenAI context should have confidence < 0.5"
    else:
        # If not unknown, confidence must be < 0.5 per requirement 3.6
        assert metadata.confidence < 0.5, \
            "Threats without GenAI context should have confidence < 0.5 if not classified as unknown"


# ============================================================================
# Task 5.6: Property test for GenAI context indicator recognition
# ============================================================================

@pytest.mark.asyncio
@given(description=genai_threat_descriptions())
@settings(max_examples=100)
async def test_property_genai_context_indicator_recognition(description):
    """
    **Property 3: GenAI Context Indicator Recognition**
    **Validates: Requirements 3.5**
    
    For any threat description with GenAI context indicators (model-related,
    interaction-related, architecture-related, or system-related terms) that
    is not primarily a web vulnerability, the classifier should NOT assign
    category "unknown" with confidence >= 0.5.
    
    Feature: llm-classification-improvements, Property 3: GenAI Context Indicator Recognition
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for GenAI threat with context indicators
    # The genai_threat_descriptions() generator creates descriptions with
    # GenAI context (model/interaction/architecture/system indicators)
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",  # Any GenAI category except "unknown"
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm"],
                "confidence": 0.85,  # High confidence >= 0.5
                "reasoning": "GenAI context present with clear indicators. Attack vector identified. Not a web vulnerability. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    # Classify the threat
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Property: GenAI context indicators should NOT result in "unknown" with confidence >= 0.5
    if category == "unknown":
        assert metadata.confidence < 0.5, \
            f"GenAI threat with context indicators should not be 'unknown' with confidence >= 0.5. " \
            f"Description: '{description}', Confidence: {metadata.confidence}"
    else:
        # If not unknown, should be a valid GenAI threat category
        assert category in ["prompt_injection", "extraction", "poisoning", "adversarial", 
                           "privacy", "fairness", "robustness", "supply_chain"], \
            f"Expected GenAI threat category, got '{category}' for description: '{description}'"
        
        # Should have at least one target system for GenAI threats
        assert len(metadata.target_systems) > 0, \
            f"GenAI threat should have at least one target system. Description: '{description}'"
        
        # Confidence should be >= 0.5 for non-unknown GenAI threats
        assert metadata.confidence >= 0.5, \
            f"GenAI threat with context indicators should have confidence >= 0.5. " \
            f"Description: '{description}', Confidence: {metadata.confidence}"


# ============================================================================
# Task 5.7: Property test for missing context indicator skepticism
# ============================================================================

@pytest.mark.asyncio
@given(description=ambiguous_threat_descriptions())
@settings(max_examples=100)
async def test_property_missing_context_indicator_skepticism(description):
    """
    **Property 4: Missing Context Indicator Skepticism**
    **Validates: Requirements 3.6**
    
    For any threat description lacking GenAI context indicators, the classifier
    should assign category "unknown" OR set confidence < 0.5.
    
    Feature: llm-classification-improvements, Property 4: Missing Context Indicator Skepticism
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for ambiguous threat without clear GenAI context
    # The ambiguous_threat_descriptions() generator creates vague descriptions
    # with only generic terms like "vulnerability", "attack", "threat"
    mock_response = {
        'response': json.dumps({
            "category": "unknown",  # Should be unknown for ambiguous threats
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.3,  # Low confidence < 0.5
                "reasoning": "Insufficient GenAI context indicators. Generic threat description without specific attack vectors or GenAI system references. Cannot confidently classify as GenAI threat."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    # Classify the threat
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Property: Threats lacking GenAI context should be "unknown" OR have confidence < 0.5
    is_unknown = (category == "unknown")
    is_low_confidence = (metadata.confidence < 0.5)
    
    assert is_unknown or is_low_confidence, \
        f"Threat without clear GenAI context should be 'unknown' OR have confidence < 0.5. " \
        f"Description: '{description}', Category: '{category}', Confidence: {metadata.confidence}"
    
    # Additional validation: if classified as a GenAI threat with high confidence,
    # this would violate the property
    if not is_unknown and not is_low_confidence:
        pytest.fail(
            f"PROPERTY VIOLATION: Ambiguous threat classified as '{category}' with confidence {metadata.confidence} >= 0.5. "
            f"Description: '{description}'. "
            f"Threats without clear GenAI context indicators should be 'unknown' OR have confidence < 0.5."
        )
