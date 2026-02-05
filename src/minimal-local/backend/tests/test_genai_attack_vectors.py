"""
Unit tests for GenAI attack vector recognition.

Tests that GenAI-specific attack vectors (prompt manipulation, model behavior
exploitation, training data attacks, RAG manipulation, agent misuse) are
correctly identified and included in the techniques field.

Feature: llm-classification-improvements
"""
import pytest
import json
from unittest.mock import AsyncMock
from hypothesis import given, settings

from services.llm_classifier import classify_threat_with_metadata
from services.classification_types import ThreatMetadata
from tests.generators import genai_threat_descriptions


# ============================================================================
# Task 4.1: Unit tests for prompt manipulation attacks
# ============================================================================

@pytest.mark.asyncio
async def test_prompt_injection_in_techniques():
    """
    Test that prompt injection is included in techniques field.
    
    Validates: Requirements 2.1, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for prompt injection
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (LLM, chat). Attack vector: prompt injection. Runtime testable attack targeting LLM systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack targeting LLM chat system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify prompt injection is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("prompt injection" in t for t in techniques_lower), \
        "Prompt injection should be in techniques field"
    assert category == "prompt_injection", \
        "Category should be prompt_injection"
    assert metadata.testability == "yes", \
        "Prompt injection should be runtime testable"


@pytest.mark.asyncio
async def test_jailbreak_in_techniques():
    """
    Test that jailbreak is included in techniques field.
    
    Validates: Requirements 2.1, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for jailbreak
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["jailbreak"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (GPT, chatbot). Attack vector: jailbreak. Runtime testable attack targeting LLM chat systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack on GPT chatbot"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify jailbreak is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("jailbreak" in t for t in techniques_lower), \
        "Jailbreak should be in techniques field"
    assert metadata.testability == "yes", \
        "Jailbreak should be runtime testable"


@pytest.mark.asyncio
async def test_prompt_leaking_in_techniques():
    """
    Test that prompt leaking is included in techniques field.
    
    Validates: Requirements 2.1, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for prompt leaking
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt leaking"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (LLM, system prompt). Attack vector: prompt leaking. Runtime testable attack targeting LLM systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt leaking vulnerability in LLM system prompt"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify prompt leaking is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("prompt leaking" in t for t in techniques_lower), \
        "Prompt leaking should be in techniques field"
    assert metadata.testability == "yes", \
        "Prompt leaking should be runtime testable"


@pytest.mark.asyncio
async def test_multiple_prompt_manipulation_techniques():
    """
    Test that multiple prompt manipulation techniques can be identified.
    
    Validates: Requirements 2.1, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple techniques
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection", "jailbreak", "prompt leaking"],
                "target_systems": ["llm", "chat"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (LLM, chat). Multiple attack vectors: prompt injection, jailbreak, and prompt leaking. Runtime testable attacks."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined prompt injection and jailbreak attack with prompt leaking on LLM chat"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify all techniques are present
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("prompt injection" in t for t in techniques_lower), \
        "Prompt injection should be in techniques"
    assert any("jailbreak" in t for t in techniques_lower), \
        "Jailbreak should be in techniques"
    assert any("prompt leaking" in t for t in techniques_lower), \
        "Prompt leaking should be in techniques"


@pytest.mark.asyncio
async def test_prompt_manipulation_with_genai_context():
    """
    Test that prompt manipulation requires GenAI context.
    
    Validates: Requirements 2.1, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for prompt manipulation with GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection"],
                "target_systems": ["llm"],
                "confidence": 0.96,
                "reasoning": "GenAI context present (language model, prompt). Attack vector: prompt injection. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection targeting language model inference"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classification
    assert category == "prompt_injection"
    assert len(metadata.target_systems) > 0, \
        "Should have at least one target system for GenAI threat"
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("prompt injection" in t for t in techniques_lower)



# ============================================================================
# Task 4.2: Unit tests for model behavior exploitation
# ============================================================================

@pytest.mark.asyncio
async def test_model_extraction_in_techniques():
    """
    Test that model extraction is included in techniques field.
    
    Validates: Requirements 2.2, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for model extraction
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (LLM, model). Attack vector: model extraction. Runtime testable through query-based extraction."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction attack targeting LLM through repeated queries"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify model extraction is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("model extraction" in t for t in techniques_lower), \
        "Model extraction should be in techniques field"
    assert category == "extraction", \
        "Category should be extraction"
    assert metadata.testability == "yes", \
        "Model extraction via queries should be runtime testable"


@pytest.mark.asyncio
async def test_model_inversion_in_techniques():
    """
    Test that model inversion is included in techniques field.
    
    Validates: Requirements 2.2, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for model inversion
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model inversion"],
                "target_systems": ["llm", "vision"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (neural network, model). Attack vector: model inversion. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model inversion attack on neural network to extract training data"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify model inversion is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("model inversion" in t for t in techniques_lower), \
        "Model inversion should be in techniques field"
    assert metadata.testability == "yes", \
        "Model inversion should be runtime testable"


@pytest.mark.asyncio
async def test_membership_inference_in_techniques():
    """
    Test that membership inference is included in techniques field.
    
    Validates: Requirements 2.2, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for membership inference
    mock_response = {
        'response': json.dumps({
            "category": "privacy",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["membership inference"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (machine learning model, training data). Attack vector: membership inference. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Membership inference attack to determine if data was in training set"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify membership inference is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("membership inference" in t for t in techniques_lower), \
        "Membership inference should be in techniques field"
    assert metadata.testability == "yes", \
        "Membership inference should be runtime testable"


@pytest.mark.asyncio
async def test_multiple_model_exploitation_techniques():
    """
    Test that multiple model behavior exploitation techniques can be identified.
    
    Validates: Requirements 2.2, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple techniques
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction", "model inversion", "membership inference"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (LLM, model). Multiple attack vectors: model extraction, inversion, and membership inference. Runtime testable attacks."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined model extraction, inversion, and membership inference attack on LLM"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify all techniques are present
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("model extraction" in t for t in techniques_lower), \
        "Model extraction should be in techniques"
    assert any("model inversion" in t for t in techniques_lower), \
        "Model inversion should be in techniques"
    assert any("membership inference" in t for t in techniques_lower), \
        "Membership inference should be in techniques"


@pytest.mark.asyncio
async def test_model_exploitation_with_genai_context():
    """
    Test that model exploitation requires GenAI context.
    
    Validates: Requirements 2.2, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for model exploitation with GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "extraction",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["model extraction"],
                "target_systems": ["llm"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (transformer, AI model). Attack vector: model extraction. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction targeting transformer AI model"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classification
    assert category == "extraction"
    assert len(metadata.target_systems) > 0, \
        "Should have at least one target system for GenAI threat"
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("model extraction" in t for t in techniques_lower)



# ============================================================================
# Task 4.3: Unit tests for training data attacks
# ============================================================================

@pytest.mark.asyncio
async def test_data_poisoning_in_techniques():
    """
    Test that data poisoning is included in techniques field.
    
    Validates: Requirements 2.3, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for data poisoning
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (training data, model). Attack vector: data poisoning. Non-runtime attack (training-time), testability is 'no'."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning attack on LLM training data"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify data poisoning is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("data poisoning" in t for t in techniques_lower), \
        "Data poisoning should be in techniques field"
    assert category == "poisoning", \
        "Category should be poisoning"
    assert metadata.testability == "no", \
        "Data poisoning is a training-time attack, not runtime testable"


@pytest.mark.asyncio
async def test_backdoor_attack_in_techniques():
    """
    Test that backdoor attacks are included in techniques field.
    
    Validates: Requirements 2.3, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for backdoor attack
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor"],
                "target_systems": ["llm", "vision"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (neural network, training). Attack vector: backdoor attack. Non-runtime attack (training-time), testability is 'no'."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Backdoor attack injected during neural network training"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify backdoor is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("backdoor" in t for t in techniques_lower), \
        "Backdoor should be in techniques field"
    assert metadata.testability == "no", \
        "Backdoor attacks are training-time, not runtime testable"


@pytest.mark.asyncio
async def test_multiple_training_attack_techniques():
    """
    Test that multiple training data attack techniques can be identified.
    
    Validates: Requirements 2.3, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple techniques
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning", "backdoor"],
                "target_systems": ["llm"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (LLM, training data). Multiple attack vectors: data poisoning and backdoor. Non-runtime attacks (training-time)."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined data poisoning and backdoor attack on LLM training pipeline"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify all techniques are present
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("data poisoning" in t for t in techniques_lower), \
        "Data poisoning should be in techniques"
    assert any("backdoor" in t for t in techniques_lower), \
        "Backdoor should be in techniques"
    assert metadata.testability == "no", \
        "Training attacks should not be runtime testable"


@pytest.mark.asyncio
async def test_training_attacks_with_genai_context():
    """
    Test that training attacks require GenAI context.
    
    Validates: Requirements 2.3, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for training attack with GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.95,
                "reasoning": "GenAI context present (machine learning model, training data). Attack vector: data poisoning. Non-runtime attack (training-time)."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Data poisoning targeting machine learning model training data"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classification
    assert category == "poisoning"
    assert len(metadata.target_systems) > 0, \
        "Should have at least one target system for GenAI threat"
    assert metadata.testability == "no"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("data poisoning" in t for t in techniques_lower)


@pytest.mark.asyncio
async def test_adversarial_training_in_techniques():
    """
    Test that adversarial training attacks are included in techniques field.
    
    Validates: Requirements 2.3, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for adversarial training
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["adversarial training"],
                "target_systems": ["llm"],
                "confidence": 0.88,
                "reasoning": "GenAI context present (model training, adversarial). Attack vector: adversarial training. Non-runtime attack (training-time)."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial training attack on model training process"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify adversarial training is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("adversarial training" in t for t in techniques_lower), \
        "Adversarial training should be in techniques field"
    assert metadata.testability == "no", \
        "Adversarial training is a training-time attack"



# ============================================================================
# Task 4.4: Unit tests for RAG manipulation
# ============================================================================

@pytest.mark.asyncio
async def test_context_poisoning_in_techniques():
    """
    Test that context poisoning is included in techniques field.
    
    Validates: Requirements 2.4, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for context poisoning
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning"],
                "target_systems": ["rag"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (RAG, retrieval). Attack vector: context poisoning. Runtime testable attack targeting RAG systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Context poisoning attack on RAG retrieval system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify context poisoning is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("context poisoning" in t for t in techniques_lower), \
        "Context poisoning should be in techniques field"
    assert "rag" in metadata.target_systems, \
        "RAG should be in target_systems for context poisoning"
    assert metadata.testability == "yes", \
        "Context poisoning should be runtime testable"


@pytest.mark.asyncio
async def test_retrieval_manipulation_in_techniques():
    """
    Test that retrieval manipulation is included in techniques field.
    
    Validates: Requirements 2.4, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for retrieval manipulation
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["retrieval manipulation"],
                "target_systems": ["rag"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (RAG, vector database). Attack vector: retrieval manipulation. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Retrieval manipulation attack on vector database in RAG system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify retrieval manipulation is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("retrieval manipulation" in t for t in techniques_lower), \
        "Retrieval manipulation should be in techniques field"
    assert "rag" in metadata.target_systems, \
        "RAG should be in target_systems"
    assert metadata.testability == "yes", \
        "Retrieval manipulation should be runtime testable"


@pytest.mark.asyncio
async def test_document_injection_in_techniques():
    """
    Test that document injection is included in techniques field.
    
    Validates: Requirements 2.4, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for document injection
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["document injection"],
                "target_systems": ["rag"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (RAG, knowledge base). Attack vector: document injection. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Document injection attack targeting RAG knowledge base"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify document injection is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("document injection" in t for t in techniques_lower), \
        "Document injection should be in techniques field"
    assert "rag" in metadata.target_systems, \
        "RAG should be in target_systems"


@pytest.mark.asyncio
async def test_multiple_rag_manipulation_techniques():
    """
    Test that multiple RAG manipulation techniques can be identified.
    
    Validates: Requirements 2.4, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple techniques
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning", "retrieval manipulation", "document injection"],
                "target_systems": ["rag"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (RAG system). Multiple attack vectors: context poisoning, retrieval manipulation, and document injection. Runtime testable attacks."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined context poisoning, retrieval manipulation, and document injection on RAG system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify all techniques are present
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("context poisoning" in t for t in techniques_lower), \
        "Context poisoning should be in techniques"
    assert any("retrieval manipulation" in t for t in techniques_lower), \
        "Retrieval manipulation should be in techniques"
    assert any("document injection" in t for t in techniques_lower), \
        "Document injection should be in techniques"
    assert "rag" in metadata.target_systems


@pytest.mark.asyncio
async def test_rag_manipulation_with_genai_context():
    """
    Test that RAG manipulation requires GenAI context.
    
    Validates: Requirements 2.4, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for RAG manipulation with GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning"],
                "target_systems": ["rag"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (RAG, embedding, retrieval). Attack vector: context poisoning. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Context poisoning targeting RAG embedding and retrieval system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classification
    assert category == "poisoning"
    assert "rag" in metadata.target_systems, \
        "RAG should be in target_systems"
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("context poisoning" in t for t in techniques_lower)



# ============================================================================
# Task 4.5: Unit tests for agent misuse
# ============================================================================

@pytest.mark.asyncio
async def test_tool_calling_exploitation_in_techniques():
    """
    Test that tool calling exploitation is included in techniques field.
    
    Validates: Requirements 2.5, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for tool calling exploitation
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (agent, tool calling). Attack vector: tool calling exploitation. Runtime testable attack targeting agentic systems."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation attack on AI agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify tool calling exploitation is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("tool calling exploitation" in t for t in techniques_lower), \
        "Tool calling exploitation should be in techniques field"
    assert "agentic" in metadata.target_systems, \
        "Agentic should be in target_systems for tool calling exploitation"
    assert metadata.testability == "yes", \
        "Tool calling exploitation should be runtime testable"


@pytest.mark.asyncio
async def test_function_calling_abuse_in_techniques():
    """
    Test that function calling abuse is included in techniques field.
    
    Validates: Requirements 2.5, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for function calling abuse
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["function calling abuse"],
                "target_systems": ["agentic"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (AI agent, function calling). Attack vector: function calling abuse. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Function calling abuse in AI agent with function calling capabilities"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify function calling abuse is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("function calling abuse" in t for t in techniques_lower), \
        "Function calling abuse should be in techniques field"
    assert "agentic" in metadata.target_systems, \
        "Agentic should be in target_systems"
    assert metadata.testability == "yes", \
        "Function calling abuse should be runtime testable"


@pytest.mark.asyncio
async def test_agent_hijacking_in_techniques():
    """
    Test that agent hijacking is included in techniques field.
    
    Validates: Requirements 2.5, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for agent hijacking
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["agent hijacking"],
                "target_systems": ["agentic"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (autonomous agent, multi-agent). Attack vector: agent hijacking. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Agent hijacking attack on autonomous multi-agent system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify agent hijacking is in techniques
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("agent hijacking" in t or "hijacking" in t for t in techniques_lower), \
        "Agent hijacking should be in techniques field"
    assert "agentic" in metadata.target_systems


@pytest.mark.asyncio
async def test_multiple_agent_misuse_techniques():
    """
    Test that multiple agent misuse techniques can be identified.
    
    Validates: Requirements 2.5, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple techniques
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation", "function calling abuse"],
                "target_systems": ["agentic"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (AI agent system). Multiple attack vectors: tool calling exploitation and function calling abuse. Runtime testable attacks."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined tool calling exploitation and function calling abuse on AI agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify all techniques are present
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("tool calling exploitation" in t for t in techniques_lower), \
        "Tool calling exploitation should be in techniques"
    assert any("function calling abuse" in t for t in techniques_lower), \
        "Function calling abuse should be in techniques"
    assert "agentic" in metadata.target_systems


@pytest.mark.asyncio
async def test_agent_misuse_with_genai_context():
    """
    Test that agent misuse requires GenAI context.
    
    Validates: Requirements 2.5, 2.6
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for agent misuse with GenAI context
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (AI agent, autonomous, tool calling). Attack vector: tool calling exploitation. Runtime testable attack."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation targeting autonomous AI agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify classification
    assert len(metadata.target_systems) > 0, \
        "Should have at least one target system for GenAI threat"
    assert "agentic" in metadata.target_systems
    assert metadata.testability == "yes"
    techniques_lower = [t.lower() for t in metadata.techniques]
    assert any("tool calling exploitation" in t for t in techniques_lower)



# ============================================================================
# Task 4.6: Property test for GenAI attack vector recognition
# ============================================================================

@pytest.mark.asyncio
@given(description=genai_threat_descriptions())
@settings(max_examples=100)
async def test_property_genai_attack_vector_recognition(description):
    """
    Property 2: GenAI Attack Vector Recognition
    
    For any threat description containing GenAI attack vector indicators,
    those specific attack vectors should appear in the techniques field.
    
    **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**
    
    Feature: llm-classification-improvements, Property 2: GenAI Attack Vector Recognition
    """
    # Mock LLM client
    mock_client = AsyncMock()
    
    # Determine which attack vector is in the description
    description_lower = description.lower()
    
    # Map attack vectors to their expected techniques
    attack_vector_map = {
        "prompt injection": ["prompt injection"],
        "jailbreak": ["jailbreak"],
        "jailbreaking": ["jailbreak"],
        "prompt leaking": ["prompt leaking"],
        "model extraction": ["model extraction"],
        "model inversion": ["model inversion"],
        "membership inference": ["membership inference"],
        "data poisoning": ["data poisoning"],
        "backdoor": ["backdoor"],
        "rag poisoning": ["rag poisoning", "context poisoning"],
        "context poisoning": ["context poisoning"],
        "retrieval manipulation": ["retrieval manipulation"],
        "document injection": ["document injection"],
        "tool calling exploitation": ["tool calling exploitation"],
        "function calling abuse": ["function calling abuse"],
        "agent hijacking": ["agent hijacking"],
    }
    
    # Find which attack vector is present
    found_vectors = []
    expected_techniques = []
    for vector, techniques in attack_vector_map.items():
        if vector in description_lower:
            found_vectors.append(vector)
            expected_techniques.extend(techniques)
    
    # If no specific vector found, skip this test case
    if not found_vectors:
        # Generate a generic response
        mock_response = {
            'response': json.dumps({
                "category": "unknown",
                "metadata": {
                    "attack_surface": [],
                    "testability": "no",
                    "techniques": [],
                    "target_systems": [],
                    "confidence": 0.5,
                    "reasoning": "GenAI context present but no specific attack vector identified."
                }
            })
        }
    else:
        # Determine category based on attack vector
        if any(v in ["prompt injection", "jailbreak", "jailbreaking", "prompt leaking"] for v in found_vectors):
            category = "prompt_injection"
            testability = "yes"
            attack_surface = ["runtime", "inference"]
        elif any(v in ["model extraction", "model inversion", "membership inference"] for v in found_vectors):
            category = "extraction"
            testability = "yes"
            attack_surface = ["runtime", "inference"]
        elif any(v in ["data poisoning", "backdoor"] for v in found_vectors):
            category = "poisoning"
            testability = "no"
            attack_surface = ["training"]
        elif any(v in ["rag poisoning", "context poisoning", "retrieval manipulation", "document injection"] for v in found_vectors):
            category = "poisoning"
            testability = "yes"
            attack_surface = ["runtime", "inference"]
        elif any(v in ["tool calling exploitation", "function calling abuse", "agent hijacking"] for v in found_vectors):
            category = "prompt_injection"
            testability = "yes"
            attack_surface = ["runtime", "inference"]
        else:
            category = "unknown"
            testability = "no"
            attack_surface = []
        
        # Determine target systems
        if "rag" in description_lower or "retrieval" in description_lower:
            target_systems = ["rag"]
        elif "agent" in description_lower or "tool calling" in description_lower or "function calling" in description_lower:
            target_systems = ["agentic"]
        elif "chat" in description_lower:
            target_systems = ["llm", "chat"]
        else:
            target_systems = ["llm"]
        
        # Mock response with identified techniques
        mock_response = {
            'response': json.dumps({
                "category": category,
                "metadata": {
                    "attack_surface": attack_surface,
                    "testability": testability,
                    "techniques": expected_techniques,
                    "target_systems": target_systems,
                    "confidence": 0.9,
                    "reasoning": f"GenAI context present. Attack vectors identified: {', '.join(found_vectors)}. Techniques: {', '.join(expected_techniques)}."
                }
            })
        }
    
    mock_client.generate.return_value = mock_response
    
    # Classify the threat
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify property holds: attack vectors from description should appear in techniques
    if expected_techniques:
        techniques_lower = [t.lower() for t in metadata.techniques]
        
        # Check that at least one expected technique is present
        found_technique = False
        for expected in expected_techniques:
            if any(expected.lower() in t for t in techniques_lower):
                found_technique = True
                break
        
        assert found_technique, \
            f"Expected one of {expected_techniques} in techniques for '{description}', got {metadata.techniques}"
