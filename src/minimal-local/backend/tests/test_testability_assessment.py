"""
Unit tests for testability assessment.

Tests that runtime-testable GenAI attacks have testability set to "yes"
and that the reasoning field explains the testability decision.

Feature: llm-classification-improvements
Task: 6.1 - Write unit tests for runtime-testable attacks
"""
import pytest
import json
from unittest.mock import AsyncMock

from services.llm_classifier import classify_threat_with_metadata
from services.classification_types import ThreatMetadata


# ============================================================================
# Task 6.1: Unit tests for runtime-testable attacks
# ============================================================================

@pytest.mark.asyncio
async def test_prompt_injection_testability_yes():
    """
    Test that prompt injection has testability "yes".
    
    Prompt injection is a runtime-testable attack that can be tested
    by sending crafted prompts to the LLM system.
    
    Validates: Requirements 4.2, 4.5
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
                "reasoning": "GenAI context present (LLM, chat). Attack vector: prompt injection. Runtime testable - can be tested by sending crafted prompts to the system."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt injection attack targeting LLM chat system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Prompt injection should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None, \
        "Reasoning field should not be None"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"
    
    # Check that reasoning mentions testability or runtime testing
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_rag_poisoning_testability_yes():
    """
    Test that RAG poisoning has testability "yes".
    
    RAG poisoning is a runtime-testable attack that can be tested
    by injecting malicious documents and observing retrieval behavior.
    
    Validates: Requirements 4.2, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for RAG poisoning
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["context poisoning", "RAG poisoning"],
                "target_systems": ["rag"],
                "confidence": 0.93,
                "reasoning": "GenAI context present (RAG, retrieval). Attack vector: RAG poisoning. Runtime testable - can be tested by injecting malicious documents and observing retrieval behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "RAG poisoning attack on retrieval augmented generation system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "RAG poisoning should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None, \
        "Reasoning field should not be None"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"
    
    # Check that reasoning mentions testability or runtime testing
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_agent_behavior_exploitation_testability_yes():
    """
    Test that agent behavior exploitation has testability "yes".
    
    Agent behavior exploitation is a runtime-testable attack that can be
    tested by interacting with the agent and observing its behavior.
    
    Validates: Requirements 4.2, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for agent behavior exploitation
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["tool calling exploitation", "agent behavior exploitation"],
                "target_systems": ["agentic"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (AI agent, tool calling). Attack vector: agent behavior exploitation. Runtime testable - can be tested by interacting with the agent and observing tool calling behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Agent behavior exploitation attack on AI agent with tool calling"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Agent behavior exploitation should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None, \
        "Reasoning field should not be None"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"
    
    # Check that reasoning mentions testability or runtime testing
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_jailbreak_testability_yes():
    """
    Test that jailbreak attacks have testability "yes".
    
    Jailbreak is a runtime-testable attack that can be tested by
    sending crafted prompts designed to bypass safety guardrails.
    
    Validates: Requirements 4.2, 4.5
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
                "confidence": 0.94,
                "reasoning": "GenAI context present (LLM, chatbot). Attack vector: jailbreak. Runtime testable - can be tested by sending prompts designed to bypass safety guardrails."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Jailbreak attack on LLM chatbot to bypass safety guardrails"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Jailbreak should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_model_extraction_runtime_testability_yes():
    """
    Test that runtime model extraction has testability "yes".
    
    Model extraction via runtime queries is testable by sending
    queries to the model and analyzing responses.
    
    Validates: Requirements 4.2, 4.5
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
                "confidence": 0.91,
                "reasoning": "GenAI context present (LLM, model). Attack vector: model extraction via runtime queries. Runtime testable - can be tested by sending queries and analyzing responses."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model extraction attack via repeated runtime queries to LLM"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Runtime model extraction should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing", "queries"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_context_poisoning_testability_yes():
    """
    Test that context poisoning has testability "yes".
    
    Context poisoning in RAG systems is runtime-testable by injecting
    malicious context and observing model behavior.
    
    Validates: Requirements 4.2, 4.5
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
                "reasoning": "GenAI context present (RAG, context). Attack vector: context poisoning. Runtime testable - can be tested by injecting malicious context and observing model behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Context poisoning attack on RAG system"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Context poisoning should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_tool_calling_exploitation_testability_yes():
    """
    Test that tool calling exploitation has testability "yes".
    
    Tool calling exploitation is runtime-testable by interacting with
    the agent and observing tool invocations.
    
    Validates: Requirements 4.2, 4.5
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
                "reasoning": "GenAI context present (agent, tool calling). Attack vector: tool calling exploitation. Runtime testable - can be tested by interacting with agent and observing tool invocations."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Tool calling exploitation attack on AI agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Tool calling exploitation should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_function_calling_abuse_testability_yes():
    """
    Test that function calling abuse has testability "yes".
    
    Function calling abuse is runtime-testable by interacting with
    the agent and observing function invocations.
    
    Validates: Requirements 4.2, 4.5
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
                "reasoning": "GenAI context present (agent, function calling). Attack vector: function calling abuse. Runtime testable - can be tested by interacting with agent and observing function invocations."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Function calling abuse in AI agent with function calling capabilities"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Function calling abuse should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_prompt_leaking_testability_yes():
    """
    Test that prompt leaking has testability "yes".
    
    Prompt leaking is runtime-testable by sending crafted prompts
    designed to extract system prompts.
    
    Validates: Requirements 4.2, 4.5
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
                "confidence": 0.90,
                "reasoning": "GenAI context present (LLM, system prompt). Attack vector: prompt leaking. Runtime testable - can be tested by sending crafted prompts to extract system prompts."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Prompt leaking vulnerability in LLM system prompt"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Prompt leaking should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_retrieval_manipulation_testability_yes():
    """
    Test that retrieval manipulation has testability "yes".
    
    Retrieval manipulation is runtime-testable by manipulating queries
    and observing retrieval results.
    
    Validates: Requirements 4.2, 4.5
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
                "reasoning": "GenAI context present (RAG, retrieval). Attack vector: retrieval manipulation. Runtime testable - can be tested by manipulating queries and observing retrieval results."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Retrieval manipulation attack on RAG vector database"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Retrieval manipulation should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_multiple_runtime_testable_attacks():
    """
    Test that multiple runtime-testable attacks all have testability "yes".
    
    When a threat description contains multiple runtime-testable attack
    vectors, testability should still be "yes".
    
    Validates: Requirements 4.2, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response with multiple runtime-testable techniques
    mock_response = {
        'response': json.dumps({
            "category": "prompt_injection",
            "metadata": {
                "attack_surface": ["runtime", "inference"],
                "testability": "yes",
                "techniques": ["prompt injection", "jailbreak", "tool calling exploitation"],
                "target_systems": ["llm", "agentic"],
                "confidence": 0.94,
                "reasoning": "GenAI context present (LLM, agent). Multiple runtime-testable attack vectors: prompt injection, jailbreak, and tool calling exploitation. All can be tested at runtime."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Combined prompt injection, jailbreak, and tool calling exploitation on LLM agent"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Multiple runtime-testable attacks should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_inference_time_attack_testability_yes():
    """
    Test that inference-time attacks have testability "yes".
    
    Inference-time attacks are runtime-testable as they occur during
    model inference.
    
    Validates: Requirements 4.2, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for inference-time attack
    mock_response = {
        'response': json.dumps({
            "category": "adversarial",
            "metadata": {
                "attack_surface": ["inference"],
                "testability": "yes",
                "techniques": ["adversarial example"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (LLM, inference). Attack vector: adversarial example at inference time. Runtime testable - can be tested by sending adversarial inputs during inference."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial example attack during LLM inference"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "yes"
    assert metadata.testability == "yes", \
        "Inference-time attacks should have testability 'yes'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    testability_keywords = ["testable", "runtime", "test", "testing", "inference"]
    assert any(keyword in reasoning_lower for keyword in testability_keywords), \
        f"Reasoning should explain testability, got: {metadata.reasoning}"


# ============================================================================
# Task 6.2: Unit tests for non-runtime attacks
# ============================================================================

@pytest.mark.asyncio
async def test_training_data_poisoning_testability_no():
    """
    Test that training-time data poisoning has testability "no".
    
    Training-time data poisoning is not runtime-testable because it
    occurs during model training, not during inference/runtime.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for training-time data poisoning
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["data poisoning", "training data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.92,
                "reasoning": "GenAI context present (LLM, training data). Attack vector: training-time data poisoning. Not runtime testable - occurs during model training phase, not during inference."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Training-time data poisoning attack on LLM training dataset"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Training-time data poisoning should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None, \
        "Reasoning field should not be None"
    assert len(metadata.reasoning) >= 20, \
        "Reasoning should be at least 20 characters"
    
    # Check that reasoning mentions non-testability or training-time
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "training", "training-time", "training phase"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_backdoor_attack_testability_no():
    """
    Test that backdoor attacks during training have testability "no".
    
    Backdoor attacks are injected during training and are not
    runtime-testable in the traditional sense.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for backdoor attack
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["backdoor attack", "trigger injection"],
                "target_systems": ["llm"],
                "confidence": 0.91,
                "reasoning": "GenAI context present (LLM, model training). Attack vector: backdoor attack with trigger injection. Not runtime testable - backdoor is embedded during training, requires access to training process."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Backdoor attack injected during LLM training with trigger patterns"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Backdoor attacks should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "training", "embedded during training"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_supply_chain_attack_testability_no():
    """
    Test that supply chain attacks have testability "no".
    
    Supply chain attacks target the model distribution and deployment
    pipeline, not the runtime behavior.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for supply chain attack
    mock_response = {
        'response': json.dumps({
            "category": "supply_chain",
            "metadata": {
                "attack_surface": ["deployment"],
                "testability": "no",
                "techniques": ["supply chain attack", "model tampering"],
                "target_systems": ["llm"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (LLM, model distribution). Attack vector: supply chain attack. Not runtime testable - targets model distribution pipeline, not runtime behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Supply chain attack targeting LLM model distribution pipeline"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Supply chain attacks should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "supply chain", "distribution", "pipeline"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_model_weights_tampering_testability_no():
    """
    Test that model weights tampering has testability "no".
    
    Tampering with model weights is a supply chain attack that
    is not runtime-testable.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for model weights tampering
    mock_response = {
        'response': json.dumps({
            "category": "supply_chain",
            "metadata": {
                "attack_surface": ["deployment"],
                "testability": "no",
                "techniques": ["model tampering", "weight modification"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (LLM, model weights). Attack vector: model weights tampering. Not runtime testable - requires access to model files, not testable through runtime interaction."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model weights tampering attack on LLM checkpoint files"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Model weights tampering should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "model files", "not testable through runtime"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_web_vulnerability_xss_testability_no():
    """
    Test that XSS web vulnerabilities have testability "no".
    
    Traditional web vulnerabilities like XSS are not GenAI-specific
    and are not testable in a GenAI runtime environment.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for XSS web vulnerability
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.95,
                "reasoning": "Traditional web vulnerability, not GenAI-specific. XSS attack without GenAI context. Not runtime testable in GenAI environment - this is a web application vulnerability."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Cross-site scripting (XSS) vulnerability in web form"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "XSS web vulnerabilities should have testability 'no'"
    
    # Verify category is "unknown" for web vulnerabilities
    assert category == "unknown", \
        "Web vulnerabilities should be classified as 'unknown'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    # Should mention both web vulnerability and not testable
    assert "web vulnerability" in reasoning_lower or "traditional" in reasoning_lower, \
        f"Reasoning should mention web vulnerability, got: {metadata.reasoning}"
    assert "not" in reasoning_lower and ("testable" in reasoning_lower or "genai" in reasoning_lower), \
        f"Reasoning should explain not testable in GenAI context, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_web_vulnerability_sqli_testability_no():
    """
    Test that SQL injection web vulnerabilities have testability "no".
    
    SQL injection is a traditional web vulnerability, not a GenAI threat,
    and is not testable in a GenAI runtime environment.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for SQL injection
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.94,
                "reasoning": "Traditional web vulnerability, not GenAI-specific. SQL injection without GenAI context. Not runtime testable in GenAI environment - this is a database/web application vulnerability."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "SQL injection vulnerability in authentication endpoint"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "SQL injection should have testability 'no'"
    
    # Verify category is "unknown"
    assert category == "unknown", \
        "Web vulnerabilities should be classified as 'unknown'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    assert "web vulnerability" in reasoning_lower or "traditional" in reasoning_lower, \
        f"Reasoning should mention web vulnerability, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_web_vulnerability_csrf_testability_no():
    """
    Test that CSRF web vulnerabilities have testability "no".
    
    CSRF is a traditional web vulnerability, not a GenAI threat.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for CSRF
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": [],
                "testability": "no",
                "techniques": [],
                "target_systems": [],
                "confidence": 0.93,
                "reasoning": "Traditional web vulnerability, not GenAI-specific. CSRF attack without GenAI context. Not runtime testable in GenAI environment."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Cross-Site Request Forgery (CSRF) vulnerability in API"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "CSRF should have testability 'no'"
    
    # Verify category is "unknown"
    assert category == "unknown"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20


@pytest.mark.asyncio
async def test_infrastructure_attack_testability_no():
    """
    Test that infrastructure attacks have testability "no".
    
    Infrastructure attacks target the underlying infrastructure,
    not the GenAI runtime behavior.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for infrastructure attack
    mock_response = {
        'response': json.dumps({
            "category": "unknown",
            "metadata": {
                "attack_surface": ["deployment"],
                "testability": "no",
                "techniques": ["infrastructure attack"],
                "target_systems": [],
                "confidence": 0.70,
                "reasoning": "Infrastructure-level attack. Not runtime testable in GenAI environment - targets underlying infrastructure, not model behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Infrastructure attack targeting LLM deployment servers"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Infrastructure attacks should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "infrastructure"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_model_architecture_modification_testability_no():
    """
    Test that model architecture modifications have testability "no".
    
    Modifying model architecture is not a runtime attack and cannot
    be tested through runtime interaction.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for architecture modification
    mock_response = {
        'response': json.dumps({
            "category": "supply_chain",
            "metadata": {
                "attack_surface": ["training", "deployment"],
                "testability": "no",
                "techniques": ["model architecture modification"],
                "target_systems": ["llm"],
                "confidence": 0.88,
                "reasoning": "GenAI context present (LLM, model architecture). Attack vector: model architecture modification. Not runtime testable - requires access to model definition, not testable through runtime queries."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Model architecture modification attack on neural network structure"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Model architecture modifications should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "architecture", "model definition"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_label_flipping_attack_testability_no():
    """
    Test that label flipping attacks have testability "no".
    
    Label flipping is a training-time attack that is not runtime-testable.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for label flipping
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["label flipping", "training data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.90,
                "reasoning": "GenAI context present (LLM, training). Attack vector: label flipping during training. Not runtime testable - occurs during training phase, affects model learning."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Label flipping attack on LLM training labels"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Label flipping should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "training"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"


@pytest.mark.asyncio
async def test_adversarial_training_attack_testability_no():
    """
    Test that adversarial training attacks have testability "no".
    
    Adversarial training attacks occur during the training phase
    and are not runtime-testable.
    
    Validates: Requirements 4.3, 4.5
    """
    mock_client = AsyncMock()
    
    # Mock LLM response for adversarial training
    mock_response = {
        'response': json.dumps({
            "category": "poisoning",
            "metadata": {
                "attack_surface": ["training"],
                "testability": "no",
                "techniques": ["adversarial training", "training data poisoning"],
                "target_systems": ["llm"],
                "confidence": 0.89,
                "reasoning": "GenAI context present (LLM, adversarial training). Attack vector: adversarial training attack. Not runtime testable - manipulates training process, not inference behavior."
            }
        })
    }
    mock_client.generate.return_value = mock_response
    
    description = "Adversarial training attack manipulating LLM training process"
    category, metadata = await classify_threat_with_metadata(description, mock_client)
    
    # Verify testability is "no"
    assert metadata.testability == "no", \
        "Adversarial training attacks should have testability 'no'"
    
    # Verify reasoning explains testability
    assert metadata.reasoning is not None
    assert len(metadata.reasoning) >= 20
    
    reasoning_lower = metadata.reasoning.lower()
    non_testability_keywords = ["not runtime testable", "not testable", "training"]
    assert any(keyword in reasoning_lower for keyword in non_testability_keywords), \
        f"Reasoning should explain why not runtime testable, got: {metadata.reasoning}"
