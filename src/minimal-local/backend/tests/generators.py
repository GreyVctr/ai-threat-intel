"""
Custom Hypothesis strategies for generating threat descriptions.

These generators create threat descriptions with specific characteristics
for property-based testing of the LLM classification improvements.

Feature: llm-classification-improvements
"""
from hypothesis import strategies as st


# Web vulnerability indicators (without GenAI context)
WEB_VULNERABILITY_TYPES = [
    "XSS",
    "Cross-site scripting",
    "SQL injection",
    "SQLi",
    "CSRF",
    "Cross-site request forgery",
    "SSRF",
    "Server-side request forgery",
    "XXE",
    "XML external entity",
    "Path traversal",
    "Directory traversal",
    "IDOR",
    "Insecure direct object reference",
    "Authentication bypass",
    "Session hijacking",
]

WEB_VULNERABILITY_CONTEXTS = [
    "in web form",
    "in login page",
    "in API endpoint",
    "in authentication system",
    "in web application",
    "vulnerability",
    "exploit",
    "in user input field",
    "in HTTP request",
    "in cookie handling",
]


# GenAI attack vectors
GENAI_ATTACK_VECTORS = [
    "Prompt injection",
    "Jailbreak",
    "Jailbreaking",
    "Model extraction",
    "Model inversion",
    "Membership inference",
    "Data poisoning",
    "Backdoor attack",
    "RAG poisoning",
    "Context poisoning",
    "Retrieval manipulation",
    "Document injection",
    "Tool calling exploitation",
    "Function calling abuse",
    "Agent hijacking",
    "Prompt leaking",
    "System prompt extraction",
]


# GenAI context indicators
GENAI_MODEL_INDICATORS = [
    "LLM",
    "language model",
    "GPT",
    "transformer",
    "BERT",
    "neural network",
    "AI model",
    "machine learning model",
    "deep learning model",
]

GENAI_INTERACTION_INDICATORS = [
    "prompt",
    "chat",
    "chatbot",
    "conversation",
    "completion",
    "generation",
    "inference",
    "query",
    "response",
]

GENAI_ARCHITECTURE_INDICATORS = [
    "embedding",
    "vector",
    "RAG",
    "retrieval",
    "fine-tuning",
    "RLHF",
    "alignment",
    "training data",
    "model weights",
]

GENAI_SYSTEM_INDICATORS = [
    "agent",
    "AI agent",
    "tool calling",
    "function calling",
    "multi-agent",
    "autonomous",
    "AI system",
]


# Ambiguous/generic terms
GENERIC_TERMS = [
    "vulnerability",
    "attack",
    "security issue",
    "exploit",
    "threat",
    "weakness",
    "flaw",
]


@st.composite
def web_vulnerability_descriptions(draw):
    """
    Generate threat descriptions with web vulnerability indicators.
    
    These descriptions contain traditional web vulnerability keywords
    WITHOUT GenAI context indicators, and should be classified as "unknown".
    
    Examples:
    - "XSS vulnerability in web form"
    - "SQL injection in login page"
    - "CSRF token bypass in authentication system"
    """
    vuln_type = draw(st.sampled_from(WEB_VULNERABILITY_TYPES))
    context = draw(st.sampled_from(WEB_VULNERABILITY_CONTEXTS))
    
    # Randomly choose format
    format_choice = draw(st.integers(min_value=0, max_value=2))
    
    if format_choice == 0:
        return f"{vuln_type} {context}"
    elif format_choice == 1:
        return f"{vuln_type} vulnerability {context}"
    else:
        return f"Detected {vuln_type} {context}"


@st.composite
def genai_threat_descriptions(draw):
    """
    Generate threat descriptions with GenAI context and attack vectors.
    
    These descriptions contain both GenAI attack vectors AND GenAI context
    indicators (model/interaction/architecture/system terms).
    
    Examples:
    - "Prompt injection attack targeting LLM"
    - "Jailbreak attempt on GPT chatbot"
    - "RAG poisoning in retrieval system"
    """
    attack = draw(st.sampled_from(GENAI_ATTACK_VECTORS))
    
    # Choose a context indicator category
    context_category = draw(st.integers(min_value=0, max_value=3))
    
    if context_category == 0:
        context = draw(st.sampled_from(GENAI_MODEL_INDICATORS))
    elif context_category == 1:
        context = draw(st.sampled_from(GENAI_INTERACTION_INDICATORS))
    elif context_category == 2:
        context = draw(st.sampled_from(GENAI_ARCHITECTURE_INDICATORS))
    else:
        context = draw(st.sampled_from(GENAI_SYSTEM_INDICATORS))
    
    # Randomly choose format
    format_choice = draw(st.integers(min_value=0, max_value=3))
    
    if format_choice == 0:
        return f"{attack} attack targeting {context}"
    elif format_choice == 1:
        return f"{attack} in {context} system"
    elif format_choice == 2:
        return f"{attack} vulnerability affecting {context}"
    else:
        return f"Detected {attack} attack on {context}"


@st.composite
def mixed_threat_descriptions(draw):
    """
    Generate threat descriptions with both web and GenAI indicators.
    
    These descriptions contain BOTH web vulnerability keywords AND GenAI
    context, with varying primary attack vectors. The classifier should
    classify based on the primary attack vector.
    
    Examples:
    - "XSS vulnerability in LLM chat interface"
    - "Prompt injection via SQL injection vector"
    - "CSRF in AI agent tool calling system"
    """
    web_vuln = draw(st.sampled_from(WEB_VULNERABILITY_TYPES))
    genai_attack = draw(st.sampled_from(GENAI_ATTACK_VECTORS))
    genai_context = draw(st.sampled_from(
        GENAI_MODEL_INDICATORS + 
        GENAI_INTERACTION_INDICATORS + 
        GENAI_ARCHITECTURE_INDICATORS + 
        GENAI_SYSTEM_INDICATORS
    ))
    
    # Randomly choose which is primary
    primary_is_web = draw(st.booleans())
    
    if primary_is_web:
        # Web vulnerability is primary
        return f"{web_vuln} vulnerability in {genai_context} system"
    else:
        # GenAI attack is primary
        return f"{genai_attack} attack exploiting {web_vuln} in {genai_context}"


@st.composite
def ambiguous_threat_descriptions(draw):
    """
    Generate vague threat descriptions without clear indicators.
    
    These descriptions use only generic terms without specific web
    vulnerability or GenAI context indicators. Should be classified
    as "unknown" or with low confidence.
    
    Examples:
    - "Security vulnerability detected"
    - "System attack identified"
    - "Potential threat in application"
    """
    term1 = draw(st.sampled_from(GENERIC_TERMS))
    term2 = draw(st.sampled_from(GENERIC_TERMS))
    
    # Randomly choose format
    format_choice = draw(st.integers(min_value=0, max_value=3))
    
    if format_choice == 0:
        return f"{term1} detected"
    elif format_choice == 1:
        return f"Potential {term1} in system"
    elif format_choice == 2:
        return f"{term1} and {term2} identified"
    else:
        return f"Security {term1}"


@st.composite
def semantic_similarity_pairs(draw):
    """
    Generate pairs of semantically similar threat descriptions.
    
    These pairs describe the same threat with varied wording. The classifier
    should produce consistent classifications for both descriptions.
    
    Returns: tuple of (description1, description2)
    
    Examples:
    - ("Jailbreak attack on GPT", "GPT jailbreaking vulnerability")
    - ("Prompt injection in LLM", "LLM prompt injection attack")
    """
    attack = draw(st.sampled_from(GENAI_ATTACK_VECTORS))
    context = draw(st.sampled_from(
        GENAI_MODEL_INDICATORS + 
        GENAI_INTERACTION_INDICATORS + 
        GENAI_ARCHITECTURE_INDICATORS + 
        GENAI_SYSTEM_INDICATORS
    ))
    
    # Create two variations of the same threat
    desc1 = f"{attack} attack on {context}"
    desc2 = f"{context} {attack} vulnerability"
    
    return (desc1, desc2)


@st.composite
def length_variation_triplets(draw):
    """
    Generate short, medium, and long versions of the same threat.
    
    These triplets describe the same threat at different levels of detail.
    The classifier should produce consistent classifications across all
    length variations.
    
    Returns: tuple of (short, medium, long)
    
    Examples:
    - ("Prompt injection", 
       "Prompt injection attack targeting LLM",
       "A sophisticated prompt injection attack that targets large language models...")
    """
    attack = draw(st.sampled_from(GENAI_ATTACK_VECTORS))
    context = draw(st.sampled_from(GENAI_MODEL_INDICATORS))
    
    # Short version (just the attack)
    short = attack
    
    # Medium version (attack + context)
    medium = f"{attack} attack targeting {context}"
    
    # Long version (detailed description)
    long = (
        f"A sophisticated {attack.lower()} attack that targets {context} systems. "
        f"This threat exploits vulnerabilities in the {context.lower()} to compromise "
        f"security and integrity. The attack vector involves manipulating inputs to "
        f"achieve unauthorized access or behavior modification."
    )
    
    return (short, medium, long)


@st.composite
def runtime_testable_threats(draw):
    """
    Generate threat descriptions for runtime-testable attacks.
    
    These threats can be tested in a GenAI runtime environment and should
    have testability set to "yes".
    
    Examples:
    - "Prompt injection in LLM chat"
    - "RAG poisoning attack"
    - "Agent behavior exploitation"
    """
    runtime_attacks = [
        "Prompt injection",
        "Jailbreak",
        "Prompt leaking",
        "RAG poisoning",
        "Context poisoning",
        "Model extraction",
        "Agent behavior exploitation",
        "Tool calling exploitation",
        "Function calling abuse",
    ]
    
    attack = draw(st.sampled_from(runtime_attacks))
    context = draw(st.sampled_from(
        GENAI_MODEL_INDICATORS + 
        GENAI_INTERACTION_INDICATORS + 
        GENAI_ARCHITECTURE_INDICATORS + 
        GENAI_SYSTEM_INDICATORS
    ))
    
    return f"{attack} attack on {context}"


@st.composite
def non_runtime_testable_threats(draw):
    """
    Generate threat descriptions for non-runtime attacks.
    
    These threats cannot be tested in a GenAI runtime environment and should
    have testability set to "no".
    
    Examples:
    - "Training data poisoning attack"
    - "Supply chain backdoor in model"
    - "Infrastructure attack on training pipeline"
    """
    non_runtime_attacks = [
        "Training data poisoning",
        "Backdoor attack during training",
        "Supply chain attack",
        "Model architecture modification",
        "Infrastructure attack",
        "Label flipping during training",
    ]
    
    attack = draw(st.sampled_from(non_runtime_attacks))
    
    contexts = [
        "in training pipeline",
        "during model training",
        "in model supply chain",
        "in training infrastructure",
        "affecting training data",
    ]
    
    context = draw(st.sampled_from(contexts))
    
    return f"{attack} {context}"


@st.composite
def conditional_testable_threats(draw):
    """
    Generate threat descriptions for conditionally testable attacks.
    
    These threats require specific configurations to test and should
    have testability set to "conditional".
    
    Examples:
    - "Attack requiring specific model configuration"
    - "Threat dependent on RAG setup"
    """
    conditional_contexts = [
        "requiring specific model configuration",
        "dependent on RAG setup",
        "requiring specific agent configuration",
        "dependent on fine-tuning setup",
        "requiring specific system configuration",
    ]
    
    attack = draw(st.sampled_from(GENAI_ATTACK_VECTORS))
    context = draw(st.sampled_from(conditional_contexts))
    
    return f"{attack} attack {context}"
