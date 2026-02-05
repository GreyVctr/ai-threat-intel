"""
LLM-based threat classification using Ollama.

This module implements threat classification using a large language model
(Ollama with qwen2.5:7b) for cases where keyword matching has low confidence
or requires validation.
"""
import logging
import httpx
import re
from typing import List, Optional

from services.classification_types import LLMResult
from services.classification_config import ClassificationConfig

logger = logging.getLogger(__name__)


METADATA_EXTRACTION_PROMPT = """You are a security expert specializing in GenAI threat classification. Your task is to analyze threat descriptions and distinguish between traditional web vulnerabilities and GenAI-specific threats.

Follow this multi-stage analysis process:

## STAGE 1: GenAI Context Validation (CHECK THIS FIRST!)

**CRITICAL**: Check for GenAI-specific context indicators BEFORE anything else:

**Model-related**: LLM, language model, GPT, transformer, BERT, neural network, machine learning model, AI model, deep learning, model weights, parameters, gradients

**Interaction-related**: prompt, chat, conversation, completion, generation, inference, query, response, prediction

**Architecture-related**: embedding, vector, RAG, retrieval, fine-tuning, RLHF, alignment, training data, model weights, unlearning, forgetting

**Attack-related**: extraction, membership inference, model inversion, model stealing, adversarial examples, jailbreak, prompt injection, data poisoning, backdoor

**System-related**: agent, tool calling, function calling, multi-agent, autonomous, AI system, chatbot

**Decision Rules**:
- If ANY of the above indicators are present → This IS a GenAI threat, proceed to Stage 3
- If MULTIPLE indicators are present → High confidence GenAI threat, proceed to Stage 3
- If NO indicators are present → Check Stage 2 for web vulnerabilities

## STAGE 2: Web Vulnerability Exclusion (ONLY if NO GenAI context found)

Only reach this stage if Stage 1 found NO GenAI context.

Check if this is a traditional web application vulnerability:
- XSS (Cross-Site Scripting)
- SQLi (SQL Injection)
- CSRF (Cross-Site Request Forgery)
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Path traversal / Directory traversal
- IDOR (Insecure Direct Object Reference)
- Authentication bypass
- Session hijacking

If it's a web vulnerability AND Stage 1 found NO GenAI context:
- Set category to "unknown"
- Set target_systems to []
- Set testability to "no"
- Include reasoning: "Traditional web vulnerability, not GenAI-specific"

## STAGE 3: GenAI Attack Vector Identification

Identify specific attack techniques (you reached this stage because Stage 1 found GenAI context):

**Prompt Manipulation**: prompt injection, jailbreak, prompt leaking, system prompt extraction, delimiter injection

**Model Behavior Exploitation**: model extraction, model inversion, membership inference, model stealing, reverse engineering, unlearning attacks, forgetting attacks

**Training Data Attacks**: data poisoning, backdoor attacks, adversarial training, label flipping, trigger injection

**RAG Manipulation**: context poisoning, retrieval manipulation, document injection, knowledge base poisoning, vector database manipulation

**Agent Misuse**: tool calling exploitation, function calling abuse, action hijacking, multi-agent manipulation, autonomous behavior exploitation

**Privacy Attacks**: data extraction, training data leakage, model memorization, privacy violations

Include ALL identified attack vectors in the "techniques" field.

## STAGE 4: Testability Determination

Determine if the threat can be tested in a GenAI runtime environment:

**IMPORTANT**: Focus on the ATTACK TECHNIQUE described, not whether it's a research paper or deployed threat.

**"yes"** - Runtime-testable attacks (can test by querying/interacting with deployed model):
- Prompt injection, jailbreak, prompt leaking
- RAG poisoning, context manipulation
- Model extraction via runtime queries (membership inference, model inversion, unlearning attacks)
- Agent behavior exploitation
- Tool/function calling abuse
- Inference-time attacks
- Adversarial examples (input perturbations)
- Privacy attacks via queries (data extraction, memorization testing)
- **Research papers describing any of the above** → "yes" (the attack IS testable even if paper is theoretical)

**"no"** - Non-runtime attacks (requires training access or infrastructure):
- Training-time attacks (data poisoning, backdoors during training)
- Supply chain attacks (compromised model repositories)
- Web vulnerabilities (XSS, SQLi, CSRF)
- Infrastructure attacks (server compromise)
- Model architecture modifications (requires retraining)
- **Research papers about training/supply chain** → "no"
- **Theoretical analysis without attack techniques** → "no"

**"conditional"** - Configuration-dependent attacks:
- Requires specific model configurations
- Requires specific RAG setups
- Requires specific agent configurations
- Requires specific fine-tuning setups
- **Research papers about configuration-specific attacks** → "conditional"

**Key Examples for Unlearning/Extraction**:
- Paper about "unlearning" or "forgetting" that measures "extraction strength" → "yes" (testing extraction attacks)
- Paper about "model inversion" or "membership inference" → "yes" (runtime extraction attacks)
- Paper about "data poisoning during training" → "no" (training-time attack)

## STAGE 5: Category Assignment

Based on the analysis, assign the primary category:
- **prompt_injection**: Prompt manipulation attacks
- **extraction**: Model extraction, inversion, membership inference, unlearning attacks, privacy attacks
- **poisoning**: Data poisoning, backdoors, training attacks
- **adversarial**: Adversarial examples, evasion attacks
- **privacy**: Privacy violations, data leakage (use "extraction" if it involves model extraction)
- **fairness**: Bias, discrimination issues
- **robustness**: Model robustness issues
- **supply_chain**: Supply chain attacks
- **unknown**: ONLY if Stage 1 found NO GenAI context AND it's a web vulnerability

---

Threat Description:
{description}

---

YOU MUST RESPOND WITH VALID JSON ONLY. DO NOT include any explanatory text before or after the JSON.

Your response must be EXACTLY in this format:

{{"category": "prompt_injection", "metadata": {{"attack_surface": ["runtime"], "testability": "yes", "techniques": ["jailbreak"], "target_systems": ["llm"], "confidence": 0.8, "reasoning": "This is a GenAI-specific prompt injection attack that can be tested at runtime."}}}}

CRITICAL JSON REQUIREMENTS:
1. Response must be VALID JSON starting with {{ and ending with }}
2. Use double quotes for all strings
3. testability must be one of: "yes", "no", "conditional"
4. target_systems must ONLY contain: "llm", "vision", "multimodal", "rag", "agentic", "chat"
5. target_systems must be [] for web vulnerabilities
6. target_systems must have AT LEAST ONE value for GenAI threats
7. reasoning must be AT LEAST 20 characters
8. confidence must be a number between 0.0 and 1.0
9. DO NOT add any text before or after the JSON

Now analyze the threat and respond with JSON:"""


class LLMClassifier:
    """
    Classifies threats using Ollama LLM.
    
    The LLMClassifier interfaces with the Ollama API to classify threat
    descriptions when keyword matching has insufficient confidence. It
    constructs prompts that guide the LLM to select from valid threat types
    and parses the responses to extract the classification.
    
    Configuration is loaded from ClassificationConfig, which reads from
    environment variables (OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT).
    
    Attributes:
        ollama_url: Ollama API URL (from ClassificationConfig)
        model: Model name to use (from ClassificationConfig)
        timeout: Request timeout in seconds (from ClassificationConfig)
        client: Async HTTP client for API calls
    """
    
    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        """
        Initialize LLM classifier.
        
        Args:
            ollama_url: Ollama API URL (defaults to ClassificationConfig.OLLAMA_URL)
            model: Model name to use (defaults to ClassificationConfig.OLLAMA_MODEL)
            timeout: Request timeout in seconds (defaults to ClassificationConfig.OLLAMA_TIMEOUT)
        """
        self.ollama_url = (ollama_url or ClassificationConfig.OLLAMA_URL).rstrip('/')
        self.model = model or ClassificationConfig.OLLAMA_MODEL
        self.timeout = timeout or ClassificationConfig.OLLAMA_TIMEOUT
        self.client = httpx.AsyncClient(timeout=self.timeout)
        
        logger.info(
            f"Initialized LLM classifier: {self.ollama_url}, "
            f"model={self.model}, timeout={self.timeout}s"
        )
    
    async def classify(
        self,
        description: str,
        valid_types: List[str],
        context: Optional[str] = None
    ) -> LLMResult:
        """
        Classify threat using LLM.
        
        Sends the threat description to the Ollama LLM with a carefully
        constructed prompt that guides the model to select from the valid
        threat types. Handles errors gracefully and returns structured results.
        
        Args:
            description: Threat description text to classify
            valid_types: List of valid threat type strings
            context: Optional context from keyword matching (e.g., "keyword analysis suggests: adversarial")
            
        Returns:
            LLMResult with:
                - threat_type: The classified threat type
                - raw_response: Complete LLM response text
                - success: True if classification succeeded
                - error: Error message if classification failed
            
        Raises:
            ConnectionError: When Ollama service is unavailable
            TimeoutError: When request exceeds timeout
        """
        logger.info(f"Classifying threat with LLM (description length: {len(description)} chars)")
        
        # Build the prompt
        prompt = self._build_prompt(description, valid_types, context)
        
        # Prepare request payload
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        try:
            # Make request to Ollama
            response = await self.client.post(
                f"{self.ollama_url}/api/generate",
                json=payload
            )
            
            # Check response status
            if response.status_code == 404:
                error_msg = f"Model '{self.model}' not found. Please pull the model first."
                logger.error(error_msg)
                return LLMResult(
                    threat_type="unknown",
                    raw_response="",
                    success=False,
                    error=error_msg
                )
            
            if response.status_code != 200:
                error_msg = f"Ollama request failed with status {response.status_code}: {response.text}"
                logger.error(error_msg)
                return LLMResult(
                    threat_type="unknown",
                    raw_response="",
                    success=False,
                    error=error_msg
                )
            
            # Parse response
            result = response.json()
            
            # Validate response structure
            if 'response' not in result:
                error_msg = "Invalid Ollama response: missing 'response' field"
                logger.error(error_msg)
                return LLMResult(
                    threat_type="unknown",
                    raw_response="",
                    success=False,
                    error=error_msg
                )
            
            raw_response = result['response']
            
            # Parse the threat type from the response
            threat_type = self._parse_response(raw_response, valid_types)
            
            # Check if parsing resulted in "unknown" (invalid response)
            if threat_type == "unknown":
                error_msg = f"LLM returned invalid or unparseable threat type from response: {raw_response[:100]}"
                logger.warning(error_msg)
                return LLMResult(
                    threat_type="unknown",
                    raw_response=raw_response,
                    success=False,
                    error=error_msg
                )
            
            # Verify the parsed type is in valid types
            if threat_type not in valid_types:
                error_msg = f"LLM returned invalid threat type: {threat_type}"
                logger.warning(error_msg)
                return LLMResult(
                    threat_type="unknown",
                    raw_response=raw_response,
                    success=False,
                    error=error_msg
                )
            
            logger.info(f"LLM classified threat as: {threat_type}")
            
            return LLMResult(
                threat_type=threat_type,
                raw_response=raw_response,
                success=True,
                error=None
            )
            
        except httpx.ConnectError as e:
            error_msg = f"Failed to connect to Ollama at {self.ollama_url}: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        
        except httpx.TimeoutException as e:
            error_msg = f"Ollama request timed out after {self.timeout}s"
            logger.error(error_msg)
            raise TimeoutError(error_msg) from e
        
        except httpx.HTTPError as e:
            error_msg = f"HTTP error communicating with Ollama: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        
        except Exception as e:
            error_msg = f"Unexpected error during LLM classification: {str(e)}"
            logger.error(error_msg)
            return LLMResult(
                threat_type="unknown",
                raw_response="",
                success=False,
                error=error_msg
            )
    
    def _build_prompt(
        self,
        description: str,
        valid_types: List[str],
        context: Optional[str]
    ) -> str:
        """
        Build classification prompt for LLM.
        
        Constructs a carefully engineered prompt that guides the LLM to
        classify the threat into one of the valid types. The prompt includes
        the threat description, valid categories, and optional context from
        keyword matching.
        
        Args:
            description: Threat description text
            valid_types: List of valid threat type strings
            context: Optional context from keyword matching
            
        Returns:
            Formatted prompt string for the LLM
        """
        prompt = f"""You are a threat classification expert for AI/ML systems.

Classify the following threat description into ONE of these categories:
{', '.join(valid_types)}

Threat Description:
{description}

"""
        if context:
            prompt += f"""
Keyword Analysis Context:
{context}

"""
        
        prompt += """Respond with ONLY the category name, nothing else.
If uncertain, choose the most likely category.

Category:"""
        
        return prompt
    
    def _parse_response(self, response: str, valid_types: List[str]) -> str:
        """
        Extract threat type from LLM response.
        
        Parses the LLM's response text to extract the threat type classification.
        Handles various response formats and attempts to match against valid types.
        
        Args:
            response: Raw response text from LLM
            valid_types: List of valid threat type strings
            
        Returns:
            Extracted threat type string, or "unknown" if parsing fails
        """
        # Clean up the response
        response = response.strip().lower()
        
        # Remove common prefixes/suffixes
        response = re.sub(r'^(category:|classification:|answer:|result:)\s*', '', response, flags=re.IGNORECASE)
        response = response.strip()
        
        # Try exact match first (case-insensitive)
        for valid_type in valid_types:
            if response == valid_type.lower():
                return valid_type
        
        # Try to find valid type as substring in response
        for valid_type in valid_types:
            if valid_type.lower() in response:
                return valid_type
        
        # Try to extract first word
        first_word = response.split()[0] if response.split() else ""
        for valid_type in valid_types:
            if first_word == valid_type.lower():
                return valid_type
        
        # If no match found, return unknown
        logger.warning(f"Could not parse threat type from response: {response}")
        return "unknown"
    
    async def generate(
        self,
        prompt: str,
        options: Optional[dict] = None
    ) -> dict:
        """
        Generate text using the LLM.
        
        This method provides a generic interface for text generation,
        used by the metadata extraction functionality.
        
        Args:
            prompt: The prompt text to send to the LLM
            options: Optional generation options (e.g., temperature)
            
        Returns:
            Dictionary with 'response' key containing the generated text
            
        Raises:
            ConnectionError: When Ollama service is unavailable
            TimeoutError: When request exceeds timeout
        """
        logger.debug(f"Generating text with LLM (prompt length: {len(prompt)} chars)")
        
        # Prepare request payload
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        # Add options if provided
        if options:
            payload["options"] = options
        
        try:
            # Make request to Ollama
            response = await self.client.post(
                f"{self.ollama_url}/api/generate",
                json=payload
            )
            
            # Check response status
            if response.status_code == 404:
                error_msg = f"Model '{self.model}' not found. Please pull the model first."
                logger.error(error_msg)
                raise ConnectionError(error_msg)
            
            if response.status_code != 200:
                error_msg = f"Ollama request failed with status {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise ConnectionError(error_msg)
            
            # Parse and return response
            result = response.json()
            
            if 'response' not in result:
                error_msg = "Invalid Ollama response: missing 'response' field"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            return result
            
        except httpx.ConnectError as e:
            error_msg = f"Failed to connect to Ollama at {self.ollama_url}: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        
        except httpx.TimeoutException as e:
            error_msg = f"Ollama request timed out after {self.timeout}s"
            logger.error(error_msg)
            raise TimeoutError(error_msg) from e
        
        except httpx.HTTPError as e:
            error_msg = f"HTTP error communicating with Ollama: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()



async def classify_threat_with_metadata(
    description: str,
    llm_client,
    max_retries: int = 2
) -> tuple[str, 'ThreatMetadata']:
    """
    Classify threat and extract metadata using LLM with retry logic.
    
    This function uses the enhanced METADATA_EXTRACTION_PROMPT to extract
    both the threat category and rich metadata from the threat description.
    It handles JSON parsing, validation, and error cases gracefully with
    automatic retries if JSON parsing fails.
    
    Args:
        description: Threat description text to classify
        llm_client: LLM client instance (OllamaClient or compatible)
        max_retries: Maximum number of retry attempts (default: 2)
        
    Returns:
        Tuple of (category, metadata):
            - category: The classified threat category string
            - metadata: ThreatMetadata object with extracted metadata
            
    Raises:
        ConnectionError: When LLM service is unavailable
        TimeoutError: When request exceeds timeout
        ValueError: When response cannot be parsed after all retries
    """
    import json
    from services.classification_types import ThreatMetadata, validate_metadata
    
    logger.info(f"Classifying threat with metadata extraction (description length: {len(description)} chars)")
    
    # Format the prompt with the threat description
    prompt = METADATA_EXTRACTION_PROMPT.format(description=description)
    
    last_error = None
    
    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                logger.warning(f"Retry attempt {attempt}/{max_retries} for metadata extraction")
                # On retry, add extra emphasis to JSON requirement
                retry_prompt = prompt + "\n\nREMINDER: You MUST respond with ONLY valid JSON. No other text."
            else:
                retry_prompt = prompt
            
            # Call LLM to generate response
            response = await llm_client.generate(
                prompt=retry_prompt,
                options={"temperature": 0.1}  # Low temperature for more consistent extraction
            )
            
            # Extract the response text
            raw_response = response.get('response', '')
            
            if not raw_response:
                last_error = "LLM returned empty response"
                logger.error(last_error)
                continue
            
            logger.debug(f"Raw LLM response (attempt {attempt + 1}): {raw_response[:200]}...")
            
            # Try to parse JSON from the response
            # The LLM might include extra text, so we need to extract the JSON
            # Try multiple strategies to find JSON
            
            # Strategy 1: Look for JSON object with curly braces
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', raw_response, re.DOTALL)
            
            if not json_match:
                # Strategy 2: Try to find JSON starting from first {
                first_brace = raw_response.find('{')
                last_brace = raw_response.rfind('}')
                if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                    json_str = raw_response[first_brace:last_brace + 1]
                else:
                    last_error = f"Could not find JSON in LLM response: {raw_response[:200]}"
                    logger.warning(last_error)
                    continue
            else:
                json_str = json_match.group(0)
            
            # Try to parse the JSON
            try:
                result = json.loads(json_str)
            except json.JSONDecodeError as e:
                last_error = f"JSON decode error: {e}"
                logger.warning(f"{last_error}. JSON string: {json_str[:200]}")
                continue
            
            # Extract category
            category = result.get("category", "unknown")
            if not category or category == "unknown":
                logger.warning("LLM did not return a valid category")
                category = "unknown"
            
            # Extract metadata
            metadata_dict = result.get("metadata", {})
            
            # Validate metadata using the schema
            try:
                metadata = validate_metadata(metadata_dict)
                logger.info(
                    f"Successfully extracted metadata (attempt {attempt + 1}): category={category}, "
                    f"attack_surface={len(metadata.attack_surface)}, "
                    f"testability={metadata.testability}, "
                    f"techniques={len(metadata.techniques)}, "
                    f"target_systems={len(metadata.target_systems)}"
                )
                return category, metadata
                
            except Exception as e:
                last_error = f"Metadata validation failed: {e}"
                logger.warning(f"{last_error}. Using empty metadata.")
                # If validation fails, return empty metadata rather than failing completely
                metadata = ThreatMetadata()
                return category, metadata
        
        except json.JSONDecodeError as e:
            last_error = f"Failed to parse JSON from LLM response: {e}"
            logger.warning(last_error)
            continue
        
        except (ConnectionError, TimeoutError) as e:
            # Re-raise connection and timeout errors immediately (don't retry)
            logger.error(f"LLM service error: {e}")
            raise
        
        except Exception as e:
            last_error = f"Unexpected error during metadata extraction: {e}"
            logger.warning(last_error)
            continue
    
    # If we've exhausted all retries, return unknown category with empty metadata
    logger.error(f"Failed to extract metadata after {max_retries + 1} attempts. Last error: {last_error}")
    return "unknown", ThreatMetadata()
