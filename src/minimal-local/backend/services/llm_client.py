"""
Ollama LLM client service for local language model inference.

Provides connection to the containerized Ollama service with timeout
and error handling for threat analysis.
"""
import logging
import httpx
from typing import Dict, Optional, Any

from config import settings

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    Client for interacting with Ollama LLM service.
    
    Provides methods for generating text completions using local LLMs
    running in the Ollama container.
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        """
        Initialize Ollama client.
        
        Args:
            base_url: Ollama service URL (defaults to settings.ollama_url)
            model: Default model name (defaults to settings.ollama_model)
            timeout: Request timeout in seconds (defaults to settings.ollama_timeout)
        """
        self.base_url = base_url or settings.ollama_url
        self.model = model or settings.ollama_model
        self.timeout = timeout or settings.ollama_timeout
        
        # Ensure base_url doesn't end with /
        self.base_url = self.base_url.rstrip('/')
        
        logger.info(f"Initialized Ollama client: {self.base_url}, model={self.model}, timeout={self.timeout}s")
    
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        stream: bool = False,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate text completion using Ollama.
        
        Args:
            prompt: Input prompt for the LLM
            model: Model name (defaults to self.model)
            stream: Whether to stream the response (not supported yet)
            options: Additional generation options (temperature, top_p, etc.)
        
        Returns:
            Dictionary with generation results:
            {
                'model': str,
                'response': str,
                'done': bool,
                'context': list (optional),
                'total_duration': int (optional),
                'load_duration': int (optional),
                'prompt_eval_count': int (optional),
                'eval_count': int (optional)
            }
        
        Raises:
            ConnectionError: If Ollama service is unavailable
            TimeoutError: If request exceeds timeout
            ValueError: If response is invalid
        """
        model_name = model or self.model
        
        logger.info(f"Generating completion with model {model_name} (prompt length: {len(prompt)} chars)")
        
        # Prepare request payload
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": stream
        }
        
        if options:
            payload["options"] = options
        
        # Make request to Ollama
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )
                
                # Check response status
                if response.status_code == 404:
                    error_msg = f"Model '{model_name}' not found. Please pull the model first: docker compose exec ollama ollama pull {model_name}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                if response.status_code != 200:
                    error_msg = f"Ollama request failed with status {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                # Parse response
                result = response.json()
                
                # Validate response
                if 'response' not in result:
                    error_msg = f"Invalid Ollama response: missing 'response' field"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                logger.info(f"Generated completion: {len(result['response'])} chars")
                
                return result
                
        except httpx.ConnectError as e:
            error_msg = f"Failed to connect to Ollama at {self.base_url}: {str(e)}"
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
    
    async def check_health(self) -> bool:
        """
        Check if Ollama service is available.
        
        Returns:
            True if service is healthy, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return False
    
    async def list_models(self) -> list:
        """
        List available models in Ollama.
        
        Returns:
            List of model names
        
        Raises:
            ConnectionError: If Ollama service is unavailable
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                
                if response.status_code != 200:
                    error_msg = f"Failed to list models: status {response.status_code}"
                    logger.error(error_msg)
                    raise ConnectionError(error_msg)
                
                result = response.json()
                models = [model['name'] for model in result.get('models', [])]
                
                logger.info(f"Available models: {models}")
                return models
                
        except httpx.HTTPError as e:
            error_msg = f"Failed to list models: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e


# Global client instance
_ollama_client: Optional[OllamaClient] = None


def get_ollama_client() -> OllamaClient:
    """
    Get or create global Ollama client instance.
    
    Returns:
        OllamaClient instance
    """
    global _ollama_client
    
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    
    return _ollama_client
