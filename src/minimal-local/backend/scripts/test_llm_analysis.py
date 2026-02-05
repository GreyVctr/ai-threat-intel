#!/usr/bin/env python3
"""
Test script for LLM analysis pipeline.

This script tests:
1. Ollama client connection
2. LLM analysis service
3. End-to-end analysis workflow
"""
import asyncio
import sys
import logging
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from config import settings
from models.threat import Threat
from services.llm_client import OllamaClient
from services.analysis import AnalysisService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Override Ollama URL for localhost testing (outside containers)
OLLAMA_URL = "http://localhost:11434"


async def test_ollama_connection():
    """Test connection to Ollama service."""
    logger.info("=" * 60)
    logger.info("TEST 1: Ollama Connection")
    logger.info("=" * 60)
    
    try:
        # Use localhost URL for testing outside containers
        client = OllamaClient(base_url=OLLAMA_URL)
        
        # Check health
        is_healthy = await client.check_health()
        logger.info(f"Ollama health check: {'✓ PASSED' if is_healthy else '✗ FAILED'}")
        
        if not is_healthy:
            logger.error("Ollama service is not available")
            return False
        
        # List models
        try:
            models = await client.list_models()
            logger.info(f"Available models: {models}")
            
            if not models:
                logger.warning("No models available. Please pull a model first:")
                logger.warning("  docker compose -f docker-compose.minimal.yml exec ollama ollama pull phi3:mini")
                return False
            
            # Check if default model is available
            if settings.ollama_model not in models:
                logger.warning(f"Default model '{settings.ollama_model}' not found")
                logger.warning(f"Available models: {models}")
                logger.warning("Please pull the default model:")
                logger.warning(f"  docker compose -f docker-compose.minimal.yml exec ollama ollama pull {settings.ollama_model}")
                return False
            
            logger.info(f"✓ Default model '{settings.ollama_model}' is available")
            
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return False
        
        # Test generation
        logger.info("Testing text generation...")
        try:
            response = await client.generate(
                prompt="What is adversarial machine learning? Answer in one sentence.",
                options={'num_predict': 50}
            )
            
            logger.info(f"✓ Generation test passed")
            logger.info(f"Response: {response['response'][:100]}...")
            
        except Exception as e:
            logger.error(f"Generation test failed: {e}")
            return False
        
        logger.info("✓ All Ollama connection tests passed")
        return True
        
    except Exception as e:
        logger.error(f"Ollama connection test failed: {e}", exc_info=True)
        return False


async def test_analysis_service():
    """Test LLM analysis service."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 2: Analysis Service")
    logger.info("=" * 60)
    
    try:
        # Create database session
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with async_session_maker() as session:
            # Find a threat to analyze
            result = await session.execute(
                select(Threat).limit(1)
            )
            threat = result.scalar_one_or_none()
            
            if not threat:
                logger.warning("No threats found in database")
                logger.info("Creating a test threat...")
                
                # Create a test threat
                threat = Threat(
                    title="Test Adversarial Attack on Image Classifiers",
                    description="A new adversarial attack technique that can fool image classifiers with minimal perturbations.",
                    content="Researchers have discovered a novel adversarial attack method that generates imperceptible perturbations to fool deep learning image classifiers. The attack achieves high success rates against popular models like ResNet and VGG.",
                    source="test",
                    source_url="https://example.com/test",
                    content_hash="test_hash_" + str(asyncio.get_event_loop().time()),
                    threat_type="adversarial"
                )
                session.add(threat)
                await session.commit()
                await session.refresh(threat)
                logger.info(f"✓ Created test threat: {threat.id}")
            
            logger.info(f"Testing analysis on threat: {threat.id}")
            logger.info(f"Title: {threat.title}")
            
            # Create analysis service with localhost Ollama client
            analysis_service = AnalysisService(session)
            analysis_service.ollama_client = OllamaClient(base_url=OLLAMA_URL)
            
            # Perform analysis
            logger.info("Performing LLM analysis (this may take 30-60 seconds)...")
            result = await analysis_service.analyze_threat(str(threat.id))
            
            if result.get('success'):
                logger.info("✓ Analysis completed successfully")
                logger.info(f"Analysis ID: {result.get('analysis_id')}")
                logger.info(f"Model: {result.get('model_name')}")
                
                # Fetch and display analysis
                analysis = await analysis_service.get_analysis(str(threat.id))
                if analysis:
                    logger.info("\n--- Analysis Results ---")
                    logger.info(f"Summary: {analysis.summary}")
                    logger.info(f"Key Findings: {len(analysis.key_findings or [])} items")
                    if analysis.key_findings:
                        for i, finding in enumerate(analysis.key_findings[:3], 1):
                            logger.info(f"  {i}. {finding}")
                    logger.info(f"Attack Vectors: {len(analysis.attack_vectors or [])} items")
                    if analysis.attack_vectors:
                        for i, vector in enumerate(analysis.attack_vectors[:3], 1):
                            logger.info(f"  {i}. {vector}")
                    logger.info(f"Mitigations: {len(analysis.mitigations or [])} items")
                    if analysis.mitigations:
                        for i, mitigation in enumerate(analysis.mitigations[:3], 1):
                            logger.info(f"  {i}. {mitigation}")
                    logger.info("------------------------\n")
                
                return True
            else:
                logger.error(f"✗ Analysis failed: {result.get('error')}")
                return False
        
        await engine.dispose()
        
    except Exception as e:
        logger.error(f"Analysis service test failed: {e}", exc_info=True)
        return False


async def main():
    """Run all tests."""
    logger.info("Starting LLM Analysis Pipeline Tests")
    logger.info("=" * 60)
    
    # Test 1: Ollama connection
    test1_passed = await test_ollama_connection()
    
    if not test1_passed:
        logger.error("\n✗ Ollama connection test failed. Cannot proceed with analysis tests.")
        logger.info("\nTroubleshooting:")
        logger.info("1. Ensure Ollama container is running:")
        logger.info("   docker compose -f docker-compose.minimal.yml ps ollama")
        logger.info("2. Check Ollama logs:")
        logger.info("   docker compose -f docker-compose.minimal.yml logs ollama")
        logger.info("3. Pull the default model:")
        logger.info(f"   docker compose -f docker-compose.minimal.yml exec ollama ollama pull {settings.ollama_model}")
        return False
    
    # Test 2: Analysis service
    test2_passed = await test_analysis_service()
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Ollama Connection: {'✓ PASSED' if test1_passed else '✗ FAILED'}")
    logger.info(f"Analysis Service: {'✓ PASSED' if test2_passed else '✗ FAILED'}")
    logger.info("=" * 60)
    
    if test1_passed and test2_passed:
        logger.info("\n✓ All tests passed! LLM analysis pipeline is working correctly.")
        return True
    else:
        logger.error("\n✗ Some tests failed. Please review the errors above.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
