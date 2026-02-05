#!/usr/bin/env python3
"""
Simple test for LLM analysis using available model.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from config import settings
from models.threat import Threat
from services.llm_client import OllamaClient
from services.analysis import AnalysisService

# Use localhost and available model
OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "llama3.2:latest"


async def main():
    print("Testing LLM Analysis with available model...")
    print(f"Ollama URL: {OLLAMA_URL}")
    print(f"Model: {MODEL_NAME}")
    print("=" * 60)
    
    # Create client
    client = OllamaClient(base_url=OLLAMA_URL, model=MODEL_NAME)
    
    # Test connection
    print("\n1. Testing Ollama connection...")
    is_healthy = await client.check_health()
    if not is_healthy:
        print("❌ Ollama is not available")
        return False
    print("✅ Ollama is available")
    
    # Test generation
    print("\n2. Testing text generation...")
    try:
        response = await client.generate(
            prompt="What is adversarial machine learning? Answer in one sentence.",
            options={'num_predict': 50}
        )
        print(f"✅ Generation successful")
        print(f"Response: {response['response'][:100]}...")
    except Exception as e:
        print(f"❌ Generation failed: {e}")
        return False
    
    # Test analysis service
    print("\n3. Testing analysis service...")
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        # Find or create a test threat
        result = await session.execute(select(Threat).limit(1))
        threat = result.scalar_one_or_none()
        
        if not threat:
            print("Creating test threat...")
            threat = Threat(
                title="Test Adversarial Attack",
                description="A test adversarial attack on image classifiers",
                content="This is a test threat for LLM analysis",
                source="test",
                content_hash=f"test_{asyncio.get_event_loop().time()}",
                threat_type="adversarial"
            )
            session.add(threat)
            await session.commit()
            await session.refresh(threat)
        
        print(f"Using threat: {threat.id}")
        print(f"Title: {threat.title}")
        
        # Create analysis service with custom client
        analysis_service = AnalysisService(session)
        analysis_service.ollama_client = client
        
        print("\n4. Performing LLM analysis (may take 30-60 seconds)...")
        result = await analysis_service.analyze_threat(str(threat.id))
        
        if result.get('success'):
            print("✅ Analysis successful!")
            print(f"Analysis ID: {result.get('analysis_id')}")
            
            # Get analysis
            analysis = await analysis_service.get_analysis(str(threat.id))
            if analysis:
                print("\n--- Analysis Results ---")
                print(f"Summary: {analysis.summary[:200] if analysis.summary else 'None'}...")
                print(f"Key Findings: {len(analysis.key_findings or [])}")
                print(f"Attack Vectors: {len(analysis.attack_vectors or [])}")
                print(f"Mitigations: {len(analysis.mitigations or [])}")
                print("------------------------")
            
            return True
        else:
            print(f"❌ Analysis failed: {result.get('error')}")
            return False
    
    await engine.dispose()


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
