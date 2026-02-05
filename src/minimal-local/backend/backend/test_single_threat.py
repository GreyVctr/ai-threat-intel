#!/usr/bin/env python3
"""
Test script to process a single threat with the new prompt and model.
"""
import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select
from models import AsyncSessionLocal, Threat
from services.classification_service import ClassificationService


async def test_single_threat(threat_id: str):
    """Test classification on a single threat."""
    print(f"\n{'='*80}")
    print(f"Testing threat: {threat_id}")
    print(f"{'='*80}\n")
    
    # Get database session
    async with AsyncSessionLocal() as session:
        # Fetch the threat
        result = await session.execute(
            select(Threat).where(Threat.id == threat_id)
        )
        threat = result.scalar_one_or_none()
        
        if not threat:
            print(f"❌ Threat not found: {threat_id}")
            return
        
        print(f"📄 Title: {threat.title}")
        print(f"📝 Description length: {len(threat.description)} chars")
        print(f"\n{'='*80}")
        print(f"CURRENT CLASSIFICATION:")
        print(f"{'='*80}")
        print(f"Category: {threat.threat_type}")
        
        if threat.classification_metadata:
            meta = threat.classification_metadata.get('threat_metadata', {})
            print(f"Testability: {meta.get('testability')}")
            print(f"Attack Surface: {meta.get('attack_surface')}")
            print(f"Techniques: {meta.get('techniques')}")
            print(f"Target Systems: {meta.get('target_systems')}")
            print(f"Confidence: {meta.get('confidence')}")
            print(f"Reasoning: {meta.get('reasoning', 'N/A')[:200]}")
        
        print(f"\n{'='*80}")
        print(f"RUNNING NEW CLASSIFICATION...")
        print(f"{'='*80}\n")
        
        # Initialize classifier
        classifier = ClassificationService()
        
        # Run classification
        result = await classifier.classify_threat(threat, session)
        
        print(f"\n{'='*80}")
        print(f"NEW CLASSIFICATION RESULT:")
        print(f"{'='*80}")
        print(f"✅ Category: {result.threat_type}")
        print(f"✅ Method: {result.method}")
        print(f"✅ Confidence: {result.confidence}")
        
        if result.metadata:
            # metadata is a dict, not an object
            print(f"✅ Testability: {result.metadata.get('testability')}")
            print(f"✅ Attack Surface: {result.metadata.get('attack_surface')}")
            print(f"✅ Techniques: {result.metadata.get('techniques')}")
            print(f"✅ Target Systems: {result.metadata.get('target_systems')}")
            print(f"✅ LLM Confidence: {result.metadata.get('confidence')}")
            reasoning = result.metadata.get('reasoning', 'N/A')
            print(f"✅ Reasoning: {reasoning[:200] if reasoning else 'N/A'}")
        
        print(f"\n{'='*80}")
        print(f"COMPARISON:")
        print(f"{'='*80}")
        
        old_testability = threat.classification_metadata.get('threat_metadata', {}).get('testability') if threat.classification_metadata else None
        new_testability = result.metadata.get('testability') if result.metadata else None
        
        if old_testability != new_testability:
            print(f"🔄 Testability changed: {old_testability} → {new_testability}")
        else:
            print(f"⚪ Testability unchanged: {old_testability}")
        
        if threat.threat_type != result.threat_type:
            print(f"🔄 Category changed: {threat.threat_type} → {result.threat_type}")
        else:
            print(f"⚪ Category unchanged: {threat.threat_type}")
        
        print(f"\n{'='*80}\n")


if __name__ == "__main__":
    threat_id = "b9d4478f-cbe6-4c9e-9c0d-6afc5ac21f60"
    asyncio.run(test_single_threat(threat_id))
