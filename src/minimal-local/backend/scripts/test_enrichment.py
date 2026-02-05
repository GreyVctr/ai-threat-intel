#!/usr/bin/env python3
"""
Test script for threat enrichment pipeline.

This script tests:
1. Threat type classification
2. CVE extraction
3. Framework extraction
4. Entity extraction
5. MITRE ATLAS mapping
6. Severity scoring
7. Complete enrichment workflow
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add backend directory to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from config import settings
from services.enrichment import EnrichmentService
from services.ingestion import get_ingestion_service
from models.threat import Threat
from models.entity import Entity
from models.mitre import MitreMapping


async def test_threat_classification():
    """Test threat type classification"""
    print("=" * 80)
    print("Testing Threat Type Classification")
    print("=" * 80)
    
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            enrichment_service = EnrichmentService(session)
            
            test_cases = [
                {
                    "content": "Adversarial attack using FGSM perturbations to fool BERT model",
                    "expected": "adversarial"
                },
                {
                    "content": "Model extraction attack via API queries to steal GPT-3 weights",
                    "expected": "extraction"
                },
                {
                    "content": "Data poisoning with backdoor triggers in training dataset",
                    "expected": "poisoning"
                },
                {
                    "content": "Prompt injection attack to jailbreak LLM safety guardrails",
                    "expected": "prompt_injection"
                },
                {
                    "content": "Membership inference attack reveals training data privacy leakage",
                    "expected": "privacy"
                },
                {
                    "content": "Supply chain compromise via malicious pretrained model from Hugging Face",
                    "expected": "supply_chain"
                },
            ]
            
            passed = 0
            failed = 0
            
            for i, test_case in enumerate(test_cases, 1):
                print(f"\nTest {i}: {test_case['content'][:60]}...")
                result = await enrichment_service.classify_threat_type(test_case['content'])
                
                if result == test_case['expected']:
                    print(f"   ✅ PASSED: Classified as '{result}'")
                    passed += 1
                else:
                    print(f"   ❌ FAILED: Expected '{test_case['expected']}', got '{result}'")
                    failed += 1
            
            print(f"\n{'=' * 80}")
            print(f"Classification Tests: {passed} passed, {failed} failed")
            print(f"{'=' * 80}")
            
            return failed == 0
            
        finally:
            await engine.dispose()


async def test_entity_extraction():
    """Test entity extraction (CVEs and frameworks)"""
    print("\n" + "=" * 80)
    print("Testing Entity Extraction")
    print("=" * 80)
    
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            enrichment_service = EnrichmentService(session)
            
            # Test CVE extraction
            print("\n1. Testing CVE extraction...")
            content_with_cves = """
            Security vulnerability CVE-2023-12345 affects TensorFlow models.
            Related to cve-2023-67890 and CVE-2024-11111.
            """
            
            cves = await enrichment_service.extract_cves(content_with_cves)
            print(f"   Extracted CVEs: {cves}")
            
            if len(cves) == 3 and "CVE-2023-12345" in cves:
                print("   ✅ PASSED: CVE extraction")
            else:
                print(f"   ❌ FAILED: Expected 3 CVEs, got {len(cves)}")
                return False
            
            # Test framework extraction
            print("\n2. Testing framework extraction...")
            content_with_frameworks = """
            Attack targets PyTorch and TensorFlow models.
            Also affects Hugging Face transformers and scikit-learn.
            """
            
            frameworks = await enrichment_service.extract_frameworks(content_with_frameworks)
            print(f"   Extracted frameworks: {frameworks}")
            
            expected_frameworks = {"pytorch", "tensorflow", "huggingface", "scikit-learn"}
            if expected_frameworks.issubset(set(frameworks)):
                print("   ✅ PASSED: Framework extraction")
            else:
                print(f"   ❌ FAILED: Expected {expected_frameworks}, got {set(frameworks)}")
                return False
            
            # Test complete entity extraction
            print("\n3. Testing complete entity extraction...")
            test_threat_id = "00000000-0000-0000-0000-000000000001"
            content = """
            CVE-2023-99999 affects PyTorch models.
            TensorFlow is also vulnerable.
            """
            
            entities = await enrichment_service.extract_entities(test_threat_id, content)
            print(f"   Extracted {len(entities)} entities")
            
            cve_entities = [e for e in entities if e.entity_type == "cve"]
            framework_entities = [e for e in entities if e.entity_type == "framework"]
            
            print(f"   - CVEs: {len(cve_entities)}")
            print(f"   - Frameworks: {len(framework_entities)}")
            
            if len(cve_entities) >= 1 and len(framework_entities) >= 2:
                print("   ✅ PASSED: Complete entity extraction")
            else:
                print("   ❌ FAILED: Insufficient entities extracted")
                return False
            
            print(f"\n{'=' * 80}")
            print("✅ All entity extraction tests passed!")
            print(f"{'=' * 80}")
            
            return True
            
        finally:
            await engine.dispose()


async def test_mitre_mapping():
    """Test MITRE ATLAS mapping"""
    print("\n" + "=" * 80)
    print("Testing MITRE ATLAS Mapping")
    print("=" * 80)
    
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            enrichment_service = EnrichmentService(session)
            
            test_cases = [
                {
                    "threat_type": "adversarial",
                    "expected_min_mappings": 2,
                    "expected_techniques": ["AML.T0043", "AML.T0015"]
                },
                {
                    "threat_type": "extraction",
                    "expected_min_mappings": 2,
                    "expected_techniques": ["AML.T0040", "AML.T0024"]
                },
                {
                    "threat_type": "poisoning",
                    "expected_min_mappings": 2,
                    "expected_techniques": ["AML.T0020", "AML.T0018"]
                },
            ]
            
            passed = 0
            failed = 0
            
            for i, test_case in enumerate(test_cases, 1):
                print(f"\nTest {i}: Mapping '{test_case['threat_type']}' threat type...")
                
                test_threat_id = f"00000000-0000-0000-0000-00000000000{i}"
                mappings = await enrichment_service.map_to_mitre_atlas(
                    test_threat_id,
                    test_case['threat_type']
                )
                
                print(f"   Created {len(mappings)} mappings")
                
                technique_ids = [m.technique_id for m in mappings]
                print(f"   Technique IDs: {technique_ids}")
                
                if len(mappings) >= test_case['expected_min_mappings']:
                    # Check if expected techniques are present
                    if all(tid in technique_ids for tid in test_case['expected_techniques']):
                        print(f"   ✅ PASSED: Correct MITRE ATLAS mappings")
                        passed += 1
                    else:
                        print(f"   ❌ FAILED: Missing expected techniques")
                        failed += 1
                else:
                    print(f"   ❌ FAILED: Expected at least {test_case['expected_min_mappings']} mappings")
                    failed += 1
            
            print(f"\n{'=' * 80}")
            print(f"MITRE Mapping Tests: {passed} passed, {failed} failed")
            print(f"{'=' * 80}")
            
            return failed == 0
            
        finally:
            await engine.dispose()


async def test_severity_scoring():
    """Test severity scoring"""
    print("\n" + "=" * 80)
    print("Testing Severity Scoring")
    print("=" * 80)
    
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            enrichment_service = EnrichmentService(session)
            
            test_cases = [
                {
                    "threat_type": "poisoning",
                    "has_cve": True,
                    "has_poc": True,
                    "expected_min": 9,
                    "description": "Poisoning with CVE and PoC"
                },
                {
                    "threat_type": "adversarial",
                    "has_cve": False,
                    "has_poc": False,
                    "expected_min": 7,
                    "description": "Adversarial without CVE or PoC"
                },
                {
                    "threat_type": "fairness",
                    "has_cve": False,
                    "has_poc": False,
                    "expected_min": 5,
                    "description": "Fairness issue"
                },
            ]
            
            passed = 0
            failed = 0
            
            for i, test_case in enumerate(test_cases, 1):
                print(f"\nTest {i}: {test_case['description']}")
                
                severity = await enrichment_service.calculate_severity(
                    test_case['threat_type'],
                    test_case['has_cve'],
                    test_case['has_poc']
                )
                
                print(f"   Calculated severity: {severity}")
                print(f"   Expected minimum: {test_case['expected_min']}")
                
                if severity >= test_case['expected_min']:
                    print(f"   ✅ PASSED")
                    passed += 1
                else:
                    print(f"   ❌ FAILED: Severity too low")
                    failed += 1
            
            # Test PoC detection
            print("\n4. Testing PoC detection...")
            content_with_poc = "Proof of concept available on GitHub: github.com/example/exploit"
            has_poc = await enrichment_service.detect_poc_availability(content_with_poc)
            
            if has_poc:
                print("   ✅ PASSED: PoC detected")
                passed += 1
            else:
                print("   ❌ FAILED: PoC not detected")
                failed += 1
            
            print(f"\n{'=' * 80}")
            print(f"Severity Scoring Tests: {passed} passed, {failed} failed")
            print(f"{'=' * 80}")
            
            return failed == 0
            
        finally:
            await engine.dispose()


async def test_complete_enrichment():
    """Test complete enrichment workflow"""
    print("\n" + "=" * 80)
    print("Testing Complete Enrichment Workflow")
    print("=" * 80)
    
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            # First, ingest a test threat
            print("\n1. Ingesting test threat...")
            ingestion_service = get_ingestion_service(session)
            
            test_threat = {
                'title': 'Adversarial Attack on PyTorch Models - CVE-2023-99999',
                'description': 'FGSM-based adversarial perturbations targeting PyTorch image classifiers',
                'content': '''
                A new adversarial attack technique has been discovered that affects PyTorch
                and TensorFlow models. The attack uses FGSM perturbations to create
                adversarial examples that fool image classification models.
                
                CVE-2023-99999 has been assigned to this vulnerability.
                
                Proof of concept code is available on GitHub at github.com/example/attack.
                The attack achieves 95% success rate on ImageNet models.
                ''',
                'source': 'Test Source',
                'url': 'https://test.example.com/threat',
                'authors': ['Test Researcher'],
                'published_at': datetime.now().isoformat()
            }
            
            ingest_result = await ingestion_service.ingest(test_threat)
            
            if ingest_result['status'] not in ['success', 'duplicate']:
                print(f"   ❌ FAILED: Ingestion failed: {ingest_result['message']}")
                return False
            
            threat_id = ingest_result['threat_id']
            print(f"   ✅ Threat ingested: {threat_id}")
            
            # Now enrich the threat
            print("\n2. Enriching threat...")
            enrichment_service = EnrichmentService(session)
            
            enrich_result = await enrichment_service.enrich_threat(threat_id)
            
            if not enrich_result['success']:
                print(f"   ❌ FAILED: Enrichment failed: {enrich_result.get('error')}")
                return False
            
            print(f"   ✅ Enrichment completed")
            print(f"   - Threat Type: {enrich_result['threat_type']}")
            print(f"   - Severity: {enrich_result['severity']}")
            print(f"   - Entities: {enrich_result['entities_count']}")
            print(f"   - MITRE Mappings: {enrich_result['mappings_count']}")
            
            if enrich_result.get('errors'):
                print(f"   ⚠️  Partial enrichment with errors: {enrich_result['errors']}")
            
            # Verify enrichment in database
            print("\n3. Verifying enrichment in database...")
            
            result = await session.execute(
                select(Threat).where(Threat.id == threat_id)
            )
            threat = result.scalar_one_or_none()
            
            if not threat:
                print("   ❌ FAILED: Threat not found in database")
                return False
            
            print(f"   Threat Type: {threat.threat_type}")
            print(f"   Severity: {threat.severity}")
            print(f"   Exploitability: {threat.exploitability_score}")
            print(f"   Enrichment Status: {threat.enrichment_status}")
            
            # Check entities
            entity_result = await session.execute(
                select(Entity).where(Entity.threat_id == threat_id)
            )
            entities = entity_result.scalars().all()
            print(f"   Entities in DB: {len(entities)}")
            
            for entity in entities:
                print(f"     - {entity.entity_type}: {entity.entity_value}")
            
            # Check MITRE mappings
            mapping_result = await session.execute(
                select(MitreMapping).where(MitreMapping.threat_id == threat_id)
            )
            mappings = mapping_result.scalars().all()
            print(f"   MITRE Mappings in DB: {len(mappings)}")
            
            for mapping in mappings:
                print(f"     - {mapping.technique_id}: {mapping.technique}")
            
            # Validate results
            checks_passed = 0
            checks_total = 5
            
            if threat.threat_type == "adversarial":
                print("   ✅ Correct threat type")
                checks_passed += 1
            else:
                print(f"   ❌ Wrong threat type: {threat.threat_type}")
            
            if threat.severity >= 7:
                print("   ✅ Appropriate severity score")
                checks_passed += 1
            else:
                print(f"   ❌ Severity too low: {threat.severity}")
            
            if len(entities) >= 3:  # Should have CVE + 2 frameworks
                print("   ✅ Sufficient entities extracted")
                checks_passed += 1
            else:
                print(f"   ❌ Insufficient entities: {len(entities)}")
            
            if len(mappings) >= 2:
                print("   ✅ MITRE mappings created")
                checks_passed += 1
            else:
                print(f"   ❌ Insufficient MITRE mappings: {len(mappings)}")
            
            if threat.enrichment_status in ['complete', 'partial']:
                print("   ✅ Enrichment status updated")
                checks_passed += 1
            else:
                print(f"   ❌ Wrong enrichment status: {threat.enrichment_status}")
            
            print(f"\n{'=' * 80}")
            print(f"Complete Enrichment: {checks_passed}/{checks_total} checks passed")
            print(f"{'=' * 80}")
            
            return checks_passed == checks_total
            
        except Exception as e:
            print(f"\n❌ Test failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            await engine.dispose()


async def main():
    """Run all enrichment tests"""
    print("\n" + "=" * 80)
    print("THREAT ENRICHMENT PIPELINE TEST SUITE")
    print("=" * 80)
    
    results = {}
    
    # Run individual component tests
    results['classification'] = await test_threat_classification()
    results['entity_extraction'] = await test_entity_extraction()
    results['mitre_mapping'] = await test_mitre_mapping()
    results['severity_scoring'] = await test_severity_scoring()
    
    # Run complete workflow test
    results['complete_enrichment'] = await test_complete_enrichment()
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
    
    print("=" * 80)
    
    all_passed = all(results.values())
    return all_passed


if __name__ == '__main__':
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
