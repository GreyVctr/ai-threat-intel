#!/usr/bin/env python3
"""
Test script for threat ingestion pipeline.

This script tests:
1. Content hash calculation
2. Deduplication check
3. Metadata extraction
4. MinIO storage
5. PostgreSQL storage
6. Celery task execution
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from minio import Minio

from config import settings
from services.ingestion import get_ingestion_service
from models.threat import Threat


async def test_ingestion_service():
    """Test the ingestion service directly (without Celery)"""
    print("=" * 80)
    print("Testing Threat Ingestion Service")
    print("=" * 80)
    
    # Create database session
    engine = create_async_engine(settings.database_url, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        try:
            # Create ingestion service
            ingestion_service = get_ingestion_service(session)
            
            # Test 1: Ingest a new threat
            print("\n1. Testing new threat ingestion...")
            test_threat_1 = {
                'title': 'Test Adversarial Attack on BERT Model',
                'description': 'Researchers discover new adversarial attack technique',
                'content': 'A new adversarial attack technique has been discovered that can fool BERT models with minimal perturbations.',
                'source': 'arXiv',
                'url': 'https://arxiv.org/abs/2024.12345',
                'authors': ['John Doe', 'Jane Smith'],
                'published_at': datetime.now().isoformat()
            }
            
            result_1 = await ingestion_service.ingest(test_threat_1)
            print(f"   Status: {result_1['status']}")
            print(f"   Threat ID: {result_1['threat_id']}")
            print(f"   Content Hash: {result_1['content_hash'][:16]}...")
            print(f"   Message: {result_1['message']}")
            
            if result_1['status'] != 'success':
                print("   ❌ FAILED: Expected success status")
                return False
            
            threat_id_1 = result_1['threat_id']
            content_hash_1 = result_1['content_hash']
            
            # Test 2: Try to ingest duplicate (should be detected)
            print("\n2. Testing duplicate detection...")
            result_2 = await ingestion_service.ingest(test_threat_1)
            print(f"   Status: {result_2['status']}")
            print(f"   Threat ID: {result_2['threat_id']}")
            print(f"   Message: {result_2['message']}")
            
            if result_2['status'] != 'duplicate':
                print("   ❌ FAILED: Expected duplicate status")
                return False
            
            if result_2['threat_id'] != threat_id_1:
                print("   ❌ FAILED: Duplicate should return same threat ID")
                return False
            
            # Test 3: Ingest a different threat
            print("\n3. Testing second unique threat ingestion...")
            test_threat_2 = {
                'title': 'Model Extraction Attack on GPT-3',
                'description': 'New technique for extracting model weights',
                'content': 'Researchers have developed a novel model extraction attack that can recover GPT-3 model weights through API queries.',
                'source': 'Security Blog',
                'url': 'https://security.example.com/model-extraction',
                'authors': 'Alice Johnson',
                'published': '2024-01-15T10:30:00Z'
            }
            
            result_3 = await ingestion_service.ingest(test_threat_2)
            print(f"   Status: {result_3['status']}")
            print(f"   Threat ID: {result_3['threat_id']}")
            print(f"   Content Hash: {result_3['content_hash'][:16]}...")
            
            if result_3['status'] != 'success':
                print("   ❌ FAILED: Expected success status")
                return False
            
            threat_id_2 = result_3['threat_id']
            
            if threat_id_2 == threat_id_1:
                print("   ❌ FAILED: Different threats should have different IDs")
                return False
            
            # Test 4: Verify data in database
            print("\n4. Verifying data in database...")
            from sqlalchemy import select
            
            result = await session.execute(
                select(Threat).where(Threat.id == threat_id_1)
            )
            threat_1_db = result.scalar_one_or_none()
            
            if not threat_1_db:
                print("   ❌ FAILED: Threat 1 not found in database")
                return False
            
            print(f"   Threat 1 Title: {threat_1_db.title}")
            print(f"   Threat 1 Source: {threat_1_db.source}")
            print(f"   Threat 1 Authors: {threat_1_db.authors}")
            print(f"   Threat 1 Raw Data Key: {threat_1_db.raw_data_key}")
            
            if not threat_1_db.raw_data_key:
                print("   ❌ FAILED: Raw data key not set")
                return False
            
            # Test 5: Verify data in MinIO
            print("\n5. Verifying data in MinIO...")
            try:
                minio_client = Minio(
                    settings.minio_endpoint,
                    access_key=settings.minio_access_key,
                    secret_key=settings.minio_secret_key,
                    secure=settings.minio_secure
                )
                
                # Try to retrieve the object
                response = minio_client.get_object(
                    settings.minio_bucket,
                    threat_1_db.raw_data_key
                )
                raw_data = response.read()
                response.close()
                response.release_conn()
                
                print(f"   Retrieved {len(raw_data)} bytes from MinIO")
                print(f"   Storage Key: {threat_1_db.raw_data_key}")
                
                if len(raw_data) == 0:
                    print("   ❌ FAILED: No data retrieved from MinIO")
                    return False
                
            except Exception as e:
                print(f"   ❌ FAILED: Error retrieving from MinIO: {e}")
                return False
            
            # Test 6: Test content hash calculation
            print("\n6. Testing content hash calculation...")
            hash_1 = ingestion_service.calculate_content_hash(test_threat_1['content'])
            hash_2 = ingestion_service.calculate_content_hash(test_threat_1['content'])
            
            if hash_1 != hash_2:
                print("   ❌ FAILED: Same content should produce same hash")
                return False
            
            if hash_1 != content_hash_1:
                print("   ❌ FAILED: Hash doesn't match stored hash")
                return False
            
            print(f"   Content hash is consistent: {hash_1[:16]}...")
            
            # Test 7: Test metadata extraction
            print("\n7. Testing metadata extraction...")
            metadata = ingestion_service.extract_metadata(test_threat_2)
            
            print(f"   Title: {metadata['title']}")
            print(f"   Source: {metadata['source']}")
            print(f"   Authors: {metadata['authors']}")
            print(f"   Published: {metadata['published_at']}")
            
            if metadata['title'] != test_threat_2['title']:
                print("   ❌ FAILED: Title not extracted correctly")
                return False
            
            if not isinstance(metadata['authors'], list):
                print("   ❌ FAILED: Authors should be a list")
                return False
            
            print("\n" + "=" * 80)
            print("✅ All ingestion service tests passed!")
            print("=" * 80)
            
            return True
            
        except Exception as e:
            print(f"\n❌ Test failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            await engine.dispose()


async def test_celery_task():
    """Test the Celery ingestion task"""
    print("\n" + "=" * 80)
    print("Testing Celery Ingestion Task")
    print("=" * 80)
    
    try:
        from tasks import ingest_threat
        
        # Test data
        test_threat = {
            'title': 'Celery Test: Data Poisoning Attack',
            'description': 'Testing Celery task execution',
            'content': 'This is a test threat for Celery task execution. It tests the async ingestion pipeline.',
            'source': 'Test Source',
            'url': 'https://test.example.com/threat',
            'authors': ['Test Author'],
            'published_at': datetime.now().isoformat()
        }
        
        print("\n1. Submitting task to Celery...")
        result = ingest_threat.delay(test_threat)
        
        print(f"   Task ID: {result.id}")
        print(f"   Task State: {result.state}")
        
        print("\n2. Waiting for task to complete (timeout: 30s)...")
        task_result = result.get(timeout=30)
        
        print(f"   Status: {task_result['status']}")
        print(f"   Threat ID: {task_result.get('threat_id')}")
        print(f"   Message: {task_result['message']}")
        
        if task_result['status'] not in ['success', 'duplicate']:
            print("   ❌ FAILED: Task did not complete successfully")
            return False
        
        print("\n" + "=" * 80)
        print("✅ Celery task test passed!")
        print("=" * 80)
        
        return True
        
    except Exception as e:
        print(f"\n❌ Celery test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("THREAT INGESTION PIPELINE TEST SUITE")
    print("=" * 80)
    
    # Test ingestion service
    service_passed = await test_ingestion_service()
    
    # Test Celery task (optional - requires Celery worker)
    print("\n\nNote: Celery task test requires a running Celery worker.")
    print("To test Celery tasks, run: docker compose exec celery_worker python scripts/test_ingestion.py --celery")
    
    if '--celery' in sys.argv:
        celery_passed = await test_celery_task()
    else:
        celery_passed = True  # Skip Celery test
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Ingestion Service: {'✅ PASSED' if service_passed else '❌ FAILED'}")
    if '--celery' in sys.argv:
        print(f"Celery Task: {'✅ PASSED' if celery_passed else '❌ FAILED'}")
    print("=" * 80)
    
    return service_passed and celery_passed


if __name__ == '__main__':
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
