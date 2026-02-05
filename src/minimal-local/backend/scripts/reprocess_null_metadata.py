#!/usr/bin/env python3
"""
Reprocess threats with null metadata.

This script identifies threats that have null testability metadata
and requeues them for enrichment with the improved LLM prompt.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select, text
from models import get_db, Threat
from tasks import enrich_threat


async def find_null_metadata_threats():
    """Find all threats with null testability metadata."""
    async for db in get_db():
        try:
            # Query for threats with null testability
            # Using raw SQL for JSON path query
            query = text("""
                SELECT id, title 
                FROM threats 
                WHERE classification_metadata->'threat_metadata'->>'testability' IS NULL
                ORDER BY ingested_at DESC
            """)
            
            result = await db.execute(query)
            threats = result.all()
            
            print(f"\n{'='*80}")
            print(f"Found {len(threats)} threats with null metadata")
            print(f"{'='*80}\n")
            
            if threats:
                print("Sample threats to be reprocessed:")
                for i, (threat_id, title) in enumerate(threats[:5], 1):
                    print(f"  {i}. {title[:70]}...")
                
                if len(threats) > 5:
                    print(f"  ... and {len(threats) - 5} more")
            
            return threats
            
        except Exception as e:
            print(f"Error finding threats: {e}")
            return []


async def requeue_threats(threats, batch_size=50):
    """
    Requeue threats for enrichment in batches.
    
    Args:
        threats: List of (threat_id, title) tuples
        batch_size: Number of threats to queue at once
    """
    if not threats:
        print("\nNo threats to reprocess.")
        return
    
    print(f"\n{'='*80}")
    print(f"Requeuing {len(threats)} threats for enrichment")
    print(f"{'='*80}\n")
    
    total = len(threats)
    queued = 0
    
    for i in range(0, total, batch_size):
        batch = threats[i:i + batch_size]
        
        for threat_id, title in batch:
            try:
                # Queue the enrichment task
                enrich_threat.delay(str(threat_id))
                queued += 1
                
                if queued % 10 == 0:
                    print(f"Queued {queued}/{total} threats...")
                    
            except Exception as e:
                print(f"Error queueing threat {threat_id}: {e}")
        
        # Small delay between batches to avoid overwhelming the queue
        if i + batch_size < total:
            await asyncio.sleep(0.5)
    
    print(f"\n{'='*80}")
    print(f"✅ Successfully queued {queued}/{total} threats")
    print(f"{'='*80}\n")
    
    # Calculate estimated time
    with_12_workers = (total * 85) / 12 / 60  # 85 seconds per threat, 12 workers
    print(f"Estimated completion time:")
    print(f"  - With 12 workers: ~{with_12_workers:.0f} minutes")
    print(f"  - Monitor progress at: http://localhost:3000")
    print(f"  - Check logs: docker logs ai-shield-celery-worker -f")
    print()


async def main():
    """Main execution function."""
    print("\n" + "="*80)
    print("Reprocess Null Metadata Threats")
    print("="*80)
    print("\nThis script will:")
    print("  1. Find all threats with null testability metadata")
    print("  2. Requeue them for enrichment with the improved LLM prompt")
    print("  3. Process them with 12 concurrent workers")
    print()
    
    # Find threats
    threats = await find_null_metadata_threats()
    
    if not threats:
        print("\n✅ No threats need reprocessing. All metadata is complete!")
        return
    
    # Confirm before proceeding
    print(f"\nReady to requeue {len(threats)} threats.")
    response = input("Continue? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        print("\n❌ Cancelled by user.")
        return
    
    # Requeue threats
    await requeue_threats(threats)
    
    print("\n✅ Reprocessing started!")
    print("\nNext steps:")
    print("  1. Monitor progress in the UI: http://localhost:3000")
    print("  2. Check worker logs: docker logs ai-shield-celery-worker -f")
    print("  3. Verify results after completion with:")
    print("     docker compose -f docker-compose.minimal.yml exec postgres \\")
    print("       psql -U ai_shield -d ai_shield -c \\")
    print("       \"SELECT classification_metadata->'threat_metadata'->>'testability' as testability, COUNT(*) FROM threats GROUP BY testability;\"")
    print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        sys.exit(1)
