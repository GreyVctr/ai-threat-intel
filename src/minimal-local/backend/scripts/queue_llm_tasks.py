"""Queue LLM analysis tasks for pending threats"""
import asyncio
from sqlalchemy import select
from models import Threat, get_db
from tasks import analyze_with_llm

async def main():
    async for db in get_db():
        # Get threats with pending LLM analysis
        result = await db.execute(
            select(Threat.id)
            .where(Threat.llm_analysis_status == 'pending')
            .limit(50)
        )
        threat_ids = result.scalars().all()
        
        # Queue LLM analysis tasks
        for threat_id in threat_ids:
            analyze_with_llm.delay(str(threat_id))
        
        print(f"Queued {len(threat_ids)} LLM analysis tasks")
        break

if __name__ == "__main__":
    asyncio.run(main())
