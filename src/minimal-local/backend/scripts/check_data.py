#!/usr/bin/env python3
"""Quick script to check if there's data in the database."""
import asyncio
import sys
from pathlib import Path

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import select, func
from models import get_db, Threat

async def main():
    async for db in get_db():
        result = await db.execute(select(func.count(Threat.id)))
        count = result.scalar()
        print(f'Total threats in database: {count}')
        
        if count > 0:
            result = await db.execute(select(Threat).limit(3))
            threats = result.scalars().all()
            print('\nSample threats:')
            for threat in threats:
                print(f'  - {threat.title[:60]}')
        break

asyncio.run(main())
