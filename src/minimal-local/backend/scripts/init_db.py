#!/usr/bin/env python3
"""
Database initialization script for AI Shield Intelligence.

This script:
1. Enables required PostgreSQL extensions (pg_trgm, btree_gin)
2. Creates all database tables from SQLAlchemy models
3. Creates GIN indexes for full-text search
4. Creates trigram indexes for fuzzy matching

Requirements: 3.1, 3.3, 3.4, 3.5, 3.6
"""
import asyncio
import sys
import os
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from models import Base, engine


async def enable_extensions():
    """
    Enable required PostgreSQL extensions.
    
    - pg_trgm: Trigram matching for fuzzy text search
    - btree_gin: GIN indexes for full-text search
    """
    print("Enabling PostgreSQL extensions...")
    
    async with engine.begin() as conn:
        try:
            # Enable pg_trgm extension for fuzzy matching
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm;"))
            print("  ✓ pg_trgm extension enabled")
            
            # Enable btree_gin extension for full-text search
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS btree_gin;"))
            print("  ✓ btree_gin extension enabled")
            
        except ProgrammingError as e:
            print(f"  ✗ Error enabling extensions: {e}")
            raise


async def create_tables():
    """
    Create all database tables from SQLAlchemy models.
    
    If tables already exist, this operation is idempotent and will skip creation.
    """
    print("\nCreating database tables...")
    
    try:
        async with engine.begin() as conn:
            # Create all tables defined in Base metadata
            await conn.run_sync(Base.metadata.create_all)
            print("  ✓ All tables created successfully")
            
    except Exception as e:
        print(f"  ✗ Error creating tables: {e}")
        raise


async def create_indexes():
    """
    Create specialized indexes for search and performance.
    
    - GIN indexes for full-text search on threat titles and descriptions
    - Trigram indexes for fuzzy matching on threat titles
    """
    print("\nCreating specialized indexes...")
    
    async with engine.begin() as conn:
        try:
            # Create GIN index for full-text search
            # This index enables fast full-text search on threat titles and descriptions
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_search_idx 
                ON threats 
                USING GIN (to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(description, '')));
            """))
            print("  ✓ Full-text search GIN index created on threats table")
            
            # Create trigram index for fuzzy matching on titles
            # This index enables fast fuzzy/similarity search on threat titles
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_title_trgm_idx 
                ON threats 
                USING GIN (title gin_trgm_ops);
            """))
            print("  ✓ Trigram index created on threats.title for fuzzy matching")
            
            # Create trigram index for fuzzy matching on descriptions
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_description_trgm_idx 
                ON threats 
                USING GIN (description gin_trgm_ops);
            """))
            print("  ✓ Trigram index created on threats.description for fuzzy matching")
            
            # Create index on content_hash for fast deduplication checks
            # Note: This is already created as a unique constraint in the model,
            # but we ensure it exists here for clarity
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_content_hash_idx 
                ON threats (content_hash);
            """))
            print("  ✓ Index created on threats.content_hash for deduplication")
            
            # Create composite index for common query patterns
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_source_ingested_idx 
                ON threats (source, ingested_at DESC);
            """))
            print("  ✓ Composite index created on threats (source, ingested_at)")
            
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS threats_type_severity_idx 
                ON threats (threat_type, severity DESC);
            """))
            print("  ✓ Composite index created on threats (threat_type, severity)")
            
        except ProgrammingError as e:
            print(f"  ✗ Error creating indexes: {e}")
            raise


async def verify_schema():
    """
    Verify that the database schema was created successfully.
    """
    print("\nVerifying database schema...")
    
    async with engine.begin() as conn:
        # Check that all expected tables exist
        result = await conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """))
        
        tables = [row[0] for row in result]
        expected_tables = ['threats', 'entities', 'mitre_mappings', 'llm_analysis', 'users', 'sources']
        
        print(f"  Found {len(tables)} tables:")
        for table in tables:
            status = "✓" if table in expected_tables else "?"
            print(f"    {status} {table}")
        
        missing_tables = set(expected_tables) - set(tables)
        if missing_tables:
            print(f"\n  ✗ Missing tables: {', '.join(missing_tables)}")
            return False
        
        # Check that extensions are enabled
        result = await conn.execute(text("""
            SELECT extname 
            FROM pg_extension 
            WHERE extname IN ('pg_trgm', 'btree_gin')
            ORDER BY extname;
        """))
        
        extensions = [row[0] for row in result]
        print(f"\n  Found {len(extensions)} required extensions:")
        for ext in extensions:
            print(f"    ✓ {ext}")
        
        if len(extensions) < 2:
            print("  ✗ Missing required extensions")
            return False
        
        print("\n✓ Database schema verification successful!")
        return True


async def main():
    """
    Main initialization function.
    
    Runs all initialization steps in order:
    1. Enable extensions
    2. Create tables
    3. Create indexes
    4. Verify schema
    """
    print("=" * 60)
    print("AI Shield Intelligence - Database Initialization")
    print("=" * 60)
    
    try:
        # Step 1: Enable extensions
        await enable_extensions()
        
        # Step 2: Create tables
        await create_tables()
        
        # Step 3: Create indexes
        await create_indexes()
        
        # Step 4: Verify schema
        success = await verify_schema()
        
        if success:
            print("\n" + "=" * 60)
            print("✓ Database initialization completed successfully!")
            print("=" * 60)
            return 0
        else:
            print("\n" + "=" * 60)
            print("✗ Database initialization completed with warnings")
            print("=" * 60)
            return 1
            
    except Exception as e:
        print("\n" + "=" * 60)
        print(f"✗ Database initialization failed: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Close the engine
        await engine.dispose()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
