#!/usr/bin/env python3
"""
Simple verification script to check that all models can be imported.
"""
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

def main():
    """Verify all models can be imported."""
    print("Verifying database models...")
    
    try:
        from models import (
            Base,
            engine,
            AsyncSessionLocal,
            get_db,
            Threat,
            Entity,
            MitreMapping,
            LLMAnalysis,
            User,
            Source,
        )
        
        print("✓ All models imported successfully")
        print(f"  - Base: {Base}")
        print(f"  - Threat: {Threat}")
        print(f"  - Entity: {Entity}")
        print(f"  - MitreMapping: {MitreMapping}")
        print(f"  - LLMAnalysis: {LLMAnalysis}")
        print(f"  - User: {User}")
        print(f"  - Source: {Source}")
        
        # Check that all models are registered with Base
        tables = Base.metadata.tables.keys()
        print(f"\n✓ Found {len(tables)} tables in metadata:")
        for table in sorted(tables):
            print(f"  - {table}")
        
        expected_tables = {'threats', 'entities', 'mitre_mappings', 'llm_analysis', 'users', 'sources'}
        if set(tables) == expected_tables:
            print("\n✓ All expected tables are registered")
            return 0
        else:
            missing = expected_tables - set(tables)
            extra = set(tables) - expected_tables
            if missing:
                print(f"\n✗ Missing tables: {missing}")
            if extra:
                print(f"\n✗ Extra tables: {extra}")
            return 1
            
    except ImportError as e:
        print(f"✗ Import error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
