"""
Simple test to verify API imports work correctly.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("Testing imports...")

try:
    print("  - Importing auth module...")
    from api import auth
    print("    ✓ auth module imported")
    
    print("  - Importing threats module...")
    from api import threats
    print("    ✓ threats module imported")
    
    print("  - Importing search module...")
    from api import search
    print("    ✓ search module imported")
    
    print("  - Importing sources module...")
    from api import sources
    print("    ✓ sources module imported")
    
    print("  - Importing health module...")
    from api import health
    print("    ✓ health module imported")
    
    print("\n✓ All API modules imported successfully!")
    print("\nAPI Routers available:")
    print(f"  - auth.router: {auth.router.prefix}")
    print(f"  - threats.router: {threats.router.prefix}")
    print(f"  - search.router: {search.router.prefix}")
    print(f"  - sources.router: {sources.router.prefix}")
    print(f"  - health.router: {health.router.prefix}")
    
except Exception as e:
    print(f"\n✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
