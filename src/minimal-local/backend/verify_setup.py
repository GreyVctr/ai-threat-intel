#!/usr/bin/env python3
"""
Verification script for FastAPI backend setup
Tests that all modules can be imported and basic configuration works
"""
import sys


def verify_imports():
    """Verify all required modules can be imported"""
    print("Verifying imports...")
    
    try:
        import fastapi
        print("✓ FastAPI imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import FastAPI: {e}")
        return False
    
    try:
        import uvicorn
        print("✓ Uvicorn imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import Uvicorn: {e}")
        return False
    
    try:
        import sqlalchemy
        print("✓ SQLAlchemy imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import SQLAlchemy: {e}")
        return False
    
    try:
        import redis
        print("✓ Redis imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import Redis: {e}")
        return False
    
    try:
        import pydantic
        print("✓ Pydantic imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import Pydantic: {e}")
        return False
    
    try:
        import httpx
        print("✓ HTTPX imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import HTTPX: {e}")
        return False
    
    try:
        import minio
        print("✓ MinIO imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import MinIO: {e}")
        return False
    
    return True


def verify_config():
    """Verify configuration module works"""
    print("\nVerifying configuration...")
    
    try:
        from config import settings
        print(f"✓ Configuration loaded successfully")
        print(f"  - Environment: {settings.environment}")
        print(f"  - Log Level: {settings.log_level}")
        print(f"  - API Version: {settings.api_version}")
        return True
    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        return False


def verify_main_app():
    """Verify main application can be imported"""
    print("\nVerifying main application...")
    
    try:
        from main import app
        print(f"✓ FastAPI app created successfully")
        print(f"  - Title: {app.title}")
        print(f"  - Version: {app.version}")
        return True
    except Exception as e:
        print(f"✗ Failed to create FastAPI app: {e}")
        return False


def verify_health_endpoint():
    """Verify health endpoint can be imported"""
    print("\nVerifying health endpoint...")
    
    try:
        from api.health import router
        print(f"✓ Health router imported successfully")
        print(f"  - Routes: {len(router.routes)}")
        for route in router.routes:
            print(f"    - {route.methods} {route.path}")
        return True
    except Exception as e:
        print(f"✗ Failed to import health router: {e}")
        return False


def main():
    """Run all verification checks"""
    print("=" * 60)
    print("FastAPI Backend Setup Verification")
    print("=" * 60)
    
    checks = [
        verify_imports(),
        verify_config(),
        verify_main_app(),
        verify_health_endpoint()
    ]
    
    print("\n" + "=" * 60)
    if all(checks):
        print("✓ All verification checks passed!")
        print("=" * 60)
        return 0
    else:
        print("✗ Some verification checks failed")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
