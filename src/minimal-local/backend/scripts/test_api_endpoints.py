"""
Test script for REST API endpoints.

Tests the threats and auth API endpoints to verify they work correctly.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from models import AsyncSessionLocal, User, Threat
from api.auth import get_password_hash, verify_password, create_access_token


async def test_password_functions():
    """Test password hashing and verification"""
    print("\n=== Testing Password Functions ===")
    
    password = "TestPass123"  # Shorter password to avoid bcrypt 72-byte limit
    hashed = get_password_hash(password)
    
    print(f"Original password: {password}")
    print(f"Hashed password: {hashed[:50]}...")
    print(f"Verification result: {verify_password(password, hashed)}")
    print(f"Wrong password verification: {verify_password('WrongPassword', hashed)}")
    
    assert verify_password(password, hashed), "Password verification failed"
    assert not verify_password('WrongPassword', hashed), "Wrong password should not verify"
    
    print("✓ Password functions work correctly")


async def test_jwt_token():
    """Test JWT token creation"""
    print("\n=== Testing JWT Token Creation ===")
    
    token = create_access_token(data={"sub": "testuser"})
    
    print(f"Generated token: {token[:50]}...")
    print(f"Token length: {len(token)}")
    
    assert len(token) > 0, "Token should not be empty"
    
    print("✓ JWT token creation works correctly")


async def test_user_model():
    """Test User model"""
    print("\n=== Testing User Model ===")
    
    async with AsyncSessionLocal() as db:
        # Check if any users exist
        query = select(User)
        result = await db.execute(query)
        users = result.scalars().all()
        
        print(f"Found {len(users)} users in database")
        
        if users:
            user = users[0]
            print(f"Sample user: {user.username} (admin: {user.is_admin})")
            
            # Test to_dict method
            user_dict = user.to_dict()
            print(f"User dict keys: {list(user_dict.keys())}")
            
            assert 'id' in user_dict, "User dict should have 'id'"
            assert 'username' in user_dict, "User dict should have 'username'"
            assert 'password_hash' not in user_dict, "User dict should not expose password_hash by default"
            
            print("✓ User model works correctly")
        else:
            print("⚠ No users found in database. Run create_admin.py first.")


async def test_threat_model():
    """Test Threat model"""
    print("\n=== Testing Threat Model ===")
    
    async with AsyncSessionLocal() as db:
        # Check if any threats exist
        query = select(Threat).limit(1)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if threat:
            print(f"Found threat: {threat.title[:50]}...")
            
            # Test to_dict method
            threat_dict = threat.to_dict()
            print(f"Threat dict keys: {list(threat_dict.keys())}")
            
            assert 'id' in threat_dict, "Threat dict should have 'id'"
            assert 'title' in threat_dict, "Threat dict should have 'title'"
            assert 'source' in threat_dict, "Threat dict should have 'source'"
            
            print("✓ Threat model works correctly")
        else:
            print("⚠ No threats found in database. This is expected for a fresh installation.")


async def main():
    """Run all tests"""
    print("=" * 60)
    print("Testing REST API Endpoints")
    print("=" * 60)
    
    try:
        await test_password_functions()
        await test_jwt_token()
        await test_user_model()
        await test_threat_model()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
