#!/usr/bin/env python3
"""
Test script for admin user creation functionality.

This script tests the password validation and hashing functions
without requiring a database connection.
"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from create_admin import validate_password, hash_password


def test_password_validation():
    """Test password validation function."""
    print("Testing password validation...")
    print()
    
    test_cases = [
        # (password, should_pass, description)
        ("short", False, "Too short (< 8 chars)"),
        ("alllowercase123", False, "No uppercase letter"),
        ("ALLUPPERCASE123", False, "No lowercase letter"),
        ("NoNumbers", False, "No numbers"),
        ("ValidPass123", True, "Valid password"),
        ("AnotherGood1", True, "Valid password (8 chars)"),
        ("Complex!Pass123", True, "Valid with special chars"),
        ("VeryLongPasswordWithNumbers123", True, "Valid long password"),
    ]
    
    passed = 0
    failed = 0
    
    for password, should_pass, description in test_cases:
        is_valid, error_msg = validate_password(password)
        
        if is_valid == should_pass:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
        
        print(f"{status}: {description}")
        print(f"  Password: '{password}'")
        print(f"  Expected: {'Valid' if should_pass else 'Invalid'}")
        print(f"  Got: {'Valid' if is_valid else f'Invalid - {error_msg}'}")
        print()
    
    print(f"Results: {passed} passed, {failed} failed")
    return failed == 0


def test_password_hashing():
    """Test password hashing function."""
    print("\nTesting password hashing...")
    print()
    
    test_password = "TestPassword123"
    
    # Hash the password
    hash1 = hash_password(test_password)
    print(f"✓ Password hashed successfully")
    print(f"  Original: {test_password}")
    print(f"  Hash: {hash1[:50]}...")
    print()
    
    # Verify hash is different each time (bcrypt uses random salt)
    hash2 = hash_password(test_password)
    if hash1 != hash2:
        print(f"✓ Each hash is unique (uses random salt)")
        print(f"  Hash 2: {hash2[:50]}...")
    else:
        print(f"✗ Hashes should be different due to random salt")
        return False
    
    print()
    
    # Verify hash format (bcrypt hashes start with $2b$)
    if hash1.startswith("$2b$") or hash1.startswith("$2a$"):
        print(f"✓ Hash format is correct (bcrypt)")
    else:
        print(f"✗ Hash format is incorrect")
        return False
    
    print()
    
    # Verify hash length (bcrypt hashes are 60 characters)
    if len(hash1) == 60:
        print(f"✓ Hash length is correct (60 characters)")
    else:
        print(f"✗ Hash length is incorrect: {len(hash1)}")
        return False
    
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("Admin User Creation - Validation Tests")
    print("=" * 60)
    print()
    
    # Test password validation
    validation_passed = test_password_validation()
    
    # Test password hashing
    hashing_passed = test_password_hashing()
    
    print()
    print("=" * 60)
    if validation_passed and hashing_passed:
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
    else:
        print("✗ Some tests failed")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
