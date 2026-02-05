#!/usr/bin/env python3
"""
Simple test for password validation without database dependencies.
Tests only the validation logic, not the hashing (which has bcrypt version issues).
"""
import re


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    
    Args:
        password: The password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    return True, ""


def main():
    """Test password validation."""
    print("=" * 60)
    print("Password Validation Tests")
    print("=" * 60)
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
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
