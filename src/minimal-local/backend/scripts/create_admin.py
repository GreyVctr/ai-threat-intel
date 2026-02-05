#!/usr/bin/env python3
"""
Admin user creation script for AI Shield Intelligence.

This script creates an admin user account with proper password validation
and hashing. It handles existing admin users gracefully.

Supports both interactive and non-interactive modes:
- Interactive: Run without environment variables, prompts for input
- Non-interactive: Set ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD environment variables

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
"""
import asyncio
import bcrypt
import getpass
import os
import re
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from models import AsyncSessionLocal, User, engine


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


def hash_password(password: str) -> str:
    """
    Hash password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


async def check_existing_admin() -> User | None:
    """
    Check if an admin user already exists.
    
    Returns:
        Existing admin user or None
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.is_admin == True)
        )
        return result.scalar_one_or_none()


async def create_admin_user(username: str, email: str, password_hash: str) -> User:
    """
    Create an admin user in the database.
    
    Args:
        username: Username for the admin
        email: Email address for the admin
        password_hash: Hashed password
        
    Returns:
        Created User object
        
    Raises:
        IntegrityError: If username or email already exists
    """
    async with AsyncSessionLocal() as session:
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            is_admin=True
        )
        
        session.add(user)
        await session.commit()
        await session.refresh(user)
        
        return user


async def main():
    """Main script execution."""
    print("=" * 60)
    print("AI Shield Intelligence - Admin User Creation")
    print("=" * 60)
    print()
    
    # Check for existing admin
    existing_admin = await check_existing_admin()
    if existing_admin:
        print(f"⚠️  An admin user already exists: {existing_admin.username}")
        print(f"   Email: {existing_admin.email}")
        print(f"   Created: {existing_admin.created_at}")
        print()
        print("If you need to create another admin or reset the password,")
        print("please use the database directly or delete the existing admin first.")
        return 1
    
    # Check for environment variables (non-interactive mode)
    env_username = os.getenv('ADMIN_USERNAME')
    env_email = os.getenv('ADMIN_EMAIL')
    env_password = os.getenv('ADMIN_PASSWORD')
    
    if env_username and env_email and env_password:
        print("Using credentials from environment variables...")
        print()
        username = env_username
        email = env_email
        password = env_password
        
        # Validate password strength
        is_valid, error_message = validate_password(password)
        if not is_valid:
            print(f"❌ {error_message}")
            print()
            print("Password requirements:")
            print("  • Minimum 8 characters")
            print("  • At least one uppercase letter (A-Z)")
            print("  • At least one lowercase letter (a-z)")
            print("  • At least one number (0-9)")
            return 1
    else:
        # Interactive mode
        print("No admin user found. Let's create one!")
        print()
        
        # Prompt for username
        while True:
            username = input("Enter username: ").strip()
            if not username:
                print("❌ Username cannot be empty")
                continue
            if len(username) > 100:
                print("❌ Username must be 100 characters or less")
                continue
            break
        
        # Prompt for email
        while True:
            email = input("Enter email: ").strip()
            if not email:
                print("❌ Email cannot be empty")
                continue
            if len(email) > 255:
                print("❌ Email must be 255 characters or less")
                continue
            # Basic email validation
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                print("❌ Invalid email format")
                continue
            break
        
        # Prompt for password with validation
        while True:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("❌ Password cannot be empty")
                continue
            
            # Validate password strength
            is_valid, error_message = validate_password(password)
            if not is_valid:
                print(f"❌ {error_message}")
                print()
                print("Password requirements:")
                print("  • Minimum 8 characters")
                print("  • At least one uppercase letter (A-Z)")
                print("  • At least one lowercase letter (a-z)")
                print("  • At least one number (0-9)")
                print()
                continue
            
            # Confirm password
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("❌ Passwords do not match")
                continue
            
            break
    
    print()
    print("Creating admin user...")
    
    try:
        # Hash the password
        password_hash = hash_password(password)
        
        # Create the user
        user = await create_admin_user(username, email, password_hash)
        
        print()
        print("✅ Admin user created successfully!")
        print()
        print(f"   Username: {user.username}")
        print(f"   Email: {user.email}")
        print(f"   User ID: {user.id}")
        print(f"   Created: {user.created_at}")
        print()
        print("You can now use these credentials to log in to the system.")
        
        return 0
        
    except IntegrityError as e:
        print()
        print("❌ Failed to create admin user:")
        if "username" in str(e):
            print(f"   Username '{username}' already exists")
        elif "email" in str(e):
            print(f"   Email '{email}' already exists")
        else:
            print(f"   {e}")
        return 1
        
    except Exception as e:
        print()
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print()
        print("❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print()
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
