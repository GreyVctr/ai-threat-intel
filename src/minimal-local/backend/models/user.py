"""
User model for authentication and authorization.
"""
from sqlalchemy import Column, String, Boolean, TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from . import Base


class User(Base):
    """
    Represents a user account with authentication credentials.
    
    Supports admin privileges for system management operations.
    Passwords are hashed using bcrypt before storage.
    """
    __tablename__ = "users"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # User credentials
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Authorization
    is_admin = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), default=func.now(), nullable=False)
    last_login = Column(TIMESTAMP(timezone=True))
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}', is_admin={self.is_admin})>"
    
    def to_dict(self, include_sensitive=False):
        """
        Convert user to dictionary for API responses.
        
        Args:
            include_sensitive: If True, include sensitive fields (for admin use only)
        """
        data = {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        
        if include_sensitive:
            data["password_hash"] = self.password_hash
        
        return data
