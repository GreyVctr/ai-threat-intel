"""
Database models for AI Shield Intelligence minimal local profile.
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
import os

# Create declarative base
Base = declarative_base()

# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://ai_shield:changeme@localhost:5432/ai_shield"
)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    poolclass=NullPool,  # Use NullPool for better connection management
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """
    Dependency for getting database sessions.
    
    Usage:
        async with get_db() as db:
            # Use db session
            pass
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Import all models to ensure they're registered with Base
from .threat import Threat
from .entity import Entity
from .mitre import MitreMapping
from .llm_analysis import LLMAnalysis
from .user import User
from .source import Source

__all__ = [
    "Base",
    "engine",
    "AsyncSessionLocal",
    "get_db",
    "Threat",
    "Entity",
    "MitreMapping",
    "LLMAnalysis",
    "User",
    "Source",
]
