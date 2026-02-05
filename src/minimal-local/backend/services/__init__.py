"""
Services package

Business logic and service layer for the AI Shield Intelligence system.
"""

from .source_manager import SourceManager, SourceConfig, get_source_manager

__all__ = [
    "SourceManager",
    "SourceConfig",
    "get_source_manager",
]
