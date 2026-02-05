"""
Search service for AI Shield Intelligence.

Provides full-text search, fuzzy matching, relevance ranking, and filtering
for threat intelligence data using PostgreSQL's advanced search capabilities.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8
"""
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func, or_, and_, text
from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat

logger = logging.getLogger(__name__)


class SearchService:
    """
    Service for searching threat intelligence data.
    
    Features:
    - Full-text search using PostgreSQL tsvector
    - Fuzzy matching using pg_trgm extension
    - Relevance ranking
    - Filtering by threat type, severity, and date range
    - Pagination support
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize search service.
        
        Args:
            db_session: SQLAlchemy async database session
        """
        self.db = db_session
    
    async def search(
        self,
        query: Optional[str] = None,
        threat_type: Optional[str] = None,
        testability: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Dict[str, Any]:
        """
        Search threats with filters and pagination.
        
        Args:
            query: Search query string (searches title and description)
            threat_type: Filter by threat type (e.g., 'adversarial', 'extraction')
            testability: Filter by testability (yes, no, conditional)
            severity_min: Minimum severity level (1-10)
            severity_max: Maximum severity level (1-10)
            date_from: Filter threats published after this date
            date_to: Filter threats published before this date
            page: Page number (1-indexed)
            per_page: Results per page (default: 20)
        
        Returns:
            Dictionary containing:
            - results: List of matching threats
            - total: Total number of matching threats
            - page: Current page number
            - per_page: Results per page
            - total_pages: Total number of pages
        
        Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8
        """
        logger.info(f"Search request: query='{query}', type={threat_type}, testability={testability}, "
                   f"severity={severity_min}-{severity_max}, page={page}")
        
        # Build base query
        stmt = select(Threat)
        
        # Apply search query with relevance ranking
        if query and query.strip():
            # Use both full-text search and fuzzy matching for better results
            # Full-text search using tsvector
            search_vector = func.to_tsvector('english', 
                                            func.coalesce(Threat.title, '') + ' ' + 
                                            func.coalesce(Threat.description, ''))
            search_query = func.plainto_tsquery('english', query)
            
            # Fuzzy matching using trigrams (similarity score)
            # Use COALESCE to handle NULL descriptions
            title_similarity = func.similarity(func.coalesce(Threat.title, ''), query)
            desc_similarity = func.similarity(func.coalesce(Threat.description, ''), query)
            
            # Combine full-text search and fuzzy matching
            # Full-text search provides exact matches, fuzzy matching catches typos
            stmt = stmt.where(
                or_(
                    search_vector.op('@@')(search_query),  # Full-text match
                    title_similarity > 0.3,  # Fuzzy match on title (30% similarity)
                    desc_similarity > 0.2    # Fuzzy match on description (20% similarity)
                )
            )
            
            # Calculate relevance score for ranking
            # Higher score = more relevant
            # Factors:
            # - Full-text search rank (ts_rank)
            # - Title similarity (weighted higher)
            # - Description similarity
            relevance_score = (
                func.ts_rank(search_vector, search_query) * 10 +  # Full-text relevance
                title_similarity * 5 +  # Title similarity (weighted 5x)
                desc_similarity * 2     # Description similarity (weighted 2x)
            ).label('relevance')
            
            # Add relevance score to query and order by it
            stmt = stmt.add_columns(relevance_score)
            stmt = stmt.order_by(text('relevance DESC'))
        else:
            # No search query - order by ingestion date (most recent first)
            stmt = stmt.order_by(Threat.ingested_at.desc())
        
        # Apply filters
        filters = []
        
        if threat_type:
            filters.append(Threat.threat_type == threat_type)
        
        if severity_min is not None:
            filters.append(Threat.severity >= severity_min)
        
        if severity_max is not None:
            filters.append(Threat.severity <= severity_max)
        
        if date_from:
            filters.append(Threat.published_at >= date_from)
        
        if date_to:
            filters.append(Threat.published_at <= date_to)
        
        # Apply metadata filters (testability)
        if testability:
            from utils.query_builders import build_metadata_filter
            metadata_filters = build_metadata_filter(
                Threat,
                testability=testability
            )
            if metadata_filters:
                filters.extend(metadata_filters)
        
        if filters:
            stmt = stmt.where(and_(*filters))
        
        # Count total results (before pagination)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        result = await self.db.execute(count_stmt)
        total = result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        stmt = stmt.offset(offset).limit(per_page)
        
        # Execute query
        result = await self.db.execute(stmt)
        
        # Extract threats from results
        if query and query.strip():
            # Results include relevance score
            rows = result.all()
            threats = [row[0] for row in rows]
            relevance_scores = [row[1] for row in rows]
            logger.debug(f"Relevance scores: {relevance_scores[:5]}")  # Log top 5 scores
        else:
            threats = result.scalars().all()
        
        # Calculate pagination metadata
        total_pages = (total + per_page - 1) // per_page  # Ceiling division
        
        logger.info(f"Search completed: {total} total results, returning page {page}/{total_pages}")
        
        return {
            "results": [threat.to_dict() for threat in threats],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    
    async def search_by_content_hash(self, content_hash: str) -> Optional[Threat]:
        """
        Search for a threat by its content hash.
        
        Used for deduplication during ingestion.
        
        Args:
            content_hash: SHA-256 hash of threat content
        
        Returns:
            Threat if found, None otherwise
        """
        stmt = select(Threat).where(Threat.content_hash == content_hash)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_threat_by_id(self, threat_id: str) -> Optional[Threat]:
        """
        Get a specific threat by ID.
        
        Args:
            threat_id: UUID of the threat
        
        Returns:
            Threat if found, None otherwise
        """
        stmt = select(Threat).where(Threat.id == threat_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_recent_threats(self, limit: int = 10) -> List[Threat]:
        """
        Get most recently ingested threats.
        
        Args:
            limit: Maximum number of threats to return
        
        Returns:
            List of recent threats
        """
        stmt = select(Threat).order_by(Threat.ingested_at.desc()).limit(limit)
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def get_high_severity_threats(
        self,
        severity_threshold: int = 7,
        limit: int = 10
    ) -> List[Threat]:
        """
        Get high-severity threats.
        
        Args:
            severity_threshold: Minimum severity level (default: 7)
            limit: Maximum number of threats to return
        
        Returns:
            List of high-severity threats
        """
        stmt = (
            select(Threat)
            .where(Threat.severity >= severity_threshold)
            .order_by(Threat.severity.desc(), Threat.ingested_at.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def get_threat_types(self) -> List[str]:
        """
        Get list of all unique threat types in the database.
        
        Returns:
            List of threat type strings
        """
        stmt = (
            select(Threat.threat_type)
            .where(Threat.threat_type.isnot(None))
            .distinct()
            .order_by(Threat.threat_type)
        )
        result = await self.db.execute(stmt)
        return [row[0] for row in result.all()]
    
    async def get_search_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the threat database.
        
        Returns:
            Dictionary with statistics:
            - total_threats: Total number of threats
            - threat_types: Count by threat type
            - severity_distribution: Count by severity level
            - sources: Count by source
        """
        # Total threats
        total_stmt = select(func.count(Threat.id))
        result = await self.db.execute(total_stmt)
        total_threats = result.scalar()
        
        # Threat types distribution
        type_stmt = (
            select(Threat.threat_type, func.count(Threat.id))
            .where(Threat.threat_type.isnot(None))
            .group_by(Threat.threat_type)
            .order_by(func.count(Threat.id).desc())
        )
        result = await self.db.execute(type_stmt)
        threat_types = {row[0]: row[1] for row in result.all()}
        
        # Severity distribution
        severity_stmt = (
            select(Threat.severity, func.count(Threat.id))
            .where(Threat.severity.isnot(None))
            .group_by(Threat.severity)
            .order_by(Threat.severity)
        )
        result = await self.db.execute(severity_stmt)
        severity_distribution = {row[0]: row[1] for row in result.all()}
        
        # Sources distribution
        source_stmt = (
            select(Threat.source, func.count(Threat.id))
            .group_by(Threat.source)
            .order_by(func.count(Threat.id).desc())
            .limit(10)  # Top 10 sources
        )
        result = await self.db.execute(source_stmt)
        sources = {row[0]: row[1] for row in result.all()}
        
        return {
            "total_threats": total_threats,
            "threat_types": threat_types,
            "severity_distribution": severity_distribution,
            "top_sources": sources
        }


async def get_search_service(db_session: AsyncSession) -> SearchService:
    """
    Factory function to create a SearchService instance.
    
    Args:
        db_session: SQLAlchemy async database session
    
    Returns:
        SearchService instance
    """
    return SearchService(db_session)
