"""
Search API endpoints for AI Shield Intelligence.

Provides REST API for searching threat intelligence data with filters and pagination.

Requirements: 12.7
"""
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_db
from services.search import get_search_service, SearchService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["search"])


@router.get("/search")
async def search_threats(
    q: Optional[str] = Query(None, description="Search query (searches title and description)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    testability: Optional[str] = Query(None, description="Filter by testability (yes, no, conditional)"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    date_from: Optional[datetime] = Query(None, description="Filter threats published after this date (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published before this date (ISO 8601)"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(20, ge=1, le=100, description="Results per page (max 100)"),
    db: AsyncSession = Depends(get_db)
):
    """
    Search threats with filters and pagination.
    
    **Search Features:**
    - Full-text search using PostgreSQL tsvector
    - Fuzzy matching using pg_trgm extension (catches typos)
    - Relevance ranking (most relevant results first)
    
    **Filters:**
    - `threat_type`: Filter by threat type (e.g., 'adversarial', 'extraction', 'poisoning')
    - `testability`: Filter by testability (yes, no, conditional)
    - `severity_min`, `severity_max`: Filter by severity range (1-10)
    - `date_from`, `date_to`: Filter by publication date range
    
    **Pagination:**
    - `page`: Page number (default: 1)
    - `per_page`: Results per page (default: 20, max: 100)
    
    **Response:**
    - `results`: List of matching threats
    - `total`: Total number of matching threats
    - `page`: Current page number
    - `per_page`: Results per page
    - `total_pages`: Total number of pages
    - `has_next`: Whether there's a next page
    - `has_prev`: Whether there's a previous page
    
    **Examples:**
    - Search for "adversarial attack": `/api/v1/search?q=adversarial+attack`
    - High severity threats: `/api/v1/search?severity_min=8`
    - Recent extraction attacks: `/api/v1/search?threat_type=extraction&date_from=2024-01-01`
    - Testable threats: `/api/v1/search?testability=yes`
    - Paginated results: `/api/v1/search?q=model&page=2&per_page=10`
    
    Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 12.7
    """
    try:
        # Validate severity range
        if severity_min is not None and severity_max is not None:
            if severity_min > severity_max:
                raise HTTPException(
                    status_code=400,
                    detail="severity_min cannot be greater than severity_max"
                )
        
        # Validate date range
        if date_from is not None and date_to is not None:
            if date_from > date_to:
                raise HTTPException(
                    status_code=400,
                    detail="date_from cannot be after date_to"
                )
        
        # Get search service
        search_service = await get_search_service(db)
        
        # Perform search
        results = await search_service.search(
            query=q,
            threat_type=threat_type,
            testability=testability,
            severity_min=severity_min,
            severity_max=severity_max,
            date_from=date_from,
            date_to=date_to,
            page=page,
            per_page=per_page
        )
        
        logger.info(f"Search completed: {results['total']} results, page {page}/{results['total_pages']}")
        
        return results
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/search/statistics")
async def get_search_statistics(
    db: AsyncSession = Depends(get_db)
):
    """
    Get statistics about the threat database.
    
    Returns:
    - `total_threats`: Total number of threats in database
    - `threat_types`: Count of threats by type
    - `severity_distribution`: Count of threats by severity level
    - `top_sources`: Top 10 sources by threat count
    
    Useful for:
    - Dashboard statistics
    - Understanding data distribution
    - Populating filter dropdowns
    """
    try:
        search_service = await get_search_service(db)
        stats = await search_service.get_search_statistics()
        
        logger.info(f"Statistics retrieved: {stats['total_threats']} total threats")
        
        return stats
    
    except Exception as e:
        logger.error(f"Statistics error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@router.get("/search/threat-types")
async def get_threat_types(
    db: AsyncSession = Depends(get_db)
):
    """
    Get list of all unique threat types in the database.
    
    Returns:
    - List of threat type strings
    
    Useful for populating threat type filter dropdowns.
    """
    try:
        search_service = await get_search_service(db)
        threat_types = await search_service.get_threat_types()
        
        logger.info(f"Retrieved {len(threat_types)} threat types")
        
        return {
            "threat_types": threat_types,
            "count": len(threat_types)
        }
    
    except Exception as e:
        logger.error(f"Threat types error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve threat types: {str(e)}"
        )


@router.get("/threats/recent")
async def get_recent_threats(
    limit: int = Query(10, ge=1, le=50, description="Maximum number of threats to return"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get most recently ingested threats.
    
    Parameters:
    - `limit`: Maximum number of threats to return (default: 10, max: 50)
    
    Returns:
    - List of recent threats ordered by ingestion date (newest first)
    
    Useful for dashboard "Recent Threats" widget.
    """
    try:
        search_service = await get_search_service(db)
        threats = await search_service.get_recent_threats(limit=limit)
        
        logger.info(f"Retrieved {len(threats)} recent threats")
        
        return {
            "threats": [threat.to_dict() for threat in threats],
            "count": len(threats)
        }
    
    except Exception as e:
        logger.error(f"Recent threats error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve recent threats: {str(e)}"
        )


@router.get("/threats/high-severity")
async def get_high_severity_threats(
    severity_threshold: int = Query(7, ge=1, le=10, description="Minimum severity level"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of threats to return"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get high-severity threats.
    
    Parameters:
    - `severity_threshold`: Minimum severity level (default: 7)
    - `limit`: Maximum number of threats to return (default: 10, max: 50)
    
    Returns:
    - List of high-severity threats ordered by severity (highest first)
    
    Useful for dashboard "High Severity Alerts" widget.
    """
    try:
        search_service = await get_search_service(db)
        threats = await search_service.get_high_severity_threats(
            severity_threshold=severity_threshold,
            limit=limit
        )
        
        logger.info(f"Retrieved {len(threats)} high-severity threats (>= {severity_threshold})")
        
        return {
            "threats": [threat.to_dict() for threat in threats],
            "count": len(threats),
            "severity_threshold": severity_threshold
        }
    
    except Exception as e:
        logger.error(f"High severity threats error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve high-severity threats: {str(e)}"
        )


@router.get("/threats/{threat_id}")
async def get_threat_by_id(
    threat_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific threat by ID.
    
    Parameters:
    - `threat_id`: UUID of the threat
    
    Returns:
    - Threat details including all enrichment data
    
    Raises:
    - 404 if threat not found
    """
    try:
        search_service = await get_search_service(db)
        threat = await search_service.get_threat_by_id(threat_id)
        
        if not threat:
            raise HTTPException(
                status_code=404,
                detail=f"Threat with ID {threat_id} not found"
            )
        
        logger.info(f"Retrieved threat {threat_id}")
        
        return threat.to_dict()
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get threat error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve threat: {str(e)}"
        )
