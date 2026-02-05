"""
Threats API endpoints for AI Shield Intelligence.

Provides REST API for CRUD operations on threat intelligence data.

Requirements: 12.2, 12.3, 12.4, 12.5, 12.6
"""
import logging
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field, validator
from sqlalchemy import select, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models import get_db, Threat, Entity, MitreMapping, LLMAnalysis
from api.auth import get_current_user, get_current_admin_user
from utils.hashing import calculate_content_hash
from utils.query_builders import build_metadata_filter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])


# Pydantic models for request/response validation

class ThreatCreate(BaseModel):
    """Request model for creating a threat"""
    title: str = Field(..., min_length=1, max_length=500, description="Threat title")
    description: Optional[str] = Field(None, description="Brief description of the threat")
    content: Optional[str] = Field(None, description="Full threat content")
    source: str = Field(..., min_length=1, max_length=255, description="Source name")
    source_url: Optional[str] = Field(None, description="URL to original source")
    authors: Optional[List[str]] = Field(None, description="List of authors")
    published_at: Optional[datetime] = Field(None, description="Publication date")
    threat_type: Optional[str] = Field(None, max_length=50, description="Threat type")
    severity: Optional[int] = Field(None, ge=1, le=10, description="Severity score (1-10)")
    metadata: Optional[dict] = Field(None, description="Additional metadata")
    
    @validator('severity')
    def validate_severity(cls, v):
        if v is not None and (v < 1 or v > 10):
            raise ValueError('Severity must be between 1 and 10')
        return v


class ThreatUpdate(BaseModel):
    """Request model for updating a threat"""
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    content: Optional[str] = None
    source: Optional[str] = Field(None, min_length=1, max_length=255)
    source_url: Optional[str] = None
    authors: Optional[List[str]] = None
    published_at: Optional[datetime] = None
    threat_type: Optional[str] = Field(None, max_length=50)
    severity: Optional[int] = Field(None, ge=1, le=10)
    metadata: Optional[dict] = None
    
    @validator('severity')
    def validate_severity(cls, v):
        if v is not None and (v < 1 or v > 10):
            raise ValueError('Severity must be between 1 and 10')
        return v


class EntityResponse(BaseModel):
    """Response model for an entity"""
    id: str
    entity_type: str
    entity_value: str
    confidence: Optional[float]
    extracted_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class MitreMappingResponse(BaseModel):
    """Response model for a MITRE ATLAS mapping"""
    id: str
    tactic: Optional[str]
    technique: Optional[str]
    technique_id: Optional[str]
    confidence: Optional[float]
    
    class Config:
        from_attributes = True


class LLMAnalysisResponse(BaseModel):
    """Response model for LLM analysis"""
    id: str
    summary: Optional[str]
    key_findings: Optional[List[str]]
    attack_vectors: Optional[List[str]]
    mitigations: Optional[List[str]]
    model_name: Optional[str]
    analyzed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class ThreatResponse(BaseModel):
    """Response model for a threat"""
    id: str
    title: str
    description: Optional[str]
    content: Optional[str]
    source: str
    source_url: Optional[str]
    authors: Optional[List[str]]
    published_at: Optional[datetime]
    ingested_at: Optional[datetime]
    content_hash: str
    threat_type: Optional[str]
    severity: Optional[int]
    exploitability_score: Optional[str]
    raw_data_key: Optional[str]
    metadata: Optional[dict]
    classification_metadata: Optional[dict] = Field(None, description="Structured threat classification metadata")
    enrichment_status: Optional[str]
    llm_analysis_status: Optional[str]
    entities: Optional[List[EntityResponse]] = None
    mitre_mappings: Optional[List[MitreMappingResponse]] = None
    llm_analysis: Optional[LLMAnalysisResponse] = None
    
    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    """Response model for paginated threat list"""
    threats: List[ThreatResponse]
    total: int
    page: int
    per_page: int
    total_pages: int
    has_next: bool
    has_prev: bool


# API Endpoints

@router.get("", response_model=ThreatListResponse)
async def list_threats(
    page: int = 1,
    per_page: int = 20,
    threat_type: Optional[str] = None,
    severity_min: Optional[int] = None,
    severity_max: Optional[int] = None,
    source: Optional[str] = None,
    attack_surface: Optional[List[str]] = Query(None, description="Filter by attack surface tags"),
    testability: Optional[str] = Query(None, description="Filter by testability (yes, no, conditional)"),
    techniques: Optional[List[str]] = Query(None, description="Filter by technique tags"),
    target_systems: Optional[List[str]] = Query(None, description="Filter by target system tags"),
    db: AsyncSession = Depends(get_db)
):
    """
    List threats with pagination and optional filters.
    
    **Query Parameters:**
    - `page`: Page number (default: 1)
    - `per_page`: Results per page (default: 20, max: 100)
    - `threat_type`: Filter by threat type
    - `severity_min`: Minimum severity (1-10)
    - `severity_max`: Maximum severity (1-10)
    - `source`: Filter by source name
    - `attack_surface`: Filter by attack surface tags (runtime, training, inference, fine-tuning, deployment)
    - `testability`: Filter by testability flag (yes, no, conditional)
    - `techniques`: Filter by technique tags (e.g., jailbreak, FGSM, backdoor)
    - `target_systems`: Filter by target system tags (llm, vision, multimodal, rag, agentic, chat)
    
    **Returns:**
    - Paginated list of threats with metadata
    
    Requirements: 12.2, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
    """
    try:
        # Validate pagination parameters
        if page < 1:
            raise HTTPException(status_code=400, detail="Page must be >= 1")
        if per_page < 1 or per_page > 100:
            raise HTTPException(status_code=400, detail="per_page must be between 1 and 100")
        
        # Build query
        query = select(Threat)
        
        # Apply basic filters
        if threat_type:
            query = query.where(Threat.threat_type == threat_type)
        if severity_min is not None:
            query = query.where(Threat.severity >= severity_min)
        if severity_max is not None:
            query = query.where(Threat.severity <= severity_max)
        if source:
            query = query.where(Threat.source == source)
        
        # Apply metadata filters
        metadata_filters = build_metadata_filter(
            Threat,
            attack_surface=attack_surface,
            testability=testability,
            techniques=techniques,
            target_systems=target_systems
        )
        if metadata_filters:
            query = query.where(and_(*metadata_filters))
        
        # Order by ingestion date (newest first)
        query = query.order_by(Threat.ingested_at.desc())
        
        # Count total results
        count_query = select(func.count()).select_from(query.subquery())
        result = await db.execute(count_query)
        total = result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        threats = result.scalars().all()
        
        # Calculate pagination metadata
        total_pages = (total + per_page - 1) // per_page
        has_next = page < total_pages
        has_prev = page > 1
        
        logger.info(f"Listed {len(threats)} threats (page {page}/{total_pages}, total: {total})")
        
        # Convert threats to response format
        threat_responses = []
        for t in threats:
            threat_responses.append(ThreatResponse(
                id=str(t.id),
                title=t.title,
                description=t.description,
                content=t.content,
                source=t.source,
                source_url=t.source_url,
                authors=t.authors,
                published_at=t.published_at,
                ingested_at=t.ingested_at,
                content_hash=t.content_hash,
                threat_type=t.threat_type,
                severity=t.severity,
                exploitability_score=t.exploitability_score,
                raw_data_key=t.raw_data_key,
                metadata=t.extra_metadata,
                classification_metadata=t.classification_metadata,
                enrichment_status=t.enrichment_status,
                llm_analysis_status=t.llm_analysis_status
            ))
        
        return ThreatListResponse(
            threats=threat_responses,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            has_next=has_next,
            has_prev=has_prev
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing threats: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list threats: {str(e)}"
        )


@router.get("/recent", response_model=ThreatListResponse)
async def get_recent_threats(
    limit: int = Query(10, ge=1, le=50, description="Maximum number of threats to return"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recently ingested threats.
    
    **Query Parameters:**
    - `limit`: Maximum number of threats to return (default: 10, max: 50)
    
    **Returns:**
    - List of recent threats ordered by ingestion time (newest first)
    """
    try:
        query = select(Threat).order_by(Threat.ingested_at.desc()).limit(limit)
        result = await db.execute(query)
        threats = result.scalars().all()
        
        logger.info(f"Retrieved {len(threats)} recent threats")
        
        threat_responses = [
            ThreatResponse(
                id=str(t.id),
                title=t.title,
                description=t.description,
                content=t.content,
                source=t.source,
                source_url=t.source_url,
                authors=t.authors,
                published_at=t.published_at,
                ingested_at=t.ingested_at,
                content_hash=t.content_hash,
                threat_type=t.threat_type,
                severity=t.severity,
                exploitability_score=t.exploitability_score,
                raw_data_key=t.raw_data_key,
                metadata=t.extra_metadata,
                classification_metadata=t.classification_metadata,
                enrichment_status=t.enrichment_status,
                llm_analysis_status=t.llm_analysis_status
            )
            for t in threats
        ]
        
        return ThreatListResponse(
            threats=threat_responses,
            total=len(threat_responses),
            page=1,
            per_page=limit,
            total_pages=1,
            has_next=False,
            has_prev=False
        )
    except Exception as e:
        logger.error(f"Recent threats error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve recent threats: {str(e)}"
        )


@router.get("/high-severity")
async def get_high_severity_threats(
    severity_threshold: int = Query(7, ge=1, le=10, description="Minimum severity level"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of threats to return"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get high-severity threats.
    
    **Query Parameters:**
    - `severity_threshold`: Minimum severity level (default: 7)
    - `limit`: Maximum number of threats to return (default: 10, max: 50)
    
    **Returns:**
    - List of high-severity threats ordered by severity (highest first)
    - Total count of all threats matching the severity threshold
    """
    try:
        # Get total count of high-severity threats
        count_query = select(func.count()).select_from(Threat).where(Threat.severity >= severity_threshold)
        count_result = await db.execute(count_query)
        total_count = count_result.scalar()
        
        # Get limited list for display
        query = (
            select(Threat)
            .where(Threat.severity >= severity_threshold)
            .order_by(Threat.severity.desc(), Threat.ingested_at.desc())
            .limit(limit)
        )
        result = await db.execute(query)
        threats = result.scalars().all()
        
        logger.info(f"Retrieved {len(threats)} of {total_count} high-severity threats (>= {severity_threshold})")
        
        # Return format compatible with Dashboard expectations
        return {
            "threats": [t.to_dict() for t in threats],
            "count": total_count,  # Total count, not limited
            "displayed": len(threats),  # Number actually returned
            "severity_threshold": severity_threshold
        }
    except Exception as e:
        logger.error(f"High severity threats error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve high-severity threats: {str(e)}"
        )


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: UUID,
    include_enrichment: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific threat by ID.
    
    **Path Parameters:**
    - `threat_id`: UUID of the threat
    
    **Query Parameters:**
    - `include_enrichment`: Include entities, MITRE mappings, and LLM analysis (default: true)
    
    **Returns:**
    - Threat details with optional enrichment data
    
    **Raises:**
    - 404: Threat not found
    
    Requirements: 12.3
    """
    try:
        # Build query with optional eager loading
        query = select(Threat).where(Threat.id == threat_id)
        
        if include_enrichment:
            query = query.options(
                selectinload(Threat.entities),
                selectinload(Threat.mitre_mappings),
                selectinload(Threat.llm_analysis)
            )
        
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if not threat:
            raise HTTPException(
                status_code=404,
                detail=f"Threat with ID {threat_id} not found"
            )
        
        logger.info(f"Retrieved threat {threat_id}")
        
        # Convert to response model
        response_data = {
            "id": str(threat.id),
            "title": threat.title,
            "description": threat.description,
            "content": threat.content,
            "source": threat.source,
            "source_url": threat.source_url,
            "authors": threat.authors,
            "published_at": threat.published_at,
            "ingested_at": threat.ingested_at,
            "content_hash": threat.content_hash,
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "exploitability_score": threat.exploitability_score,
            "raw_data_key": threat.raw_data_key,
            "metadata": threat.extra_metadata,
            "classification_metadata": threat.classification_metadata,
            "enrichment_status": threat.enrichment_status,
            "llm_analysis_status": threat.llm_analysis_status,
        }
        
        if include_enrichment:
            response_data["entities"] = [
                EntityResponse(
                    id=str(e.id),
                    entity_type=e.entity_type,
                    entity_value=e.entity_value,
                    confidence=float(e.confidence) if e.confidence else None,
                    extracted_at=e.extracted_at
                )
                for e in threat.entities
            ]
            response_data["mitre_mappings"] = [
                MitreMappingResponse(
                    id=str(m.id),
                    tactic=m.tactic,
                    technique=m.technique,
                    technique_id=m.technique_id,
                    confidence=float(m.confidence) if m.confidence else None
                )
                for m in threat.mitre_mappings
            ]
            if threat.llm_analysis:
                response_data["llm_analysis"] = LLMAnalysisResponse(
                    id=str(threat.llm_analysis.id),
                    summary=threat.llm_analysis.summary,
                    key_findings=threat.llm_analysis.key_findings,
                    attack_vectors=threat.llm_analysis.attack_vectors,
                    mitigations=threat.llm_analysis.mitigations,
                    model_name=threat.llm_analysis.model_name,
                    analyzed_at=threat.llm_analysis.analyzed_at
                )
        
        return ThreatResponse(**response_data)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving threat {threat_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve threat: {str(e)}"
        )


@router.post("", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    threat_data: ThreatCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create a new threat.
    
    **Request Body:**
    - Threat data (see ThreatCreate model)
    
    **Returns:**
    - Created threat with ID
    
    **Raises:**
    - 400: Invalid data
    - 401: Not authenticated
    - 409: Duplicate content (same content_hash already exists)
    
    Requirements: 12.4, 12.10
    """
    try:
        # Calculate content hash for deduplication using shared utility
        content_for_hash = threat_data.content or threat_data.description or threat_data.title
        content_hash = calculate_content_hash(content_for_hash)
        
        # Check for duplicate
        existing_query = select(Threat).where(Threat.content_hash == content_hash)
        result = await db.execute(existing_query)
        existing_threat = result.scalar_one_or_none()
        
        if existing_threat:
            raise HTTPException(
                status_code=409,
                detail=f"Threat with same content already exists (ID: {existing_threat.id})"
            )
        
        # Create new threat
        threat = Threat(
            title=threat_data.title,
            description=threat_data.description,
            content=threat_data.content,
            source=threat_data.source,
            source_url=threat_data.source_url,
            authors=threat_data.authors,
            published_at=threat_data.published_at,
            content_hash=content_hash,
            threat_type=threat_data.threat_type,
            severity=threat_data.severity,
            extra_metadata=threat_data.metadata
        )
        
        db.add(threat)
        await db.commit()
        await db.refresh(threat)
        
        logger.info(f"Created threat {threat.id}: {threat.title}")
        
        return ThreatResponse(
            id=str(threat.id),
            title=threat.title,
            description=threat.description,
            content=threat.content,
            source=threat.source,
            source_url=threat.source_url,
            authors=threat.authors,
            published_at=threat.published_at,
            ingested_at=threat.ingested_at,
            content_hash=threat.content_hash,
            threat_type=threat.threat_type,
            severity=threat.severity,
            exploitability_score=threat.exploitability_score,
            raw_data_key=threat.raw_data_key,
            metadata=threat.extra_metadata,
            classification_metadata=threat.classification_metadata,
            enrichment_status=threat.enrichment_status,
            llm_analysis_status=threat.llm_analysis_status
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating threat: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create threat: {str(e)}"
        )


@router.put("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: UUID,
    threat_data: ThreatUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Update an existing threat.
    
    **Path Parameters:**
    - `threat_id`: UUID of the threat to update
    
    **Request Body:**
    - Threat data to update (see ThreatUpdate model)
    - Only provided fields will be updated
    
    **Returns:**
    - Updated threat
    
    **Raises:**
    - 404: Threat not found
    - 400: Invalid data
    - 401: Not authenticated
    
    Requirements: 12.5, 12.10
    """
    try:
        # Fetch existing threat
        query = select(Threat).where(Threat.id == threat_id)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if not threat:
            raise HTTPException(
                status_code=404,
                detail=f"Threat with ID {threat_id} not found"
            )
        
        # Update fields
        update_data = threat_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "metadata":
                setattr(threat, "extra_metadata", value)
            else:
                setattr(threat, field, value)
        
        await db.commit()
        await db.refresh(threat)
        
        logger.info(f"Updated threat {threat_id}")
        
        return ThreatResponse(
            id=str(threat.id),
            title=threat.title,
            description=threat.description,
            content=threat.content,
            source=threat.source,
            source_url=threat.source_url,
            authors=threat.authors,
            published_at=threat.published_at,
            ingested_at=threat.ingested_at,
            content_hash=threat.content_hash,
            threat_type=threat.threat_type,
            severity=threat.severity,
            exploitability_score=threat.exploitability_score,
            raw_data_key=threat.raw_data_key,
            metadata=threat.extra_metadata,
            classification_metadata=threat.classification_metadata,
            enrichment_status=threat.enrichment_status,
            llm_analysis_status=threat.llm_analysis_status
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating threat {threat_id}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update threat: {str(e)}"
        )


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Delete a threat.
    
    **Path Parameters:**
    - `threat_id`: UUID of the threat to delete
    
    **Returns:**
    - 204 No Content on success
    
    **Raises:**
    - 404: Threat not found
    - 401: Not authenticated
    
    Requirements: 12.6, 12.10
    """
    try:
        # Check if threat exists
        query = select(Threat).where(Threat.id == threat_id)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if not threat:
            raise HTTPException(
                status_code=404,
                detail=f"Threat with ID {threat_id} not found"
            )
        
        # Delete threat (cascade will delete related entities, mappings, and analysis)
        await db.delete(threat)
        await db.commit()
        
        logger.info(f"Deleted threat {threat_id}")
        
        return None
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting threat {threat_id}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete threat: {str(e)}"
        )
