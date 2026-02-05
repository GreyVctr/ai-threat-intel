"""
Sources API Endpoints

Provides REST API endpoints for managing intelligence sources.
"""

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from services.source_manager import SourceManager, SourceConfig, get_source_manager
from api.auth import get_current_user

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


class SourceResponse(BaseModel):
    """Response model for a source"""
    name: str
    type: str
    url: str
    enabled: bool
    frequency: str
    description: Optional[str] = None
    tags: List[str] = []


class SourcesListResponse(BaseModel):
    """Response model for list of sources"""
    sources: List[SourceResponse]
    stats: Dict


class MessageResponse(BaseModel):
    """Generic message response"""
    message: str


class ErrorResponse(BaseModel):
    """Error response"""
    error: str


@router.get("", response_model=SourcesListResponse)
async def list_sources(
    enabled_only: bool = False,
    source_type: Optional[str] = None,
    frequency: Optional[str] = None,
    manager: SourceManager = Depends(get_source_manager)
):
    """
    List all configured intelligence sources
    
    Query Parameters:
    - enabled_only: If true, only return enabled sources
    - source_type: Filter by source type (rss, api, web_scrape)
    - frequency: Filter by collection frequency (hourly, daily, weekly)
    
    Returns:
    - List of sources with statistics
    """
    # Get sources based on filters
    if source_type:
        sources = manager.get_sources_by_type(source_type)
    elif frequency:
        sources = manager.get_sources_by_frequency(frequency)
    elif enabled_only:
        sources = manager.get_enabled_sources()
    else:
        sources = list(manager.sources.values())
    
    # Convert to response models
    source_responses = [
        SourceResponse(
            name=source.name,
            type=source.type,
            url=source.url,
            enabled=source.enabled,
            frequency=source.frequency,
            description=source.description,
            tags=source.tags
        )
        for source in sources
    ]
    
    return SourcesListResponse(
        sources=source_responses,
        stats=manager.get_stats()
    )


@router.get("/stats", response_model=Dict)
async def get_statistics(
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Get statistics about configured sources
    
    Returns:
    - Source statistics including counts by type, frequency, and status
    """
    return manager.get_stats()


@router.get("/{name}", response_model=SourceResponse)
async def get_source(
    name: str,
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Get details of a specific source
    
    Path Parameters:
    - name: Source name
    
    Returns:
    - Source details
    
    Raises:
    - 404: Source not found
    """
    source = manager.get_source(name)
    
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{name}' not found"
        )
    
    return SourceResponse(
        name=source.name,
        type=source.type,
        url=source.url,
        enabled=source.enabled,
        frequency=source.frequency,
        description=source.description,
        tags=source.tags
    )


@router.post("/{name}/enable", response_model=MessageResponse)
async def enable_source(
    name: str,
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Enable a source
    
    Path Parameters:
    - name: Source name
    
    Returns:
    - Success message
    
    Raises:
    - 404: Source not found
    """
    if manager.enable_source(name):
        return MessageResponse(message=f"Source '{name}' enabled successfully")
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Source '{name}' not found"
    )


@router.post("/{name}/disable", response_model=MessageResponse)
async def disable_source(
    name: str,
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Disable a source
    
    Path Parameters:
    - name: Source name
    
    Returns:
    - Success message
    
    Raises:
    - 404: Source not found
    """
    if manager.disable_source(name):
        return MessageResponse(message=f"Source '{name}' disabled successfully")
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Source '{name}' not found"
    )


@router.post("/{name}/validate", response_model=Dict[str, bool])
async def validate_source(
    name: str,
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Validate that a source is publicly accessible
    
    Path Parameters:
    - name: Source name
    
    Returns:
    - Validation result
    
    Raises:
    - 404: Source not found
    """
    source = manager.get_source(name)
    
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{name}' not found"
        )
    
    async with manager:
        is_accessible = await manager.validate_source_accessibility(source)
    
    return {
        "name": name,
        "accessible": is_accessible
    }


@router.post("/reload", response_model=MessageResponse)
async def reload_configuration(
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Reload source configuration from file
    
    Returns:
    - Success message with reload status
    """
    try:
        manager.load_sources()
        stats = manager.get_stats()
        return MessageResponse(
            message=f"Configuration reloaded successfully. "
                   f"Total sources: {stats['total']}, Enabled: {stats['enabled']}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload configuration: {str(e)}"
        )


@router.post("/validate-all", response_model=Dict[str, Optional[bool]])
async def validate_all_sources(
    manager: SourceManager = Depends(get_source_manager)
):
    """
    Validate accessibility of all enabled sources
    
    Returns:
    - Dictionary mapping source names to accessibility status
      (True = accessible, False = not accessible, None = disabled/skipped)
    """
    async with manager:
        results = await manager.validate_all_sources()
    
    return results


class SourceCreateRequest(BaseModel):
    """Request model for creating a source"""
    name: str
    type: str
    url: str
    enabled: bool = True
    frequency: str = "daily"
    description: Optional[str] = None
    tags: List[str] = []
    config: Dict = {}


class SourceUpdateRequest(BaseModel):
    """Request model for updating a source"""
    type: Optional[str] = None
    url: Optional[str] = None
    enabled: Optional[bool] = None
    frequency: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    config: Optional[Dict] = None


@router.post("", response_model=SourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    source_data: SourceCreateRequest,
    manager: SourceManager = Depends(get_source_manager),
    current_user = Depends(get_current_user)
):
    """
    Create a new intelligence source
    
    Request Body:
    - Source configuration (see SourceCreateRequest model)
    
    Returns:
    - Created source details
    
    Raises:
    - 400: Invalid source data
    - 409: Source with same name already exists
    """
    # Check if source already exists
    if manager.get_source(source_data.name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Source '{source_data.name}' already exists"
        )
    
    # Validate source type
    if source_data.type not in ["rss", "api", "web_scrape"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source type '{source_data.type}'. Must be one of: rss, api, web_scrape"
        )
    
    # Validate frequency
    if source_data.frequency not in ["hourly", "daily", "weekly"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid frequency '{source_data.frequency}'. Must be one of: hourly, daily, weekly"
        )
    
    # Validate URL format
    if not manager._validate_url_format(source_data.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL format: {source_data.url}. Must be a valid HTTP/HTTPS URL"
        )
    
    try:
        # Create source config
        source = SourceConfig(
            name=source_data.name,
            type=source_data.type,
            url=source_data.url,
            enabled=source_data.enabled,
            frequency=source_data.frequency,
            description=source_data.description,
            tags=source_data.tags,
            config=source_data.config
        )
        
        # Add to manager
        manager.sources[source.name] = source
        
        # Save to YAML file
        _save_sources_to_yaml(manager)
        
        return SourceResponse(
            name=source.name,
            type=source.type,
            url=source.url,
            enabled=source.enabled,
            frequency=source.frequency,
            description=source.description,
            tags=source.tags
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create source: {str(e)}"
        )


@router.put("/{name}", response_model=SourceResponse)
async def update_source(
    name: str,
    source_data: SourceUpdateRequest,
    manager: SourceManager = Depends(get_source_manager),
    current_user = Depends(get_current_user)
):
    """
    Update an existing intelligence source
    
    Path Parameters:
    - name: Source name
    
    Request Body:
    - Source fields to update (see SourceUpdateRequest model)
    - Only provided fields will be updated
    
    Returns:
    - Updated source details
    
    Raises:
    - 404: Source not found
    - 400: Invalid source data
    """
    source = manager.get_source(name)
    
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{name}' not found"
        )
    
    # Update fields
    update_data = source_data.dict(exclude_unset=True)
    
    # Validate type if provided
    if "type" in update_data and update_data["type"] not in ["rss", "api", "web_scrape"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source type '{update_data['type']}'. Must be one of: rss, api, web_scrape"
        )
    
    # Validate frequency if provided
    if "frequency" in update_data and update_data["frequency"] not in ["hourly", "daily", "weekly"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid frequency '{update_data['frequency']}'. Must be one of: hourly, daily, weekly"
        )
    
    # Validate URL format if provided
    if "url" in update_data and not manager._validate_url_format(update_data["url"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL format: {update_data['url']}. Must be a valid HTTP/HTTPS URL"
        )
    
    try:
        # Update source fields
        for field, value in update_data.items():
            setattr(source, field, value)
        
        # Save to YAML file
        _save_sources_to_yaml(manager)
        
        return SourceResponse(
            name=source.name,
            type=source.type,
            url=source.url,
            enabled=source.enabled,
            frequency=source.frequency,
            description=source.description,
            tags=source.tags
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update source: {str(e)}"
        )


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    name: str,
    manager: SourceManager = Depends(get_source_manager),
    current_user = Depends(get_current_user)
):
    """
    Delete an intelligence source
    
    Path Parameters:
    - name: Source name
    
    Returns:
    - 204 No Content on success
    
    Raises:
    - 404: Source not found
    """
    source = manager.get_source(name)
    
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{name}' not found"
        )
    
    try:
        # Remove from manager
        del manager.sources[name]
        
        # Save to YAML file
        _save_sources_to_yaml(manager)
        
        return None
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete source: {str(e)}"
        )


def _save_sources_to_yaml(manager: SourceManager) -> None:
    """
    Save sources to YAML configuration file
    
    Args:
        manager: SourceManager instance with sources to save
    
    Raises:
        Exception: If file write fails
    """
    import yaml
    
    # Convert sources to dict format
    sources_list = []
    for source in manager.sources.values():
        source_dict = {
            "name": source.name,
            "type": source.type,
            "url": source.url,
            "enabled": source.enabled,
            "frequency": source.frequency,
        }
        
        if source.description:
            source_dict["description"] = source.description
        
        if source.tags:
            source_dict["tags"] = source.tags
        
        if source.config:
            source_dict["config"] = source.config
        
        sources_list.append(source_dict)
    
    # Write to YAML file
    config_data = {"sources": sources_list}
    
    with open(manager.config_path, 'w') as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
