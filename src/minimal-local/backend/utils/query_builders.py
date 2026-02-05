"""
Query builder utilities for database operations.

Provides helper functions for building complex SQL queries,
particularly for JSON field filtering.
"""
from typing import List, Optional, Dict, Any
from sqlalchemy import and_, or_, cast, String, func
from sqlalchemy.sql import ColumnElement


def build_metadata_filter(
    model_class: Any,
    attack_surface: Optional[List[str]] = None,
    testability: Optional[str] = None,
    techniques: Optional[List[str]] = None,
    target_systems: Optional[List[str]] = None
) -> List[ColumnElement]:
    """
    Build SQLAlchemy filter conditions for metadata filtering.
    
    This function creates filter conditions for querying the classification_metadata
    JSON field in the threats table. It supports filtering by attack surface,
    testability, techniques, and target systems using PostgreSQL's JSON operators.
    
    Args:
        model_class: The SQLAlchemy model class (e.g., Threat)
        attack_surface: List of attack surface values to filter by
        testability: Testability value to filter by (yes, no, conditional)
        techniques: List of technique tags to filter by
        target_systems: List of target system values to filter by
        
    Returns:
        List of SQLAlchemy filter conditions to be used with .where() or .filter()
        
    Example:
        filters = build_metadata_filter(
            Threat,
            attack_surface=["runtime"],
            testability="yes",
            techniques=["jailbreak"],
            target_systems=["llm"]
        )
        query = select(Threat).where(and_(*filters))
    
    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 5.1
    """
    conditions = []
    
    # Get the classification_metadata column
    metadata_col = model_class.classification_metadata
    
    # Filter by attack_surface (array contains check)
    if attack_surface:
        # For each attack surface value, check if it exists in the JSON array
        surface_conditions = []
        for surface in attack_surface:
            # Use PostgreSQL's jsonb_array_elements_text to check if value exists in array
            # Cast the JSON field to text and use LIKE for substring matching
            surface_conditions.append(
                cast(metadata_col['threat_metadata']['attack_surface'], String).contains(f'"{surface}"')
            )
        # OR logic for multiple attack surfaces (match any)
        if surface_conditions:
            conditions.append(or_(*surface_conditions))
    
    # Filter by testability (exact match)
    if testability:
        conditions.append(
            cast(metadata_col['threat_metadata']['testability'], String) == f'"{testability}"'
        )
    
    # Filter by techniques (array contains check)
    if techniques:
        # For each technique, check if it exists in the JSON array
        technique_conditions = []
        for technique in techniques:
            technique_conditions.append(
                cast(metadata_col['threat_metadata']['techniques'], String).contains(f'"{technique}"')
            )
        # OR logic for multiple techniques (match any)
        if technique_conditions:
            conditions.append(or_(*technique_conditions))
    
    # Filter by target_systems (array contains check)
    if target_systems:
        # For each target system, check if it exists in the JSON array
        system_conditions = []
        for system in target_systems:
            system_conditions.append(
                cast(metadata_col['threat_metadata']['target_systems'], String).contains(f'"{system}"')
            )
        # OR logic for multiple target systems (match any)
        if system_conditions:
            conditions.append(or_(*system_conditions))
    
    return conditions
