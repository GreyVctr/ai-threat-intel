"""
Unit tests for query builder functions.

Tests the query building logic without requiring database connectivity.
"""
import pytest
from models import Threat
from utils.query_builders import build_metadata_filter


class TestBuildMetadataFilter:
    """Test suite for build_metadata_filter function"""
    
    def test_no_filters_returns_empty_list(self):
        """Test that calling with no filters returns empty list"""
        filters = build_metadata_filter(Threat)
        assert filters == []
    
    def test_attack_surface_filter_creates_conditions(self):
        """Test that attack_surface parameter creates filter conditions"""
        filters = build_metadata_filter(Threat, attack_surface=["runtime"])
        assert len(filters) == 1
        # Verify it's a valid SQLAlchemy condition
        assert hasattr(filters[0], 'compile')
    
    def test_testability_filter_creates_conditions(self):
        """Test that testability parameter creates filter conditions"""
        filters = build_metadata_filter(Threat, testability="yes")
        assert len(filters) == 1
        assert hasattr(filters[0], 'compile')
    
    def test_techniques_filter_creates_conditions(self):
        """Test that techniques parameter creates filter conditions"""
        filters = build_metadata_filter(Threat, techniques=["jailbreak"])
        assert len(filters) == 1
        assert hasattr(filters[0], 'compile')
    
    def test_target_systems_filter_creates_conditions(self):
        """Test that target_systems parameter creates filter conditions"""
        filters = build_metadata_filter(Threat, target_systems=["llm"])
        assert len(filters) == 1
        assert hasattr(filters[0], 'compile')
    
    def test_multiple_filters_creates_multiple_conditions(self):
        """Test that multiple filter parameters create multiple conditions"""
        filters = build_metadata_filter(
            Threat,
            attack_surface=["runtime"],
            testability="yes",
            techniques=["jailbreak"],
            target_systems=["llm"]
        )
        # Should have 4 conditions (one for each parameter)
        assert len(filters) == 4
        for f in filters:
            assert hasattr(f, 'compile')
    
    def test_multiple_values_in_same_filter(self):
        """Test that multiple values in same filter parameter work"""
        filters = build_metadata_filter(
            Threat,
            attack_surface=["runtime", "training"]
        )
        # Should have 1 condition (OR of the two values)
        assert len(filters) == 1
        assert hasattr(filters[0], 'compile')
    
    def test_empty_lists_ignored(self):
        """Test that empty lists are ignored"""
        filters = build_metadata_filter(
            Threat,
            attack_surface=[],
            techniques=[]
        )
        assert filters == []
    
    def test_none_values_ignored(self):
        """Test that None values are ignored"""
        filters = build_metadata_filter(
            Threat,
            attack_surface=None,
            testability=None,
            techniques=None,
            target_systems=None
        )
        assert filters == []
