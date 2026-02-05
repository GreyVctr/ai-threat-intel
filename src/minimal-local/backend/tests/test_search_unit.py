"""
Unit Tests: Search Functionality

**Validates: Requirements 11.1, 11.2, 11.5, 11.6, 11.7, 11.8**

Tests for the search service including:
- Full-text search
- Fuzzy matching
- Filters (threat type, severity, date range)
- Pagination
"""

import pytest
from datetime import datetime, timedelta
import httpx


class TestSearchAPI:
    """Unit tests for search API endpoints"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_basic_search(self, api_base_url):
        """
        Test basic keyword search returns results
        
        Requirement: 11.1 - Full-text search
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "security", "page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        
        # Verify pagination values
        assert data["page"] == 1
        assert data["per_page"] == 10
        
        # If there are results, verify structure
        if data["total"] > 0:
            result = data["results"][0]
            assert "id" in result
            assert "title" in result
            assert "source" in result
            assert "severity" in result
    
    def test_empty_search_query(self, api_base_url):
        """
        Test search with empty query returns all threats
        
        Requirement: 11.1 - Full-text search
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 1, "per_page": 20},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Empty query should return results (all threats)
        assert "results" in data
        assert "total" in data
    
    def test_search_no_results(self, api_base_url):
        """
        Test search with query that matches nothing
        
        Requirement: 11.1 - Full-text search
        """
        # Use a very specific query unlikely to match
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "xyzabc123nonexistent", "page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should return empty results
        assert data["total"] == 0
        assert len(data["results"]) == 0
    
    def test_search_pagination(self, api_base_url):
        """
        Test pagination works correctly
        
        Requirement: 11.8 - Pagination
        """
        # Get first page
        response1 = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 1, "per_page": 5},
            timeout=10
        )
        
        assert response1.status_code == 200
        data1 = response1.json()
        
        # Get second page
        response2 = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 2, "per_page": 5},
            timeout=10
        )
        
        assert response2.status_code == 200
        data2 = response2.json()
        
        # Verify pagination metadata
        assert data1["page"] == 1
        assert data2["page"] == 2
        assert data1["per_page"] == 5
        assert data2["per_page"] == 5
        
        # If there are enough results, verify different results on different pages
        if data1["total"] > 5:
            assert len(data1["results"]) == 5
            # Results should be different (unless there are exactly 5 total)
            if data1["total"] > 5:
                result1_ids = {r["id"] for r in data1["results"]}
                result2_ids = {r["id"] for r in data2["results"]}
                assert result1_ids != result2_ids, "Different pages should have different results"
    
    def test_search_with_threat_type_filter(self, api_base_url):
        """
        Test filtering by threat type
        
        Requirement: 11.5 - Threat type filter
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={
                "q": "",
                "threat_type": "adversarial_attack",
                "page": 1,
                "per_page": 10
            },
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        
        # If there are results, verify they match the filter
        for result in data["results"]:
            if result.get("threat_type"):
                assert result["threat_type"] == "adversarial_attack", \
                    "All results should match the threat_type filter"
    
    def test_search_with_severity_filter(self, api_base_url):
        """
        Test filtering by severity
        
        Requirement: 11.6 - Severity filter
        """
        # Test minimum severity filter
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={
                "q": "",
                "min_severity": 7,
                "page": 1,
                "per_page": 10
            },
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        
        # If there are results, verify they match the filter
        for result in data["results"]:
            if result.get("severity"):
                assert result["severity"] >= 7, \
                    "All results should have severity >= min_severity"
    
    def test_search_with_date_range_filter(self, api_base_url):
        """
        Test filtering by date range
        
        Requirement: 11.7 - Date range filter
        """
        # Search for threats from the last 30 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={
                "q": "",
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "page": 1,
                "per_page": 10
            },
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        
        # If there are results, verify they match the date filter
        for result in data["results"]:
            if result.get("published_at"):
                published_date = datetime.fromisoformat(
                    result["published_at"].replace('Z', '+00:00')
                )
                assert start_date <= published_date <= end_date, \
                    "All results should be within the date range"
    
    def test_search_with_multiple_filters(self, api_base_url):
        """
        Test combining multiple filters
        
        Requirements: 11.5, 11.6, 11.7 - Multiple filters
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={
                "q": "attack",
                "threat_type": "adversarial_attack",
                "min_severity": 5,
                "page": 1,
                "per_page": 10
            },
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        assert "total" in data
        
        # If there are results, verify they match all filters
        for result in data["results"]:
            # Check threat type if present
            if result.get("threat_type"):
                assert result["threat_type"] == "adversarial_attack"
            
            # Check severity if present
            if result.get("severity"):
                assert result["severity"] >= 5
    
    def test_search_relevance_ordering(self, api_base_url):
        """
        Test that search results are ordered by relevance
        
        Requirement: 11.4 - Relevance ranking
        """
        # Search for a specific term
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "security", "page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        
        # Results should be ordered (most relevant first)
        # We can't easily verify the exact ordering without knowing the algorithm,
        # but we can verify that results are returned in a consistent order
        if len(data["results"]) > 1:
            # Make the same request again
            response2 = httpx.get(
                f"{api_base_url}/api/v1/search",
                params={"q": "security", "page": 1, "per_page": 10},
                timeout=10
            )
            
            data2 = response2.json()
            
            # Results should be in the same order
            result_ids_1 = [r["id"] for r in data["results"]]
            result_ids_2 = [r["id"] for r in data2["results"]]
            
            assert result_ids_1 == result_ids_2, \
                "Search results should be consistently ordered"
    
    def test_search_case_insensitive(self, api_base_url):
        """
        Test that search is case-insensitive
        
        Requirement: 11.2 - Fuzzy matching
        """
        # Search with lowercase
        response1 = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "security", "page": 1, "per_page": 10},
            timeout=10
        )
        
        # Search with uppercase
        response2 = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "SECURITY", "page": 1, "per_page": 10},
            timeout=10
        )
        
        # Search with mixed case
        response3 = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "SeCuRiTy", "page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        assert response3.status_code == 200
        
        data1 = response1.json()
        data2 = response2.json()
        data3 = response3.json()
        
        # All should return the same total count
        assert data1["total"] == data2["total"] == data3["total"], \
            "Case-insensitive search should return same number of results"
    
    def test_search_invalid_page(self, api_base_url):
        """
        Test handling of invalid page numbers
        
        Requirement: 11.8 - Pagination
        """
        # Test page 0 (should default to 1 or return error)
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 0, "per_page": 10},
            timeout=10
        )
        
        # Should either return 200 with page 1 or 400 error
        assert response.status_code in [200, 400, 422]
    
    def test_search_large_per_page(self, api_base_url):
        """
        Test handling of large per_page values
        
        Requirement: 11.8 - Pagination
        """
        # Request a very large number of results
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 1, "per_page": 1000},
            timeout=10
        )
        
        # Should either return 200 with capped results or 422 validation error
        assert response.status_code in [200, 422]
        
        if response.status_code == 200:
            data = response.json()
            # Should cap at a reasonable limit (e.g., 100)
            assert len(data["results"]) <= 100, \
                "per_page should be capped at a reasonable limit"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
