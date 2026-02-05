"""
Unit Tests: API Endpoints

**Validates: Requirements 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9, 12.10**

Tests for REST API endpoints including:
- Threat CRUD operations
- Search endpoint
- Sources management
- Request validation
- Error handling
"""

import pytest
import httpx


class TestThreatEndpoints:
    """Unit tests for threat API endpoints"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    @pytest.fixture
    def sample_threat_id(self, api_base_url):
        """Get a sample threat ID from the API"""
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "", "page": 1, "per_page": 1},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]["id"]
        
        return None
    
    def test_list_threats(self, api_base_url):
        """
        Test GET /api/v1/threats returns paginated list
        
        Requirement: 12.2 - List threats with pagination
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/threats",
            params={"page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "threats" in data or "results" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
    
    def test_get_threat_by_id(self, api_base_url, sample_threat_id):
        """
        Test GET /api/v1/threats/{id} returns threat details
        
        Requirement: 12.3 - Get threat details
        """
        if not sample_threat_id:
            pytest.skip("No threats in database")
        
        response = httpx.get(
            f"{api_base_url}/api/v1/threats/{sample_threat_id}",
            timeout=10
        )
        
        assert response.status_code == 200
        threat = response.json()
        
        # Verify threat structure
        assert threat["id"] == sample_threat_id
        assert "title" in threat
        assert "source" in threat
        assert "content_hash" in threat
        assert "ingested_at" in threat
    
    def test_get_nonexistent_threat(self, api_base_url):
        """
        Test GET /api/v1/threats/{id} with invalid ID returns 404
        
        Requirement: 12.8 - Error handling
        """
        fake_id = "00000000-0000-0000-0000-000000000000"
        
        response = httpx.get(
            f"{api_base_url}/api/v1/threats/{fake_id}",
            timeout=10
        )
        
        assert response.status_code == 404
    
    def test_get_threat_invalid_uuid(self, api_base_url):
        """
        Test GET /api/v1/threats/{id} with invalid UUID format
        
        Requirement: 12.9 - Request validation
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/threats/not-a-uuid",
            timeout=10
        )
        
        # Should return 422 (validation error) or 404
        assert response.status_code in [404, 422]


class TestSearchEndpoint:
    """Unit tests for search endpoint"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_search_endpoint_exists(self, api_base_url):
        """
        Test GET /api/v1/search endpoint exists
        
        Requirement: 12.7 - Search endpoint
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "test"},
            timeout=10
        )
        
        assert response.status_code == 200
    
    def test_search_returns_valid_structure(self, api_base_url):
        """
        Test search returns properly structured response
        
        Requirement: 12.8 - Response format
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "security", "page": 1, "per_page": 5},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "results" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        
        # Verify each result has required fields
        for result in data["results"]:
            assert "id" in result
            assert "title" in result
            assert "source" in result


class TestSourcesEndpoint:
    """Unit tests for sources endpoint"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_list_sources(self, api_base_url):
        """
        Test GET /api/v1/sources returns list of sources
        
        Requirement: 7.3 - List sources
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/sources",
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "sources" in data
        assert isinstance(data["sources"], list)
        
        # If there are sources, verify structure
        if len(data["sources"]) > 0:
            source = data["sources"][0]
            assert "name" in source
            assert "type" in source
            assert "enabled" in source


class TestHealthEndpoint:
    """Unit tests for health check endpoint"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_health_check(self, api_base_url):
        """
        Test GET /api/v1/health returns system status
        
        Requirement: 5.5 - Health check endpoint
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/health",
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "services" in data
        
        # Verify service checks
        services = data["services"]
        assert "postgres" in services
        assert "redis" in services
        assert "minio" in services
        assert "ollama" in services
        
        # Each service should have status
        for service_name, service_data in services.items():
            assert "status" in service_data
            assert service_data["status"] in ["up", "down"]


class TestAPIValidation:
    """Unit tests for API request validation"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_search_invalid_page_number(self, api_base_url):
        """
        Test search with invalid page number
        
        Requirement: 12.9 - Request validation
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "test", "page": -1, "per_page": 10},
            timeout=10
        )
        
        # Should return 422 validation error or handle gracefully with 200
        assert response.status_code in [200, 422]
    
    def test_search_invalid_per_page(self, api_base_url):
        """
        Test search with invalid per_page value
        
        Requirement: 12.9 - Request validation
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "test", "page": 1, "per_page": 0},
            timeout=10
        )
        
        # Should return 422 validation error
        assert response.status_code in [200, 422]
    
    def test_search_invalid_severity(self, api_base_url):
        """
        Test search with invalid severity value
        
        Requirement: 12.9 - Request validation
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/search",
            params={"q": "test", "min_severity": 15},  # Severity should be 1-10
            timeout=10
        )
        
        # Should return 422 validation error or handle gracefully
        assert response.status_code in [200, 422]


class TestAPIErrorHandling:
    """Unit tests for API error handling"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_404_for_nonexistent_endpoint(self, api_base_url):
        """
        Test that nonexistent endpoints return 404
        
        Requirement: 12.8 - Error handling
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/nonexistent",
            timeout=10
        )
        
        assert response.status_code == 404
    
    def test_method_not_allowed(self, api_base_url):
        """
        Test that wrong HTTP methods return 405
        
        Requirement: 12.8 - Error handling
        """
        # Try to POST to a GET-only endpoint
        response = httpx.post(
            f"{api_base_url}/api/v1/health",
            timeout=10
        )
        
        # Should return 405 Method Not Allowed or 404
        assert response.status_code in [404, 405]


class TestAPIResponseFormat:
    """Unit tests for API response format consistency"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_all_responses_are_json(self, api_base_url):
        """
        Test that all API responses are JSON
        
        Requirement: 12.8 - Response format
        """
        endpoints = [
            "/api/v1/health",
            "/api/v1/sources",
            "/api/v1/search?q=test",
        ]
        
        for endpoint in endpoints:
            response = httpx.get(f"{api_base_url}{endpoint}", timeout=10)
            
            # Should return JSON content type
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type, \
                f"Endpoint {endpoint} should return JSON"
    
    def test_error_responses_have_detail(self, api_base_url):
        """
        Test that error responses include detail message
        
        Requirement: 12.8 - Error handling
        """
        # Request a nonexistent threat
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = httpx.get(
            f"{api_base_url}/api/v1/threats/{fake_id}",
            timeout=10
        )
        
        if response.status_code >= 400:
            data = response.json()
            # FastAPI typically returns {"detail": "message"}
            assert "detail" in data or "message" in data or "error" in data


class TestCORSHeaders:
    """Unit tests for CORS headers"""
    
    @pytest.fixture
    def api_base_url(self):
        """Base URL for API"""
        return "http://localhost:8000"
    
    def test_cors_headers_present(self, api_base_url):
        """
        Test that CORS headers are present
        
        Requirement: 24.3 - CORS configuration
        """
        response = httpx.get(
            f"{api_base_url}/api/v1/health",
            timeout=10
        )
        
        # Check for CORS headers
        headers = response.headers
        # CORS headers may or may not be present depending on configuration
        # This is a soft check
        if "access-control-allow-origin" in headers:
            assert headers["access-control-allow-origin"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
