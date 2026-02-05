"""
Comprehensive backend functionality verification script.

This script verifies:
1. All API endpoints are accessible
2. Search functionality works correctly
3. Authentication works
4. Database operations work
5. Service health checks pass

Requirements: Task 15 - Checkpoint - Verify backend functionality
"""
import asyncio
import sys
import httpx
from datetime import datetime


BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"


class BackendVerifier:
    """Verifies backend functionality"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.token = None
        self.test_threat_id = None
        self.passed = 0
        self.failed = 0
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
    
    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result"""
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
        if details:
            print(f"  {details}")
        
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    async def test_root_endpoint(self):
        """Test root endpoint"""
        try:
            response = await self.client.get(BASE_URL)
            passed = response.status_code == 200 and "AI Shield Intelligence API" in response.text
            self.log_test(
                "Root endpoint",
                passed,
                f"Status: {response.status_code}"
            )
            return passed
        except Exception as e:
            self.log_test("Root endpoint", False, f"Error: {e}")
            return False
    
    async def test_health_endpoint(self):
        """Test health check endpoint"""
        try:
            response = await self.client.get(f"{API_BASE}/health")
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                services = data.get("services", {})
                all_healthy = all(
                    service.get("status") == "up"
                    for service in services.values()
                )
                self.log_test(
                    "Health check endpoint",
                    all_healthy,
                    f"Services: {', '.join(services.keys())}"
                )
                return all_healthy
            else:
                self.log_test("Health check endpoint", False, f"Status: {response.status_code}")
                return False
        
        except Exception as e:
            self.log_test("Health check endpoint", False, f"Error: {e}")
            return False
    
    async def test_authentication(self):
        """Test authentication endpoints"""
        # Note: This requires an admin user to exist
        # Run create_admin.py first if needed
        try:
            # Try to login (will fail if no admin user exists)
            response = await self.client.post(
                f"{API_BASE}/auth/login",
                json={"username": "admin", "password": "admin123"}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                passed = self.token is not None
                self.log_test(
                    "Authentication - Login",
                    passed,
                    "Token received" if passed else "No token in response"
                )
                return passed
            elif response.status_code == 401:
                self.log_test(
                    "Authentication - Login",
                    False,
                    "No admin user found. Run create_admin.py first."
                )
                return False
            else:
                self.log_test(
                    "Authentication - Login",
                    False,
                    f"Status: {response.status_code}"
                )
                return False
        
        except Exception as e:
            self.log_test("Authentication - Login", False, f"Error: {e}")
            return False
    
    async def test_threats_list(self):
        """Test threats list endpoint"""
        try:
            response = await self.client.get(f"{API_BASE}/threats")
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                total = data.get("total", 0)
                self.log_test(
                    "Threats - List",
                    True,
                    f"Found {total} threats"
                )
            else:
                self.log_test("Threats - List", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Threats - List", False, f"Error: {e}")
            return False
    
    async def test_threats_create(self):
        """Test threat creation (requires authentication)"""
        if not self.token:
            self.log_test("Threats - Create", False, "No authentication token")
            return False
        
        try:
            threat_data = {
                "title": "Test Threat - Backend Verification",
                "description": "This is a test threat created during backend verification",
                "content": "Test content for verification purposes",
                "source": "verification_script",
                "threat_type": "test",
                "severity": 5
            }
            
            response = await self.client.post(
                f"{API_BASE}/threats",
                json=threat_data,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            
            passed = response.status_code == 201
            
            if passed:
                data = response.json()
                self.test_threat_id = data.get("id")
                self.log_test(
                    "Threats - Create",
                    True,
                    f"Created threat ID: {self.test_threat_id}"
                )
            else:
                self.log_test("Threats - Create", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Threats - Create", False, f"Error: {e}")
            return False
    
    async def test_threats_get(self):
        """Test getting a specific threat"""
        if not self.test_threat_id:
            self.log_test("Threats - Get", False, "No test threat ID")
            return False
        
        try:
            response = await self.client.get(f"{API_BASE}/threats/{self.test_threat_id}")
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                title = data.get("title", "")
                self.log_test(
                    "Threats - Get",
                    True,
                    f"Retrieved: {title[:50]}"
                )
            else:
                self.log_test("Threats - Get", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Threats - Get", False, f"Error: {e}")
            return False
    
    async def test_threats_update(self):
        """Test updating a threat"""
        if not self.test_threat_id or not self.token:
            self.log_test("Threats - Update", False, "Missing threat ID or token")
            return False
        
        try:
            update_data = {
                "description": "Updated description during verification",
                "severity": 7
            }
            
            response = await self.client.put(
                f"{API_BASE}/threats/{self.test_threat_id}",
                json=update_data,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                severity = data.get("severity")
                self.log_test(
                    "Threats - Update",
                    severity == 7,
                    f"Updated severity to {severity}"
                )
                return severity == 7
            else:
                self.log_test("Threats - Update", False, f"Status: {response.status_code}")
                return False
        
        except Exception as e:
            self.log_test("Threats - Update", False, f"Error: {e}")
            return False
    
    async def test_search(self):
        """Test search functionality"""
        try:
            # Test basic search
            response = await self.client.get(
                f"{API_BASE}/search",
                params={"q": "test", "per_page": 5}
            )
            
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                total = data.get("total", 0)
                self.log_test(
                    "Search - Basic",
                    True,
                    f"Found {total} results for 'test'"
                )
            else:
                self.log_test("Search - Basic", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Search - Basic", False, f"Error: {e}")
            return False
    
    async def test_search_filters(self):
        """Test search with filters"""
        try:
            response = await self.client.get(
                f"{API_BASE}/search",
                params={
                    "severity_min": 5,
                    "severity_max": 10,
                    "per_page": 5
                }
            )
            
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                total = data.get("total", 0)
                self.log_test(
                    "Search - Filters",
                    True,
                    f"Found {total} results with severity 5-10"
                )
            else:
                self.log_test("Search - Filters", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Search - Filters", False, f"Error: {e}")
            return False
    
    async def test_search_statistics(self):
        """Test search statistics endpoint"""
        try:
            response = await self.client.get(f"{API_BASE}/search/statistics")
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                total = data.get("total_threats", 0)
                self.log_test(
                    "Search - Statistics",
                    True,
                    f"Total threats: {total}"
                )
            else:
                self.log_test("Search - Statistics", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Search - Statistics", False, f"Error: {e}")
            return False
    
    async def test_sources_list(self):
        """Test sources list endpoint"""
        try:
            response = await self.client.get(f"{API_BASE}/sources")
            passed = response.status_code == 200
            
            if passed:
                data = response.json()
                sources = data.get("sources", [])
                self.log_test(
                    "Sources - List",
                    True,
                    f"Found {len(sources)} configured sources"
                )
            else:
                self.log_test("Sources - List", False, f"Status: {response.status_code}")
            
            return passed
        
        except Exception as e:
            self.log_test("Sources - List", False, f"Error: {e}")
            return False
    
    async def test_threats_delete(self):
        """Test deleting a threat (cleanup)"""
        if not self.test_threat_id or not self.token:
            self.log_test("Threats - Delete", False, "Missing threat ID or token")
            return False
        
        try:
            response = await self.client.delete(
                f"{API_BASE}/threats/{self.test_threat_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            
            passed = response.status_code == 204
            self.log_test(
                "Threats - Delete",
                passed,
                "Test threat cleaned up" if passed else f"Status: {response.status_code}"
            )
            
            return passed
        
        except Exception as e:
            self.log_test("Threats - Delete", False, f"Error: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all verification tests"""
        print("=" * 60)
        print("AI Shield Intelligence - Backend Verification")
        print("=" * 60)
        print()
        
        # Test basic connectivity
        print("Testing Basic Connectivity...")
        await self.test_root_endpoint()
        await self.test_health_endpoint()
        print()
        
        # Test authentication
        print("Testing Authentication...")
        auth_ok = await self.test_authentication()
        print()
        
        # Test threats API
        print("Testing Threats API...")
        await self.test_threats_list()
        if auth_ok:
            await self.test_threats_create()
            await self.test_threats_get()
            await self.test_threats_update()
        print()
        
        # Test search API
        print("Testing Search API...")
        await self.test_search()
        await self.test_search_filters()
        await self.test_search_statistics()
        print()
        
        # Test sources API
        print("Testing Sources API...")
        await self.test_sources_list()
        print()
        
        # Cleanup
        if auth_ok and self.test_threat_id:
            print("Cleaning Up...")
            await self.test_threats_delete()
            print()
        
        # Summary
        print("=" * 60)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        print("=" * 60)
        
        return self.failed == 0


async def main():
    """Main entry point"""
    verifier = BackendVerifier()
    
    try:
        success = await verifier.run_all_tests()
        await verifier.close()
        
        if success:
            print("\n✓ All backend functionality verified successfully!")
            sys.exit(0)
        else:
            print("\n✗ Some tests failed. Please check the output above.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\nVerification interrupted by user")
        await verifier.close()
        sys.exit(1)
    
    except Exception as e:
        print(f"\n✗ Verification failed with error: {e}")
        await verifier.close()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
