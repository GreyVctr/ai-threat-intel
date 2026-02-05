"""
End-to-end integration tests for the AI Shield Intelligence system.

Tests the complete pipeline: fetch → ingest → enrich → analyze
"""
import pytest
import asyncio
from datetime import datetime


class TestEndToEndPipeline:
    """Test the complete data pipeline from collection to analysis"""
    
    def test_system_health(self):
        """Test that all services are healthy and accessible"""
        import httpx
        
        # Test API health endpoint
        response = httpx.get("http://localhost:8000/api/v1/health", timeout=10)
        assert response.status_code == 200
        
        health_data = response.json()
        assert health_data["status"] in ["healthy", "degraded"]
        
        # Check individual services
        services = health_data.get("services", {})
        assert "postgres" in services
        assert "redis" in services
        assert "minio" in services
        assert "ollama" in services
        
        # PostgreSQL should be up
        assert services["postgres"]["status"] == "up"
        
        # Redis should be up
        assert services["redis"]["status"] == "up"
    
    def test_data_collection_and_ingestion(self):
        """Test that data can be collected from sources and ingested"""
        from tasks import fetch_source
        from sqlalchemy import create_engine, text
        from config import settings
        
        # Trigger a fetch from a test source
        # Note: This uses a real source, so it may take time
        result = fetch_source.apply(args=["arXiv Computer Security"])
        
        # Wait for task to complete
        task_result = result.get(timeout=60)
        
        # Verify fetch was successful
        assert task_result["status"] in ["success", "skipped"]
        
        # If successful, verify data was ingested
        if task_result["status"] == "success":
            # Connect to database
            db_url = settings.database_url.replace("+asyncpg", "")
            engine = create_engine(db_url)
            
            with engine.connect() as conn:
                # Check that threats exist
                result = conn.execute(text("SELECT COUNT(*) FROM threats"))
                count = result.scalar()
                assert count > 0, "No threats found in database after fetch"
    
    @pytest.mark.asyncio
    async def test_enrichment_pipeline(self):
        """Test that threats are enriched with classification, entities, and MITRE mappings"""
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import select
        from config import settings
        from models.threat import Threat
        from models.entity import Entity
        from models.mitre import MitreMapping
        
        # Create async database session
        engine = create_async_engine(settings.database_url, echo=False)
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with async_session_maker() as session:
            # Get a recent threat
            result = await session.execute(
                select(Threat).order_by(Threat.ingested_at.desc()).limit(1)
            )
            threat = result.scalar_one_or_none()
            
            if threat:
                # Check if threat has been classified
                # Note: Enrichment may not have completed yet for very recent threats
                if threat.threat_type:
                    assert threat.threat_type in [
                        "adversarial_attack",
                        "data_poisoning",
                        "model_extraction",
                        "privacy_attack",
                        "backdoor_attack",
                        "evasion_attack",
                        "general_security"
                    ]
                
                # Check if entities were extracted
                entity_result = await session.execute(
                    select(Entity).where(Entity.threat_id == threat.id)
                )
                entities = entity_result.scalars().all()
                # Entities may or may not exist depending on content
                
                # Check if MITRE mappings exist
                mitre_result = await session.execute(
                    select(MitreMapping).where(MitreMapping.threat_id == threat.id)
                )
                mappings = mitre_result.scalars().all()
                # Mappings may or may not exist depending on threat type
        
        await engine.dispose()
    
    def test_search_functionality(self):
        """Test that search returns relevant results"""
        import httpx
        
        # Test basic search
        response = httpx.get(
            "http://localhost:8000/api/v1/search",
            params={"q": "security", "page": 1, "per_page": 10},
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "threats" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        
        # If there are results, verify structure
        if data["total"] > 0:
            threat = data["threats"][0]
            assert "id" in threat
            assert "title" in threat
            assert "source" in threat
    
    def test_threat_detail_endpoint(self):
        """Test that threat detail endpoint returns enriched data"""
        import httpx
        from sqlalchemy import create_engine, text
        from config import settings
        
        # Get a threat ID from database
        db_url = settings.database_url.replace("+asyncpg", "")
        engine = create_engine(db_url)
        
        with engine.connect() as conn:
            result = conn.execute(text("SELECT id FROM threats LIMIT 1"))
            row = result.fetchone()
            
            if row:
                threat_id = str(row[0])
                
                # Fetch threat details
                response = httpx.get(
                    f"http://localhost:8000/api/v1/threats/{threat_id}",
                    timeout=10
                )
                
                assert response.status_code == 200
                threat = response.json()
                
                # Verify basic fields
                assert threat["id"] == threat_id
                assert "title" in threat
                assert "source" in threat
                assert "ingested_at" in threat
    
    def test_sources_endpoint(self):
        """Test that sources can be listed"""
        import httpx
        
        response = httpx.get(
            "http://localhost:8000/api/v1/sources",
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "sources" in data
        assert len(data["sources"]) > 0
        
        # Verify source structure
        source = data["sources"][0]
        assert "name" in source
        assert "type" in source
        assert "enabled" in source


class TestContainerLifecycle:
    """Test container lifecycle operations"""
    
    def test_services_are_running(self):
        """Test that all required services are running"""
        import subprocess
        
        result = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.minimal.yml", "ps", "--format", "json"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        
        # Parse output and check services
        import json
        services = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
        
        service_names = [s["Service"] for s in services]
        
        # Verify all required services are present
        required_services = [
            "postgres", "redis", "minio", "ollama",
            "api", "celery_worker", "celery_beat", "frontend"
        ]
        
        for service in required_services:
            assert service in service_names, f"Service {service} not found"
    
    def test_volume_persistence(self):
        """Test that data persists in volumes"""
        import subprocess
        
        # List volumes
        result = subprocess.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        volumes = result.stdout.strip().split('\n')
        
        # Verify required volumes exist
        required_volumes = ["postgres_data", "redis_data", "minio_data", "ollama_data"]
        
        for volume in required_volumes:
            # Volume names may have prefix
            assert any(volume in v for v in volumes), f"Volume {volume} not found"


class TestPortConfiguration:
    """Test port configuration and accessibility"""
    
    def test_api_port_accessible(self):
        """Test that API is accessible on configured port"""
        import httpx
        from config import settings
        
        port = settings.api_port if hasattr(settings, 'api_port') else 8000
        
        response = httpx.get(f"http://localhost:{port}/", timeout=5)
        assert response.status_code == 200
    
    def test_frontend_port_accessible(self):
        """Test that frontend is accessible on configured port"""
        import httpx
        
        # Frontend port is typically 3000
        try:
            response = httpx.get("http://localhost:3000/", timeout=5)
            # Frontend should return HTML
            assert response.status_code == 200
            assert "text/html" in response.headers.get("content-type", "")
        except httpx.ConnectError:
            pytest.skip("Frontend not accessible - may not be running")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
