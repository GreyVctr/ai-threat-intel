"""
AI Shield Intelligence - Health Check API
Endpoint for checking system health and service connectivity
"""
import asyncio
import time
from typing import Dict, Any

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
import redis.asyncio as aioredis
from minio import Minio

from config import settings

router = APIRouter()


async def check_postgresql() -> Dict[str, Any]:
    """
    Check PostgreSQL database connectivity.
    
    Returns:
        Dict with status, response_time_ms, and optional error
    """
    start_time = time.time()
    try:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "response_time_ms": round(response_time, 2)
        }
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "down",
            "response_time_ms": round(response_time, 2),
            "error": str(e)
        }


async def check_redis() -> Dict[str, Any]:
    """
    Check Redis connectivity.
    
    Returns:
        Dict with status, response_time_ms, and optional error
    """
    start_time = time.time()
    try:
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis_client.ping()
        await redis_client.close()
        
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "response_time_ms": round(response_time, 2)
        }
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "down",
            "response_time_ms": round(response_time, 2),
            "error": str(e)
        }


async def check_minio() -> Dict[str, Any]:
    """
    Check MinIO object storage connectivity.
    
    Returns:
        Dict with status, response_time_ms, and optional error
    """
    start_time = time.time()
    try:
        # Create MinIO client
        minio_client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure
        )
        
        # Check if we can list buckets (basic connectivity test)
        buckets = minio_client.list_buckets()
        
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "response_time_ms": round(response_time, 2),
            "buckets": len(buckets)
        }
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "down",
            "response_time_ms": round(response_time, 2),
            "error": str(e)
        }


async def check_ollama() -> Dict[str, Any]:
    """
    Check Ollama LLM service connectivity.
    
    Returns:
        Dict with status, response_time_ms, and optional error
    """
    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check if Ollama is responding
            response = await client.get(f"{settings.ollama_url}/api/tags")
            response.raise_for_status()
            
            response_time = (time.time() - start_time) * 1000
            
            # Parse available models
            data = response.json()
            models = [model.get("name") for model in data.get("models", [])]
            
            return {
                "status": "up",
                "response_time_ms": round(response_time, 2),
                "models": models
            }
    except httpx.TimeoutException:
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "down",
            "response_time_ms": round(response_time, 2),
            "error": "Connection timeout"
        }
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return {
            "status": "down",
            "response_time_ms": round(response_time, 2),
            "error": str(e)
        }


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Health check endpoint that verifies connectivity to all dependent services.
    
    Checks:
    - PostgreSQL database
    - Redis cache/broker
    - MinIO object storage
    - Ollama LLM service
    
    Returns:
        JSON response with overall status and individual service statuses
        
    Status Codes:
        200: All services are healthy
        503: One or more services are unhealthy
    """
    # Run all health checks concurrently
    postgres_check, redis_check, minio_check, ollama_check = await asyncio.gather(
        check_postgresql(),
        check_redis(),
        check_minio(),
        check_ollama(),
        return_exceptions=True
    )
    
    # Handle any exceptions from health checks
    def safe_check(check_result, service_name):
        if isinstance(check_result, Exception):
            return {
                "status": "down",
                "response_time_ms": 0,
                "error": f"Health check failed: {str(check_result)}"
            }
        return check_result
    
    postgres_status = safe_check(postgres_check, "postgres")
    redis_status = safe_check(redis_check, "redis")
    minio_status = safe_check(minio_check, "minio")
    ollama_status = safe_check(ollama_check, "ollama")
    
    # Determine overall health status
    # Ollama is optional, so we only check critical services
    critical_services_up = all([
        postgres_status["status"] == "up",
        redis_status["status"] == "up",
        minio_status["status"] == "up"
    ])
    
    # Determine overall status
    if critical_services_up:
        if ollama_status["status"] == "up":
            overall_status = "healthy"
        else:
            overall_status = "degraded"  # Ollama down but core services up
    else:
        overall_status = "unhealthy"
    
    # Return 200 if critical services are up (even if Ollama is down)
    http_status = status.HTTP_200_OK if critical_services_up else status.HTTP_503_SERVICE_UNAVAILABLE
    
    response_data = {
        "status": overall_status,
        "version": settings.api_version,
        "environment": settings.environment,
        "services": {
            "postgres": postgres_status,
            "redis": redis_status,
            "minio": minio_status,
            "ollama": ollama_status
        }
    }
    
    # Add warning if Ollama is down
    if ollama_status["status"] == "down" and critical_services_up:
        response_data["warning"] = "LLM analysis service (Ollama) is unavailable. Core functionality remains operational."
    
    return JSONResponse(
        status_code=http_status,
        content=response_data
    )
