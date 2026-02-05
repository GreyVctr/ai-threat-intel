"""
AI Shield Intelligence - FastAPI Backend
Main application entry point
"""
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from logging_config import setup_logging, get_logger, log_with_context

# Configure structured logging
setup_logging(
    log_level=settings.log_level,
    json_format=settings.environment == "production"
)

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting AI Shield Intelligence API")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Database URL: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'configured'}")
    logger.info(f"Redis URL: {settings.redis_url}")
    logger.info(f"MinIO Endpoint: {settings.minio_endpoint}")
    logger.info(f"Ollama URL: {settings.ollama_url}")
    
    # Initialize source manager and start file watcher
    from services.source_manager import get_source_manager
    source_manager = get_source_manager()
    source_manager.start_watching()
    logger.info("Source configuration file watcher started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down AI Shield Intelligence API")
    source_manager.stop_watching()
    logger.info("Source configuration file watcher stopped")


# Create FastAPI application
app = FastAPI(
    title="AI Shield Intelligence API",
    description="Threat intelligence platform for AI/ML security threats",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests with timing and status"""
    start_time = time.time()
    
    # Log request
    log_with_context(
        logger, "info", "HTTP Request",
        method=request.method,
        path=request.url.path,
        client_host=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "unknown")
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration_ms = (time.time() - start_time) * 1000
    
    # Log response
    log_with_context(
        logger, "info", "HTTP Response",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2)
    )
    
    return response


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "AI Shield Intelligence API",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions with detailed logging"""
    log_with_context(
        logger, "error", "Unhandled exception",
        method=request.method,
        path=request.url.path,
        exception_type=type(exc).__name__,
        exception_message=str(exc),
        client_host=request.client.host if request.client else None
    )
    logger.error(f"Exception details: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.environment == "development" else "An error occurred"
        }
    )


# Import and include routers
from api import health, sources, search, threats, auth, system

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(system.router)
app.include_router(auth.router)
app.include_router(threats.router)
app.include_router(sources.router)
app.include_router(search.router, tags=["search"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "development"
    )
