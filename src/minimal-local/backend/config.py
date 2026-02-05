"""
AI Shield Intelligence - Configuration
Environment-based configuration using pydantic-settings
"""
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings can be overridden via environment variables.
    For example, DATABASE_URL can be set in .env file or as an environment variable.
    """
    
    # Environment
    environment: str = Field(default="development", description="Environment mode: development or production")
    
    # Database Configuration
    database_url: str = Field(
        default="postgresql+asyncpg://ai_shield:changeme@postgres:5432/ai_shield",
        description="PostgreSQL database URL"
    )
    
    # Redis Configuration
    redis_url: str = Field(
        default="redis://redis:6379/0",
        description="Redis URL for caching and Celery broker"
    )
    
    # MinIO Configuration
    minio_endpoint: str = Field(
        default="minio:9000",
        description="MinIO endpoint (host:port)"
    )
    minio_access_key: str = Field(
        default="minioadmin",
        description="MinIO access key"
    )
    minio_secret_key: str = Field(
        default="minioadmin",
        description="MinIO secret key"
    )
    minio_secure: bool = Field(
        default=False,
        description="Use HTTPS for MinIO connections"
    )
    minio_bucket: str = Field(
        default="ai-shield-raw",
        description="MinIO bucket name for raw data storage"
    )
    
    # Ollama Configuration
    ollama_url: str = Field(
        default="http://ollama:11434",
        description="Ollama LLM service URL"
    )
    ollama_model: str = Field(
        default="qwen2.5:7b",
        description="Default Ollama model for analysis (Qwen2.5:7b - optimized for technical analysis)"
    )
    ollama_timeout: int = Field(
        default=60,
        description="Ollama request timeout in seconds"
    )
    
    # CORS Configuration
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    
    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    
    # JWT Configuration
    jwt_secret_key: str = Field(
        default="changeme_jwt_secret_key_for_production",
        description="Secret key for JWT token generation"
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT algorithm"
    )
    jwt_expiration_minutes: int = Field(
        default=60 * 24,  # 24 hours
        description="JWT token expiration time in minutes"
    )
    
    # Celery Configuration
    celery_broker_url: str = Field(
        default="redis://redis:6379/0",
        description="Celery broker URL (same as Redis URL)"
    )
    celery_result_backend: str = Field(
        default="redis://redis:6379/0",
        description="Celery result backend URL"
    )
    celery_worker_concurrency: int = Field(
        default=8,
        description="Number of concurrent Celery workers"
    )
    
    # Alert Configuration
    alert_enabled: bool = Field(
        default=False,
        description="Master switch to enable/disable all alerts"
    )
    alert_email_enabled: bool = Field(
        default=False,
        description="Enable email alerts"
    )
    alert_webhook_enabled: bool = Field(
        default=False,
        description="Enable webhook alerts"
    )
    alert_severity_threshold: int = Field(
        default=8,
        description="Minimum severity level (1-10) to trigger alerts"
    )
    alert_email_to: List[str] = Field(
        default=[],
        description="List of email addresses to receive alerts"
    )
    alert_webhook_url: str = Field(
        default="",
        description="Webhook URL to receive alerts (singular)"
    )
    smtp_host: str = Field(
        default="localhost",
        description="SMTP server hostname"
    )
    smtp_port: int = Field(
        default=587,
        description="SMTP server port"
    )
    smtp_user: str = Field(
        default="",
        description="SMTP username (optional)"
    )
    smtp_password: str = Field(
        default="",
        description="SMTP password (optional)"
    )
    smtp_from: str = Field(
        default="alerts@aishield.local",
        description="From email address for alerts"
    )
    
    # Application Configuration
    api_title: str = Field(
        default="AI Shield Intelligence API",
        description="API title"
    )
    api_version: str = Field(
        default="0.1.0",
        description="API version"
    )
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Create global settings instance
settings = Settings()


# Validate critical settings on import
def validate_settings():
    """Validate critical configuration settings"""
    errors = []
    
    # Check database URL
    if "changeme" in settings.database_url and settings.environment == "production":
        errors.append("DATABASE_URL contains default password in production mode")
    
    # Check JWT secret
    if settings.jwt_secret_key == "changeme_jwt_secret_key_for_production" and settings.environment == "production":
        errors.append("JWT_SECRET_KEY is using default value in production mode")
    
    # Check MinIO credentials
    if settings.minio_access_key == "minioadmin" and settings.environment == "production":
        errors.append("MINIO_ACCESS_KEY is using default value in production mode")
    
    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        if settings.environment == "production":
            raise ValueError(error_msg)
        else:
            import logging
            logging.warning(error_msg)


# Run validation on import
validate_settings()
