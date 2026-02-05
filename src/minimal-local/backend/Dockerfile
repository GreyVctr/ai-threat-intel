# AI Shield Intelligence - Backend Dockerfile
# Uses uv for fast Python package management

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv - fast Python package installer
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.cargo/bin/uv /usr/local/bin/uv || \
    mv /root/.local/bin/uv /usr/local/bin/uv || \
    find /root -name uv -type f -exec mv {} /usr/local/bin/uv \;

# Copy dependency file and backend code (needed for package installation)
# Context is minimal-local/, so we copy from there
COPY pyproject.toml ./
COPY backend/ ./backend/

# Install Python dependencies using uv
# Install in editable mode since we have the source code
RUN uv pip install --system --no-cache -e . && \
    uv pip install --system --no-cache pytest pytest-asyncio pytest-cov hypothesis

# Set working directory to backend for runtime
WORKDIR /app/backend

# Create non-root user for security
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Default command (can be overridden in docker-compose)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
