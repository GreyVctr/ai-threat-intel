#!/bin/bash

# AI Shield Intelligence - Minimal Local Profile
# Quick Start Script

set -e

echo "=========================================="
echo "AI Shield Intelligence - Quick Start"
echo "Minimal Local Profile"
echo "=========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "Please install Docker Engine (Linux) or OrbStack (macOS)"
    echo ""
    echo "Linux: https://docs.docker.com/engine/install/"
    echo "macOS: brew install orbstack"
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    echo "❌ Error: Docker Compose is not available"
    echo "Please install Docker Compose v2.0 or higher"
    exit 1
fi

echo "✅ Docker is installed"
echo ""

# Check if .env.minimal exists
if [ ! -f .env.minimal ]; then
    echo "📝 Creating .env.minimal from template..."
    cp .env.example .env.minimal
    echo ""
    echo "⚠️  IMPORTANT: Please edit .env.minimal and set secure passwords:"
    echo "   - POSTGRES_PASSWORD"
    echo "   - MINIO_ROOT_PASSWORD"
    echo ""
    echo "Run this command to edit:"
    echo "   nano .env.minimal"
    echo ""
    read -p "Press Enter after you've set the passwords..."
fi

echo "✅ Environment file exists"
echo ""

# Start services
echo "🚀 Starting services..."
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
echo "   This may take 30-60 seconds..."
echo ""

# Wait for services to be healthy
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if docker compose -f docker-compose.minimal.yml ps | grep -q "unhealthy"; then
        echo "   Still waiting... (attempt $((attempt + 1))/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    else
        break
    fi
done

# Check if all services are running
if docker compose -f docker-compose.minimal.yml ps | grep -q "unhealthy"; then
    echo ""
    echo "⚠️  Warning: Some services are not healthy yet"
    echo "Check status with: docker compose -f docker-compose.minimal.yml ps"
    echo "Check logs with: docker compose -f docker-compose.minimal.yml logs"
else
    echo "✅ All services are running"
fi

echo ""
echo "=========================================="
echo "🎉 AI Shield Intelligence is starting!"
echo "=========================================="
echo ""
echo "Access the system at:"
echo "  • Frontend:      http://localhost:3000"
echo "  • API:           http://localhost:8000"
echo "  • API Docs:      http://localhost:8000/docs"
echo "  • MinIO Console: http://localhost:9001"
echo ""
echo "Next steps:"
echo "  1. Initialize database:"
echo "     docker compose -f docker-compose.minimal.yml exec api python scripts/init_db.py"
echo ""
echo "  2. Create admin user:"
echo "     docker compose -f docker-compose.minimal.yml exec api python scripts/create_admin.py"
echo ""
echo "  3. Pull LLM model:"
echo "     docker compose -f docker-compose.minimal.yml exec ollama ollama pull phi3:mini"
echo ""
echo "View logs:"
echo "  docker compose -f docker-compose.minimal.yml logs -f"
echo ""
echo "Stop services:"
echo "  docker compose -f docker-compose.minimal.yml down"
echo ""
echo "=========================================="
