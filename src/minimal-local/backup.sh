#!/bin/bash
set -e

# AI Shield Intelligence - Backup Script
# Backs up all Docker volumes to timestamped directory

# Configuration
BACKUP_DIR="${BACKUP_DIR:-$HOME/ai-shield-backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup-$TIMESTAMP"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create backup directory
mkdir -p "$BACKUP_PATH"

echo -e "${BLUE}Starting backup to $BACKUP_PATH...${NC}"
echo ""

# Backup PostgreSQL
echo "Backing up PostgreSQL database..."
docker run --rm \
  -v minimal-local_postgres_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/postgres_data.tar.gz /data
echo -e "${GREEN}✓ PostgreSQL backed up${NC}"

# Backup MinIO
echo "Backing up MinIO object storage..."
docker run --rm \
  -v minimal-local_minio_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/minio_data.tar.gz /data
echo -e "${GREEN}✓ MinIO backed up${NC}"

# Backup Redis (optional, usually small)
echo "Backing up Redis cache..."
docker run --rm \
  -v minimal-local_redis_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/redis_data.tar.gz /data
echo -e "${GREEN}✓ Redis backed up${NC}"

# Backup Ollama models (if using containerized Ollama)
if docker volume ls | grep -q minimal-local_ollama_data; then
  echo "Backing up Ollama models..."
  docker run --rm \
    -v minimal-local_ollama_data:/data \
    -v "$BACKUP_PATH":/backup \
    alpine tar czf /backup/ollama_data.tar.gz /data
  echo -e "${GREEN}✓ Ollama backed up${NC}"
fi

# Create metadata file
echo "Creating backup metadata..."
cat > "$BACKUP_PATH/backup_info.txt" << EOF
AI Shield Intelligence Backup
=============================
Backup Date: $(date)
Hostname: $(hostname)
Docker Version: $(docker --version)
System: $(uname -s) $(uname -m)

Data Statistics:
EOF

# Try to get threat count (may fail if containers aren't running)
if docker ps | grep -q ai-shield-postgres; then
  THREAT_COUNT=$(docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec -T postgres psql -U ai_shield -d ai_shield -t -c "SELECT COUNT(*) FROM threats;" 2>/dev/null | tr -d ' ' || echo "N/A")
  echo "Threat Count: $THREAT_COUNT" >> "$BACKUP_PATH/backup_info.txt"
else
  echo "Threat Count: N/A (containers not running)" >> "$BACKUP_PATH/backup_info.txt"
fi

echo ""
echo -e "${GREEN}✓ Backup complete!${NC}"
echo ""
echo "Location: $BACKUP_PATH"
echo "Size: $(du -sh "$BACKUP_PATH" | cut -f1)"
echo ""
echo "Files:"
ls -lh "$BACKUP_PATH"

# Optional: Keep only last 7 backups
echo ""
echo "Cleaning old backups (keeping last 7)..."
cd "$BACKUP_DIR"
ls -t | tail -n +8 | xargs -I {} rm -rf {} 2>/dev/null || true
echo -e "${GREEN}✓ Cleanup complete${NC}"

echo ""
echo "To restore this backup on another system, see BACKUP_RESTORE.md"
