# AI Shield Intelligence - Backup & Restore Guide

This guide covers backing up your threat intelligence data and transferring it to another system.

## Quick Backup (All Data)

### 1. Create Backup Directory

```bash
cd ~/Desktop  # Or wherever you want to save backups
mkdir ai-shield-backup-$(date +%Y%m%d)
cd ai-shield-backup-$(date +%Y%m%d)
```

### 2. Backup All Docker Volumes

```bash
# Backup PostgreSQL (database)
docker run --rm \
  -v minimal-local_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_data.tar.gz /data

# Backup MinIO (object storage - raw threat data)
docker run --rm \
  -v minimal-local_minio_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/minio_data.tar.gz /data

# Backup Redis (cache/queue - optional, can skip)
docker run --rm \
  -v minimal-local_redis_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/redis_data.tar.gz /data

# Backup Ollama models (if using containerized Ollama)
docker run --rm \
  -v minimal-local_ollama_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/ollama_data.tar.gz /data
```

### 3. Verify Backup

```bash
ls -lh
# You should see:
# postgres_data.tar.gz  (size varies, ~100MB-10GB depending on data)
# minio_data.tar.gz     (size varies, ~100MB-50GB depending on data)
# redis_data.tar.gz     (small, ~1-10MB)
# ollama_data.tar.gz    (large, ~4-20GB depending on models)
```

---

## Alternative: SQL Export (Portable, Human-Readable)

### Export Database Only

```bash
cd ~/Desktop
mkdir ai-shield-export-$(date +%Y%m%d)
cd ai-shield-export-$(date +%Y%m%d)

# Export PostgreSQL database to SQL file
docker compose -f /path/to/docker-compose.minimal.yml \
  --env-file /path/to/.env.minimal \
  exec -T postgres pg_dump -U ai_shield ai_shield > ai_shield_db.sql

# Compress it
gzip ai_shield_db.sql
```

**Pros**: Human-readable, portable across PostgreSQL versions  
**Cons**: Doesn't include MinIO files (raw threat data), larger file size

---

## Restore on Same System

### Restore from Volume Backups

```bash
# Stop services first
cd /path/to/ai-threat-intel/src/minimal-local
docker compose -f docker-compose.minimal.yml --env-file .env.minimal down

# Restore PostgreSQL
docker run --rm \
  -v minimal-local_postgres_data:/data \
  -v ~/Desktop/ai-shield-backup-20260130:/backup \
  alpine sh -c "cd /data && tar xzf /backup/postgres_data.tar.gz --strip 1"

# Restore MinIO
docker run --rm \
  -v minimal-local_minio_data:/data \
  -v ~/Desktop/ai-shield-backup-20260130:/backup \
  alpine sh -c "cd /data && tar xzf /backup/minio_data.tar.gz --strip 1"

# Restore Redis (optional)
docker run --rm \
  -v minimal-local_redis_data:/data \
  -v ~/Desktop/ai-shield-backup-20260130:/backup \
  alpine sh -c "cd /data && tar xzf /backup/redis_data.tar.gz --strip 1"

# Restore Ollama (optional)
docker run --rm \
  -v minimal-local_ollama_data:/data \
  -v ~/Desktop/ai-shield-backup-20260130:/backup \
  alpine sh -c "cd /data && tar xzf /backup/ollama_data.tar.gz --strip 1"

# Start services
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d
```

### Restore from SQL Export

```bash
cd /path/to/ai-threat-intel/src/minimal-local

# Start services (creates empty database)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d

# Wait for PostgreSQL to be ready
sleep 5

# Restore database
gunzip -c ~/Desktop/ai-shield-export-20260130/ai_shield_db.sql.gz | \
  docker compose -f docker-compose.minimal.yml --env-file .env.minimal \
  exec -T postgres psql -U ai_shield ai_shield
```

---

## Transfer to Another System

### Step 1: Backup on Source System

```bash
# On your Mac
cd ~/Desktop
mkdir ai-shield-transfer
cd ai-shield-transfer

# Backup volumes (as shown above)
docker run --rm -v minimal-local_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data.tar.gz /data
docker run --rm -v minimal-local_minio_data:/data -v $(pwd):/backup alpine tar czf /backup/minio_data.tar.gz /data
```

### Step 2: Copy to Target System

```bash
# Option A: USB drive
cp -r ~/Desktop/ai-shield-transfer /Volumes/USB_DRIVE/

# Option B: Network transfer (if both systems are on same network)
# On target system, run: nc -l 9999 | tar xzf -
# On source system:
tar czf - ~/Desktop/ai-shield-transfer | nc target-ip 9999

# Option C: Cloud storage
# Upload to Dropbox/Google Drive/etc, then download on target system
```

### Step 3: Restore on Target System

```bash
# On target system (Linux/Mac/Windows with Docker)
cd /path/to/ai-threat-intel/src/minimal-local

# Create volumes (if they don't exist)
docker volume create minimal-local_postgres_data
docker volume create minimal-local_minio_data
docker volume create minimal-local_redis_data
docker volume create minimal-local_ollama_data

# Restore data
docker run --rm \
  -v minimal-local_postgres_data:/data \
  -v /path/to/ai-shield-transfer:/backup \
  alpine sh -c "cd /data && tar xzf /backup/postgres_data.tar.gz --strip 1"

docker run --rm \
  -v minimal-local_minio_data:/data \
  -v /path/to/ai-shield-transfer:/backup \
  alpine sh -c "cd /data && tar xzf /backup/minio_data.tar.gz --strip 1"

# Start services
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d
```

---

## Automated Backup Script

Save this as `backup.sh` in your project:

```bash
#!/bin/bash
set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-$HOME/ai-shield-backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup-$TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_PATH"

echo "Starting backup to $BACKUP_PATH..."

# Backup PostgreSQL
echo "Backing up PostgreSQL..."
docker run --rm \
  -v minimal-local_postgres_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/postgres_data.tar.gz /data

# Backup MinIO
echo "Backing up MinIO..."
docker run --rm \
  -v minimal-local_minio_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/minio_data.tar.gz /data

# Backup Redis (optional)
echo "Backing up Redis..."
docker run --rm \
  -v minimal-local_redis_data:/data \
  -v "$BACKUP_PATH":/backup \
  alpine tar czf /backup/redis_data.tar.gz /data

# Create metadata file
cat > "$BACKUP_PATH/backup_info.txt" << EOF
Backup Date: $(date)
Hostname: $(hostname)
Docker Version: $(docker --version)
Threat Count: $(docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec -T postgres psql -U ai_shield -d ai_shield -t -c "SELECT COUNT(*) FROM threats;" 2>/dev/null | tr -d ' ')
EOF

echo ""
echo "✓ Backup complete!"
echo "Location: $BACKUP_PATH"
echo "Size: $(du -sh "$BACKUP_PATH" | cut -f1)"
echo ""
ls -lh "$BACKUP_PATH"

# Optional: Keep only last 7 backups
echo ""
echo "Cleaning old backups (keeping last 7)..."
cd "$BACKUP_DIR"
ls -t | tail -n +8 | xargs -I {} rm -rf {}
echo "✓ Cleanup complete"
```

Make it executable:
```bash
chmod +x backup.sh
```

Run it:
```bash
./backup.sh
```

---

## Scheduled Backups (macOS)

Create a cron job to backup daily:

```bash
# Edit crontab
crontab -e

# Add this line (backup daily at 2 AM)
0 2 * * * /path/to/ai-threat-intel/src/minimal-local/backup.sh >> /tmp/ai-shield-backup.log 2>&1
```

---

## Backup Size Estimates

Based on typical usage:

| Component | Size (1K threats) | Size (10K threats) | Size (100K threats) |
|-----------|-------------------|--------------------|--------------------|
| PostgreSQL | ~50 MB | ~500 MB | ~5 GB |
| MinIO | ~100 MB | ~1 GB | ~10 GB |
| Redis | ~5 MB | ~10 MB | ~20 MB |
| Ollama | ~4-8 GB | ~4-8 GB | ~4-8 GB |
| **Total** | **~4-8 GB** | **~5-9 GB** | **~19-23 GB** |

---

## Troubleshooting

### Backup fails with "permission denied"

```bash
# Run with sudo (Linux) or ensure Docker Desktop has disk access (macOS)
sudo docker run --rm -v minimal-local_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data.tar.gz /data
```

### Restore fails with "directory not empty"

```bash
# Remove existing volume and recreate
docker volume rm minimal-local_postgres_data
docker volume create minimal-local_postgres_data
# Then restore again
```

### Backup is too large

```bash
# Backup only PostgreSQL (skip MinIO raw data)
# You can always re-fetch from sources if needed
docker run --rm -v minimal-local_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data.tar.gz /data
```

---

## Best Practices

1. **Backup before major changes** - Before upgrading, changing config, or modifying code
2. **Test restores** - Periodically test that your backups actually work
3. **Store offsite** - Keep backups on external drive or cloud storage
4. **Automate** - Use cron jobs or scheduled tasks for regular backups
5. **Document** - Keep notes on what each backup contains and when it was created
6. **Compress** - All backup commands use gzip compression (`.tar.gz`)
7. **Verify** - Check backup file sizes and integrity after creation
