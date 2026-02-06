# AI Shield Intelligence - Minimal Local Profile

A minimal local deployment system for AI Shield Intelligence, designed for early pilots and smaller teams. Optimized for Apple Silicon Macs (M1/M2/M3) with 16-32 GB RAM, 4-8 cores, and 50-100 GB disk space.

## Documentation

- **[Configuration Guide](CONFIGURATION_GUIDE.md)** - Detailed guide for environment variables, Ollama models, and collection scheduling
- **[Performance Tuning Guide](PERFORMANCE_TUNING.md)** - Optimize performance for your environment (GPU vs CPU, host vs container)

## Overview

This deployment profile provides core threat intelligence capabilities through 8 containerized services orchestrated by Docker Compose:

### Core Services

- **PostgreSQL (Database)** - Primary data store for threat intelligence metadata, entities, MITRE mappings, and LLM analysis results
- **Redis** - Message broker for Celery task queue and caching layer for improved performance
- **MinIO (Storage)** - S3-compatible object storage for raw threat data (JSON) and artifacts
- **Ollama (LLM)** - Local LLM runtime for AI-powered threat analysis (summaries, attack vectors, mitigations)

### Application Services

- **FastAPI (API)** - REST API backend providing endpoints for threat management, search, and system status
- **Celery Worker** - Asynchronous task processing engine that handles LLM analysis, enrichment, and data collection (12 concurrent workers by default)
- **Celery Beat (Scheduler)** - Cron-like scheduler that triggers automated threat collection every 12 hours
- **React Frontend (UI)** - Web user interface for browsing threats, searching, and monitoring system health

### Service Dependencies

If any service fails, here's the impact:
- **Database down** (`ai-shield-postgres`) → Cannot store or query threats (system stops)
- **Redis down** (`ai-shield-redis`) → Task queue stops, no background processing (system stops)
- **Storage down** (`ai-shield-minio`) → Cannot store raw threat data (collection fails)
- **LLM down** (`ai-shield-ollama` or host Ollama) → No AI analysis, but enrichment continues (degraded)
- **Worker down** (`ai-shield-celery-worker`) → No task processing, collection, or analysis (system stops)
- **Scheduler down** (`ai-shield-celery-beat`) → No automated collection, manual triggers still work (degraded)
- **API down** (`ai-shield-api`) → No access to system (frontend and CLI stop)
- **Frontend down** (`ai-shield-frontend`) → No web UI, but API still accessible (degraded)

## Prerequisites

### Required

- **Docker Engine** (Linux) or **OrbStack** (macOS)
- **Docker Compose** v2.0 or higher
- **Minimum Resources**:
  - 32 GB RAM
  - Apple M3 Max or newer
  - 50 GB disk space (100 GB recommended)

### Installation

**Linux (Docker Engine)**:
```bash
# Install Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt-get update
sudo apt-get install docker-compose-plugin
```

**macOS (OrbStack)**:
```bash
# Install OrbStack (recommended for macOS)
brew install orbstack

# Or use Docker Desktop
brew install --cask docker
```

## Quick Start

### 1. Clone and Configure

```bash
# Navigate to the minimal-local directory
cd src/minimal-local

# Copy environment template
cp .env.example .env.minimal

# Edit .env.minimal and set required passwords
# REQUIRED: POSTGRES_PASSWORD, MINIO_ROOT_PASSWORD
nano .env.minimal
```

### 2. Start Services

```bash
# Start all services
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d

# View logs
docker compose -f docker-compose.minimal.yml logs -f

# Check service status
docker compose -f docker-compose.minimal.yml ps
```

**Note**: If you plan to use host Ollama (for GPU acceleration on macOS), the containerized Ollama service won't start by default. See step 5 below for host Ollama setup.

### 3. Initialize Database

```bash
# Run database initialization script
docker compose -f docker-compose.minimal.yml exec -w /app api python scripts/init_db.py

# Create admin user
docker compose -f docker-compose.minimal.yml exec -w /app api python scripts/create_admin.py
```

**Admin User Creation Modes:**

The `create_admin.py` script supports two modes:

1. **Interactive Mode** (default): Prompts you for username, email, and password
   - Just run the command above and follow the prompts
   - Best for initial setup or when you want to enter credentials securely
   
2. **Non-Interactive Mode** (automated): Reads credentials from environment variables
   - Useful for automated deployments or CI/CD pipelines
   - Set `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` in `.env.minimal`
   - Restart the API container to load the new environment variables:
     ```bash
     docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d api
     ```
   - Then run the create_admin.py script - it will automatically use the environment variables

**Example `.env.minimal` configuration for automated admin creation:**
```bash
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=YourSecurePassword123
```

**Important Notes:**
- The `-w /app` flag changes the working directory inside the container to `/app` where the scripts are located
- Environment variables must be set in `.env.minimal` AND the container must be restarted to pick them up
- If environment variables are not set, the script will automatically fall back to interactive mode

### 4. Pull LLM Model

**Option A: Using Containerized Ollama (CPU-only)**

If you want to use the containerized Ollama (CPU-only on macOS):

```bash
# Start with containerized Ollama
docker compose -f docker-compose.minimal.yml --env-file .env.minimal --profile ollama-container up -d

# Pull the model
docker compose -f docker-compose.minimal.yml exec ollama ollama pull qwen2.5:7b
```

**Option B: Using Host Ollama (GPU-accelerated - Recommended for macOS)**

Skip this step if using host Ollama. See step 5 below.

### 5. (Optional) Use Host Ollama for GPU Acceleration

**macOS Users**: For 3-6x faster LLM processing using Apple Silicon GPU/Neural Engine, use Ollama on your host Mac instead of the containerized version.

**Setup**:

1. **Install Ollama on your Mac** (if not already installed):
   ```bash
   brew install ollama
   ```

2. **Start Ollama service**:
   ```bash
   ollama serve
   ```
   Leave this running in a terminal, or set it to start automatically.

3. **Pull the model on host**:
   ```bash
   ollama pull qwen2.5:7b
   ```

4. **Update `.env.minimal`** to point to host Ollama:
   ```bash
   # Add this line to .env.minimal
   OLLAMA_URL=http://host.docker.internal:11434
   ```

5. **Restart services** to pick up the new configuration:
   ```bash
   docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d
   ```
   
   **Note**: The containerized Ollama service is disabled by default when using host Ollama. It won't start unless you explicitly use `--profile ollama-container`.

**Performance Comparison**:
- **Containerized Ollama (CPU-only)**: ~15-40 seconds per threat, ~10-20 threats/minute
- **Host Ollama (GPU-accelerated)**: ~3-10 seconds per threat, ~30-60 threats/minute

**Why Docker can't use GPU on macOS**: Docker on macOS cannot access Apple Silicon GPUs from containers, so the containerized Ollama runs CPU-only. Using host Ollama enables GPU acceleration.

**To switch back to containerized Ollama**:
```bash
# Remove OLLAMA_URL from .env.minimal (or set to http://ollama:11434)
# Start with containerized Ollama profile
docker compose -f docker-compose.minimal.yml --env-file .env.minimal --profile ollama-container up -d
```

### 6. Access Services

Once all services are healthy, access the system at:

- **Web UI**: http://localhost:3000 (Dashboard, threat list, search, and detail views)
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs (interactive Swagger UI)
- **MinIO Console**: http://localhost:9001
  - Username: `minioadmin` (or value from `MINIO_ROOT_USER` in `.env.minimal`)
  - Password: Value from `MINIO_ROOT_PASSWORD` in `.env.minimal`

## API Authentication

The API uses a hybrid authentication model:

**Public Endpoints** (No authentication required):
- `GET /api/v1/threats` - List and search threats
- `GET /api/v1/threats/{id}` - View threat details
- `GET /api/v1/search` - Search threats
- `GET /api/v1/health` - System health check

**Protected Endpoints** (Authentication required):
- All `POST`, `PUT`, `DELETE` operations
- Source management (`/api/v1/sources/*`)
- User management (`/api/v1/auth/me`, `/api/v1/auth/logout`)
- **System control endpoints** (`/api/v1/system/*`):
  - `GET /api/v1/system/status` - System status and metrics (Public - Read-only)
  - `GET /api/v1/system/llm-analysis-stats` - LLM analysis statistics (Public - Read-only)
  - `POST /api/v1/system/retry-failed-llm` - Retry failed LLM analysis (**Admin only** - Write operation)
  - `GET /api/v1/system/ollama-config` - Ollama configuration (Public - Read-only)
  - `GET /api/v1/system/threat-type-info` - Threat type information (Public - Read-only)

This design allows threat intelligence and system status to be shared publicly while protecting write operations and privileged actions.

**Security Notes**:
- Read-only system endpoints are public for dashboard visibility
- Write operations (retry-failed-llm) require **admin authentication**
- Rate limiting should be implemented at the API gateway level (not in application)
- Audit logging for admin actions logs to stdout/Docker logs (can be forwarded to log aggregation systems)
- Input validation limits are not enforced at application level (should be handled by gateway/proxy)

Some API endpoints require authentication (marked with a padlock 🔒 in Swagger UI).

### Getting an Authentication Token

**Option 1: Using Swagger UI (http://localhost:8000/docs)**

1. Find the `/api/v1/auth/login` endpoint
2. Click "Try it out"
3. Enter your admin credentials:
   ```json
   {
     "username": "admin",
     "password": "AdminPass123"
   }
   ```
   (Use the credentials from `ADMIN_USERNAME` and `ADMIN_PASSWORD` in your `.env.minimal`)
4. Click "Execute"
5. Copy the `access_token` from the response
6. Click the "Authorize" button at the top of the page
7. Paste the token in the "Value" field
8. Click "Authorize"

Now all protected endpoints will work!

**Option 2: Using curl**

```bash
# Get authentication token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "AdminPass123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Using the Token in API Calls**

```bash
# Example: Get system status
curl -X GET http://localhost:8000/api/v1/system/status \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Default Admin Credentials**

If you set admin credentials in `.env.minimal`:
- **Username**: Value from `ADMIN_USERNAME` (default: `admin`)
- **Password**: Value from `ADMIN_PASSWORD` (default: `AdminPass123`)
- **Email**: Value from `ADMIN_EMAIL`

**Security Note**: Change the default password in production by updating `ADMIN_PASSWORD` in `.env.minimal` before creating the admin user.

## Service Management

### Start Services

```bash
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d
```

### Stop Services

```bash
docker compose -f docker-compose.minimal.yml down
```

### Update Services After Code Changes

When you modify backend code (like security fixes), you need to rebuild and restart the affected containers:

```bash
# Rebuild and restart API container (for backend code changes)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build api

# Rebuild and restart Celery worker (if worker code changed)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build celery_worker

# Rebuild all services (if multiple services changed)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build

# Quick restart without rebuild (for config changes only)
docker compose -f docker-compose.minimal.yml restart api
```

**When to rebuild:**
- ✅ After modifying Python code in `backend/`
- ✅ After updating dependencies in `pyproject.toml`
- ✅ After security fixes or code updates
- ❌ After only changing `.env.minimal` (just restart)
- ❌ After only changing `config/sources.yaml` (auto-reloads)

### Restart a Service

```bash
docker compose -f docker-compose.minimal.yml restart api
```

### View Logs

```bash
# All services
docker compose -f docker-compose.minimal.yml logs -f

# Specific service
docker compose -f docker-compose.minimal.yml logs -f api

# With timestamps
docker compose -f docker-compose.minimal.yml logs -f --timestamps api
```

### Execute Commands in Containers

```bash
# Access API container shell
docker compose -f docker-compose.minimal.yml exec api sh

# Access PostgreSQL
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield

# Access Redis CLI
docker compose -f docker-compose.minimal.yml exec redis redis-cli
```

## Configuration

> **📖 For detailed configuration guidance**, see [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) which covers:
> - How to set the Ollama model
> - Environment mode differences (development vs production)
> - Adjusting collection schedule based on processing capacity

### Environment Variables

All configuration is managed through `.env.minimal`. See `.env.example` for available options.

**Required**:
- `POSTGRES_PASSWORD` - PostgreSQL database password
- `MINIO_ROOT_USER` - MinIO username (default: `minioadmin`)
- `MINIO_ROOT_PASSWORD` - MinIO object storage password

**Optional** (with defaults):
- `ENVIRONMENT` - Environment mode (default: `development`)
  - `development`: Relaxed security validation, verbose logging, hot-reload enabled
  - `production`: Strict security validation, JSON logging, enforces strong passwords
- `OLLAMA_MODEL` - LLM model for threat analysis (default: `qwen2.5:7b`)
  - `qwen2.5:7b`: Recommended - best balance of quality and speed
  - `phi3:mini`: Faster but lower quality analysis
  - `qwen2.5:14b` or `qwen2.5:32b`: Higher quality but slower
- `POSTGRES_PORT` - PostgreSQL port (default: 5432)
- `REDIS_PORT` - Redis port (default: 6379)
- `MINIO_PORT` - MinIO API port (default: 9000)
- `MINIO_CONSOLE_PORT` - MinIO console port (default: 9001)
- `OLLAMA_PORT` - Ollama port (default: 11434)
- `API_PORT` - FastAPI port (default: 8000)
- `FRONTEND_PORT` - React frontend port (default: 3000)

### Port Conflicts

If you have port conflicts with existing services, update the port variables in `.env.minimal`:

```bash
# Example: Change API port from 8000 to 8080
API_PORT=8080
```

### Alert Configuration

The system can send notifications when high-severity threats are detected. Alerts are configured via environment variables in `.env.minimal`.

**Alert Settings**:
- `ALERT_ENABLED` - Enable/disable alerts (default: `false`)
- `ALERT_SEVERITY_THRESHOLD` - Minimum severity to trigger alerts (default: `8`)
- `ALERT_EMAIL_ENABLED` - Enable email notifications (default: `false`)
- `ALERT_WEBHOOK_ENABLED` - Enable webhook notifications (default: `false`)

**Email Configuration** (if `ALERT_EMAIL_ENABLED=true`):
- `ALERT_EMAIL_SMTP_HOST` - SMTP server hostname (e.g., `smtp.gmail.com`)
- `ALERT_EMAIL_SMTP_PORT` - SMTP server port (default: `587`)
- `ALERT_EMAIL_FROM` - Sender email address
- `ALERT_EMAIL_TO` - JSON array of recipient email addresses (e.g., `["user1@example.com", "user2@example.com"]`)
- `ALERT_EMAIL_USERNAME` - SMTP authentication username
- `ALERT_EMAIL_PASSWORD` - SMTP authentication password

**Webhook Configuration** (if `ALERT_WEBHOOK_ENABLED=true`):
- `ALERT_WEBHOOK_URL` - Webhook endpoint URL (e.g., Slack, Discord, custom endpoint)
- `ALERT_WEBHOOK_METHOD` - HTTP method (default: `POST`)
- `ALERT_WEBHOOK_HEADERS` - Optional JSON string of headers (e.g., `{"Authorization": "Bearer token"}`)

**Example Configuration**:

```bash
# Enable alerts for high-severity threats
ALERT_ENABLED=true
ALERT_SEVERITY_THRESHOLD=8

# Email alerts
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_SMTP_HOST=smtp.gmail.com
ALERT_EMAIL_SMTP_PORT=587
ALERT_EMAIL_FROM=alerts@example.com
ALERT_EMAIL_TO=["security-team@example.com"]
ALERT_EMAIL_USERNAME=alerts@example.com
ALERT_EMAIL_PASSWORD=your-app-password

# Webhook alerts (Slack example)
ALERT_WEBHOOK_ENABLED=true
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Testing Alerts**:

```bash
# Restart services after updating alert configuration
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart api celery_worker

# Check logs to verify alert configuration
docker compose -f docker-compose.minimal.yml logs celery_worker | grep -i alert
```

**Note**: For Gmail, you'll need to use an [App Password](https://support.google.com/accounts/answer/185833) instead of your regular password.

### Customizing Threat Types

The system classifies threats into 8 categories using keyword-based classification. You can customize these threat types and their descriptions by editing the enrichment service configuration.

**Threat Type Descriptions** are displayed in the UI when users click the help icon (?) next to "Threat Types" on the Dashboard.

**Where to Customize:**

The threat type keywords and descriptions are defined in `src/minimal-local/backend/services/enrichment.py`:

```bash
# View current threat types
cat src/minimal-local/backend/services/enrichment.py | grep -A 20 "THREAT_TYPE_KEYWORDS"

# Edit in your editor
code src/minimal-local/backend/services/enrichment.py  # VS Code
nano src/minimal-local/backend/services/enrichment.py  # Terminal editor
```

**Current Threat Types:**
- `adversarial` - Attacks that manipulate model inputs/outputs using perturbations
- `extraction` - Attempts to steal model parameters or behavior through queries
- `poisoning` - Attacks that corrupt training data or inject backdoors/trojans
- `prompt_injection` - LLM attacks using jailbreaks or prompt manipulation
- `privacy` - Attacks targeting sensitive data in models
- `fairness` - Bias and discrimination issues in ML models
- `robustness` - Defenses and certified protections against attacks
- `supply_chain` - Compromised pretrained models or malicious model repositories

**To Add or Modify Threat Types:**

1. **Edit the file:**
   ```bash
   nano src/minimal-local/backend/services/enrichment.py
   ```

2. **Find the `THREAT_TYPE_KEYWORDS` dictionary** (around line 20-50)

3. **Add a new threat type or modify keywords:**
   ```python
   THREAT_TYPE_KEYWORDS = {
       "adversarial": [
           "adversarial", "perturbation", "evasion", "fgsm", "pgd",
           # Add more keywords here
       ],
       # Add new threat type
       "my_new_type": [
           "keyword1", "keyword2", "keyword3"
       ],
   }
   ```

4. **Update the descriptions in `backend/api/system.py`** (around line 700):
   ```python
   descriptions = {
       "adversarial": "Your description here",
       "my_new_type": "Description for new type",
   }
   ```

5. **Rebuild and restart the API container:**
   ```bash
   cd src/minimal-local
   docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build api
   ```

6. **Verify the changes:**
   - Open the Dashboard at http://localhost:3000
   - Click the help icon (?) next to "Threat Types"
   - Your new descriptions should appear in the modal

**Note**: The UI dynamically fetches threat type information from the backend API (`/api/v1/system/threat-type-info`), so changes to the enrichment service will be reflected in the UI after restarting the API container.

### Celery Beat Schedule (Automated Data Collection)

The system automatically fetches threat intelligence on a schedule using Celery Beat.

**Current Schedule:** Every 6 hours at minute 0 (12:00 AM, 6:00 AM, 12:00 PM, 6:00 PM)

**Where to Find the Configuration:**

The schedule is defined in `src/minimal-local/backend/tasks.py` around **line 67-73**.

To view it:
```bash
# From the project root
cat src/minimal-local/backend/tasks.py | grep -A 10 "beat_schedule"

# Or open in your editor
code src/minimal-local/backend/tasks.py  # VS Code
nano src/minimal-local/backend/tasks.py  # Terminal editor
```

**Current Configuration:**

```python
# In backend/tasks.py (lines 67-73)
beat_schedule={
    'fetch-sources-every-6-hours': {
        'task': 'tasks.scheduled_source_fetch',
        'schedule': crontab(minute=0, hour='*/6'),  # ← Every 6 hours
        'options': {'expires': 21000}
    },
}
```

**Understanding the Schedule:**
- `crontab(minute=0, hour='*/6')` means "run at minute 0 every 6 hours"
- This triggers at 12:00 AM, 6:00 AM, 12:00 PM, 6:00 PM
- The task fetches from all enabled sources in `config/sources.yaml`
- Gives 6 hours to process threats before next collection

**Common Schedule Examples:**

| Frequency | Configuration | When It Runs |
|-----------|--------------|--------------|
| Every 6 hours (default) | `crontab(minute=0, hour='*/6')` | 12:00 AM, 6:00 AM, 12:00 PM, 6:00 PM |
| Every hour | `crontab(minute=0)` | 12:00, 1:00, 2:00, ... |
| Every 30 minutes | `crontab(minute='*/30')` | 12:00, 12:30, 1:00, 1:30, ... |
| Every 15 minutes | `crontab(minute='*/15')` | 12:00, 12:15, 12:30, 12:45, ... |
| Every 12 hours | `crontab(minute=0, hour='*/12')` | 12:00 AM, 12:00 PM |
| Daily at 2 AM | `crontab(minute=0, hour=2)` | 2:00 AM every day |
| Twice daily (6 AM & 6 PM) | `crontab(minute=0, hour='6,18')` | 6:00 AM and 6:00 PM |
| Every weekday at 9 AM | `crontab(minute=0, hour=9, day_of_week='1-5')` | 9:00 AM Mon-Fri |

**To Change the Schedule:**

1. **Edit the file:**
   ```bash
   nano src/minimal-local/backend/tasks.py
   ```

2. **Find line 70** and change the `schedule` value:
   ```python
   'schedule': crontab(minute=0),  # Change to every hour
   # Or keep default: crontab(minute=0, hour='*/6')  # Every 6 hours
   ```

3. **Save and exit** (Ctrl+O, Enter, Ctrl+X in nano)

4. **Trigger the update by rebuilding and restarting:**
   ```bash
   cd src/minimal-local
   docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build celery_worker celery_beat
   ```
   
   **Note**: The `--build` flag rebuilds the images with your updated `tasks.py`, and `-d` restarts them in the background with the new schedule.

5. **Verify the change took effect:**
   ```bash
   docker compose -f docker-compose.minimal.yml logs celery_beat | grep -i schedule
   ```

**Manual Trigger (Fetch Immediately Without Waiting):**

```bash
# Option 1: Using Celery call command (recommended)
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks call tasks.scheduled_source_fetch

# Option 2: Using Python directly
docker compose -f docker-compose.minimal.yml exec celery_worker python -c "from tasks import scheduled_source_fetch; scheduled_source_fetch.delay()"

# Option 3: From backend container
docker compose -f docker-compose.minimal.yml exec backend python -c "from tasks import scheduled_source_fetch; scheduled_source_fetch.delay()"

# Fetch specific source
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks call tasks.fetch_source --args='["arXiv Computer Security"]'
```

**Check When Next Fetch Will Run:**

```bash
# View Celery Beat logs to see scheduled tasks
docker compose -f docker-compose.minimal.yml logs celery_beat --tail=50
```

**Adjusting Schedule Based on Processing Capacity:**

The system processes threats at approximately **6-12 threats per minute** (360-720 per hour) with 12 workers and Qwen2.5:7b on host Ollama with GPU. If you're collecting more threats than you can process, consider:

1. **Reduce Collection Frequency**:
   ```python
   # Change from hourly to every 6 hours
   'schedule': crontab(minute=0, hour='*/6')
   ```

2. **Increase Worker Concurrency** (in `.env.minimal`):
   ```bash
   CELERY_WORKER_CONCURRENCY=16  # Increase from 12 to 16
   ```
   Then restart: `docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d`

3. **Use Faster Model** (in `.env.minimal`):
   ```bash
   OLLAMA_MODEL=phi3:mini  # Faster but lower quality
   ```

4. **Disable LLM Analysis Temporarily**:
   - LLM analysis is optional - threats are still enriched with classification, entities, MITRE mappings, and severity
   - To pause LLM processing, stop the celery_worker and only restart when backlog is manageable

**Example Calculation**:
- Default: 6-hour collection schedule with 6-12 processed/minute = 360-720/hour processed
- This gives 6 hours (2,160-4,320 threats) to process before next collection
- If you collect more than this, increase workers or extend collection interval

## Data Persistence

All data is stored in Docker named volumes:

- `postgres_data` - PostgreSQL database
- `redis_data` - Redis cache
- `minio_data` - MinIO object storage
- `ollama_data` - Ollama models

### Threat Data Fields

When viewing threat details (e.g., `http://localhost:3000/threats/{id}`), you'll see these key fields:

- **Title**: The headline or title of the threat intelligence article
- **Description**: A brief summary or abstract (typically from RSS feed's `<description>` or `<summary>` tag)
- **Content**: The full article text (from RSS feed's `<content>` tag or scraped from the source URL)
- **Source**: The intelligence source name (e.g., "arXiv Computer Security", "Hugging Face Blog")
- **Published At**: When the article was originally published
- **Threat Type**: Classification result (e.g., "adversarial", "prompt_injection", "data_poisoning")
- **Classification Method**: How it was classified:
  - `keyword` - High confidence keyword matching (5+ matches)
  - `hybrid` - Keyword + LLM validation (2-4 matches)
  - `llm` - LLM-only classification (0-1 matches)
  - `keyword_fallback` - LLM failed, used keyword result
- **Entities**: Extracted CVEs, frameworks, techniques
- **MITRE ATLAS Mappings**: Mapped tactics and techniques

**Note**: Not all sources provide both Description and Content. Some RSS feeds only include summaries, while others provide full article text. The system uses whatever is available from the source.

### Backup & Restore

**Quick Backup** (automated script):

```bash
# Run the backup script
./backup.sh

# Backups are saved to ~/ai-shield-backups/backup-YYYYMMDD-HHMMSS/
```

**Manual Backup** (PostgreSQL only):

```bash
# Backup PostgreSQL database to SQL file
docker compose -f docker-compose.minimal.yml exec postgres pg_dump -U ai_shield ai_shield > backup.sql

# Backup all volumes
docker run --rm -v minimal-local_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data.tar.gz /data
docker run --rm -v minimal-local_minio_data:/data -v $(pwd):/backup alpine tar czf /backup/minio_data.tar.gz /data
```

**For complete backup/restore instructions**, including transferring data to another system, see [BACKUP_RESTORE.md](./BACKUP_RESTORE.md).

### Remove All Data

```bash
# Stop services and remove volumes (WARNING: deletes all data)
docker compose -f docker-compose.minimal.yml down -v
```

## Health Checks

Check system health:

```bash
# API health endpoint
curl http://localhost:8000/api/v1/health

# Individual service health
docker compose -f docker-compose.minimal.yml ps
```

## Troubleshooting

### Service-Specific Debugging

If the Dashboard shows a service is down (red dot), use these commands to diagnose and fix:

#### Database (PostgreSQL) - `ai-shield-postgres`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps postgres

# View logs
docker logs ai-shield-postgres --tail=50

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart postgres

# Test connection
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield -c "SELECT 1;"
```

#### Redis - `ai-shield-redis`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps redis

# View logs
docker logs ai-shield-redis --tail=50

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart redis

# Test connection
docker compose -f docker-compose.minimal.yml exec redis redis-cli ping
```

#### Storage (MinIO) - `ai-shield-minio`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps minio

# View logs
docker logs ai-shield-minio --tail=50

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart minio

# Access MinIO Console
# Open http://localhost:9001 in browser
```

#### LLM (Ollama) - `ai-shield-ollama` or host Ollama
```bash
# For containerized Ollama:
docker logs ai-shield-ollama --tail=50
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart ollama

# For host Ollama:
curl http://localhost:11434/api/tags
ollama serve  # If not running
ollama list   # Check available models
```

#### Worker (Celery Worker) - `ai-shield-celery-worker`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps celery_worker

# View logs (most common for debugging task failures)
docker logs ai-shield-celery-worker --tail=100 -f

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart celery_worker

# Check active tasks
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks inspect active
```

#### Scheduler (Celery Beat) - `ai-shield-celery-beat`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps celery_beat

# View logs (shows scheduled task execution)
docker logs ai-shield-celery-beat --tail=50 -f

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart celery_beat

# Check schedule
docker logs ai-shield-celery-beat | grep -i schedule
```

#### API (FastAPI) - `ai-shield-api`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps api

# View logs
docker logs ai-shield-api --tail=100 -f

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart api

# Test API health
curl http://localhost:8000/api/v1/health
```

#### Frontend (React) - `ai-shield-frontend`
```bash
# Check status
docker compose -f docker-compose.minimal.yml --env-file .env.minimal ps frontend

# View logs
docker logs ai-shield-frontend --tail=50

# Restart service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart frontend

# Access frontend
# Open http://localhost:3000 in browser
```

### Services Won't Start

1. Check Docker is running: `docker ps`
2. Check port conflicts: `lsof -i :8000` (macOS/Linux)
3. Check logs: `docker compose -f docker-compose.minimal.yml logs`
4. Verify environment file: `cat .env.minimal`

### Database Connection Errors

1. Ensure PostgreSQL is healthy: `docker compose -f docker-compose.minimal.yml ps postgres`
2. Check password in `.env.minimal` matches
3. Run initialization: `docker compose -f docker-compose.minimal.yml exec api python scripts/init_db.py`

#### "Too Many Clients Already" Error

If you see `"sorry, too many clients already"` errors in logs or the database shows a red dot on the Dashboard:

**Cause**: PostgreSQL has reached its connection limit (default: 100 connections). With 12 Celery workers, API, Celery Beat, and concurrent requests, you can easily exceed this limit.

**Solution**: The system is configured with `max_connections=200` by default. If you still see this error:

1. **Restart PostgreSQL** to apply the configuration:
   ```bash
   docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart postgres
   ```

2. **Verify the setting**:
   ```bash
   docker exec ai-shield-postgres psql -U ai_shield -c "SHOW max_connections;"
   # Should show: 200
   ```

3. **Check current connections**:
   ```bash
   docker exec ai-shield-postgres psql -U ai_shield -d ai_shield -c "SELECT count(*) as active_connections FROM pg_stat_activity WHERE datname = 'ai_shield';"
   ```

4. **If still hitting limits**, reduce Celery worker concurrency in `.env.minimal`:
   ```bash
   CELERY_WORKER_CONCURRENCY=8  # Reduce from 12 to 8
   ```
   Then restart: `docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart celery_worker`

### Ollama Model Not Found

```bash
# Pull the model
docker compose -f docker-compose.minimal.yml exec ollama ollama pull qwen2.5:7b

# List available models
docker compose -f docker-compose.minimal.yml exec ollama ollama list
```

### Using Host Ollama Instead of Container

If you're using host Ollama (for GPU acceleration on macOS):

```bash
# Check if host Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Pull model on host
ollama pull qwen2.5:7b

# Verify .env.minimal has the correct URL
grep OLLAMA_URL .env.minimal
# Should show: OLLAMA_URL=http://host.docker.internal:11434

# Restart services
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart api celery_worker
```

### Out of Memory

1. Check available resources: `docker stats`
2. Reduce Celery worker concurrency in `docker-compose.minimal.yml`
3. Use a smaller LLM model (e.g., `phi3:mini` instead of `qwen2.5:7b`)

### Frontend Not Available

The React frontend (port 3000) has not been implemented yet. Use the API directly:

1. **Swagger UI**: http://localhost:8000/docs (interactive API documentation)
2. **ReDoc**: http://localhost:8000/redoc (alternative API documentation)
3. **Direct API calls**: Use curl, Postman, or any HTTP client

Example API calls:
```bash
# Check health
curl http://localhost:8000/api/v1/health

# List sources (once implemented)
curl http://localhost:8000/api/v1/sources
```

## Development

### Local Development Setup

If you want to develop outside Docker:

```bash
# Navigate to minimal-local directory
cd src/minimal-local

# Create virtual environment using uv (recommended)
uv venv --python 3.12
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Or using standard Python venv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies with uv (fast)
uv pip install -e .

# Or using regular pip
pip install -e .
```

**Note**: The virtual environment and `pyproject.toml` are both at `src/minimal-local/` for simplicity.

### Hot Reloading

The system is configured for development with hot reloading:

- **Backend**: FastAPI auto-reloads on code changes
- **Frontend**: Vite HMR (Hot Module Replacement)

### Running Tests

```bash
# Backend unit tests
docker compose -f docker-compose.minimal.yml exec api pytest tests/unit/ -v

# Backend property tests
docker compose -f docker-compose.minimal.yml exec api pytest tests/property/ -v

# Frontend tests
docker compose -f docker-compose.minimal.yml exec frontend npm test
```

## How It Works

### Data Pipeline Overview

The system processes threat intelligence through multiple stages, transforming raw data from external sources into actionable, enriched intelligence:

```
External Sources → Collection → Ingestion → Enrichment → Analysis → Presentation
```

### Automated Data Collection

The system automatically fetches threat intelligence from configured sources **every hour** using Celery Beat (a cron-like scheduler):

1. **Celery Beat** triggers `scheduled_source_fetch` task hourly
2. Task reads enabled sources from `config/sources.yaml`
3. For each source, a `fetch_source` task is queued
4. Collectors (RSS, API, Web Scraper) fetch new data
5. Each item is queued for ingestion

**Manual Trigger** (fetch immediately without waiting):
```bash
# Option 1: Using Celery call command (recommended)
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks call tasks.scheduled_source_fetch

# Option 2: Using Python directly
docker compose -f docker-compose.minimal.yml exec celery_worker python -c "from tasks import scheduled_source_fetch; scheduled_source_fetch.delay()"

# Fetch specific source
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks call tasks.fetch_source --args='["arXiv Computer Security"]'
```

**Note**: Manual triggers do NOT reset the scheduled collection time. The next automatic collection will still run at the scheduled interval (every 12 hours at 12:00 AM and 12:00 PM).

### Verifying Data Collection

After triggering data collection (manually or automatically), you can verify it's working using these commands:

#### 1. Check Total Threat Count
```bash
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield -d ai_shield -c "SELECT COUNT(*) as total_threats FROM threats;"
```

#### 2. Check New Threats (Last 5 Minutes)
```bash
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield -d ai_shield -c "SELECT COUNT(*) as new_in_last_5min FROM threats WHERE ingested_at > NOW() - INTERVAL '5 minutes';"
```

#### 3. View Most Recent Threats
```bash
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield -d ai_shield -c "SELECT title, source, ingested_at FROM threats ORDER BY ingested_at DESC LIMIT 5;"
```

#### 4. Check Collection Status by Source
```bash
docker compose -f docker-compose.minimal.yml exec postgres psql -U ai_shield -d ai_shield -c "SELECT source, COUNT(*) as count, MAX(ingested_at) as last_ingested FROM threats GROUP BY source ORDER BY last_ingested DESC;"
```

#### 5. Watch Celery Worker Logs (Real-Time)
```bash
# Watch logs in real-time (Ctrl+C to exit)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal logs celery_worker -f --tail=50

# View recent logs
docker compose -f docker-compose.minimal.yml --env-file .env.minimal logs celery_worker --tail=200
```

**What to Look For in Logs**:
- `"Starting scheduled source fetch"` - Collection triggered
- `"Queued fetch task for source: <name>"` - Sources being processed
- `"Fetch completed"` with item counts - Data fetched successfully
- `"Successfully ingested threat"` - New threats added
- `"Duplicate threat detected"` - Deduplication working (normal)
- `"Successfully analyzed threat"` - LLM analysis completed

#### 6. Check via Dashboard UI

The easiest way to verify collection:
1. Open Dashboard: http://localhost:3000
2. Note the **Total Threats** count
3. Trigger collection (using command above)
4. Wait 2-3 minutes
5. Dashboard auto-updates every 15 seconds - watch the **Total Threats** count increase
6. Check **Recent Threats** section - new threats appear at top with current timestamp
7. Watch **System Activity → Pipeline** for active tasks

### Deduplication

The system prevents duplicate threats using **content-based hashing**:

1. **Hash Calculation**: SHA-256 hash of normalized content with intelligent preprocessing:
   - Strip leading/trailing whitespace
   - Normalize arXiv metadata (removes "Announce Type" variations and version numbers)
   - Convert to lowercase using Unicode-aware casefold()
   - Calculate SHA-256 hash
2. **Duplicate Check**: Query PostgreSQL for existing threat with same `content_hash`
3. **Skip if Exists**: If found, return existing threat ID without creating new record
4. **Store if New**: If not found, store in both MinIO (raw data) and PostgreSQL (structured data)

**arXiv Cross-Post Handling**:
- arXiv cross-posts papers to multiple categories (e.g., "AI" and "Machine Learning")
- RSS feeds have slight metadata differences: "Announce Type: replace-cross" vs "replace"
- System normalizes these variations so cross-posts produce the same hash
- Prevents near-duplicate entries from different arXiv categories

**Race Condition Protection**:
- Database has unique index on `content_hash` column
- If two workers try to insert same content simultaneously, PostgreSQL rejects duplicate
- System returns existing threat instead of failing

**Example Flow**:
```
New Article → Normalize Content → Calculate Hash → Check Database
                                                        ↓
                                              Found? → Return Existing ID
                                                        ↓
                                              Not Found? → Store in MinIO + PostgreSQL
```

### Enrichment & Analysis Layer

After ingestion, each threat goes through an **automated enrichment pipeline** that adds intelligence and context. This is NOT just data collection - the system actively analyzes and enriches every threat:

#### 1. Hybrid Threat Classification (Keyword + LLM)

**Purpose**: Automatically categorize threats by attack type with high accuracy

**Method**: Intelligent hybrid approach combining keyword matching with LLM validation

The system uses a **3-tier confidence model** to optimize both speed and accuracy:

**Classification Paths**:

1. **High Confidence (≥5 keyword matches)** → Fast Path
   - Uses keyword result directly
   - No LLM call needed
   - ~100ms per threat
   - Example: "adversarial perturbation evasion attack FGSM" → 5 matches → "adversarial"

2. **Medium Confidence (2-4 matches)** → Hybrid Path
   - Keyword suggests a type, but not certain
   - LLM validates the keyword result
   - Uses LLM's classification as final result
   - ~3-10 seconds per threat (with GPU)
   - Example: "model poisoning backdoor" → 3 matches → LLM confirms "poisoning"

3. **Low/No Confidence (0-1 matches)** → LLM Path
   - Keywords insufficient or ambiguous
   - Relies entirely on LLM classification
   - ~3-10 seconds per threat (with GPU)
   - Example: "novel attack technique" → 0 matches → LLM analyzes and classifies

**Fallback Handling**:
- If LLM fails (timeout, service down), falls back to keyword result
- If both fail, marks as "unknown" for manual review
- All classification decisions are logged with metadata

**Threat Types Detected**:
- **adversarial**: Attacks that manipulate model inputs/outputs using perturbations
- **extraction**: Attempts to steal model parameters or behavior through queries
- **poisoning**: Attacks that corrupt training data or inject backdoors/trojans
- **prompt_injection**: LLM attacks using jailbreaks or prompt manipulation
- **privacy**: Attacks targeting sensitive data in models
- **fairness**: Bias and discrimination issues in ML models
- **robustness**: Defenses and certified protections against attacks
- **supply_chain**: Compromised pretrained models or malicious model repositories
- **unknown**: Unable to classify (requires manual review)

**Performance Impact**:
- **Before**: ~40-60% of threats classified as "unknown" (keyword-only)
- **After**: <20% "unknown" (80%+ reduction in manual review needed)
- **Speed**: ~50% of threats use fast path (no LLM), ~30% use hybrid, ~20% use LLM-only

**Classification Metadata**:
Each threat stores detailed classification information:
- `classification_method`: "keyword", "llm", "hybrid", "keyword_fallback", or "failed"
- `classification_confidence`: "high", "medium", "low", or "none"
- `classification_score`: Number of keyword matches (0-N)
- `classification_metadata`: JSON with keyword matches, LLM response, timestamps

**Enhanced Threat Metadata** (NEW):
For threats classified with LLM (hybrid or llm-only paths), the system extracts rich structured metadata:

- **Attack Surface**: Which ML lifecycle phases are affected
  - `runtime`: Attacks during model inference/serving
  - `training`: Attacks during model training phase
  - `inference`: Attacks during model prediction
  - `fine-tuning`: Attacks during model adaptation
  - `deployment`: Attacks on deployed systems

- **Testability**: Whether the threat can be tested at runtime
  - `yes`: Can be tested with automated tests (e.g., prompt injection, jailbreak, adversarial examples, RAG poisoning)
  - `no`: Cannot be tested at runtime (e.g., training-time attacks, supply chain attacks, research papers, announcements)
  - `conditional`: Can be tested under specific conditions (e.g., configuration-dependent attacks, model-specific vulnerabilities)
  - **Note**: While "conditional" is defined in the LLM prompt, the current model tends to make binary yes/no decisions. As of the latest data analysis, 0 threats have testability="conditional". This is acceptable behavior and can be refined in future iterations if needed.

- **Techniques**: Specific attack methods mentioned (dynamically extracted by LLM)
  - Examples: `jailbreak`, `prompt_injection`, `rag_poisoning`, `backdoor`, `fgsm`, `pgd`, `membership_inference`, `model_stealing`, `data_poisoning`
  - The LLM identifies techniques from the threat description

- **Target Systems**: Which AI systems are vulnerable
  - `llm`: Large language models
  - `vision`: Computer vision models
  - `multimodal`: Multi-modal models
  - `rag`: Retrieval-augmented generation systems
  - `agentic`: AI agent systems
  - `chat`: Conversational AI systems

- **Confidence**: LLM's confidence in the classification (0.0-1.0)

- **Reasoning**: LLM's explanation for the classification decision

**Example Enhanced Metadata**:
```json
{
  "threat_metadata": {
    "attack_surface": ["training", "inference"],
    "testability": "conditional",
    "techniques": ["backdoor", "poisoning", "trigger_injection"],
    "target_systems": ["llm", "vision"],
    "confidence": 0.85,
    "reasoning": "The threat involves injecting backdoor triggers during training that activate during inference, making it testable if you have access to the training pipeline."
  }
}
```

**UI Display**:
Enhanced metadata is displayed on the threat detail page with colored badges:
- **Testability**: Green (yes), Yellow (conditional), Red (no)
- **Attack Surface**: Blue badges
- **Techniques**: Purple badges
- **Target Systems**: Indigo badges

**Note**: Enhanced metadata is only available for threats classified after this feature was deployed. Older threats will only have basic classification information.

### Enhanced LLM Classification (Multi-Stage Analysis)

**NEW**: The LLM classifier now uses a sophisticated **5-stage analysis pipeline** to accurately distinguish between traditional web vulnerabilities and GenAI-specific threats.

**Multi-Stage Analysis Pipeline**:

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: GenAI Context Validation (CHECK THIS FIRST!)       │
│ ├─ Model-related: LLM, GPT, transformer, BERT               │
│ ├─ Interaction: prompt, chat, conversation, completion      │
│ ├─ Architecture: RAG, embedding, fine-tuning, unlearning    │
│ ├─ Attack: extraction, jailbreak, poisoning, adversarial    │
│ ├─ System: agent, tool calling, autonomous, multi-agent     │
│ └─ If GenAI context found → Proceed to Stage 3              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Web Vulnerability Exclusion (ONLY if no GenAI)     │
│ ├─ Check for: XSS, SQLi, CSRF, SSRF, XXE, path traversal    │
│ ├─ If web vuln AND no GenAI context → "unknown"             │
│ └─ Prevents misclassification of traditional web attacks    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: GenAI Attack Vector Identification                 │
│ ├─ Prompt Manipulation: injection, jailbreak, leaking       │
│ ├─ Model Behavior: extraction, inversion, unlearning        │
│ ├─ Training Data: poisoning, backdoor, adversarial          │
│ ├─ RAG Manipulation: context poisoning, retrieval attacks   │ 
│ └─ Agent Misuse: tool calling exploitation, function abuse  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Testability Determination                          │
│ ├─ "yes": Runtime-testable (prompt injection, RAG poison)   │
│ ├─ "no": Non-runtime (training attacks, supply chain)       │
│ └─ "conditional": Configuration-dependent testability       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 5: Category Assignment & Reasoning                    │
│ ├─ Assign primary category based on analysis                │
│ ├─ Generate detailed reasoning (min 20 chars)               │
│ └─ Explain: context, vectors, web status, testability       │
└─────────────────────────────────────────────────────────────┘
```

**Key Improvements**:

1. **GenAI Context First**: Validates GenAI indicators BEFORE checking for web vulnerabilities, preventing false negatives on GenAI threats

2. **Web Vulnerability Filtering**: Only excludes traditional web attacks (XSS, SQLi, CSRF) if NO GenAI context is found, reducing noise by ~40%

3. **Detailed Attack Vector Mapping**: Identifies specific techniques (prompt injection, jailbreak, RAG poisoning, model extraction, unlearning attacks) and includes them in metadata

4. **Runtime Testability Assessment**: Determines if threats can be tested in GenAI runtime environments, helping security teams prioritize testing efforts

5. **Comprehensive Reasoning**: Every classification includes detailed explanation of why decisions were made

**Example: GenAI Threat Correctly Classified**
```
Input: "Geometric-disentanglement Unlearning - measures extraction strength"

Stage 1: GenAI Context Validation
  ✓ Found: "unlearning" (architecture), "extraction" (attack), "LLM" (model)
  → High GenAI context, proceed to Stage 3

Stage 2: Web Vulnerability Exclusion
  → Skipped (GenAI context found in Stage 1)

Stage 3: Attack Vector Identification
  ✓ Identified: "model extraction", "unlearning attacks"
  → techniques=["model extraction", "unlearning attacks"]

Stage 4: Testability Determination
  ✓ Runtime-testable attack (extraction via queries)
  → testability="yes"

Stage 5: Category Assignment
  → category="extraction"
```

**Example: Web Vulnerability Correctly Excluded**
```
Input: "SQL injection vulnerability in login form"

Stage 1: GenAI Context Validation
  ✗ No GenAI context found
  → Continue to Stage 2

Stage 2: Web Vulnerability Exclusion
  ✓ Detected: SQL injection indicator
  ✗ No GenAI context (confirmed from Stage 1)
  → Result: category="unknown", reasoning="Traditional web vulnerability, not GenAI-specific"
```
  → confidence=0.95
  → reasoning="GenAI context present (LLM, prompt, chatbot). Attack vector: prompt injection. Runtime testable - can be tested by sending crafted prompts."
```

**Testing & Validation**:
- **130 unit tests** covering all classification scenarios
- **4 property-based tests** with 100+ iterations each validating universal correctness
- **9 out of 13 correctness properties** validated with comprehensive test coverage
- All tests passing with 0 failures

**Performance**:
- Same speed as before (~3-10 seconds with GPU)
- Improved accuracy: ~80% reduction in false positives (web vulns misclassified as GenAI)
- Better metadata quality: detailed reasoning and testability assessment for every threat

**Example Classification Flow**:
```
Input: "Researchers demonstrate gradient-based adversarial attack using FGSM"

Step 1: Keyword Matching
  - "adversarial" (1 match)
  - "attack" (1 match)
  - "FGSM" (1 match)
  - Total: 3 matches → "adversarial" suggested

Step 2: Confidence Evaluation
  - Score: 3 → Medium confidence

Step 3: LLM Validation
  - Prompt: "Classify this threat: [description]"
  - LLM Response: "adversarial"
  - Agreement: Yes

Result:
  - threat_type: "adversarial"
  - method: "hybrid"
  - confidence: "medium"
  - score: 3
```

**Configuration**:
- Confidence thresholds: HIGH=5, MEDIUM=2 (configurable in `classification_service.py`)
- LLM model: Uses existing Ollama configuration (default: qwen2.5:7b)
- Timeout: 30 seconds for LLM calls
- Keywords: Defined per threat type in `classification_service.py`

#### 2. Entity Extraction

**Purpose**: Extract structured information from unstructured text

**Entities Extracted**:
- **CVE IDs**: `CVE-2024-1234` - Known vulnerabilities
- **Frameworks**: TensorFlow, PyTorch, scikit-learn, Keras, JAX
- **Techniques**: gradient descent, fine-tuning, transfer learning
- **Model Names**: GPT-4, BERT, ResNet, YOLO
- **Attack Methods**: FGSM, PGD, C&W, DeepFool

**Storage**: Each entity is stored with:
- Entity type (cve, framework, technique, model, attack_method)
- Entity value (the actual text)
- Confidence score (0.0-1.0)
- Link to source threat

**Example**:
```
Input: "CVE-2024-1234 affects TensorFlow models using FGSM attacks"
Output:
  - Entity(type="cve", value="CVE-2024-1234", confidence=1.0)
  - Entity(type="framework", value="TensorFlow", confidence=0.95)
  - Entity(type="attack_method", value="FGSM", confidence=0.90)
```

#### 3. MITRE ATLAS Mapping

**Purpose**: Map threats to standardized adversarial ML tactics and techniques

**MITRE ATLAS Framework**: Industry-standard knowledge base of adversarial ML threats

**Tactics Mapped** (with example techniques):
- **Reconnaissance**: Discover ML artifacts, identify models
- **Resource Development**: Acquire ML datasets, develop attack tools
- **Initial Access**: Supply chain compromise, model injection
- **ML Attack Staging**: Craft adversarial data, poison training data
- **ML Model Access**: Inference API access, physical access
- **Execution**: Command injection, serverless execution
- **Persistence**: Backdoor ML model, poison model
- **Defense Evasion**: Evade ML model, obfuscate artifacts
- **Discovery**: Discover ML artifacts, discover model ontology
- **Collection**: ML artifact collection, data from local system
- **Exfiltration**: Exfiltration via ML inference API
- **Impact**: Erode ML model integrity, ML denial of service

**Mapping Process**:
1. Analyze threat type and content
2. Match to relevant MITRE ATLAS tactics
3. Identify specific techniques used
4. Store tactic ID, technique ID, and technique name

**Example**:
```
Input: threat_type="adversarial_attack", content="...evasion technique..."
Output:
  - Mapping(tactic="AML.TA0005", technique="AML.T0043", name="Evade ML Model")
  - Mapping(tactic="AML.TA0004", technique="AML.T0040", name="Craft Adversarial Data")
```

#### 4. Severity Scoring

**Purpose**: Prioritize threats based on risk level

**Scoring Algorithm** (1-10 scale):
```python
base_score = threat_type_severity[threat_type]  # 3-8 based on type
exploitability_bonus = 0-2  # Based on keywords like "exploit", "PoC", "weaponized"
final_score = min(10, base_score + exploitability_bonus)
```

**Severity Levels**:
- **Critical (9-10)**: Immediate action required
- **High (7-8)**: Significant risk, prioritize
- **Medium (5-6)**: Moderate risk, monitor
- **Low (1-4)**: Informational, track

**Threat Type Base Scores**:
- Backdoor Attack: 8
- Data Poisoning: 7
- Model Extraction: 6
- Adversarial Attack: 6
- Privacy Attack: 7
- Evasion Attack: 5
- General Security: 4

#### 5. LLM Analysis (Optional)

**Purpose**: Generate human-readable intelligence using local AI

**Model**: Ollama with **Qwen2.5:7b** (7B parameters, runs locally)

**Why Qwen2.5:7b?**
- **Superior technical understanding**: Trained extensively on code and technical content
- **Better reasoning**: Excels at extracting attack vectors, techniques, and mitigations
- **Structured output**: More reliable at following instructions for threat analysis
- **Efficient**: Only ~4.7GB, good balance of quality and speed
- **Multilingual**: Strong support for analyzing threats from global sources

**Analysis Generated**:
- **Summary**: Concise overview of the threat (2-3 sentences)
- **Attack Vectors**: How the attack works, entry points, prerequisites
- **Mitigations**: Defensive measures, detection methods, best practices

**Example**:
```
Input: Threat about adversarial perturbations in image classifiers

Output:
  Summary: "Researchers demonstrate that adding imperceptible noise to images 
  can cause misclassification in deep learning models. The attack achieves 
  95% success rate against production systems."
  
  Attack Vectors: "Attacker crafts adversarial examples using gradient-based 
  methods (FGSM, PGD). Requires white-box or black-box access to model. Can 
  be deployed via API queries or physical world attacks."
  
  Mitigations: "Implement adversarial training with robust examples. Use 
  input preprocessing and detection mechanisms. Apply certified defenses 
  like randomized smoothing. Monitor for unusual prediction patterns."
```

**Graceful Degradation**: If Ollama is unavailable, the system continues working - LLM analysis is marked as "pending" and can be retried later.

### Enrichment Pipeline Flow

The system processes threats in **two separate asynchronous stages**:

#### Stage 1: `enrich_threat` Task (Immediate - ~1-2 seconds)

This task runs first and completes quickly. Results are **immediately visible in the UI**:

```
Threat Ingested
      ↓
[1] Hybrid Classification (Keyword + LLM) → threat_type assigned
      ↓
[2] Entity Extraction → CVEs, frameworks, techniques extracted
      ↓
[3] MITRE ATLAS Mapping → Tactics and techniques mapped
      ↓
[4] Severity Scoring → Risk level calculated (1-10)
      ↓
Basic Enrichment Complete ✅
```

**What you see in UI after Stage 1**:
- ✅ Threat Type (e.g., "adversarial", "poisoning", "prompt_injection")
- ✅ Severity (1-10 score)
- ✅ Entities (CVEs, frameworks like TensorFlow, PyTorch)
- ✅ MITRE ATLAS Mappings (tactics and techniques)
- ✅ Classification Method (keyword, hybrid, llm)
- ✅ Classification Confidence (high, medium, low)

**Processing Time**: ~1-2 seconds per threat

#### Stage 2: `analyze_threat_with_llm` Task (Asynchronous - ~3-40 seconds)

This task runs **after Stage 1** and adds enhanced metadata. Results appear in UI once complete:

```
Basic Enrichment Complete
      ↓
[5] LLM Metadata Extraction → Enhanced threat intelligence
      ↓
Full Analysis Complete ✅
```

**What you see in UI after Stage 2**:
- ✅ **Testability** (yes/no/conditional) - Can this be tested at runtime?
- ✅ **Attack Surface** (runtime, training, inference, fine-tuning, deployment)
- ✅ **Techniques** (specific attack methods extracted by LLM)
- ✅ **Target Systems** (llm, vision, multimodal, rag, agentic, chat)
- ✅ **LLM Summary** (human-readable threat summary)
- ✅ **Attack Vectors** (how the attack works)
- ✅ **Mitigations** (defensive measures)

**Processing Time**: 
- With host Ollama (GPU): ~3-10 seconds per threat
- With containerized Ollama (CPU): ~15-40 seconds per threat

**Why Two Stages?**

This design ensures:
1. **Fast feedback**: Basic threat info appears immediately (~1-2 seconds)
2. **Non-blocking**: LLM analysis doesn't slow down data collection
3. **Graceful degradation**: If LLM is unavailable, threats are still enriched with basic info
4. **Visible progress**: UI shows separate tasks ("enrich_threat" → "analyze_threat_with_llm")

**Viewing Enriched Data**:
- **Web UI**: Navigate to threat detail page to see all enrichment data
- **API**: `GET /api/v1/threats/{id}` returns complete enriched threat
- **Database**: Query `threats`, `entities`, `mitre_mappings`, `llm_analysis` tables

### Complete Data Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL SOURCES                         │
│  arXiv • GitHub • Security Blogs • CVE/NVD • Reddit • HN    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  COLLECTION LAYER                           │
│         Celery Beat (hourly) → Collectors                   │
│              (RSS, API, Web Scraper)                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  INGESTION & DEDUPLICATION                  │
│         Content Hash → Duplicate Check → Store              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  STORAGE LAYER                              │
│    PostgreSQL (structured) • MinIO (raw) • Redis (cache)    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              ENRICHMENT & ANALYSIS LAYER                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. NLP Classification                                │   │
│  │    → Threat Type (adversarial, poisoning, etc.)      │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 2. Entity Extraction                                 │   │
│  │    → CVEs, Frameworks, Techniques, Models            │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 3. MITRE ATLAS Mapping                               │   │
│  │    → Tactics & Techniques (AML.TA0005, AML.T0043)    │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 4. Severity Scoring                                  │   │
│  │    → Risk Level (1-10 scale)                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 5. LLM Analysis (Ollama - Optional)                  │   │
│  │    → Summary, Attack Vectors, Mitigations            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  APPLICATION LAYER                          │
│              FastAPI REST API                               │
│    Search • Filter • Alerts • Export • Analytics            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  PRESENTATION LAYER                         │
│              React Frontend (Vite)                          │
│    Dashboard • Threat List • Detail View • Search           │
└─────────────────────────────────────────────────────────────┘
```

## Resource Requirements

### Minimum Configuration
- **RAM**: 16 GB
- **CPU**: 4 cores
- **Disk**: 50 GB

### Recommended Configuration (Apple M3 with 32GB RAM)
- **RAM**: 32 GB
- **CPU**: 8 cores
- **Disk**: 100 GB SSD

### Service Resource Allocation
- PostgreSQL: 1-2 GB RAM
- Redis: 512 MB - 1 GB RAM
- MinIO: 512 MB RAM
- Ollama: 4-8 GB RAM (depends on model - Qwen2.5:7b uses ~5GB)
- FastAPI: 512 MB RAM
- Celery Workers: 1 GB RAM
- Frontend: 256 MB RAM

## Security

### Best Practices

1. **Strong Passwords**: Use minimum 16 characters with mixed case, numbers, and symbols
2. **Never Commit Secrets**: Ensure `.env.minimal` is in `.gitignore`
3. **Network Isolation**: Services communicate via Docker network
4. **HTTPS**: Use reverse proxy (nginx) for production deployments
5. **Regular Updates**: Keep Docker images updated

### Production Deployment

For production use:

1. Change `ENVIRONMENT=production` in `.env.minimal`
2. Use strong, unique passwords for all services
3. Set up HTTPS with reverse proxy
4. Enable Docker secrets management
5. Configure backup automation
6. Set up monitoring and alerting

## FAQ

### General Questions

**Q: How do I authenticate with the API?**  
A: Use the `/api/v1/auth/login` endpoint with your admin credentials to get a JWT token. In Swagger UI (http://localhost:8000/docs), click "Authorize" and paste the token. See the "API Authentication" section above for detailed instructions.

**Q: How often does the system fetch new threats?**  
A: Automatically every 12 hours via Celery Beat (12:00 AM, 12:00 PM). You can also trigger manual fetches anytime.

**Configuration:** The schedule is defined in `backend/tasks.py`:
```python
beat_schedule={
    'fetch-sources-every-12-hours': {
        'task': 'tasks.scheduled_source_fetch',
        'schedule': crontab(minute=0, hour='*/12'),  # Every 12 hours
    },
}
```

**To change the frequency:**

1. **Every hour:**
   ```python
   'schedule': crontab(minute=0),  # Every hour
   ```

2. **Every 30 minutes:**
   ```python
   'schedule': crontab(minute='*/30'),  # Every 30 minutes
   ```

3. **Every 12 hours:**
   ```python
   'schedule': crontab(minute=0, hour='*/12'),  # Every 12 hours
   ```

4. **Every day at 2 AM:**
   ```python
   'schedule': crontab(minute=0, hour=2),  # Daily at 2:00 AM
   ```

5. **Twice daily (6 AM and 6 PM):**
   ```python
   'schedule': crontab(minute=0, hour='6,18'),  # 6:00 AM and 6:00 PM
   ```

After changing, rebuild and restart to trigger the update:
```bash
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build celery_worker celery_beat
```

**Q: How does the system prevent duplicate threats?**  
A: Content-based SHA-256 hashing with database-level uniqueness constraints. Same content = same hash = detected as duplicate.

**Q: What happens if I restart the services?**  
A: All data persists in Docker volumes. The system resumes where it left off. Celery Beat will continue 12-hour fetches.

**Q: Can I change the fetch schedule?**  
A: Yes, edit `backend/tasks.py` and modify the `beat_schedule` crontab. For example, change `crontab(minute=0, hour='*/12')` to `crontab(minute=0)` for hourly collection.

### Data & Storage

**Q: Where is my data stored?**  
A: 
- **Structured data** (threat metadata): PostgreSQL database
- **Raw data** (original JSON): MinIO object storage (date-based keys: YYYY/MM/DD/{hash}.json)
- **Cache**: Redis

**Q: How much disk space will I need?**  
A: Depends on sources and retention:
- ~1-5 MB per threat (raw + structured)
- 100 threats/day = ~500 MB/day
- Recommend 100+ GB for several months of data

**Q: Can I delete old threats?**  
A: Yes, via API or database. Consider implementing retention policies based on your needs.

**Q: What if MinIO and PostgreSQL get out of sync?**  
A: The ingestion service stores in MinIO first, then PostgreSQL. If PostgreSQL fails, you'll see orphaned MinIO objects logged for cleanup.

### Sources & Collection

**Q: How do I add new intelligence sources?**  
A: Edit `config/sources.yaml` and add your source. The system hot-reloads configuration automatically (no restart needed).

**Q: What types of sources are supported?**  
A: 
- **RSS feeds** (blogs, news sites)
- **REST APIs** (arXiv, GitHub, NVD)
- **Web scraping** (HTML pages with BeautifulSoup)

**Q: Can I disable a source temporarily?**  
A: Yes, set `enabled: false` in `config/sources.yaml`. The source will be skipped during scheduled fetches.

**Q: How do I test a new source?**  
A: Manually trigger a fetch:
```bash
# Using Celery call command (recommended)
docker compose -f docker-compose.minimal.yml exec celery_worker celery -A tasks call tasks.fetch_source --args='["Your Source Name"]'

# Or using Python directly
docker compose -f docker-compose.minimal.yml exec celery_worker python -c "from tasks import fetch_source; fetch_source.delay('Your Source Name')"
```

### Performance & Scaling

**Q: How many concurrent tasks can run?**  
A: Default is 12 concurrent Celery workers. Adjust in `.env.minimal` by setting `CELERY_WORKER_CONCURRENCY=16` (or your desired value), then restart services.

**Q: Can I run multiple Celery workers?**  
A: Yes, scale the worker service:
```bash
docker compose -f docker-compose.minimal.yml up -d --scale celery_worker=3
```

**Q: What if I run out of memory?**  
A: 
1. Reduce Celery worker concurrency
2. Use smaller LLM model (phi3:mini vs qwen2.5:7b)
3. Limit number of enabled sources
4. Add more RAM or upgrade to cloud deployment

**Q: How do I monitor system performance?**  
A: 
- Check health endpoint: `curl http://localhost:8000/api/v1/health`
- View Docker stats: `docker stats`
- Check Celery logs: `docker compose logs celery_worker`

### LLM & Analysis

**Q: Which LLM models are supported?**  
A: Any model available in Ollama. Recommended for threat intelligence:
- **qwen2.5:7b** (7B, ~4.7GB) - **Default**, best for technical analysis
- **gemma2:9b** (9B, ~5.5GB) - Alternative, good balance
- **phi3:mini** (3.8B, ~2.3GB) - Faster but less capable
- **llama3.2** (3B, ~2GB) - Fastest, least accurate

**Q: How do I change the LLM model?**  
A: 
```bash
# Pull new model
docker compose exec ollama ollama pull gemma2:9b

# Update OLLAMA_MODEL in .env.minimal or backend/config.py
```

**Q: Can I disable LLM analysis?**  
A: Yes, the system works without it. LLM analysis is optional enrichment. Just don't pull any Ollama models.

**Q: How long does LLM analysis take per threat?**  
A: Depends on model and hardware:
- qwen2.5:7b with host Ollama GPU: 3-10 seconds per threat (recommended)
- qwen2.5:7b with containerized CPU: 15-40 seconds per threat
- phi3:mini: 10-30 seconds per threat (faster, less accurate)
- Larger models: 30-60+ seconds per threat

### Alerts & Notifications

**Q: How do I set up email alerts?**  
A: Add these variables to `.env.minimal`:
```bash
ALERT_ENABLED=true
ALERT_SEVERITY_THRESHOLD=8
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_SMTP_HOST=smtp.gmail.com
ALERT_EMAIL_SMTP_PORT=587
ALERT_EMAIL_FROM=alerts@example.com
ALERT_EMAIL_TO=["security-team@example.com"]
ALERT_EMAIL_USERNAME=alerts@example.com
ALERT_EMAIL_PASSWORD=your-app-password
```
Then restart: `docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart api celery_worker`

**Q: How do I set up Slack/Discord alerts?**  
A: Use webhook alerts:
```bash
ALERT_ENABLED=true
ALERT_WEBHOOK_ENABLED=true
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```
For Discord, use your Discord webhook URL instead.

**Q: What severity level should I use for alerts?**  
A: 
- **8-10 (Critical/High)**: Immediate action required - recommended for production
- **6-7 (Medium)**: Important but not urgent - good for development
- **1-5 (Low)**: Informational - may generate too many alerts

**Q: How do I test if alerts are working?**  
A: 
1. Check logs: `docker compose logs celery_worker | grep -i alert`
2. Manually trigger a test alert by creating a high-severity threat
3. Verify email/webhook configuration is correct

**Q: Why am I not receiving alerts?**  
A: Check:
1. `ALERT_ENABLED=true` in `.env.minimal`
2. Services restarted after configuration change
3. Severity threshold is appropriate (threats must have severity >= threshold)
4. Email/webhook credentials are correct
5. Check celery_worker logs for error messages

### Troubleshooting

**Q: Services won't start - what should I check?**  
A: 
1. Docker is running: `docker ps`
2. Port conflicts: `lsof -i :8000` (change ports in `.env.minimal`)
3. Environment file exists: `ls -la .env.minimal`
4. Check logs: `docker compose logs`

**Q: Database connection errors?**  
A: 
1. Check PostgreSQL is healthy: `docker compose ps postgres`
2. Verify password in `.env.minimal`
3. Run init script: `docker compose exec api python scripts/init_db.py`

**Q: Celery tasks not running?**  
A: 
1. Check worker is running: `docker compose ps celery_worker`
2. Check Redis connection: `docker compose exec redis redis-cli ping`
3. View worker logs: `docker compose logs celery_worker`

**Q: Why does port 3000 show an error?**  
A: The React frontend hasn't been implemented yet (Task 17 in the roadmap). Use the API directly:
- **Swagger UI**: http://localhost:8000/docs
- **API endpoints**: http://localhost:8000/api/v1/
- **Health check**: `curl http://localhost:8000/api/v1/health`

**Q: What are the MinIO Console credentials?**  
A: 
- **URL**: http://localhost:9001
- **Username**: Value from `MINIO_ROOT_USER` in `.env.minimal` (default: `minioadmin`)
- **Password**: Value from `MINIO_ROOT_PASSWORD` in `.env.minimal`

**Q: How do I reset everything?**  
A: 
```bash
# Stop and remove all data (WARNING: deletes everything)
docker compose -f docker-compose.minimal.yml down -v

# Start fresh
docker compose -f docker-compose.minimal.yml up -d
docker compose -f docker-compose.minimal.yml exec api python scripts/init_db.py
```

### Development

**Q: How do I run tests?**  
A: 
```bash
# Backend tests (inside Docker - recommended)
docker compose -f docker-compose.minimal.yml exec api pytest tests/ -v

# Backend tests (local development)
cd src/minimal-local
source .venv/bin/activate
pytest backend/tests/ -v

# Frontend tests (when implemented)
docker compose -f docker-compose.minimal.yml exec frontend npm test
```

**Q: Does code hot-reload during development?**  
A: Yes:
- **Backend**: FastAPI auto-reloads on Python file changes
- **Frontend**: Vite HMR (Hot Module Replacement) on React file changes

**Q: How do I add a new API endpoint?**  
A: 
1. Create endpoint in `backend/api/your_module.py`
2. Register router in `backend/main.py`
3. Test at `http://localhost:8000/docs`

**Q: How do I add a new Python dependency?**  
A:

**For Docker (recommended):**
1. Add to `pyproject.toml` in the `dependencies` list
2. Rebuild Docker images: `docker compose -f docker-compose.minimal.yml build api celery_worker celery_beat`
3. Restart services: `docker compose -f docker-compose.minimal.yml up -d`

**For local development:**
1. Add to `pyproject.toml` in the `dependencies` list
2. Activate venv: `source .venv/bin/activate` (from `src/minimal-local/`)
3. Reinstall: `uv pip install -e .`

**Q: How do I debug Celery tasks?**  
A: 
1. View logs: `docker compose logs celery_worker -f`
2. Access container: `docker compose exec celery_worker sh`
3. Run task manually: `python -c "from tasks import your_task; your_task.delay(args)"`

---

## Troubleshooting

### Pipeline Monitoring

**Check if data collection is working:**

```bash
# Check threat count in database
docker compose -f docker-compose.minimal.yml exec postgres \
  psql -U ai_shield -d ai_shield -c "SELECT COUNT(*) as total, MAX(ingested_at) as last_ingested FROM threats;"

# Check if new threats are being added
docker compose -f docker-compose.minimal.yml exec postgres \
  psql -U ai_shield -d ai_shield -c "SELECT COUNT(*) FROM threats WHERE ingested_at > NOW() - INTERVAL '1 hour';"
```

**Check Celery task queue status:**

```bash
# Check number of pending tasks in queue
docker compose -f docker-compose.minimal.yml exec redis redis-cli LLEN celery

# View active tasks
docker compose -f docker-compose.minimal.yml exec celery_worker \
  celery -A tasks inspect active

# View reserved (queued) tasks
docker compose -f docker-compose.minimal.yml exec celery_worker \
  celery -A tasks inspect reserved
```

**If queue is stalled (hundreds of tasks pending):**

```bash
# Option 1: Increase worker concurrency temporarily
# Edit docker-compose.minimal.yml: change --concurrency=12 to --concurrency=16
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d celery_worker

# Option 2: Purge queue and restart (WARNING: loses pending tasks)
docker compose -f docker-compose.minimal.yml exec redis redis-cli FLUSHDB
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart celery_worker
```

### LLM Configuration

**Which LLM is being used?**

The system uses **Ollama** with the **Qwen2.5:7b** model by default.

**Why Qwen2.5:7b?**
- Excellent at technical and security content analysis
- Strong reasoning for extracting attack vectors and mitigations  
- Better structured output than smaller models
- Good balance of quality (~7B parameters) and speed (~4.7GB)

**Where is it configured?**

- **Model selection**: `backend/config.py` → `ollama_model` (default: "qwen2.5:7b")
- **Ollama URL**: `backend/config.py` → `ollama_url` (default: "http://ollama:11434")
- **Timeout**: `backend/config.py` → `ollama_timeout` (default: 60 seconds)

**Change the LLM model:**

```bash
# Option 1: Via environment variable (recommended)
# Add to .env.minimal:
OLLAMA_MODEL=llama3.2:latest

# Option 2: Pull and use a different model
docker compose -f docker-compose.minimal.yml exec ollama ollama pull llama3.2
# Then update OLLAMA_MODEL in .env.minimal
```

**Check if Ollama is working:**

```bash
# Check Ollama health
curl http://localhost:11434/api/tags

# List available models
docker compose -f docker-compose.minimal.yml exec ollama ollama list

# Test model directly
docker compose -f docker-compose.minimal.yml exec ollama \
  ollama run phi3:mini "What is adversarial machine learning?"
```

**LLM analysis is slow or timing out:**

```bash
# Check Ollama logs
docker compose -f docker-compose.minimal.yml --env-file .env.minimal logs ollama -f

# Check CPU/memory usage
docker stats ai-shield-ollama

# Increase timeout in .env.minimal:
OLLAMA_TIMEOUT=120

# Or use a smaller/faster model:
OLLAMA_MODEL=phi3:mini  # Fastest, 3.8GB
# OLLAMA_MODEL=llama3.2:latest  # Slower, better quality
```

### Common Issues

**Issue: No new threats being collected**

```bash
# 1. Check Celery Beat is running (scheduler)
docker compose -f docker-compose.minimal.yml --env-file .env.minimal logs celery_beat --tail 50

# 2. Manually trigger a fetch (using Celery call command)
docker compose -f docker-compose.minimal.yml exec celery_worker \
  celery -A tasks call tasks.scheduled_source_fetch

# 3. Check source configuration
docker compose -f docker-compose.minimal.yml exec celery_worker \
  python -c "from services.source_manager import get_source_manager; m = get_source_manager(); print(m.get_stats())"
```

**Issue: LLM analysis stuck on "pending"**

This usually means:
1. Ollama is down or overloaded
2. Task queue is backed up
3. Worker concurrency is too low

```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Check queue length
docker compose -f docker-compose.minimal.yml exec redis redis-cli LLEN celery

# If queue is large (>100), increase concurrency or purge queue (see above)
```

**Issue: High CPU usage**

```bash
# Check which service is using CPU
docker stats

# Ollama is CPU-intensive - it's limited to 4 cores by default
# To adjust: edit docker-compose.minimal.yml under ollama service:
#   deploy:
#     resources:
#       limits:
#         cpus: '2.0'  # Reduce to 2 cores
#         memory: 4G
```

**Issue: Services won't start**

```bash
# Check for port conflicts
lsof -i :8000  # API
lsof -i :3000  # Frontend
lsof -i :5432  # PostgreSQL
lsof -i :6379  # Redis
lsof -i :11434 # Ollama

# Check logs for specific service
docker compose -f docker-compose.minimal.yml --env-file .env.minimal logs <service-name>

# Restart all services
docker compose -f docker-compose.minimal.yml --env-file .env.minimal restart
```

### Performance Tuning

**Adjust worker concurrency based on your system:**

```bash
# In .env.minimal:
CELERY_WORKER_CONCURRENCY=12

# Guidelines:
# - 4 workers: CPU-only systems (containerized or host Ollama without GPU)
# - 12 workers: Host Ollama with GPU (recommended for Apple Silicon)
# - 16+ workers: High-end systems with powerful GPUs
```

**Adjust Ollama resource limits:**

```yaml
# In docker-compose.minimal.yml, ollama service:
deploy:
  resources:
    limits:
      cpus: '4.0'    # Number of CPU cores
      memory: 4G     # RAM allocation
```

**Schedule adjustments:**

```python
# In backend/tasks.py, beat_schedule:
'fetch-sources-every-6-hours': {
    'task': 'tasks.scheduled_source_fetch',
    'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours (default)
    # Change to: crontab(minute=0)  # Every hour
    # Or: crontab(minute=0, hour='*/12')  # Every 12 hours
    # Or: crontab(minute=0, hour=9)  # Once daily at 9 AM
}
```

---

## Support

For issues, questions, or contributions:

1. Check the FAQ section above
2. Check the troubleshooting section
3. Review logs: `docker compose -f docker-compose.minimal.yml logs`
4. Check service health: `curl http://localhost:8000/api/v1/health`
5. Consult the main project documentation

## License

See LICENSE file in the project root.
