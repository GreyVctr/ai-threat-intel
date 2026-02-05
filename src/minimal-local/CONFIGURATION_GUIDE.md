# AI Shield Intelligence - Configuration Guide

## Quick Answers to Common Questions

### 1. Where do I set the Ollama model?

You can set the Ollama model in **two ways**:

#### Option A: Environment Variable (Recommended)

Add to your `.env.minimal` file:

```bash
# Ollama LLM Model
OLLAMA_MODEL=qwen2.5:7b
```

**Available models:**
- `qwen2.5:7b` - **Recommended** - Best balance of quality and speed (4.7GB)
- `phi3:mini` - Faster but lower quality (2.3GB)
- `qwen2.5:14b` - Higher quality but slower (8.9GB)
- `qwen2.5:32b` - Highest quality but very slow (20GB)

After changing, restart the services:
```bash
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build api celery_worker
```

#### Option B: Direct Code Edit

Edit `src/minimal-local/backend/config.py`:

```python
ollama_model: str = Field(
    default="qwen2.5:7b",  # ← Change this
    description="Default Ollama model for analysis"
)
```

Then rebuild:
```bash
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build api celery_worker
```

**Don't forget to pull the new model:**
```bash
docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec ollama ollama pull <model-name>
```

---

### 2. What's the difference between development and production environments?

Set via `ENVIRONMENT` in `.env.minimal`:

#### Development Mode (default)
```bash
ENVIRONMENT=development
```

**Characteristics:**
- **Security**: Relaxed validation - allows default passwords for testing
- **Logging**: Verbose text-based logs for easy debugging
- **Hot Reload**: FastAPI auto-reloads on code changes
- **Warnings**: Shows configuration warnings instead of errors
- **CORS**: Permissive CORS for local development
- **Error Details**: Full stack traces in API responses

**Use when:**
- Local development and testing
- Learning the system
- Debugging issues
- Running on your laptop/desktop

#### Production Mode
```bash
ENVIRONMENT=production
```

**Characteristics:**
- **Security**: Strict validation - enforces strong passwords, rejects defaults
- **Logging**: Structured JSON logs for log aggregation (ELK, Splunk, etc.)
- **Hot Reload**: Disabled for stability
- **Warnings**: Configuration issues cause startup failures
- **CORS**: Restricted to configured origins only
- **Error Details**: Sanitized error messages (no stack traces)

**Use when:**
- Deploying to servers
- Production environments
- Shared/team deployments
- Security-sensitive contexts

**Example Production Validation:**
```python
# These will FAIL in production mode:
POSTGRES_PASSWORD=changeme  # ❌ Contains "changeme"
JWT_SECRET_KEY=changeme_jwt_secret_key_for_production  # ❌ Default value
MINIO_ACCESS_KEY=minioadmin  # ❌ Default value

# These will PASS:
POSTGRES_PASSWORD=MyS3cur3P@ssw0rd!2024  # ✅ Strong password
JWT_SECRET_KEY=randomly-generated-secret-key-here  # ✅ Custom value
MINIO_ACCESS_KEY=my-custom-access-key  # ✅ Custom value
```

---

### 3. Should we adjust the collection schedule to avoid processing backlog?

**Great observation!** Yes, you should adjust the schedule based on your processing capacity.

#### Current Situation Analysis

**Your metrics:**
- **Ingestion rate**: 102.4 threats/hour
- **Processing rate**: 8-16 threats/minute = 480-960 threats/hour
- **Current backlog**: 2,433 pending LLM analyses
- **Collection frequency**: Every hour

**Verdict**: You're processing **faster** than collecting (480-960/hr processed vs 102/hr collected), so the backlog will clear over time. However, the initial backlog of 2,433 will take:
- At 8/min: 2433 ÷ 8 = **~5 hours** to clear
- At 16/min: 2433 ÷ 16 = **~2.5 hours** to clear

#### Recommendations

##### Option 1: Keep Hourly, Let Backlog Clear (Recommended)

Since you're processing faster than collecting, the backlog will naturally clear. Just be patient:

```python
# Keep current schedule in tasks.py
'schedule': crontab(minute=0),  # Every hour
```

**Timeline:**
- Hour 1: Process 480-960, collect 102 → backlog decreases by 378-858
- Hour 2: Process 480-960, collect 102 → backlog decreases by 378-858
- Hour 3-5: Backlog fully cleared

##### Option 2: Reduce Collection Frequency Temporarily

If you want to clear the backlog faster without new data coming in:

```python
# Change to every 6 hours in tasks.py
'schedule': crontab(minute=0, hour='*/6'),
```

This gives you 6 hours to process the backlog before new data arrives.

##### Option 3: Increase Processing Speed

**Increase worker concurrency** in `docker-compose.minimal.yml`:

```yaml
celery_worker:
  command: celery -A tasks worker --loglevel=info --concurrency=16
```

This doubles your processing capacity to 16-32 threats/minute.

**Or use a faster model** in `.env.minimal`:

```bash
OLLAMA_MODEL=phi3:mini  # 2x faster, but lower quality
```

##### Option 4: Disable LLM Analysis Temporarily

LLM analysis is optional - threats are still enriched with:
- Classification (threat type)
- Entity extraction (CVEs, frameworks, techniques)
- MITRE ATLAS mappings
- Severity scoring

To pause LLM processing and clear the backlog later:

```bash
# Stop celery worker
docker compose -f docker-compose.minimal.yml --env-file .env.minimal stop celery_worker

# Restart when ready to process backlog
docker compose -f docker-compose.minimal.yml --env-file .env.minimal start celery_worker
```

#### Processing Capacity Calculator

Use this formula to determine if you need to adjust:

```
Processing Capacity (per hour) = Workers × Threats/min × 60
Collection Rate (per hour) = Threats collected per run × Runs per hour

If Processing Capacity > Collection Rate → You're fine
If Processing Capacity < Collection Rate → Adjust schedule or increase workers
```

**Your numbers:**
```
Processing: 8 workers × 8-16 threats/min × 60 = 3,840-7,680 per hour
Collection: 102 threats × 1 run/6 hours = 17 per hour (averaged)

3,840 > 17 ✅ You're processing 225x faster than collecting!
```

#### Recommended Schedule Based on Collection Rate

| Collection Rate | Recommended Schedule | Reasoning |
|----------------|---------------------|-----------|
| < 100/hour | `crontab(minute=0, hour='*/6')` (every 6 hours) | Default - plenty of processing time |
| 100-500/hour | `crontab(minute=0, hour='*/2')` (every 2 hours) | Still manageable with 8 workers |
| 500-1000/hour | `crontab(minute=0)` (hourly) | Need more frequent processing |
| 1000-3000/hour | `crontab(minute='*/30')` (every 30 min) | High volume, frequent processing |
| > 3000/hour | `crontab(minute='*/15')` (every 15 min) | Or increase to 16+ workers |

#### How to Change the Schedule

1. **Edit** `src/minimal-local/backend/tasks.py` (line ~70):
   ```python
   beat_schedule={
       'fetch-sources-every-6-hours': {
           'task': 'tasks.scheduled_source_fetch',
           'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours (default)
           'options': {'expires': 21000}
       },
   }
   ```

2. **Rebuild and restart**:
   ```bash
   cd src/minimal-local
   docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build celery_worker celery_beat
   ```

3. **Verify**:
   ```bash
   docker compose -f docker-compose.minimal.yml logs celery_beat | grep -i schedule
   ```

---

## Summary

1. **Ollama Model**: Set via `OLLAMA_MODEL` in `.env.minimal` (recommended: `qwen2.5:7b`)
2. **Environment Mode**: 
   - `development` = relaxed security, verbose logs, hot-reload
   - `production` = strict security, JSON logs, no hot-reload
3. **Collection Schedule**: Changed to every 6 hours (default) to prevent backlog. You're processing 225x faster than collecting.

## Quick Reference Commands

```bash
# Change Ollama model
echo "OLLAMA_MODEL=qwen2.5:7b" >> .env.minimal
docker compose -f docker-compose.minimal.yml --env-file .env.minimal up -d --build api celery_worker
docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec ollama ollama pull qwen2.5:7b

# Check processing status
curl -s http://localhost:8000/api/v1/system/status | python3 -m json.tool

# Monitor Ollama resource usage
docker stats --no-stream ai-shield-ollama

# Check backlog
docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec postgres psql -U ai_shield -d ai_shield -c "SELECT COUNT(*) FROM llm_analysis;"

# Manually trigger collection
docker compose -f docker-compose.minimal.yml --env-file .env.minimal exec celery_worker python -c "from tasks import scheduled_source_fetch; scheduled_source_fetch.delay()"
```
